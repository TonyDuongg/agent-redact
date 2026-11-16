import type { RedactPattern } from '../core/types.js';

/*
 * Context-aware generic secrets: values that have no vendor prefix but sit in a context that
 * makes them secret (.npmrc, .netrc, Docker config.json, quoted password assignments, UPPERCASE
 * .env keys, Kubernetes Secret manifests). Each pattern redacts only the value (secretGroup),
 * never the key, and a validator drops placeholders, templates and environment references.
 *
 * Performance and ReDoS notes: the key patterns start at the keyword itself, so most positions
 * fail on the first character, and `(?![\w.-])` pins the keyword to the end of the key name.
 * Line-start context is checked with a lookbehind only after the `=` lookahead has passed, so
 * the backward scan runs at most once per assignment. tests/perf.test.ts holds the adversarial
 * inputs.
 */

const MIN_SECRET_LENGTH = 8;

/** Values that point at a secret instead of containing one */
const REFERENCE_HINT =
  /\$\{|\$\(|^\$[A-Za-z_]|^%[A-Za-z_]\w*%$|\{\{|\{%|<%|`|process\.env|import\.meta\.env|os\.environ|getenv\s*\(|Deno\.env/i;
/** Documentation and template placeholders, masked values and our own placeholders */
const PLACEHOLDER_HINT =
  /^<.*>$|^\[.*\]$|^your[-_ ]|[-_ ]here$|example|placeholder|change[-_]?me|changeit|dummy|redacted|x{4,}|\*{3,}|•{3,}|\.{3}|…/i;
const DUMMY_WORD = /^(?:password|passwd|secret|undefined|null|none|nil|true|false)$/i;
const SINGLE_REPEATED_CHAR = /^(.)\1*$/s;

/**
 * True when `value` could be a real secret: at least 8 characters, and not a reference
 * (`${VAR}`, `$VAR`, `process.env.X`, `os.environ[...]`), a template (`{{ ... }}`), a
 * placeholder (`<your-key>`, `changeme`, `xxxx`, `****`, `...`) or a literal like `null`.
 */
export function isPlausibleSecretValue(value: string): boolean {
  if (value.length < MIN_SECRET_LENGTH) return false;
  if (SINGLE_REPEATED_CHAR.test(value)) return false;
  return !REFERENCE_HINT.test(value) && !PLACEHOLDER_HINT.test(value) && !DUMMY_WORD.test(value);
}

/** A lowercase identifier or member access such as `default_auth` or `self.password` */
const CODE_IDENTIFIER = /^[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*$/;

/**
 * Values of .npmrc `_authToken`, `_auth` and `_password` (registry-scoped or global).
 */
export const npmrcAuthPattern: RedactPattern = {
  id: 'npmrc-auth',
  name: 'npm Registry Credential (.npmrc)',
  category: 'credential',
  severity: 'critical',
  // '#' and ';' stay in the value: cutting there could leave the rest of a token visible
  regex: /^[ \t]*(?:\/\/[^\s=]*:)?(?:_authToken|_auth|_password)[ \t]*=[ \t]*["']?([^\s"']+)/gm,
  secretGroup: 1,
  validator: (v) => isPlausibleSecretValue(v) && !/[()]/.test(v) && !CODE_IDENTIFIER.test(v),
  placeholder: 'NPMRC_AUTH',
  description: '.npmrc _authToken, _auth or _password value'
};

/**
 * Password of a .netrc entry (`machine <host> login <user> password <secret>`), on one line or
 * several. Keywords are lowercase, as netrc requires.
 */
export const netrcPasswordPattern: RedactPattern = {
  id: 'netrc-password',
  name: 'netrc Password',
  category: 'credential',
  severity: 'high',
  regex: /(?<!\S)(?:machine[ \t]+\S+|default)(?:\s+(?:login|account|port)[ \t]+\S+)*\s+password[ \t]+(\S+)/g,
  secretGroup: 1,
  validator: isPlausibleSecretValue,
  placeholder: 'NETRC_PASSWORD',
  description: 'Password of a .netrc machine or default entry'
};

/** True when `value` is base64 of printable ASCII `user:password` (Docker's "auth" field) */
function isBase64UserPassword(value: string): boolean {
  let decoded: string;
  try {
    decoded = atob(value);
  } catch {
    return false;
  }
  const colon = decoded.indexOf(':');
  return /^[\x20-\x7e]+$/.test(decoded) && colon > 0 && colon < decoded.length - 1;
}

/**
 * Docker / Podman config.json registry credentials: `"auth": "<base64 user:password>"`.
 */
export const dockerConfigAuthPattern: RedactPattern = {
  id: 'docker-config-auth',
  name: 'Docker Registry Auth (config.json)',
  category: 'credential',
  severity: 'high',
  regex: /"auth"[ \t]*:[ \t]*"([A-Za-z0-9+/]{8,}={0,2})"/g,
  secretGroup: 1,
  validator: isBase64UserPassword,
  placeholder: 'DOCKER_AUTH',
  description: 'Base64 user:password in a Docker config.json "auth" field'
};

/**
 * .env style lines whose UPPERCASE key ends in PASSWORD, PASSWD, SECRET, TOKEN, API_KEY or
 * SECRET_KEY (optionally followed by a short number): `DB_PASSWORD=...`, `export JWT_SECRET="..."`,
 * docker-compose `- POSTGRES_PASSWORD=...`, Dockerfile `ENV APP_TOKEN=...`.
 * Unquoted values must follow `=` directly, so code such as `API_TOKEN = get_token()` is skipped.
 * Like dotenv, an unquoted value runs to the end of the line or a ` #` comment, spaces included,
 * so no word of it is left visible.
 */
export const dotenvSecretPattern: RedactPattern = {
  id: 'dotenv-secret',
  name: 'Secret in .env Assignment',
  category: 'credential',
  severity: 'high',
  regex:
    /(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|SECRET_(?:ACCESS_)?KEY(?:_BASE)?)(?:_?[0-9]{1,3})?(?=[ \t]*=)(?<=^[ \t]*(?:-[ \t]+)?(?:(?:export|ENV|ARG|set|SET)[ \t]+)?[A-Z][A-Z0-9_]*)[ \t]*=[ \t]*["']?((?<=")(?:[^"\\\r\n]|\\.)+(?=")|(?<=')[^'\r\n]+(?=')|(?<==)\S+(?:[ \t]+(?!#)\S+)*)/gm,
  secretGroup: 1,
  validator: isPlausibleSecretValue,
  placeholder: 'ENV_SECRET',
  description: 'Value of an UPPERCASE PASSWORD / SECRET / TOKEN / API_KEY variable'
};

/**
 * Letters-only values (words joined by - _ . ?) such as "refresh_token", "X-Secret-Header",
 * "Passwort" or "?InterpolationInTemplate" are field names, labels or lexer states assigned to
 * token-named variables, not secrets. Generated tokens almost always contain a digit or a
 * symbol: only ~3% of random 20-character base62 tokens (~0.4% at 32) have none. No case-based
 * "looks random" exception is made: CamelCase names with short words flip case as often as
 * random text, so any such threshold produced both false positives and misses.
 */
function isNameLike(value: string): boolean {
  return /^\??\p{L}+(?:[-_.]\p{L}+)*$/u.test(value);
}

/**
 * Quoted values assigned to password-like keys in code and config (JSON, YAML, TOML, XML
 * attributes, Python/JS/PHP/Go): `password: "..."`, `"client_secret": "..."`, `db_pass = '...'`.
 * Also matches JSON embedded in a JSON string (`\"password\": \"...\"`). Backslash escapes and
 * YAML's '' escape stay inside the value. Unquoted values are never matched, so
 * `password = get_pw()` is not a finding.
 */
export const quotedSecretAssignmentPattern: RedactPattern = {
  id: 'quoted-secret-assignment',
  name: 'Quoted Secret Assignment',
  category: 'credential',
  severity: 'high',
  // Starts at the keyword (cheap to scan for); (?![\w.-]) makes it the end of the key name
  regex:
    /(?:password|passwd|passphrase|[_.-]pass|secret|secret[_.-]?key|api[_.-]?key|token)(?![\w.-])(?<!(?:page|next|prev|sync|continuation|cancellation|csrf|xsrf|cursor|resume|bos|eos|pad|unk|sep|cls|mask|stop)[_.-]?token)\\?["']?[ \t]*(?:=>|:=|[:=])[ \t]*\\?["']((?<=\\")[^"\\\r\n]+(?=\\")|(?<=")(?:[^"\\\r\n]|\\.)+(?=")|(?<=')(?:[^'\\\r\n]|\\.|'')+(?='))/gi,
  secretGroup: 1,
  // No whitespace (UI labels and messages) and no letters-only names (see isNameLike)
  validator: (v) => isPlausibleSecretValue(v) && !/\s/.test(v) && !isNameLike(v),
  placeholder: 'QUOTED_SECRET',
  description: 'Quoted value assigned to a password, secret, token or API key'
};

/* ------------------------------------------------------------------------------------------
 * Kubernetes Secret manifests (YAML). A regex cannot tie a `data:` value to a `kind: Secret`
 * line that may come before or after it (`kubectl get -o yaml` sorts keys, so data comes
 * first), so this pattern uses a structural detector over a line table.
 * Cost is linear: every scan visits only non-blank lines whose indent is at least the mapping
 * column, and mappings at one column are disjoint, so a line is visited at most once per
 * column to its left.
 * ---------------------------------------------------------------------------------------- */

const KIND_SECRET_LINE = /^kind[ \t]*:[ \t]*(["']?)Secret\1[ \t]*(?:#.*)?$/;
const DATA_KEY_LINE = /^(?:data|stringData)[ \t]*:(?=[ \t]|$)/;

interface LineTable {
  start: number[];
  end: number[];
  /** Leading spaces */
  indent: number[];
  /** Column where the mapping content starts, after any "- " sequence markers */
  col: number[];
  blank: boolean[];
  boundary: boolean[];
  /** Index of the next line at or after i that is not blank (n when none) */
  nextFilled: number[];
}

function buildLineTable(text: string): LineTable {
  const t: LineTable = { start: [], end: [], indent: [], col: [], blank: [], boundary: [], nextFilled: [] };
  let pos = 0;
  for (;;) {
    let nl = text.indexOf('\n', pos);
    if (nl === -1) nl = text.length;
    let end = nl;
    if (end > pos && text.charCodeAt(end - 1) === 13) end--;
    let i = pos;
    while (i < end && text.charCodeAt(i) === 32) i++;
    const indent = i - pos;
    const blank = i >= end || text.charCodeAt(i) === 35; // empty or "# comment"
    const boundary =
      indent === 0 &&
      ((text.startsWith('---', pos) && (end - pos === 3 || /\s/.test(text[pos + 3] ?? ''))) ||
        (end - pos === 3 && text.startsWith('...', pos)));
    // "- " markers (possibly several: "- - key: v") open a mapping inside a sequence item
    while (
      i < end &&
      text.charCodeAt(i) === 45 &&
      (i + 1 === end || text.charCodeAt(i + 1) === 32 || text.charCodeAt(i + 1) === 9)
    ) {
      i++;
      while (i < end && (text.charCodeAt(i) === 32 || text.charCodeAt(i) === 9)) i++;
    }
    t.start.push(pos);
    t.end.push(end);
    t.indent.push(indent);
    t.col.push(i - pos);
    t.blank.push(blank);
    t.boundary.push(boundary);
    if (nl === text.length) break;
    pos = nl + 1;
  }
  const n = t.start.length;
  t.nextFilled = new Array<number>(n + 1);
  t.nextFilled[n] = n;
  for (let k = n - 1; k >= 0; k--) t.nextFilled[k] = t.blank[k] ? t.nextFilled[k + 1]! : k;
  return t;
}

/** End offset of a double- or single-quoted YAML scalar opened at `open`, or -1 if not closed on the line */
function closingQuote(text: string, open: number, end: number): number {
  const q = text.charCodeAt(open);
  for (let i = open + 1; i < end; i++) {
    const c = text.charCodeAt(i);
    if (q === 34 && c === 92) {
      i++; // backslash escape in "..."
    } else if (c === q) {
      if (q === 39 && text.charCodeAt(i + 1) === 39) {
        i++; // '' escape in '...'
        continue;
      }
      return i;
    }
  }
  return -1;
}

/** Offset just after the "key:" of a mapping entry starting at `p`, or -1 when the line has no key */
function afterKey(text: string, p: number, end: number): number {
  let i = p;
  const c = text.charCodeAt(p);
  if (c === 34 || c === 39) {
    const close = closingQuote(text, p, end);
    if (close === -1) return -1;
    i = close + 1;
    while (i < end && (text.charCodeAt(i) === 32 || text.charCodeAt(i) === 9)) i++;
    return i < end && text.charCodeAt(i) === 58 ? i + 1 : -1;
  }
  for (;;) {
    const colon = text.indexOf(':', i);
    if (colon === -1 || colon >= end) return -1;
    const next = text.charCodeAt(colon + 1);
    if (colon + 1 === end || next === 32 || next === 9) return colon + 1;
    i = colon + 1;
  }
}

function detectKubernetesSecretValues(text: string): Array<[number, number]> {
  const t = buildLineTable(text);
  const n = t.start.length;
  const spans: Array<[number, number]> = [];
  /** Last line already covered by a processed mapping, per mapping column */
  const doneUntil = new Map<number, number>();

  const contentStart = (k: number) => t.start[k]! + t.col[k]!;
  /** Last non-blank line after `from` whose indent is greater than `indent` (contiguous) */
  const lastDeeper = (from: number, indent: number): number => {
    let last = from;
    for (let j = t.nextFilled[from + 1]!; j < n; j = t.nextFilled[j + 1]!) {
      if (t.boundary[j] || t.indent[j]! <= indent) break;
      last = j;
    }
    return last;
  };

  for (let k = t.nextFilled[0]!; k < n; k = t.nextFilled[k + 1]!) {
    const c = t.col[k]!;
    const s = contentStart(k);
    if (!text.startsWith('kind', s) || !KIND_SECRET_LINE.test(text.slice(s, t.end[k]))) continue;
    if ((doneUntil.get(c) ?? -1) >= k) continue;

    // Bounds of the mapping that holds this "kind: Secret" line
    let a = k;
    if (t.indent[k] === c) {
      for (let j = k - 1; j >= 0; j--) {
        if (t.boundary[j]) break;
        if (t.blank[j]) continue;
        if (t.indent[j]! >= c) {
          a = j;
          continue;
        }
        if (t.col[j] === c) a = j; // the "- key:" line that opens this sequence item
        break;
      }
    }
    let b = k;
    for (let j = t.nextFilled[k + 1]!; j < n; j = t.nextFilled[j + 1]!) {
      if (t.boundary[j] || t.indent[j]! < c) break;
      b = j;
    }
    doneUntil.set(c, b);

    for (let d = a; d <= b; d = t.nextFilled[d + 1]!) {
      if (t.col[d] !== c || (t.indent[d] !== c && d !== a)) continue;
      const ds = contentStart(d);
      const key = DATA_KEY_LINE.exec(text.slice(ds, t.end[d]));
      if (!key) continue;
      const blockEnd = lastDeeper(d, c);

      // Inline value after "data:" (a flow map such as {k: v}): redact it whole, with any
      // continuation lines (fail closed)
      let v = ds + key[0].length;
      while (v < t.end[d]! && (text.charCodeAt(v) === 32 || text.charCodeAt(v) === 9)) v++;
      if (v < t.end[d]! && text.charCodeAt(v) !== 35) {
        spans.push([v, t.end[blockEnd]!]);
        continue;
      }

      // Block mapping: one span per entry value
      for (let j = t.nextFilled[d + 1]!; j <= blockEnd && j < n; j = t.nextFilled[j + 1]!) {
        const entryIndent = t.indent[j]!;
        const last = lastDeeper(j, entryIndent);
        const p = t.start[j]! + t.col[j]!;
        const lineEnd = t.end[j]!;
        const colonEnd = t.col[j] === entryIndent ? afterKey(text, p, lineEnd) : -1;
        if (colonEnd === -1) {
          // Not a "key: value" line (sequence item or stray text): redact it whole
          spans.push([p, t.end[last]!]);
          j = last;
          continue;
        }
        let vs = colonEnd;
        while (vs < lineEnd && (text.charCodeAt(vs) === 32 || text.charCodeAt(vs) === 9)) vs++;
        const ch = text.charCodeAt(vs);
        if (vs >= lineEnd || ch === 35 || ch === 124 || ch === 62) {
          // Empty, "# comment", or a block scalar header (| or >): the value is on the deeper lines
          if (last > j) {
            const first = t.nextFilled[j + 1]!;
            spans.push([t.start[first]! + t.indent[first]!, t.end[last]!]);
          }
        } else if (ch === 34 || ch === 39) {
          const close = closingQuote(text, vs, lineEnd);
          spans.push([vs + 1, close === -1 ? t.end[last]! : close]);
        } else if (last > j) {
          spans.push([vs, t.end[last]!]); // multi-line plain scalar
        } else {
          let e = lineEnd;
          const comment = text.slice(vs, lineEnd).search(/[ \t]#/);
          if (comment !== -1) e = vs + comment;
          while (e > vs && (text.charCodeAt(e - 1) === 32 || text.charCodeAt(e - 1) === 9)) e--;
          spans.push([vs, e]);
        }
        j = last;
      }
    }
  }
  return spans;
}

/**
 * Values under `data:` / `stringData:` of YAML documents with `kind: Secret`, including
 * Secrets inside a `kind: List` (`kubectl get secrets -o yaml`). Templated values
 * (`{{ .Values.x }}`) are skipped.
 */
export const kubernetesSecretPattern: RedactPattern = {
  id: 'kubernetes-secret',
  name: 'Kubernetes Secret Value',
  category: 'credential',
  severity: 'high',
  // Gate only: the values are found by `detect`
  regex: /^[ \t]*(?:-[ \t]+)*kind[ \t]*:[ \t]*["']?Secret["']?[ \t]*(?:#.*)?\r?$/m,
  detect: detectKubernetesSecretValues,
  // Skip templates and our own placeholders, so redacted output is never redacted again
  validator: (v) => v.trim().length > 0 && !/\{\{|\$\{|\{%/.test(v) && !/^\[[A-Z][A-Z0-9_]*\]$/.test(v.trim()),
  placeholder: 'K8S_SECRET_VALUE',
  description: 'Value under data/stringData of a Kubernetes Secret manifest'
};

/**
 * Context-aware patterns, on by default. Order matters only for ties (same severity and span):
 * vendor patterns come first in DEFAULT_PATTERNS, then .env keys before quoted assignments.
 */
export const CONTEXT_PATTERNS: RedactPattern[] = [
  npmrcAuthPattern,
  netrcPasswordPattern,
  dockerConfigAuthPattern,
  dotenvSecretPattern,
  quotedSecretAssignmentPattern,
  kubernetesSecretPattern
];
