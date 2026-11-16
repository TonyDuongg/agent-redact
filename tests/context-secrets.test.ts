import { describe, it, expect } from 'vitest';
import { redact, Vault, unmask, DEFAULT_PATTERNS } from '../src/index.js';

/*
 * Context-aware generic secrets (on by default): .npmrc, .netrc, Docker config.json,
 * quoted secret assignments, UPPERCASE .env keys and Kubernetes Secret manifests.
 * Every value is assembled at runtime so nothing token-shaped is committed.
 */
const j = (...p: string[]) => p.join('');
const b64 = (s: string) => Buffer.from(s, 'utf-8').toString('base64');
// Mixed-case values that match no vendor pattern
const P = j('Zx8', 'vQ2mT7pL', 'k4Rw');
const P2 = j('Hy3', 'nB6cW9qD', 'e1Fs', 'Ug5');

function found(text: string, id: string): string[] {
  return redact(text, { includeMatchedText: true })
    .matches.filter((m) => m.patternId === id)
    .map((m) => m.matchedText!);
}

function all(text: string): string[] {
  return redact(text, { includeMatchedText: true }).matches.map((m) => `${m.patternId}: ${m.matchedText}`);
}

describe('npmrc-auth', () => {
  it('redacts _authToken, _auth and _password values with and without a registry scope', () => {
    const auth = b64(j('deploy', ':', P));
    expect(found(`//registry.npmjs.org/:_authToken=${P}\n`, 'npmrc-auth')).toEqual([P]);
    expect(found(`//npm.pkg.github.com/:_authToken="${P2}"\n`, 'npmrc-auth')).toEqual([P2]);
    expect(found(`_auth=${auth}\nalways-auth=true\n`, 'npmrc-auth')).toEqual([auth]);
    expect(found(`//nexus.internal/repo/:_password = ${auth}\r\n`, 'npmrc-auth')).toEqual([auth]);
    expect(redact(`//registry.npmjs.org/:_authToken=${P}\n`).text).toBe('//registry.npmjs.org/:_authToken=[REDACTED_NPMRC_AUTH]\n');
  });

  it('ignores environment references, code and short values', () => {
    for (const text of [
      '//registry.npmjs.org/:_authToken=${NPM_TOKEN}',
      '//registry.npmjs.org/:_authToken=$NPM_TOKEN',
      '_auth = getAuth(config)',
      '_password = self.password',
      '_auth = default_auth_value',
      '_authToken=abc123'
    ]) {
      expect(all(text), text).toEqual([]);
    }
  });
});

describe('netrc-password', () => {
  it('redacts the password of single-line, multi-line and default entries', () => {
    expect(found(`machine api.example.com login bob password ${P}\n`, 'netrc-password')).toEqual([P]);
    expect(found(`machine git.example.com\n  login bob\n  password ${P}\n`, 'netrc-password')).toEqual([P]);
    expect(found(`default login anonymous password ${P2}`, 'netrc-password')).toEqual([P2]);
    expect(found(`machine a.example login x password ${P} machine b.example login y password ${P2}`, 'netrc-password')).toEqual([P, P2]);
    expect(found(`machine h.example password ${P} login z`, 'netrc-password')).toEqual([P]);
  });

  it('ignores prose and environment references', () => {
    for (const text of [
      'The machine name, login and password are stored in ~/.netrc',
      'Each machine entry has login and password fields',
      'machine learning login password reset flow',
      'machine example.com login user password ${NETRC_PASSWORD}',
      'machine example.com login user password <password>'
    ]) {
      expect(all(text), text).toEqual([]);
    }
  });
});

describe('docker-config-auth', () => {
  it('redacts base64 user:password values in config.json', () => {
    const auth = b64(j('octocat', ':', P));
    const cfg = JSON.stringify({ auths: { 'ghcr.io': { auth } } }, null, 2);
    expect(found(cfg, 'docker-config-auth')).toEqual([auth]);
    expect(found(`{"auths":{"registry.example":{"auth":"${auth}"}}}`, 'docker-config-auth')).toEqual([auth]);
  });

  it('ignores "auth" values that are not base64 user:password', () => {
    for (const text of ['{"auth": "required"}', '{"auth": "bearer"}', '{"auth": "dGVzdGluZ3Rlc3Rpbmc="}', '{"auth": ""}']) {
      expect(all(text), text).toEqual([]);
    }
  });
});

describe('quoted-secret-assignment', () => {
  it('redacts quoted values of password / secret / token / api key assignments', () => {
    const cases: Array<[string, string]> = [
      [`password: "${P}"`, P],
      [`"client_secret": "${P}"`, P],
      [`db_pass = '${P}'`, P],
      [`apiKey: '${P2}'`, P2],
      [`'password' => "${P}",`, P],
      [`secret_key = "${P2}"`, P2],
      [`"{\\"password\\": \\"${P}\\"}"`, P],
      [`Password := "${P}"`, P],
      [`connect(host="db", password="${P}")`, P],
      [`<add name="smtp" password="${P2}" />`, P2],
      [`access_token = "${P}"`, P],
      [`"passphrase": "${P2}"`, P2]
    ];
    for (const [text, value] of cases) {
      expect(found(text, 'quoted-secret-assignment'), text).toEqual([value]);
    }
  });

  it('skips letters-only values (names, labels, lexer states); one digit or symbol is enough', () => {
    for (const value of [
      'refresh_token',
      'X-Secret-Header',
      '?InterpolationInTemplate',
      '?NoLineTerminatorHere',
      'XMLHttpRequestJSONParser',
      'different',
      // Known limitation: a letters-only random token is skipped in quoted assignments...
      j('kJhGfDsA', 'qWeRtYuI', 'oPlMnB')
    ]) {
      expect(all(`token = "${value}"`), value).toEqual([]);
    }
    expect(found(`token = "${j('kJhGfDsA', 'qWeRtYuI', 'oPlMnB', '7')}"`, 'quoted-secret-assignment')).toHaveLength(1);
    expect(found(`token = "${j('kJhGfDsA', '+', 'qWeRtYuI')}"`, 'quoted-secret-assignment')).toHaveLength(1);
    // ...but still caught as an UPPERCASE .env value
    expect(found(`API_TOKEN=${j('kJhGfDsA', 'qWeRtYuI', 'oPlMnB')}`, 'dotenv-secret')).toHaveLength(1);
  });

  it('keeps escaped quotes inside the value (full span)', () => {
    const value = j('ab', '\\"', 'cd', P);
    expect(found(`{"password": "${value}"}`, 'quoted-secret-assignment')).toEqual([value]);
  });

  it('redacts only the value, never the key', () => {
    expect(redact(`password: "${P}"`).text).toBe('password: "[REDACTED_QUOTED_SECRET]"');
  });

  it('does not match unquoted code assignments, comparisons or labels', () => {
    for (const text of [
      'password = get_pw()',
      'password = os.environ["DB_PASSWORD"]',
      'password: process.env.DB_PASSWORD',
      'const password = await readSecret("db")',
      'if (password === "hunter2hunter2") {}',
      'if password == "hunter2hunter2":',
      '<input type="password" autocomplete="new-password">',
      '"password_hint": "your first pet"',
      '"next_page_token": "CAESBgoEOgIIAQ"',
      '"eos_token": "<|endoftext|>"'
    ]) {
      expect(all(text), text).toEqual([]);
    }
  });

  it('rejects placeholder and template values', () => {
    for (const value of [
      '${DB_PASSWORD}',
      '$DB_PASSWORD',
      '%DB_PASSWORD%',
      '<your-password>',
      'your_api_key_here',
      'changeme',
      'change-me-please',
      '********',
      'xxxxxxxxxxxx',
      'sk-ant-...',
      'null',
      'undefined',
      'password',
      '{{ .Values.db.password }}',
      '{{ secrets.DB_PASSWORD }}',
      'process.env.DB_PASSWORD',
      'example-password-123',
      'Forgot your password?',
      'Passwort',
      '[REDACTED_QUOTED_SECRET]',
      '[QUOTED_SECRET_1]',
      'short'
    ]) {
      expect(all(`password: "${value}"`), value).toEqual([]);
    }
  });
});

describe('dotenv-secret', () => {
  it('redacts values of UPPERCASE keys containing PASSWORD / PASSWD / SECRET / TOKEN / API_KEY', () => {
    const cases: Array<[string, string]> = [
      [`DB_PASSWORD=${P}\n`, P],
      [`MYSQL_ROOT_PASSWD=${P}`, P],
      [`JWT_SECRET='${P}'`, P],
      [`export SLACK_WEBHOOK_TOKEN="${P}"`, P],
      [`STRIPE_API_KEY=${P2}`, P2],
      [`SECRET_KEY_BASE=${P}`, P],
      [`APP_SECRET_2=${P}`, P],
      [`  - POSTGRES_PASSWORD=${P}`, P],
      [`ENV APP_TOKEN=${P}`, P],
      [`SESSION_SECRET="${j('pass ', 'phrase ', P)}"`, j('pass ', 'phrase ', P)],
      [`DB_PASSWORD=${P}\r\nNEXT=1`, P],
      // UPPERCASE constants with a quoted value (Python settings) are hardcoded secrets too
      [`SECRET_KEY = "${P2}"`, P2],
      // lowercase-only real passwords are common in .env files
      [`POSTGRES_PASSWORD=supersecretpassword`, 'supersecretpassword']
    ];
    for (const [text, value] of cases) {
      expect(found(text, 'dotenv-secret'), text).toEqual([value]);
    }
  });

  it('redacts each line of a .env file and keeps the keys', () => {
    const env = [`DB_HOST=localhost`, `DB_PASSWORD=${P}`, `API_TOKEN=${P2}`, `DEBUG=true`].join('\n');
    expect(redact(env).text).toBe(
      ['DB_HOST=localhost', 'DB_PASSWORD=[REDACTED_ENV_SECRET]', 'API_TOKEN=[REDACTED_ENV_SECRET]', 'DEBUG=true'].join('\n')
    );
  });

  it('ignores references, code, non-secret suffixes and lowercase keys', () => {
    for (const text of [
      'DB_PASSWORD=${DB_PASSWORD}',
      'DB_PASSWORD=$DB_PASSWORD',
      'DB_PASSWORD=$(cat /run/secrets/db)',
      'DB_PASSWORD=<your-password>',
      'DB_PASSWORD=changeme',
      'DB_PASSWORD=',
      'DB_PASSWORD=********',
      'API_TOKEN = get_token()',
      'SECRET_KEY = os.environ["SECRET_KEY"]',
      'TOKEN_URL=https://oauth2.example.com/token',
      'PASSWORD_MIN_LENGTH=12',
      'MAX_TOKENS=4096',
      'GITHUB_TOKEN=${{ secrets.GITHUB_TOKEN }}',
      'db_password=notmatchedbythisrule'
    ]) {
      expect(all(text), text).toEqual([]);
    }
  });

  it('defers to a vendor pattern for the same value', () => {
    const ghp = j('ghp_', 'aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6');
    const res = redact(`GITHUB_TOKEN=${ghp}`);
    expect(res.matches.map((m) => m.patternId)).toEqual(['github-token']);
  });
});

describe('kubernetes-secret', () => {
  const pw = b64(P);
  const user = b64('admin-user');

  it('redacts every value under data and stringData, keeping keys', () => {
    const yaml = [
      'apiVersion: v1',
      'kind: Secret',
      'metadata:',
      '  name: db-credentials',
      'type: Opaque',
      'data:',
      `  password: ${pw}`,
      `  "username": "${user}"`,
      'stringData:',
      `  token: ${P2}  # rotated monthly`,
      ''
    ].join('\n');
    expect(found(yaml, 'kubernetes-secret')).toEqual([pw, user, P2]);
    expect(redact(yaml).text).toContain('  password: [REDACTED_K8S_SECRET_VALUE]\n');
    expect(redact(yaml).text).toContain('  token: [REDACTED_K8S_SECRET_VALUE]  # rotated monthly\n');
    expect(redact(yaml).text).toContain('  name: db-credentials\n');
  });

  it('handles data before kind (kubectl -o yaml order) and CRLF line endings', () => {
    const yaml = ['apiVersion: v1', 'data:', `  password: ${pw}`, 'kind: Secret', 'metadata:', '  name: x', ''].join('\r\n');
    expect(found(yaml, 'kubernetes-secret')).toEqual([pw]);
  });

  it('redacts block scalars as one span', () => {
    const cert = ['line-one-of-the-key-material', 'line-two-of-the-key-material'];
    const yaml = ['kind: Secret', 'stringData:', '  tls.key: |', `    ${cert[0]}`, `    ${cert[1]}`, '  other: plainvalue1', ''].join('\n');
    expect(found(yaml, 'kubernetes-secret')).toEqual([`${cert[0]}\n    ${cert[1]}`, 'plainvalue1']);
  });

  it('only touches documents whose kind is Secret', () => {
    const yaml = [
      'kind: ConfigMap',
      'data:',
      '  log_level: debug-verbose',
      '---',
      'kind: Secret',
      'data:',
      `  password: ${pw}`,
      '---',
      'kind: Deployment',
      'spec:',
      '  data:',
      '    replicas: three-hundred',
      ''
    ].join('\n');
    expect(found(yaml, 'kubernetes-secret')).toEqual([pw]);
  });

  it('handles Secrets inside a List (kubectl get secrets -o yaml)', () => {
    const yaml = [
      'apiVersion: v1',
      'items:',
      '- apiVersion: v1',
      '  data:',
      `    password: ${pw}`,
      '  kind: Secret',
      '  metadata:',
      '    name: a',
      '- apiVersion: v1',
      '  data:',
      '    color: not-a-secret-value',
      '  kind: ConfigMap',
      'kind: List',
      ''
    ].join('\n');
    expect(found(yaml, 'kubernetes-secret')).toEqual([pw]);
  });

  it('skips templated values and redacts inline flow maps', () => {
    const tpl = ['kind: Secret', 'data:', '  password: {{ .Values.password | b64enc }}', ''].join('\n');
    expect(found(tpl, 'kubernetes-secret')).toEqual([]);
    const flow = ['kind: Secret', `data: {password: ${pw}}`, ''].join('\n');
    expect(found(flow, 'kubernetes-secret')).toEqual([`{password: ${pw}}`]);
  });

  it('round-trips through reversible masking', () => {
    const yaml = ['kind: Secret', 'data:', `  password: ${pw}`, `  user: ${user}`, ''].join('\n');
    const vault = new Vault();
    const res = redact(yaml, { reversible: true, vault });
    expect(res.text).not.toContain(pw);
    expect(unmask(res.text, vault)).toBe(yaml);
  });
});

describe('fail-closed spans (audit)', () => {
  it('.env: an unquoted value with spaces is redacted up to the comment, not just its first word', () => {
    const text = `DB_PASSWORD=${P} ${P2} # rotated\n`;
    expect(found(text, 'dotenv-secret')).toEqual([`${P} ${P2}`]);
    expect(redact(text).text).toBe('DB_PASSWORD=[REDACTED_ENV_SECRET] # rotated\n');
  });

  it("quoted: a YAML '' escape does not cut the value short (which skipped it entirely)", () => {
    const value = j('it', "''", 's', P);
    expect(found(`password: '${value}'`, 'quoted-secret-assignment')).toEqual([value]);
    expect(found(`password: 'ab''cd'`, 'quoted-secret-assignment')).toEqual([]);
    expect(all(`password: 'ab''cdefgh'`)).toEqual(["quoted-secret-assignment: ab''cdefgh"]);
  });

  it('.npmrc: # and ; inside the value do not end it', () => {
    const value = j(P, '#', P2, ';x');
    expect(found(`//registry.example/:_authToken=${value}\n`, 'npmrc-auth')).toEqual([value]);
  });

  it('re-redacting redacted output finds nothing (placeholders are never secrets)', () => {
    const pw = b64(P);
    const text = [
      `//registry.npmjs.org/:_authToken=${P}`,
      `machine h.example login u password ${P}`,
      `{"auths": {"r.example": {"auth": "${b64(j('u', ':', P))}"}}}`,
      `DB_PASSWORD=${P}`,
      `password: "${P2}"`,
      '---',
      'kind: Secret',
      'data:',
      `  password: ${pw}`,
      ''
    ].join('\n');
    for (const reversible of [false, true]) {
      const once = redact(text, { reversible });
      expect(once.totalLeaks).toBe(6);
      expect(redact(once.text).matches.map((m) => m.patternId)).toEqual([]);
    }
  });
});

describe('context patterns registry', () => {
  it('registers every new pattern by default with its own id and placeholder', () => {
    const ids = [
      'npmrc-auth',
      'netrc-password',
      'docker-config-auth',
      'quoted-secret-assignment',
      'dotenv-secret',
      'kubernetes-secret'
    ];
    const byId = new Map(DEFAULT_PATTERNS.map((p) => [p.id, p]));
    for (const id of ids) expect(byId.has(id), id).toBe(true);
    const placeholders = DEFAULT_PATTERNS.map((p) => p.placeholder);
    expect(new Set(placeholders).size).toBe(placeholders.length);
  });
});
