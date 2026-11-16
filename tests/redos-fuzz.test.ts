import { describe, it, expect } from 'vitest';
import { RedactEngine, DEFAULT_PATTERNS, PATTERN_PRESETS, createHighEntropyPattern } from '../src/index.js';
import type { RedactPattern } from '../src/index.js';

/*
 * Automatic ReDoS fuzzing for every default pattern, every preset pattern and the opt-in
 * entropy pattern. Hostile inputs are generated from each regex's own source: its literals
 * (e.g. "sk-ant-", "machine") and its character classes (members found by testing a pool of
 * characters against the class itself). Each input runs at n and 4n characters; a linear
 * pattern takes ~4x longer, a quadratic one ~16x.
 */

const N = 8_000;
const SLOW_MS = 30; // below this at 4n, timing noise dominates and the input is fine
const MAX_RATIO = 10; // linear ~4, quadratic ~16
const HARD_CAP_MS = 1_500;

const POOL = [
  ...Array.from({ length: 95 }, (_, i) => String.fromCharCode(32 + i)),
  '\t',
  '\n',
  'é'
];

function members(classSource: string, flags: string): string[] {
  let re: RegExp;
  try {
    re = new RegExp(`^${classSource}$`, flags.replace(/[gyd]/g, ''));
  } catch {
    return [];
  }
  return POOL.filter((c) => re.test(c));
}

/** Literals (2+ chars) and character classes of a regex source, roughly tokenized */
export function regexParts(re: RegExp): { literals: string[]; classes: string[][] } {
  const src = re.source;
  const literals = new Set<string>();
  const classes = new Map<string, string[]>();
  let lit = '';
  const flush = () => {
    if (lit.length >= 2) literals.add(lit);
    lit = '';
  };
  const addClass = (s: string) => {
    if (classes.has(s)) return;
    const m = members(s, re.flags);
    if (m.length > 0) classes.set(s, m);
  };
  for (let i = 0; i < src.length; i++) {
    const c = src[i]!;
    if (c === '\\') {
      const e = src[i + 1] ?? '';
      i++;
      if ('dDwWsS'.includes(e)) {
        flush();
        addClass(`\\${e}`);
      } else if ('bB'.includes(e) || /[1-9]/.test(e)) {
        flush();
      } else if (e === 'u' || e === 'x') {
        flush();
        i += e === 'x' ? 2 : 4;
      } else if (e === 'p' || e === 'P') {
        flush();
        const close = src.indexOf('}', i);
        addClass(src.slice(i - 1, close + 1));
        i = close;
      } else if (e === 'r' || e === 'n' || e === 't') {
        flush();
      } else {
        lit += e;
      }
    } else if (c === '[') {
      flush();
      let j = i + 1;
      if (src[j] === '^') j++;
      if (src[j] === ']') j++;
      while (j < src.length && src[j] !== ']') j += src[j] === '\\' ? 2 : 1;
      addClass(src.slice(i, j + 1));
      i = j;
    } else if (c === '(') {
      flush();
      if (src[i + 1] === '?') {
        const m = /^\(\?(?::|=|!|<=|<!|<[A-Za-z_]\w*>)/.exec(src.slice(i));
        if (m) i += m[0].length - 1;
      }
    } else if (c === '{') {
      flush();
      const close = src.indexOf('}', i);
      if (close !== -1 && /^\{\d+(?:,\d*)?\}$/.test(src.slice(i, close + 1))) i = close;
    } else if ('|)*+?^$'.includes(c)) {
      // a quantifier makes the previous character optional/repeated: end the literal before it
      if ('*+?'.includes(c) && lit.length > 0) lit = lit.slice(0, -1);
      flush();
    } else if (c === '.') {
      flush();
      addClass('.');
    } else {
      lit += c;
    }
  }
  flush();
  return { literals: [...literals].slice(0, 16), classes: [...classes.values()].slice(0, 16) };
}

const run = (chars: string[], len: number) => Array.from({ length: len }, (_, i) => chars[i % chars.length]).join('');
const fill = (unit: string, len: number) => unit.repeat(Math.max(1, Math.ceil(len / Math.max(1, unit.length)))).slice(0, len);

/** Hostile inputs of about `n` characters for one pattern */
export function attacks(p: RedactPattern, n: number): Map<string, string> {
  const { literals, classes } = regexParts(p.regex);
  const out = new Map<string, string>();
  const add = (name: string, text: string) => {
    if (out.size < 120) out.set(name, text);
  };
  for (const unit of ['a', '1', ' ', '-', '.', '\\', '"', "'", ':', '=', '/', '@', '_', 'a-', 'a.', '1.', 'A1', '\n', ' \n']) {
    add(`unit ${JSON.stringify(unit)}`, fill(unit, n));
  }
  classes.forEach((m, ci) => {
    add(`class#${ci} run`, run(m, n));
    add(`class#${ci} run + !`, run(m, n - 1) + '!');
    add(`class#${ci} pairs`, fill(run(m, 2) + ' ', n));
  });
  literals.forEach((l, li) => {
    add(`lit#${li} repeated`, fill(l, n));
    add(`lit#${li} lines`, fill(`${l}\n`, n));
    classes.slice(0, 6).forEach((m, ci) => {
      add(`lit#${li} + class#${ci} tail`, l + run(m, n - l.length));
      add(`lit#${li} + class#${ci}x8 repeated`, fill(l + run(m, 8), n));
      add(`lit#${li} + class#${ci}x8 + space repeated`, fill(`${l + run(m, 8)} `, n));
    });
  });
  return out;
}

function time(engine: RedactEngine, text: string, reps: number): number {
  let best = Infinity;
  for (let i = 0; i < reps; i++) {
    const t0 = performance.now();
    engine.redact(text);
    best = Math.min(best, performance.now() - t0);
  }
  return best;
}

/** Attacks whose time grows super-linearly (or exceeds the hard cap) for this pattern */
function superLinear(pattern: RedactPattern, firstOnly = false, n = N): string[] {
  const engine = new RedactEngine({ patterns: [pattern] });
  const small = attacks(pattern, n);
  const large = attacks(pattern, 4 * n);
  const slow: string[] = [];
  for (const [attack, text] of large) {
    let t4 = time(engine, text, 1);
    if (t4 < SLOW_MS) continue;
    t4 = time(engine, text, 3); // re-measure: first runs include JIT warm-up
    if (t4 < SLOW_MS) continue;
    const t1 = Math.max(time(engine, small.get(attack)!, 3), 0.5);
    if (t4 > HARD_CAP_MS || t4 / t1 > MAX_RATIO) {
      slow.push(`${attack}: ${t1.toFixed(1)} ms at ${n} chars -> ${t4.toFixed(1)} ms at ${4 * n} chars`);
      if (firstOnly) break;
    }
  }
  return slow;
}

const targets: Array<[string, RedactPattern]> = [
  ...DEFAULT_PATTERNS.map((p) => [`default/${p.id}`, p] as [string, RedactPattern]),
  ...Object.entries(PATTERN_PRESETS).flatMap(([name, ps]) => ps.map((p) => [`${name}/${p.id}`, p] as [string, RedactPattern])),
  ['opt-in/generic-high-entropy-secret', createHighEntropyPattern()]
];

describe('ReDoS fuzzing: every pattern stays linear on generated hostile input', () => {
  it('extracts literals and classes from a regex source', () => {
    const parts = regexParts(/\bsk-ant-[A-Za-z0-9_\-]{20,}(?![A-Za-z0-9_])/g);
    expect(parts.literals).toContain('sk-ant-');
    expect(parts.classes.some((m) => m.includes('-') && m.includes('Z') && !m.includes(' '))).toBe(true);
  });

  it('flags a known quadratic pattern (the harness itself works)', () => {
    const quadratic: RedactPattern = {
      id: 'quadratic-canary',
      name: 'canary',
      category: 'custom',
      severity: 'low',
      regex: /[a-z]+\d/g, // every start position scans to the end of a letter run
      placeholder: 'CANARY',
      description: 'deliberately quadratic'
    };
    // Smaller size: at 4 * N this canary takes seconds per run
    expect(superLinear(quadratic, true, 4_000)).toHaveLength(1);
  }, 60_000);

  for (const [name, pattern] of targets) {
    it(name, () => {
      expect(superLinear(pattern), 'super-linear inputs').toEqual([]);
    }, 60_000);
  }
});
