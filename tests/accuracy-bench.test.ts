import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
// @ts-expect-error -- plain .mjs benchmark module without type declarations
import { buildCorpus, evaluate, toMarkdown, replaceReadmeBlock, README_START, README_END } from '../benchmarks/accuracy.mjs';
import { redact, DEFAULT_PATTERNS } from '../src/index.js';

type Match = { patternId: string; startIndex: number; endIndex: number };
type Doc = { text: string; labels: Array<{ id: string; start: number; end: number }> };

const corpus = buildCorpus();

describe('benchmarks/accuracy.mjs (synthetic precision/recall)', () => {
  it('has generated samples for every default pattern', () => {
    const missing = DEFAULT_PATTERNS.map((p) => p.id).filter((id) => !corpus.ids.includes(id));
    expect(missing).toEqual([]);
    for (const id of corpus.ids) {
      expect((corpus.docs as Doc[]).some((d) => d.labels.some((l) => l.id === id)), id).toBe(true);
    }
  });

  it('is deterministic (fixed seed)', () => {
    expect(buildCorpus().docs).toEqual(corpus.docs);
  });

  it('labels point at the generated value in the text', () => {
    for (const d of corpus.docs as Doc[]) {
      for (const l of d.labels) expect(l.end).toBeGreaterThan(l.start);
    }
  });

  it('scores misses, shifted spans and wrong labels', () => {
    const tiny = {
      ids: ['a'],
      decoyLines: 0,
      docs: [
        { format: 'x', text: 'key=SECRETVALUE', labels: [{ id: 'a', start: 4, end: 15 }] },
        { format: 'x', text: 'nothing here', labels: [] }
      ]
    };
    const none = evaluate(() => ({ matches: [] as Match[] }), tiny);
    expect(none.per.get('a')).toMatchObject({ samples: 1, tp: 0, fn: 1 });
    expect(none.leaked).toBe(1);

    const shifted = evaluate(() => ({ matches: [{ patternId: 'a', startIndex: 5, endIndex: 15 }] }), tiny);
    expect(shifted.per.get('a')).toMatchObject({ tp: 0, fp: 2, fn: 1 }); // also fires on the decoy doc
    expect(shifted.leaked).toBe(1); // first character still visible

    const mislabeled = evaluate((t: string) => ({ matches: t.startsWith('key') ? [{ patternId: 'b', startIndex: 4, endIndex: 15 }] : [] }), tiny);
    expect(mislabeled.per.get('a')).toMatchObject({ tp: 0, fn: 1 });
    expect(mislabeled.per.get('b')).toMatchObject({ fp: 1 });
    expect(mislabeled.leaked).toBe(0); // masked, just under another label

    const perfect = evaluate((t: string) => ({ matches: t.startsWith('key') ? [{ patternId: 'a', startIndex: 4, endIndex: 15 }] : [] }), tiny);
    expect(perfect.totals).toEqual({ samples: 1, tp: 1, fp: 0, fn: 0 });
  });

  it('README publishes exactly the current results', () => {
    const table = toMarkdown(evaluate((t: string) => redact(t), corpus));
    const readme = readFileSync(join(process.cwd(), 'README.md'), 'utf-8');
    expect(readme).toContain(README_START);
    expect(replaceReadmeBlock(readme, table), 'run `npm run bench:accuracy -- --write-readme`').toBe(readme);
    expect(table).toMatch(/Synthetic data/);
  });

  it('has no false positives on the decoys and leaks only the documented limitations', () => {
    const res = evaluate((t: string) => redact(t), corpus);
    expect(res.totals.fp).toBe(0);
    const leakingIds = [...res.per].filter(([, r]) => r.samples !== r.masked).map(([id]) => id).sort();
    expect(leakingIds).toEqual(['dotenv-secret', 'kubernetes-secret', 'quoted-secret-assignment']);
    expect(README_END).toBe('<!-- accuracy:end -->');
  });
});
