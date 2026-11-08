import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const read = (...p: string[]) => readFileSync(join(process.cwd(), ...p), 'utf-8');

/** Lowest supported Node.js version. The dev toolchain needs it too (tsup 9: >=22.18, vitest 5: >=22.12). */
const MIN_NODE = '22.18.0';
const MIN_MAJOR = Number(MIN_NODE.split('.')[0]);

describe('Supported Node.js versions stay in sync', () => {
  it('package.json engines.node is the minimum version', () => {
    const pkg = JSON.parse(read('package.json')) as { engines: { node: string } };
    expect(pkg.engines.node).toBe(`>=${MIN_NODE}`);
  });

  it('no workflow runs on a Node.js major below the minimum, and CI tests the minimum major', () => {
    const dir = join(process.cwd(), '.github', 'workflows');
    for (const file of readdirSync(dir).filter((f) => f.endsWith('.yml'))) {
      const majors = [...read('.github', 'workflows', file).matchAll(/node-version:\s*(.+)/g)].flatMap((m) =>
        [...m[1]!.matchAll(/(\d+)\.x/g)].map((v) => Number(v[1]))
      );
      for (const major of majors) expect(major, `${file} uses Node ${major}.x`).toBeGreaterThanOrEqual(MIN_MAJOR);
    }
    expect(read('.github', 'workflows', 'ci.yml')).toMatch(new RegExp(`node-version: \\[${MIN_MAJOR}\\.x,`));
  });

  it('the build targets the minimum major', () => {
    expect(read('tsup.config.ts')).toContain(`target: 'node${MIN_MAJOR}'`);
  });

  it('docs state the minimum version', () => {
    expect(read('README.md')).toContain(`node-%3E%3D${MIN_NODE}-blue`);
    for (const doc of [read('README.md'), read('python', 'README.md'), read('python', 'src', 'agent_redact', '__init__.py'), read('CONTRIBUTING.md')]) {
      expect(doc).not.toMatch(/Node(\.js)? ?v?20(\+|\.0\.0| or higher)/);
    }
    expect(read('python', 'README.md')).toContain('Node.js 22.18+');
    expect(read('CONTRIBUTING.md')).toContain(`\`v${MIN_NODE}\` or higher`);
  });
});
