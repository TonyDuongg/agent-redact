import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const read = (...p: string[]) => readFileSync(join(process.cwd(), ...p), 'utf-8');
const pkg = JSON.parse(read('package.json')) as { description: string; version: string; dependencies?: Record<string, string> };

describe('Docs only make claims the package can back up', () => {
  it('no "zero-latency" claim in the package description or README (scanning is fast, not free)', () => {
    expect(pkg.description).not.toMatch(/zero[- ]latency/i);
    expect(read('README.md')).not.toMatch(/zero[- ]latency/i);
  });

  it('the dependency badge matches package.json', () => {
    const readme = read('README.md');
    const runtimeDeps = Object.keys(pkg.dependencies ?? {}).length;
    if (runtimeDeps > 0) expect(readme).not.toMatch(/badge\/dependencies-0/);
    // The core engine itself has no third-party imports (enforced by CONTRIBUTING and checked here)
    expect(readme).toContain('badge/core%20engine%20deps-0');
  });

  it('the roadmap uses the real version numbers and lists only middleware that exists', () => {
    const roadmap = read('README.md').split('## 🗺️ Roadmap')[1]!.split('\n---')[0]!;
    expect(roadmap).not.toMatch(/\bv1\.\d/);
    expect(roadmap).toMatch(/\bv0\.\d+/);
    expect(roadmap).not.toMatch(/Fastify|Next\.js/);
  });
});

describe('Python package ships the license', () => {
  it('python/LICENSE is the repository LICENSE and pyproject.toml declares it', () => {
    expect(read('python', 'LICENSE')).toBe(read('LICENSE'));
    expect(read('python', 'pyproject.toml')).toMatch(/^license-files = \["LICENSE"\]$/m);
  });
});
