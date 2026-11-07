import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const read = (...p: string[]) => readFileSync(join(process.cwd(), ...p), 'utf-8');

describe('Python package version', () => {
  it('pyproject.toml and agent_redact.__version__ match package.json', () => {
    const { version } = JSON.parse(read('package.json')) as { version: string };
    expect(read('python', 'pyproject.toml')).toMatch(new RegExp(`^version = "${version.replace(/\./g, '\\.')}"$`, 'm'));
    expect(read('python', 'src', 'agent_redact', '__init__.py')).toContain(`__version__ = "${version}"`);
  });
});
