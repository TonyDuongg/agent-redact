import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const root = process.cwd();
const read = (...p: string[]) => readFileSync(join(root, ...p), 'utf-8');
const workflows = readdirSync(join(root, '.github', 'workflows')).filter((f) => f.endsWith('.yml'));

/** Split a workflow into its jobs: { jobName: text } (jobs are the 2-space-indented keys under `jobs:`). */
function jobs(text: string): Record<string, string> {
  const body = text.split(/^jobs:\s*$/m)[1] ?? '';
  const out: Record<string, string> = {};
  for (const part of body.split(/^(?=  [A-Za-z0-9_-]+:\s*$)/m)) {
    const name = /^  ([A-Za-z0-9_-]+):/.exec(part)?.[1];
    if (name) out[name] = part;
  }
  return out;
}

describe('Supply-chain hardening of the workflows', () => {
  it('every third-party action is pinned to a full commit SHA with a version comment', () => {
    for (const file of [...workflows.map((f) => join('.github', 'workflows', f)), 'action.yml']) {
      for (const m of read(file).matchAll(/uses:\s*(\S+)(.*)$/gm)) {
        const ref = m[1]!;
        if (ref.startsWith('./')) continue;
        expect(ref, `${file}: ${ref}`).toMatch(/^[\w.-]+\/[\w./-]+@[0-9a-f]{40}$/);
        expect(m[2], `${file}: ${ref} needs a "# vX.Y.Z" comment`).toMatch(/#\s*v\d+\.\d+\.\d+/);
      }
    }
  });

  it('npm publishing uses Trusted Publishing (OIDC): no long-lived token anywhere', () => {
    const release = read('.github', 'workflows', 'release.yml');
    expect(release).not.toMatch(/NPM_TOKEN|NODE_AUTH_TOKEN/);
  });

  it('only publish jobs can mint OIDC tokens, and they install and build nothing', () => {
    for (const file of ['release.yml', 'release-python.yml']) {
      const text = read('.github', 'workflows', file);
      expect(text, `${file}: top-level permissions`).toMatch(/^permissions:\s*\n\s+contents: read\s*$/m);
      for (const [name, job] of Object.entries(jobs(text))) {
        if (!/id-token: write/.test(job)) continue;
        expect(name, `${file}: job ${name} has id-token`).toMatch(/^publish/);
        expect(job, `${file}: ${name} must run in a deployment environment`).toMatch(/environment:\s*\n\s+name: (npm|pypi|testpypi)/);
        expect(job, `${file}: ${name} must not install or build`).not.toMatch(/npm (ci|install)|npm run|pip install|python -m build/);
      }
    }
  });

  it('npm publish happens only for a tag on main whose version matches package.json', () => {
    const release = read('.github', 'workflows', 'release.yml');
    expect(release).toMatch(/merge-base --is-ancestor/);
    expect(release).toMatch(/does not match package\.json version/);
    expect(release).toMatch(/npm publish[^\n]*--ignore-scripts/);
  });

  it('Dependabot keeps npm packages and the pinned actions up to date', () => {
    expect(existsSync(join(root, '.github', 'dependabot.yml'))).toBe(true);
    const config = read('.github', 'dependabot.yml');
    expect(config).toMatch(/package-ecosystem: "?npm"?/);
    expect(config).toMatch(/package-ecosystem: "?github-actions"?/);
  });
});
