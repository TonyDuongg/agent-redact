import { redact } from '../dist/index.js';

const sampleKey = (...parts) => parts.join('');

// Sample ~4KB realistic prompt containing code, env config, and multiple secrets
const samplePrompt = `
Debug this multi-agent backend configuration:

# Environment
ANTHROPIC_API_KEY=${sampleKey('sk-', 'ant-api03-', 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345')}
OPENAI_API_KEY=${sampleKey('sk-', 'proj-', 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')}
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_URL=postgres://postgres:SuperSecretDbPass2025@db.production.internal:5432/main_db
GITHUB_TOKEN=${sampleKey('gh', 'p_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')}
STRIPE_KEY=${sampleKey('sk', '_', 'live_51AbcdefghijklmnopqrstuvwxyzA1B2C3D4E5')}
USER_EMAIL=developer@agentic-systems.io
JWT_BEARER=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

# Agent System Log
[2026-11-04 10:00:01] Agent connected from 192.168.1.105
[2026-11-04 10:00:02] Querying database with connection pool...
[2026-11-04 10:00:03] Processing prompt payload with 1,200 tokens.
[2026-11-04 10:00:04] Invoking Claude 3.5 Sonnet agent pipeline.
`.repeat(3); // ~4.5KB payload

console.log('Running agent-redact performance benchmark...');
console.log(`Payload size: ${(Buffer.byteLength(samplePrompt) / 1024).toFixed(2)} KB`);

// Warmup
for (let i = 0; i < 100; i++) {
  redact(samplePrompt, { reversible: true });
}

const ITERATIONS = 1000;
const start = performance.now();

let totalLeaksFound = 0;
for (let i = 0; i < ITERATIONS; i++) {
  const res = redact(samplePrompt, { reversible: true });
  totalLeaksFound += res.totalLeaks;
}

const totalTimeMs = performance.now() - start;
const avgLatencyMs = totalTimeMs / ITERATIONS;
const opsPerSec = Math.round((ITERATIONS / totalTimeMs) * 1000);

console.log('--- Results ---');
console.log(`Iterations:       ${ITERATIONS.toLocaleString()}`);
console.log(`Total time:       ${totalTimeMs.toFixed(2)} ms`);
console.log(`Average latency:  ${avgLatencyMs.toFixed(3)} ms / scan`);
console.log(`Throughput:       ${opsPerSec.toLocaleString()} scans / second`);
console.log(`Total leaks intercepted: ${totalLeaksFound.toLocaleString()}`);

