import { redact, createRedactStream } from '../dist/index.js';
import { Readable } from 'node:stream';

const sampleKey = (...parts) => parts.join('');

function getPercentile(times, p) {
  const sorted = [...times].sort((a, b) => a - b);
  const index = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, index)];
}

async function benchmarkTier(name, payload, iterations) {
  // Warmup
  for (let i = 0; i < 50; i++) {
    redact(payload, { reversible: true });
  }

  const times = [];
  let totalLeaks = 0;

  for (let i = 0; i < iterations; i++) {
    const t0 = performance.now();
    const res = redact(payload, { reversible: true });
    const elapsed = performance.now() - t0;
    times.push(elapsed);
    totalLeaks += res.totalLeaks;
  }

  const totalTime = times.reduce((a, b) => a + b, 0);
  const avg = totalTime / iterations;
  const p50 = getPercentile(times, 50);
  const p90 = getPercentile(times, 90);
  const p99 = getPercentile(times, 99);
  const ops = Math.round((iterations / totalTime) * 1000);

  return {
    name,
    sizeKb: (Buffer.byteLength(payload) / 1024).toFixed(2),
    iterations,
    avg: avg.toFixed(3),
    p50: p50.toFixed(3),
    p90: p90.toFixed(3),
    p99: p99.toFixed(3),
    ops: ops.toLocaleString(),
    leaksPerRun: (totalLeaks / iterations).toFixed(1)
  };
}

async function main() {
  console.log('='.repeat(70));
  console.log('AGENT-REDACT MULTI-TIER BENCHMARK & PERFORMANCE AUDIT');
  console.log('Node.js:', process.version, '| Platform:', process.platform, process.arch);
  console.log('='.repeat(70));

  const antKey = sampleKey('sk-', 'ant-api03-', 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345');
  const openAiKey = sampleKey('sk-', 'proj-', 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890');
  const ghToken = sampleKey('gh', 'p_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');

  // Tier 1: Small (~500 Bytes) - typical single chat prompt
  const smallPayload = `Please analyze this error log:
ANTHROPIC_KEY=${antKey}
User email: contact@agent.io
DB: postgres://root:supersecret@10.0.0.1:5432/app`;

  // Tier 2: Medium (~5 KB) - typical code snippet + env dump
  const mediumChunk = `
# Environment Config
ANTHROPIC_KEY=${antKey}
OPENAI_KEY=${openAiKey}
GITHUB_PAT=${ghToken}
DATABASE_URL=postgres://root:AdminSecret999@localhost:5432/app
EMAIL=admin@enterprise.org
PHONE=+1-800-555-0199

// Some code
function connect() {
  const token = "${antKey}";
  console.log("Connecting with", token);
}
`;
  const mediumPayload = mediumChunk.repeat(10); // ~5KB

  // Tier 3: Large (~100 KB) - large log file or multi-file context dump
  const largePayload = mediumChunk.repeat(200); // ~100KB

  const r1 = await benchmarkTier('Small Prompt (~500 B)', smallPayload, 2000);
  const r2 = await benchmarkTier('Medium Context (~5 KB)', mediumPayload, 1000);
  const r3 = await benchmarkTier('Large Dump (~100 KB)', largePayload, 100);

  console.log('\n--- Latency & Throughput Results ---');
  console.table([r1, r2, r3]);

  // Stream Throughput Test (5 MB stream)
  console.log('\n--- Stream Processing Throughput (5 MB Payload) ---');
  const streamChunk = mediumChunk.repeat(100); // ~50 KB per chunk
  const totalStreamChunks = 100; // 5 MB total
  const streamStart = performance.now();

  const source = Readable.from(
    (function* () {
      for (let i = 0; i < totalStreamChunks; i++) {
        yield streamChunk;
      }
    })()
  );

  const stream = createRedactStream({ reversible: true });
  let streamBytes = 0;
  for await (const chunk of source.pipe(stream)) {
    streamBytes += chunk.length;
  }
  const streamDuration = performance.now() - streamStart;
  const streamMb = streamBytes / (1024 * 1024);
  const mbPerSec = (streamMb / (streamDuration / 1000)).toFixed(2);

  console.log(`Streamed Data:      ${streamMb.toFixed(2)} MB`);
  console.log(`Stream Time:        ${streamDuration.toFixed(2)} ms`);
  console.log(`Stream Throughput:  ${mbPerSec} MB/s`);
  console.log('='.repeat(70));
}

main().catch(console.error);
