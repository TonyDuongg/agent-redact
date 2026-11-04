import { readFileSync } from 'node:fs';
import { redact } from '../core/engine.js';

function printHelp(): void {
  const helpText = `
agent-redact - Zero-latency secret & PII redactor for LLMs & agentic workflows

USAGE:
  npx agent-redact <file>               Redact secrets in a file
  cat log.txt | npx agent-redact        Redact secrets from standard input (stdin)

OPTIONS:
  -r, --reversible     Generate numbered session placeholders ([ANTHROPIC_API_KEY_1])
  -j, --json           Output result and leak metadata as JSON
  -h, --help           Show this help message
  -v, --version        Show version
`;
  console.log(helpText.trim());
}

async function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => {
      resolve(data);
    });
  });
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes('-h') || args.includes('--help')) {
    printHelp();
    process.exit(0);
  }

  if (args.includes('-v') || args.includes('--version')) {
    console.log('agent-redact v0.1.0');
    process.exit(0);
  }

  const isReversible = args.includes('-r') || args.includes('--reversible');
  const isJson = args.includes('-j') || args.includes('--json');
  const fileArg = args.find((a) => !a.startsWith('-'));

  let content = '';

  if (fileArg) {
    try {
      content = readFileSync(fileArg, 'utf-8');
    } catch (err) {
      console.error(`Error reading file: ${fileArg}`);
      process.exit(1);
    }
  } else if (!process.stdin.isTTY) {
    content = await readStdin();
  } else {
    printHelp();
    process.exit(0);
  }

  const result = redact(content, { reversible: isReversible });

  if (isJson) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    process.stdout.write(result.text);
    if (result.hasLeaks) {
      console.error(`\n[agent-redact] Redacted ${result.totalLeaks} secret(s) in ${result.durationMs}ms`);
    }
  }
}

main().catch((err) => {
  console.error('Unexpected error:', err);
  process.exit(1);
});

