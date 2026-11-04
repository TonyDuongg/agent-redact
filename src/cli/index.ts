import { readFileSync, writeFileSync } from 'node:fs';
import { redact, unmask } from '../core/engine.js';
import { Vault } from '../core/vault.js';

// Minimal zero-dependency ANSI color helpers
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  red: '\x1b[31m',
  gray: '\x1b[90m'
};

function printHelp(): void {
  const helpText = `
${colors.bold}${colors.cyan}agent-redact${colors.reset} ${colors.gray}v0.1.0${colors.reset}
${colors.dim}Universal zero-latency, zero-leak secret & PII redactor for ALL AI Agents${colors.reset}

${colors.bold}USAGE:${colors.reset}
  npx agent-redact <file> [options]         Redact secrets in a file
  cat log.txt | npx agent-redact [options]  Redact secrets from standard input (stdin)
  npx agent-redact mcp                      Start Model Context Protocol (MCP) server

${colors.bold}OPTIONS:${colors.reset}
  -r, --reversible            Generate numbered session placeholders ([ANTHROPIC_API_KEY_1])
  -o, --output <file>         Write sanitized content to target file instead of stdout
  -i, --inplace               Modify input file in-place
  -j, --json                  Output result and leak metadata as JSON
  --vault-out <file>          Save generated session vault mappings to JSON file
  --unmask <vaultFile>        Restore previously masked file using saved vault file
  --stats                     Display leak statistics breakdown table
  -h, --help                  Show this help message
  -v, --version               Show current version

${colors.bold}EXAMPLES:${colors.reset}
  ${colors.dim}# 1. Pipe and sanitize on the fly:${colors.reset}
  cat server.log | npx agent-redact

  ${colors.dim}# 2. Reversibly mask .env and save vault:${colors.reset}
  npx agent-redact .env -r -o .env.safe --vault-out session.vault.json

  ${colors.dim}# 3. Restore masked file after agent completes:${colors.reset}
  npx agent-redact .env.safe --unmask session.vault.json -o .env.restored
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

  if (args[0] === 'mcp') {
    const { runMcpServer } = await import('../mcp/server.js');
    await runMcpServer();
    return;
  }

  if (args.includes('-h') || args.includes('--help')) {
    printHelp();
    process.exit(0);
  }

  if (args.includes('-v') || args.includes('--version')) {
    console.log('agent-redact v0.1.0');
    process.exit(0);
  }

  // Parse flag options
  const isReversible = args.includes('-r') || args.includes('--reversible');
  const isJson = args.includes('-j') || args.includes('--json');
  const showStats = args.includes('--stats');
  const isInplace = args.includes('-i') || args.includes('--inplace');

  const outputIdx = args.findIndex((a) => a === '-o' || a === '--output');
  const outputFile = outputIdx !== -1 && args[outputIdx + 1] ? args[outputIdx + 1] : undefined;

  const vaultOutIdx = args.indexOf('--vault-out');
  const vaultOutFile = vaultOutIdx !== -1 && args[vaultOutIdx + 1] ? args[vaultOutIdx + 1] : undefined;

  const unmaskIdx = args.indexOf('--unmask');
  const unmaskVaultFile = unmaskIdx !== -1 && args[unmaskIdx + 1] ? args[unmaskIdx + 1] : undefined;

  // Find non-flag file argument
  const fileArg = args.find(
    (a, i) =>
      !a.startsWith('-') &&
      i !== outputIdx + 1 &&
      i !== vaultOutIdx + 1 &&
      i !== unmaskIdx + 1
  );

  let content = '';

  if (fileArg) {
    try {
      content = readFileSync(fileArg, 'utf-8');
    } catch {
      console.error(`${colors.red}Error:${colors.reset} Cannot read file: ${fileArg}`);
      process.exit(1);
    }
  } else if (!process.stdin.isTTY) {
    content = await readStdin();
  } else {
    printHelp();
    process.exit(0);
  }

  // Handle unmask mode
  if (unmaskVaultFile) {
    try {
      const rawVault = readFileSync(unmaskVaultFile, 'utf-8');
      const entries = JSON.parse(rawVault) as Array<{ placeholder: string; original: string }>;
      const vault = new Vault();
      for (const e of entries) {
        vault.getOrCreate(e.original, {
          id: 'restored',
          name: 'Restored',
          category: 'credential',
          severity: 'critical',
          regex: /(?:)/,
          placeholder: e.placeholder.replace(/^\[|\]$/g, '').replace(/_\d+$/, ''),
          description: ''
        });
      }

      const restoredText = unmask(content, vault);

      if (outputFile) {
        writeFileSync(outputFile, restoredText, 'utf-8');
        console.error(`${colors.green}✔${colors.reset} Restored output written to ${outputFile}`);
      } else if (isInplace && fileArg) {
        writeFileSync(fileArg, restoredText, 'utf-8');
        console.error(`${colors.green}✔${colors.reset} Unmasked in-place: ${fileArg}`);
      } else {
        process.stdout.write(restoredText);
      }
      return;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`${colors.red}Error during unmasking:${colors.reset} ${msg}`);
      process.exit(1);
    }
  }

  // Standard redact / mask mode
  const vault = isReversible ? new Vault() : undefined;
  const result = redact(content, { reversible: isReversible, vault });

  // Save vault file if requested
  if (vaultOutFile && vault) {
    const entries = vault.entries().map((e) => ({
      placeholder: e.placeholder,
      original: e.original,
      patternId: e.patternId,
      category: e.category
    }));
    writeFileSync(vaultOutFile, JSON.stringify(entries, null, 2), 'utf-8');
    console.error(`${colors.green}✔${colors.reset} Session vault saved to ${vaultOutFile}`);
  }

  // Output formatting
  if (isJson) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    if (outputFile) {
      writeFileSync(outputFile, result.text, 'utf-8');
      console.error(`${colors.green}✔${colors.reset} Sanitized output written to ${outputFile}`);
    } else if (isInplace && fileArg) {
      writeFileSync(fileArg, result.text, 'utf-8');
      console.error(`${colors.green}✔${colors.reset} Sanitized in-place: ${fileArg}`);
    } else {
      process.stdout.write(result.text);
    }

    if (result.hasLeaks || showStats) {
      console.error(
        `\n${colors.cyan}[agent-redact]${colors.reset} ${
          result.hasLeaks
            ? `${colors.yellow}Detected & masked ${result.totalLeaks} secret(s)${colors.reset}`
            : `${colors.green}No leaks detected${colors.reset}`
        } ${colors.gray}in ${result.durationMs}ms${colors.reset}`
      );

      if (showStats && result.hasLeaks) {
        console.error(`${colors.bold}Leak Breakdown:${colors.reset}`);
        for (const [patternId, count] of Object.entries(result.stats)) {
          console.error(`  ${colors.dim}•${colors.reset} ${patternId.padEnd(25)} ${count} occurrence(s)`);
        }
      }
    }
  }
}

main().catch((err) => {
  console.error('Unexpected error:', err);
  process.exit(1);
});
