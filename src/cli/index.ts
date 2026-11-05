#!/usr/bin/env node
import { readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { redact, unmask } from '../core/engine.js';
import { Vault } from '../core/vault.js';
import { loadConfig } from '../core/config.js';

function writeSecureFile(filePath: string, content: string): void {
  writeFileSync(filePath, content, { encoding: 'utf-8', mode: 0o600 });
  try {
    chmodSync(filePath, 0o600);
  } catch {
    // chmod may be a no-op on non-POSIX / Windows
  }
}

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
${colors.bold}${colors.cyan}agent-redact${colors.reset} ${colors.gray}v0.1.3${colors.reset}
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
  --config <path>             Path to configuration file (.agentredactrc or json)
  --entropy                   Enable Shannon entropy detection for generic secrets
  --check, --fail-on-leak     Exit with code 1 if any secrets are detected (CI/pre-commit)
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
    console.log('agent-redact v0.1.3');
    process.exit(0);
  }

  // Parse flag options
  const isReversible = args.includes('-r') || args.includes('--reversible');
  const isJson = args.includes('-j') || args.includes('--json');
  const showStats = args.includes('--stats');
  const isInplace = args.includes('-i') || args.includes('--inplace');
  const detectEntropy = args.includes('--entropy');
  const failOnLeak = args.includes('--check') || args.includes('--fail-on-leak');

  const outputIdx = args.findIndex((a) => a === '-o' || a === '--output');
  const outputFile = outputIdx !== -1 && args[outputIdx + 1] ? args[outputIdx + 1] : undefined;

  const vaultOutIdx = args.indexOf('--vault-out');
  const vaultOutFile = vaultOutIdx !== -1 && args[vaultOutIdx + 1] ? args[vaultOutIdx + 1] : undefined;

  const unmaskIdx = args.indexOf('--unmask');
  const unmaskVaultFile = unmaskIdx !== -1 && args[unmaskIdx + 1] ? args[unmaskIdx + 1] : undefined;

  const configIdx = args.indexOf('--config');
  const configPath = configIdx !== -1 && args[configIdx + 1] ? args[configIdx + 1] : undefined;

  // Track argument indices that belong to flags with values
  const skipIndices = new Set<number>();
  if (outputIdx !== -1) skipIndices.add(outputIdx + 1);
  if (vaultOutIdx !== -1) skipIndices.add(vaultOutIdx + 1);
  if (unmaskIdx !== -1) skipIndices.add(unmaskIdx + 1);
  if (configIdx !== -1) skipIndices.add(configIdx + 1);

  // Load config file if present
  let loadedConfig = null;
  try {
    loadedConfig = loadConfig(configPath);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`${colors.red}Configuration Error:${colors.reset} ${msg}`);
    process.exit(1);
  }

  // Find non-flag file arguments
  const fileArgs = args.filter(
    (a, i) => !a.startsWith('-') && !skipIndices.has(i)
  );

  const effectiveReversible = isReversible || (loadedConfig?.reversible ?? false);
  const vault = effectiveReversible ? new Vault() : undefined;

  // Multi-file screening mode (used by pre-commit or batch audits)
  if (fileArgs.length > 1) {
    let totalLeaksAcrossFiles = 0;

    for (const file of fileArgs) {
      try {
        const fileContent = readFileSync(file, 'utf-8');
        const res = redact(fileContent, {
          reversible: effectiveReversible,
          vault,
          include: loadedConfig?.include,
          exclude: loadedConfig?.exclude,
          allowlist: loadedConfig?.allowlist,
          customPatterns: loadedConfig?.customPatterns,
          detectHighEntropy: detectEntropy || (loadedConfig?.detectHighEntropy ?? false),
          entropy: loadedConfig?.entropy
        });

        if (isInplace) {
          writeFileSync(file, res.text, 'utf-8');
        }

        if (res.hasLeaks) {
          totalLeaksAcrossFiles += res.totalLeaks;
          console.error(
            `${colors.yellow}✖ [LEAK]${colors.reset} ${file}: ${res.totalLeaks} secret(s) detected`
          );
        } else {
          console.error(`${colors.green}✔ [CLEAN]${colors.reset} ${file}`);
        }
      } catch {
        console.error(`${colors.red}Error:${colors.reset} Cannot read file: ${file}`);
        process.exit(1);
      }
    }

    if (vaultOutFile && vault) {
      writeSecureFile(vaultOutFile, vault.toJSON());
      console.error(`${colors.green}✔${colors.reset} Session vault saved to ${vaultOutFile}`);
    }

    if (totalLeaksAcrossFiles > 0 && (failOnLeak || !isInplace)) {
      console.error(
        `\n${colors.red}[agent-redact] Audit failed: detected ${totalLeaksAcrossFiles} secret(s) across ${fileArgs.length} files.${colors.reset}`
      );
      process.exit(1);
    } else {
      console.error(
        `\n${colors.green}[agent-redact] All ${fileArgs.length} files ${isInplace ? 'sanitized' : 'are clean'}.${colors.reset}`
      );
      process.exit(0);
    }
  }

  const fileArg = fileArgs[0];
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
      const vault = Vault.fromJSON(rawVault);
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

  // Standard redact / mask mode (single file or stdin)
  const result = redact(content, {
    reversible: effectiveReversible,
    vault,
    include: loadedConfig?.include,
    exclude: loadedConfig?.exclude,
    allowlist: loadedConfig?.allowlist,
    customPatterns: loadedConfig?.customPatterns,
    detectHighEntropy: detectEntropy || (loadedConfig?.detectHighEntropy ?? false),
    entropy: loadedConfig?.entropy
  });

  // Save vault file if requested
  if (vaultOutFile && vault) {
    writeSecureFile(vaultOutFile, vault.toJSON());
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
    } else if (!failOnLeak) {
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

  // Exit with code 1 only if --check / --fail-on-leak is explicitly requested and leaks were detected
  if (result.hasLeaks && failOnLeak) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Unexpected error:', err);
  process.exit(1);
});
