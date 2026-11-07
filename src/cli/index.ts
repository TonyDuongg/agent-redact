#!/usr/bin/env node
import { readFileSync, writeFileSync, chmodSync, statSync } from 'node:fs';
import { relative } from 'node:path';
import { redact, unmask } from '../core/engine.js';
import { Vault } from '../core/vault.js';
import { loadConfig } from '../core/config.js';
import { readTextForScan } from '../core/files.js';
import { encryptVaultJson, decryptVaultJson, isEncryptedVault } from '../core/vault-crypto.js';
import { resolvePresets } from '../patterns/presets.js';
import { VERSION } from '../version.js';
import {
  runScan,
  expandTargets,
  formatReport,
  formatText,
  writeScanBaseline,
  type ScanFormat,
  type ScanOutcome
} from './scan.js';
import { runHook } from './hook.js';

function writeSecureFile(filePath: string, content: string): void {
  writeFileSync(filePath, content, { encoding: 'utf-8', mode: 0o600 });
  try {
    chmodSync(filePath, 0o600);
  } catch {
    // chmod may be a no-op on non-POSIX / Windows
  }
}

/**
 * Passphrase for vault encryption: the env var named by --vault-key-env (required to be set
 * when the flag is used), otherwise AGENT_REDACT_VAULT_KEY. Read from the environment, never
 * from argv, so it does not show up in shell history or process listings.
 */
function resolveVaultKey(vaultKeyEnv: string | undefined): string | undefined {
  if (vaultKeyEnv) {
    const value = process.env[vaultKeyEnv];
    if (!value) {
      console.error(`${colors.red}Error:${colors.reset} environment variable ${vaultKeyEnv} (from --vault-key-env) is not set or empty.`);
      process.exit(2);
    }
    return value;
  }
  return process.env['AGENT_REDACT_VAULT_KEY'] || undefined;
}

/** Reads a vault file, decrypting it when needed. Exits 2 for an encrypted vault without a key. */
function loadVault(path: string, vaultKeyEnv: string | undefined): Vault {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf-8');
  } catch {
    console.error(`${colors.red}Error:${colors.reset} Cannot read vault file: ${path}`);
    process.exit(1);
  }
  let json = raw;
  if (isEncryptedVault(raw)) {
    const key = resolveVaultKey(vaultKeyEnv);
    if (!key) {
      console.error(
        `${colors.red}Error:${colors.reset} ${path} is encrypted; pass --vault-key-env <VAR> ` +
          '(or set AGENT_REDACT_VAULT_KEY) with the passphrase.'
      );
      process.exit(2);
    }
    try {
      json = decryptVaultJson(raw, key);
    } catch (err: unknown) {
      console.error(`${colors.red}Error:${colors.reset} ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    }
  }
  try {
    return Vault.fromJSON(json);
  } catch (err: unknown) {
    console.error(`${colors.red}Error:${colors.reset} ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}

function saveVault(path: string, vault: Vault, vaultKeyEnv: string | undefined): void {
  const key = resolveVaultKey(vaultKeyEnv);
  writeSecureFile(path, key ? encryptVaultJson(vault.toJSON(), key) : vault.toJSON());
  if (key) {
    console.error(`${colors.green}✔${colors.reset} Encrypted session vault saved to ${path}`);
  } else {
    console.error(`${colors.green}✔${colors.reset} Session vault saved to ${path}`);
    console.error(
      `${colors.yellow}⚠${colors.reset} The vault is stored unencrypted and contains the original secrets. ` +
        'Use --vault-key-env <VAR> (or AGENT_REDACT_VAULT_KEY) to encrypt it.'
    );
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
${colors.bold}${colors.cyan}agent-redact${colors.reset} ${colors.gray}v${VERSION}${colors.reset}
${colors.dim}Secret & PII redactor for AI agents, LLM pipelines and CI${colors.reset}

${colors.bold}USAGE:${colors.reset}
  npx agent-redact <file> [options]         Redact secrets in a file
  cat log.txt | npx agent-redact [options]  Redact secrets from standard input (stdin)
  npx agent-redact <dir|files...>           Scan (honours .gitignore in git repos); exit 1 on findings
  npx agent-redact --staged                 Scan what is staged for commit (git index)
  npx agent-redact mcp                      Start Model Context Protocol (MCP) server
  npx agent-redact hook [--block-writes]    Claude Code hook (reads hook JSON on stdin)

${colors.bold}SCAN OPTIONS:${colors.reset}
  --format <text|json|sarif>  Report format (json/sarif go to stdout or --report)
  --report <file>             Write the json/sarif report to a file
  --baseline <file>           Ignore findings recorded in a baseline file
  --write-baseline <file>     Record current findings as accepted, then exit 0
  Inline: add "agent-redact-ignore" to a line, or "agent-redact-ignore-next-line" above it

${colors.bold}OPTIONS:${colors.reset}
  -r, --reversible            Generate numbered session placeholders ([ANTHROPIC_API_KEY_1])
  -o, --output <file>         Write sanitized content to target file instead of stdout
  -i, --inplace               Modify input file in-place
  -j, --json                  Output result and leak metadata as JSON
  --config <path>             Path to configuration file (.agentredactrc or json)
  --entropy                   Enable Shannon entropy detection for generic secrets
  --check, --fail-on-leak     Exit with code 1 if any secrets are detected (CI/pre-commit)
  --vault-out <file>          Save generated session vault mappings to JSON file
  --vault-key-env <VAR>       Encrypt/decrypt the vault with the passphrase in env var VAR
  --vault-in <file>           Continue an existing vault (numbering carries over between runs)
  --preset <a,b>              Enable opt-in pattern presets (e.g. vn-pii)
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

  if (args[0] === 'hook') {
    process.exit(await runHook(args.slice(1)));
  }

  if (args.includes('-h') || args.includes('--help')) {
    printHelp();
    process.exit(0);
  }

  if (args.includes('-v') || args.includes('--version')) {
    console.log(`agent-redact v${VERSION}`);
    process.exit(0);
  }

  const VALUE_FLAGS = new Set([
    '-o',
    '--output',
    '--vault-out',
    '--unmask',
    '--config',
    '--format',
    '--report',
    '--baseline',
    '--write-baseline',
    '--vault-key-env',
    '--vault-in',
    '--preset'
  ]);
  const BOOLEAN_FLAGS = new Set([
    '-r',
    '--reversible',
    '-j',
    '--json',
    '--stats',
    '-i',
    '--inplace',
    '--entropy',
    '--check',
    '--fail-on-leak',
    '--staged',
    '-h',
    '--help',
    '-v',
    '--version'
  ]);

  // Validate flags and option values
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg.startsWith('-')) {
      if (VALUE_FLAGS.has(arg)) {
        const val = args[i + 1];
        if (!val || val.startsWith('-')) {
          console.error(`${colors.red}Error:${colors.reset} Flag "${arg}" requires a file argument.`);
          process.exit(2);
        }
        i++; // skip value argument
      } else if (!BOOLEAN_FLAGS.has(arg)) {
        console.error(`${colors.red}Error:${colors.reset} Unknown flag "${arg}". Use --help for available options.`);
        process.exit(2);
      }
    }
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

  const valueAfter = (flag: string): { index: number; value?: string } => {
    const index = args.indexOf(flag);
    return { index, value: index !== -1 ? args[index + 1] : undefined };
  };
  const formatArg = valueAfter('--format');
  const reportArg = valueAfter('--report');
  const baselineArg = valueAfter('--baseline');
  const writeBaselineArg = valueAfter('--write-baseline');
  const vaultKeyArg = valueAfter('--vault-key-env');
  const vaultKeyEnv = vaultKeyArg.value;
  const vaultInArg = valueAfter('--vault-in');
  const presetArg = valueAfter('--preset');
  const isStaged = args.includes('--staged');

  // Track argument indices that belong to flags with values
  const skipIndices = new Set<number>();
  if (outputIdx !== -1) skipIndices.add(outputIdx + 1);
  if (vaultOutIdx !== -1) skipIndices.add(vaultOutIdx + 1);
  if (unmaskIdx !== -1) skipIndices.add(unmaskIdx + 1);
  if (configIdx !== -1) skipIndices.add(configIdx + 1);
  for (const a of [formatArg, reportArg, baselineArg, writeBaselineArg, vaultKeyArg, vaultInArg, presetArg]) {
    if (a.index !== -1) skipIndices.add(a.index + 1);
  }

  const format = formatArg.value as ScanFormat | undefined;
  if (format !== undefined && !['text', 'json', 'sarif'].includes(format)) {
    console.error(`${colors.red}Error:${colors.reset} --format must be one of: text, json, sarif.`);
    process.exit(2);
  }

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
  // --preset a,b adds opt-in presets on top of any configured ones; unknown names are rejected
  const effectivePresets = [
    ...(loadedConfig?.presets ?? []),
    ...(presetArg.value ?? '').split(',').map((s) => s.trim()).filter(Boolean)
  ];
  try {
    resolvePresets(effectivePresets);
  } catch (err: unknown) {
    console.error(`${colors.red}Error:${colors.reset} ${err instanceof Error ? err.message : String(err)}`);
    process.exit(2);
  }

  // --vault-in continues an existing session vault, so placeholder numbers never collide
  // across runs (used by the Python wrapper's Session)
  const vault = effectiveReversible ? (vaultInArg.value ? loadVault(vaultInArg.value, vaultKeyEnv) : new Vault()) : undefined;

  // Reversible placeholders written in-place without a saved vault can never be restored:
  // the original secrets would be destroyed. Refuse instead of silently losing data.
  if (effectiveReversible && isInplace && !vaultOutFile && !unmaskVaultFile) {
    console.error(
      `${colors.red}Error:${colors.reset} reversible in-place masking requires --vault-out <file>; ` +
        'otherwise the original values cannot be restored.'
    );
    process.exit(2);
  }

  const isDirectoryArg = (p: string) => {
    try {
      return statSync(p).isDirectory();
    } catch {
      return false;
    }
  };
  const hasDirectory = fileArgs.some(isDirectoryArg);
  const multiInput = fileArgs.length > 1 || hasDirectory;

  if (multiInput && (unmaskVaultFile || outputFile || isJson)) {
    console.error(
      `${colors.red}Error:${colors.reset} Flags -o/--output, --unmask, and -j/--json cannot be used with multiple input files.`
    );
    process.exit(2);
  }

  // Scan mode: audit directories (honouring .gitignore), several files, or the git index, and
  // report findings without secret values (text on stderr, or JSON/SARIF on stdout/--report)
  const scanMode =
    isStaged ||
    format !== undefined ||
    baselineArg.index !== -1 ||
    writeBaselineArg.index !== -1 ||
    (multiInput && !isInplace);
  if (scanMode) {
    if (isInplace || isReversible || outputFile || unmaskVaultFile || isJson) {
      console.error(
        `${colors.red}Error:${colors.reset} -i, -r, -o, --unmask and --json cannot be combined with scan mode ` +
          '(directories, --staged, --format, --baseline, --write-baseline).'
      );
      process.exit(2);
    }
    if (!isStaged && fileArgs.length === 0) {
      console.error(`${colors.red}Error:${colors.reset} scan mode needs at least one file or directory (or --staged).`);
      process.exit(2);
    }
    let outcome: ScanOutcome;
    try {
      outcome = runScan({
        targets: fileArgs,
        staged: isStaged,
        baselineFile: writeBaselineArg.index !== -1 ? undefined : baselineArg.value,
        cwd: process.cwd(),
        options: {
          include: loadedConfig?.include,
          exclude: loadedConfig?.exclude,
          allowlist: loadedConfig?.allowlist,
          customPatterns: loadedConfig?.customPatterns,
          detectHighEntropy: detectEntropy || (loadedConfig?.detectHighEntropy ?? false),
          presets: effectivePresets,
          entropy: loadedConfig?.entropy
        }
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`${colors.red}Error:${colors.reset} ${msg}`);
      process.exit(1);
    }

    if (writeBaselineArg.value) {
      writeScanBaseline(writeBaselineArg.value, outcome);
      console.error(
        `${colors.green}✔${colors.reset} Baseline with ${outcome.findings.length} finding(s) written to ${writeBaselineArg.value}`
      );
      process.exit(0);
    }

    if (format === 'json' || format === 'sarif') {
      const report = formatReport(outcome, format);
      if (reportArg.value) writeFileSync(reportArg.value, report, 'utf-8');
      else process.stdout.write(report);
    }
    console.error(formatText(outcome, colors));
    process.exit(outcome.findings.length > 0 ? 1 : 0);
  }

  // Multi-file in-place mode: rewrite every input that contains secrets
  if (multiInput) {
    let totalLeaksAcrossFiles = 0;
    let inPlaceFiles: string[];
    try {
      inPlaceFiles = expandTargets(fileArgs, process.cwd());
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`${colors.red}Error:${colors.reset} ${msg}`);
      process.exit(1);
    }

    // Read every input first so a missing/unreadable file aborts before anything is modified.
    // Binary and oversized files expanded from directories are skipped, never rewritten.
    const inputs: Array<{ file: string; content: string }> = [];
    for (const file of inPlaceFiles) {
      const read = readTextForScan(file);
      if (read.ok) {
        inputs.push({ file, content: read.content });
      } else if (read.reason === 'unreadable' || !hasDirectory) {
        console.error(`${colors.red}Error:${colors.reset} Cannot read file: ${relative(process.cwd(), file) || file}`);
        process.exit(1);
      }
    }

    const results = inputs.map(({ file, content: fileContent }) => ({
      file,
      res: redact(fileContent, {
        reversible: effectiveReversible,
        vault,
        include: loadedConfig?.include,
        exclude: loadedConfig?.exclude,
        allowlist: loadedConfig?.allowlist,
        customPatterns: loadedConfig?.customPatterns,
        detectHighEntropy: detectEntropy || (loadedConfig?.detectHighEntropy ?? false),
        presets: effectivePresets,
        entropy: loadedConfig?.entropy
      })
    }));

    // Persist the vault BEFORE rewriting inputs, so placeholders are always recoverable
    if (vaultOutFile && vault) {
      saveVault(vaultOutFile, vault, vaultKeyEnv);
    }

    for (const { file, res } of results) {
      const shown = relative(process.cwd(), file) || file;
      if (res.hasLeaks) {
        writeFileSync(file, res.text, 'utf-8');
        totalLeaksAcrossFiles += res.totalLeaks;
        console.error(`${colors.yellow}✖ [LEAK]${colors.reset} ${shown}: ${res.totalLeaks} secret(s) redacted in place`);
      } else {
        console.error(`${colors.green}✔ [CLEAN]${colors.reset} ${shown}`);
      }
    }

    if (totalLeaksAcrossFiles > 0 && failOnLeak) {
      console.error(
        `\n${colors.red}[agent-redact] Audit failed: detected ${totalLeaksAcrossFiles} secret(s) across ${results.length} files.${colors.reset}`
      );
      process.exit(1);
    }
    console.error(`\n${colors.green}[agent-redact] All ${results.length} files sanitized.${colors.reset}`);
    process.exit(0);
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
    const vault = loadVault(unmaskVaultFile, vaultKeyEnv);
    try {
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
    presets: effectivePresets,
    entropy: loadedConfig?.entropy
  });

  // Save vault file if requested
  if (vaultOutFile && vault) {
    saveVault(vaultOutFile, vault, vaultKeyEnv);
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
