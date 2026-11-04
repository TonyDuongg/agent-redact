import { readdirSync, statSync, readFileSync, appendFileSync, existsSync } from 'node:fs';
import { join, relative, extname } from 'node:path';
import { redact } from '../core/engine.js';
import { loadConfig } from '../core/config.js';
import type { RedactMatch } from '../core/types.js';

interface FileLeakRecord {
  file: string;
  line: number;
  match: RedactMatch;
}

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.svg',
  '.wasm', '.zip', '.tar', '.gz', '.7z', '.exe', '.dll',
  '.so', '.dylib', '.pdf', '.docx', '.xlsx', '.bin', '.dat'
]);

function getInput(name: string, fallback: string = ''): string {
  const envKey = `INPUT_${name.replace(/-/g, '_').toUpperCase()}`;
  return process.env[envKey] ?? fallback;
}

function setOutput(name: string, value: string): void {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile && existsSync(outputFile)) {
    appendFileSync(outputFile, `${name}=${value}\n`, 'utf-8');
  }
}

function writeSummary(markdown: string): void {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile && existsSync(summaryFile)) {
    appendFileSync(summaryFile, markdown + '\n\n', 'utf-8');
  }
}

function collectFiles(
  dir: string,
  excludeDirs: Set<string>,
  result: string[] = []
): string[] {
  try {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name.startsWith('.') && entry.name !== '.' && entry.name !== '..') {
        if (entry.name === '.git') continue;
      }

      const fullPath = join(dir, entry.name);

      if (entry.isDirectory()) {
        if (!excludeDirs.has(entry.name)) {
          collectFiles(fullPath, excludeDirs, result);
        }
      } else if (entry.isFile()) {
        const ext = extname(entry.name).toLowerCase();
        if (!BINARY_EXTENSIONS.has(ext)) {
          result.push(fullPath);
        }
      }
    }
  } catch {
    // skip unreadable directories
  }
  return result;
}

function calculateLineNumber(content: string, index: number): number {
  return content.slice(0, index).split('\n').length;
}

export async function runAction(): Promise<void> {
  const scanPath = getInput('scan-path', '.');
  const failOnLeak = getInput('fail-on-leak', 'true').toLowerCase() === 'true';
  const detectEntropy = getInput('detect-entropy', 'false').toLowerCase() === 'true';
  const configPath = getInput('config-path') || undefined;
  const excludeInput = getInput(
    'exclude',
    'node_modules,dist,build,.git,coverage,.turbo'
  );

  const excludeDirs = new Set(
    excludeInput.split(',').map((s) => s.trim()).filter(Boolean)
  );

  console.log(`[agent-redact] Starting security scan on: ${scanPath}`);
  console.log(`[agent-redact] Fail on leak: ${failOnLeak} | Entropy detection: ${detectEntropy}`);

  const loadedConfig = loadConfig(configPath);
  const filesToScan: string[] = [];

  const stat = statSync(scanPath);
  if (stat.isFile()) {
    filesToScan.push(scanPath);
  } else {
    collectFiles(scanPath, excludeDirs, filesToScan);
  }

  console.log(`[agent-redact] Discovered ${filesToScan.length} text files to analyze.`);

  const allLeaks: FileLeakRecord[] = [];
  const startTime = performance.now();

  for (const filePath of filesToScan) {
    let content: string;
    try {
      content = readFileSync(filePath, 'utf-8');
    } catch {
      continue;
    }

    const result = redact(content, {
      include: loadedConfig?.include,
      exclude: loadedConfig?.exclude,
      allowlist: loadedConfig?.allowlist,
      customPatterns: loadedConfig?.customPatterns,
      detectHighEntropy: detectEntropy || (loadedConfig?.detectHighEntropy ?? false),
      entropy: loadedConfig?.entropy
    });

    if (result.hasLeaks) {
      const relPath = relative(process.cwd(), filePath);
      for (const match of result.matches) {
        const line = calculateLineNumber(content, match.startIndex);
        allLeaks.push({ file: relPath, line, match });

        // Emit GitHub annotation for PR diffs
        console.log(
          `::error file=${relPath},line=${line}::[agent-redact] Leaked ${match.patternName} (${match.severity.toUpperCase()}) detected!`
        );
      }
    }
  }

  const durationMs = Math.round((performance.now() - startTime) * 100) / 100;
  const totalLeaks = allLeaks.length;
  const hasLeaks = totalLeaks > 0;

  // Set GitHub Action outputs
  setOutput('has-leaks', String(hasLeaks));
  setOutput('total-leaks', String(totalLeaks));

  // Build GitHub Step Summary Markdown
  let summaryMd = `## 🛡️ agent-redact Security Scan Report\n\n`;
  summaryMd += `* **Status**: ${hasLeaks ? '❌ **Secrets Detected**' : '✅ **No Leaks Found**'}\n`;
  summaryMd += `* **Files Scanned**: ${filesToScan.length}\n`;
  summaryMd += `* **Total Leaks Detected**: ${totalLeaks}\n`;
  summaryMd += `* **Scan Duration**: ${durationMs}ms\n\n`;

  if (hasLeaks) {
    summaryMd += `### 🚨 Detected Secret Leaks\n\n`;
    summaryMd += `| File | Line | Secret Type | Severity | Category |\n`;
    summaryMd += `| :--- | :---: | :--- | :---: | :---: |\n`;

    for (const leak of allLeaks) {
      summaryMd += `| \`${leak.file}\` | ${leak.line} | **${leak.match.patternName}** | \`${leak.match.severity.toUpperCase()}\` | ${leak.match.category} |\n`;
    }
  } else {
    summaryMd += `🎉 All scanned files are clean and safe from credentials & PII leaks!\n`;
  }

  writeSummary(summaryMd);

  console.log(`\n[agent-redact] Scan complete in ${durationMs}ms. Found ${totalLeaks} leak(s).`);

  if (hasLeaks && failOnLeak) {
    console.error(`\n❌ [agent-redact] Build failed due to detected sensitive credentials in repository.`);
    process.exit(1);
  }
}

// Execute when run directly as the GitHub Action entry point
const isEntryPoint =
  process.argv[1] &&
  (process.argv[1].endsWith('action/index.js') ||
    process.argv[1].endsWith('action\\index.js') ||
    process.env.RUN_AGENT_REDACT_ACTION === 'true');

if (isEntryPoint) {
  runAction().catch((err) => {
    console.error('Fatal error in agent-redact action:', err);
    process.exit(1);
  });
}
