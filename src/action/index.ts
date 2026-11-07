import { statSync, appendFileSync, existsSync, writeFileSync } from 'node:fs';
import { relative } from 'node:path';
import { loadConfig } from '../core/config.js';
import { walkFiles, readTextForScan, DEFAULT_MAX_SCAN_BYTES } from '../core/files.js';
import { scanContent, loadBaseline, toSarif, type Finding } from '../core/scan.js';
import { VERSION } from '../version.js';

function getInput(name: string, fallback: string = ''): string {
  const keyWithUnderscore = `INPUT_${name.replace(/-/g, '_').toUpperCase()}`;
  const keyWithHyphen = `INPUT_${name.toUpperCase()}`;
  const val = process.env[keyWithHyphen] ?? process.env[keyWithUnderscore];
  return val !== undefined && val.trim().length > 0 ? val.trim() : fallback;
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

/** Escaping rules for GitHub workflow command data and properties (see @actions/core) */
function escapeCommandData(value: string): string {
  return value.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

function escapeCommandProperty(value: string): string {
  return escapeCommandData(value).replace(/:/g, '%3A').replace(/,/g, '%2C');
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
  const maxFileSizeMb = Number(getInput('max-file-size', '5'));
  const maxBytes =
    Number.isFinite(maxFileSizeMb) && maxFileSizeMb > 0
      ? Math.floor(maxFileSizeMb * 1024 * 1024)
      : DEFAULT_MAX_SCAN_BYTES;

  console.log(`[agent-redact] Starting security scan on: ${scanPath}`);
  console.log(`[agent-redact] Fail on leak: ${failOnLeak} | Entropy detection: ${detectEntropy}`);

  const loadedConfig = loadConfig(configPath);
  const baselinePath = getInput('baseline') || undefined;
  const baseline = baselinePath ? loadBaseline(baselinePath) : undefined;
  const sarifPath = getInput('sarif-file') || undefined;
  const filesToScan: string[] = [];

  const stat = statSync(scanPath);
  if (stat.isFile()) {
    filesToScan.push(scanPath);
  } else {
    walkFiles(scanPath, excludeDirs, filesToScan);
  }

  console.log(`[agent-redact] Discovered ${filesToScan.length} text files to analyze.`);

  const allLeaks: Finding[] = [];
  const suppressed = { inline: 0, baseline: 0 };
  const skipped: Record<'binary' | 'too-large' | 'unreadable', number> = {
    binary: 0,
    'too-large': 0,
    unreadable: 0
  };
  const startTime = performance.now();

  for (const filePath of filesToScan) {
    // Content sniffing catches binaries with unlisted extensions (.woff2, .mp4, no extension…),
    // and the size cap keeps large blobs out of memory
    const read = readTextForScan(filePath, maxBytes);
    if (!read.ok) {
      skipped[read.reason]++;
      continue;
    }
    const relPath = relative(process.cwd(), filePath).replace(/\\/g, '/');
    // Line numbers come from a line-start index (the old slice/split per finding was O(n·m));
    // inline agent-redact-ignore comments and the optional baseline are honoured
    const result = scanContent(read.content, relPath, {
      include: loadedConfig?.include,
      exclude: loadedConfig?.exclude,
      allowlist: loadedConfig?.allowlist,
      customPatterns: loadedConfig?.customPatterns,
      detectHighEntropy: detectEntropy || (loadedConfig?.detectHighEntropy ?? false),
      presets: loadedConfig?.presets,
      entropy: loadedConfig?.entropy,
      respectInlineIgnore: true,
      baseline
    });
    suppressed.inline += result.suppressed.inline;
    suppressed.baseline += result.suppressed.baseline;

    for (const finding of result.findings) {
      allLeaks.push(finding);
      // Emit GitHub annotation for PR diffs.
      // Unescaped ',' or ':' in a path would corrupt the annotation's properties
      const annotationPath = escapeCommandProperty(finding.file);
      const message = escapeCommandData(
        `[agent-redact] Leaked ${finding.patternName} (${finding.severity.toUpperCase()}) detected!`
      );
      console.log(`::error file=${annotationPath},line=${finding.line},col=${finding.column}::${message}`);
    }
  }

  if (sarifPath) {
    writeFileSync(sarifPath, JSON.stringify(toSarif(allLeaks, VERSION), null, 2) + '\n', 'utf-8');
    console.log(`[agent-redact] SARIF report written to ${sarifPath}`);
  }
  if (suppressed.inline + suppressed.baseline > 0) {
    console.log(
      `[agent-redact] Suppressed ${suppressed.inline} finding(s) by inline comment and ${suppressed.baseline} by baseline.`
    );
  }

  const durationMs = Math.round((performance.now() - startTime) * 100) / 100;
  const totalLeaks = allLeaks.length;
  const hasLeaks = totalLeaks > 0;
  const skippedTotal = skipped.binary + skipped['too-large'] + skipped.unreadable;
  const skippedSummary =
    `Skipped ${skippedTotal} file(s): ${skipped.binary} binary, ` +
    `${skipped['too-large']} larger than ${(maxBytes / (1024 * 1024)).toFixed(2)} MB, ` +
    `${skipped.unreadable} unreadable.`;
  if (skippedTotal > 0) {
    console.log(`[agent-redact] ${skippedSummary}`);
  }

  // Set GitHub Action outputs
  setOutput('has-leaks', String(hasLeaks));
  setOutput('total-leaks', String(totalLeaks));

  // Build GitHub Step Summary Markdown
  let summaryMd = `## 🛡️ agent-redact Security Scan Report\n\n`;
  summaryMd += `* **Status**: ${hasLeaks ? '❌ **Secrets Detected**' : '✅ **No Leaks Found**'}\n`;
  summaryMd += `* **Files Scanned**: ${filesToScan.length - skippedTotal}\n`;
  if (skippedTotal > 0) {
    summaryMd += `* **Files Skipped**: ${skippedSummary}\n`;
  }
  summaryMd += `* **Total Leaks Detected**: ${totalLeaks}\n`;
  summaryMd += `* **Scan Duration**: ${durationMs}ms\n\n`;

  if (hasLeaks) {
    summaryMd += `### 🚨 Detected Secret Leaks\n\n`;
    summaryMd += `| File | Line | Secret Type | Severity | Category |\n`;
    summaryMd += `| :--- | :---: | :--- | :---: | :---: |\n`;

    for (const leak of allLeaks) {
      summaryMd += `| \`${leak.file}\` | ${leak.line} | **${leak.patternName}** | \`${leak.severity.toUpperCase()}\` | ${leak.category} |\n`;
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
