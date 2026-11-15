/**
 * `agent-redact proxy --provider anthropic|openai [options]`: runs the local redacting proxy
 * until interrupted. See src/proxy/server.ts for the behavior.
 */
import { loadConfig } from '../core/config.js';
import { resolvePresets } from '../patterns/presets.js';
import { startProxy, type ProxyProvider } from '../proxy/server.js';

const USAGE = `Usage: agent-redact proxy --provider <anthropic|openai> [options]

  --provider <name>            anthropic or openai (required)
  --port <n>                   Port on the loopback address (default 8787, 0 = any free port)
  --upstream <url>             Upstream API base (default: the provider's public API; https only)
  --unmask-tool-inputs <list>  Comma-separated tool names whose inputs get real secrets back
                               ("*" for all). Default: tool inputs stay masked.
  --preset <a,b>               Enable opt-in presets (e.g. vn-pii)
  --entropy                    Also redact high-entropy tokens
  --config <path>              Configuration file
`;

const VALUE_FLAGS = new Set(['--provider', '--port', '--upstream', '--unmask-tool-inputs', '--preset', '--config']);

export async function runProxyCli(args: string[]): Promise<number> {
  const values = new Map<string, string>();
  let entropy = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '-h' || arg === '--help') {
      process.stdout.write(USAGE);
      return 0;
    }
    if (arg === '--entropy') {
      entropy = true;
      continue;
    }
    const value = args[i + 1];
    if (!VALUE_FLAGS.has(arg) || value === undefined || value.startsWith('--')) {
      process.stderr.write(`Error: unexpected argument "${arg}"\n\n${USAGE}`);
      return 2;
    }
    values.set(arg, value);
    i++;
  }

  const provider = values.get('--provider');
  if (provider !== 'anthropic' && provider !== 'openai') {
    process.stderr.write(`Error: --provider must be "anthropic" or "openai"\n\n${USAGE}`);
    return 2;
  }
  const port = Number(values.get('--port') ?? 8787);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    process.stderr.write('Error: --port must be an integer between 0 and 65535\n');
    return 2;
  }

  const toolList = (values.get('--unmask-tool-inputs') ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const unmaskToolInputs = toolList.includes('*') ? true : toolList.length ? (name: string) => toolList.includes(name) : false;

  let redactOptions;
  try {
    const config = loadConfig(values.get('--config'));
    const presets = [...(config?.presets ?? []), ...(values.get('--preset') ?? '').split(',').map((s) => s.trim()).filter(Boolean)];
    resolvePresets(presets);
    redactOptions = {
      include: config?.include,
      exclude: config?.exclude,
      allowlist: config?.allowlist,
      customPatterns: config?.customPatterns,
      detectHighEntropy: entropy || (config?.detectHighEntropy ?? false),
      presets,
      entropy: config?.entropy
    };
  } catch (err) {
    process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 2;
  }

  let proxy;
  try {
    proxy = await startProxy({
      provider: provider as ProxyProvider,
      upstream: values.get('--upstream'),
      port,
      unmaskToolInputs,
      redactOptions,
      log: (line) => process.stderr.write(`[agent-redact proxy] ${line}\n`)
    });
  } catch (err) {
    process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }

  const env = provider === 'anthropic' ? `ANTHROPIC_BASE_URL=${proxy.url}` : `OPENAI_BASE_URL=${proxy.url}/v1`;
  process.stderr.write(
    `[agent-redact proxy] listening on ${proxy.url} (${provider}); tool inputs ${
      unmaskToolInputs === false ? 'stay masked' : `restored for: ${toolList.join(', ')}`
    }\n[agent-redact proxy] point your client at it: ${env}\n`
  );

  await new Promise<void>((resolve) => {
    const stop = () => resolve();
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  });
  await proxy.close();
  return 0;
}
