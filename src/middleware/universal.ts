import { redact, unmask } from '../core/engine.js';
import type { RedactOptions, RedactResult } from '../core/types.js';
import { Vault } from '../core/vault.js';
import { unmaskDeep, type ToolInputPolicy } from '../core/deep.js';
import { StreamingUnmasker } from '../core/unmask-stream.js';

export interface AgentInterceptorOptions extends RedactOptions {
  /**
   * If true, automatically unmasks placeholders in the response: strings, plain
   * objects/arrays (deeply) and async-generator token streams. Class instances are
   * returned untouched; use `unmaskAnthropicStream` / `unmaskOpenAIStream` for SDK streams.
   * @default true
   */
  unmaskResponse?: boolean;

  /**
   * Restore secrets inside model-generated tool-call inputs of object/stream responses.
   * Default `false`: a prompt-injected model could otherwise exfiltrate a secret by placing
   * its placeholder in a tool argument (e.g. a URL). See {@link ToolInputPolicy}.
   */
  unmaskToolInputs?: ToolInputPolicy;

  /**
   * Optional callback invoked whenever one or more secrets are detected and masked.
   */
  onLeakDetected?: (info: {
    result: RedactResult;
    originalPrompt: string;
    sanitizedPrompt: string;
  }) => void;
}

/**
 * Universal agent wrapper. Intercepts prompts sent to ANY AI agent or LLM call,
 * masks credentials before network transmission, and safely unmasks tokens
 * in the returned output.
 *
 * Compatible with OpenAI, Anthropic, Google Gemini, Ollama, DeepSeek,
 * Mistral, LangChain, Vercel AI SDK, and custom multi-agent workflows.
 */
export function wrapAgent<TOutput>(
  agentFn: (sanitizedPrompt: string) => Promise<TOutput> | TOutput,
  options: AgentInterceptorOptions = {}
): (rawPrompt: string) => Promise<TOutput> {
  const { unmaskResponse = true, unmaskToolInputs, onLeakDetected, ...redactOptions } = options;

  return async (rawPrompt: string): Promise<TOutput> => {
    const vault = new Vault();
    const redactResult = redact(rawPrompt, {
      ...redactOptions,
      reversible: true,
      vault
    });

    if (redactResult.hasLeaks && onLeakDetected) {
      onLeakDetected({
        result: redactResult,
        originalPrompt: rawPrompt,
        sanitizedPrompt: redactResult.text
      });
    }

    const agentResponse = await agentFn(redactResult.text);
    if (!unmaskResponse) {
      return agentResponse;
    }

    if (typeof agentResponse === 'string') {
      return unmask(agentResponse, vault) as unknown as TOutput;
    }
    // Async generators (e.g. `async function*` token streams) are unmasked chunk by chunk,
    // so placeholders split across chunks are still restored
    if (isAsyncGenerator(agentResponse)) {
      return unmaskMixedStream(agentResponse, vault, unmaskToolInputs) as unknown as TOutput;
    }
    // Plain objects/arrays are deep-unmasked; class instances (SDK stream objects,
    // Buffers, Dates…) are returned untouched so their methods keep working
    return unmaskDeep(agentResponse, vault, { unmaskToolInputs });
  };
}

function isAsyncGenerator(value: unknown): value is AsyncGenerator<unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as { [Symbol.toStringTag]?: string })[Symbol.toStringTag] === 'AsyncGenerator'
  );
}

/** String chunks are stream-unmasked; other items are deep-unmasked one by one */
async function* unmaskMixedStream(
  source: AsyncGenerator<unknown>,
  vault: Vault,
  unmaskToolInputs: ToolInputPolicy | undefined
): AsyncGenerator<unknown> {
  const unmasker = new StreamingUnmasker(vault);
  for await (const item of source) {
    if (typeof item === 'string') {
      const out = unmasker.push(item);
      if (out) yield out;
    } else {
      const pending = unmasker.flush();
      if (pending) yield pending;
      yield unmaskDeep(item, vault, { unmaskToolInputs });
    }
  }
  const rest = unmasker.flush();
  if (rest) yield rest;
}

