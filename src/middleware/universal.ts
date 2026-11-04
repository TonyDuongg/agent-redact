import { redact, unmask } from '../core/engine.js';
import type { RedactOptions, RedactResult } from '../core/types.js';
import { Vault } from '../core/vault.js';

export interface AgentInterceptorOptions extends RedactOptions {
  /**
   * If true, automatically unmasks placeholders in string responses.
   * @default true
   */
  unmaskResponse?: boolean;

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
  const { unmaskResponse = true, onLeakDetected, ...redactOptions } = options;

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

    // If response is a string and unmaskResponse is enabled, restore secrets
    if (unmaskResponse && typeof agentResponse === 'string') {
      return unmask(agentResponse, vault) as unknown as TOutput;
    }

    return agentResponse;
  };
}

