import type { RedactOptions, RedactResult } from '../core/types.js';
import { type ToolInputPolicy } from '../core/deep.js';
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
export declare function wrapAgent<TOutput>(agentFn: (sanitizedPrompt: string) => Promise<TOutput> | TOutput, options?: AgentInterceptorOptions): (rawPrompt: string) => Promise<TOutput>;
