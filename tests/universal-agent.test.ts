import { describe, it, expect, vi } from 'vitest';
import { wrapAgent, createExpressMiddleware } from '../src/index.js';

// Helper to construct sample secrets without triggering static push protection
const sampleKey = (...parts: string[]) => parts.join('');

describe('Universal AI Agent Interceptor & Middleware', () => {
  describe('wrapAgent (Framework Agnostic for any LLM / Agent)', () => {
    it('should intercept prompt, mask secret before calling OpenAI / DeepSeek, and unmask response', async () => {
      const fakeOpenAiKey = sampleKey(
        'sk-',
        'proj-',
        'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
      );

      let receivedPromptInLLM = '';

      // Mock agent implementation (could be OpenAI, DeepSeek, Ollama, LangChain, etc.)
      const mockLlmCall = vi.fn(async (sanitizedPrompt: string) => {
        receivedPromptInLLM = sanitizedPrompt;
        return `LLM received instruction with key ${sanitizedPrompt.match(/\[OPENAI_API_KEY_\d+\]/)?.[0]} and completed task.`;
      });

      const safeAgent = wrapAgent(mockLlmCall);

      const userInput = `Here is my OpenAI project key: ${fakeOpenAiKey}. Please run an evaluation.`;
      const response = await safeAgent(userInput);

      // Verify the agent/LLM NEVER received the raw key
      expect(receivedPromptInLLM).not.toContain(fakeOpenAiKey);
      expect(receivedPromptInLLM).toContain('[OPENAI_API_KEY_1]');

      // Verify the returned response was safely unmasked back for the local user
      expect(response).toContain(fakeOpenAiKey);
      expect(response).not.toContain('[OPENAI_API_KEY_1]');
    });

    it('should fire onLeakDetected callback when sensitive credentials are found', async () => {
      const fakeAnthropicKey = sampleKey(
        'sk-',
        'ant-api03-',
        'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345'
      );

      const onLeakSpy = vi.fn();

      const safeAgent = wrapAgent(
        async (prompt) => `Processed: ${prompt}`,
        { onLeakDetected: onLeakSpy }
      );

      await safeAgent(`Anthropic token: ${fakeAnthropicKey}`);

      expect(onLeakSpy).toHaveBeenCalledTimes(1);
      const leakInfo = onLeakSpy.mock.calls[0]![0];
      expect(leakInfo.result.hasLeaks).toBe(true);
      expect(leakInfo.result.totalLeaks).toBe(1);
      expect(leakInfo.sanitizedPrompt).toContain('[ANTHROPIC_API_KEY_1]');
    });
  });

  describe('createExpressMiddleware', () => {
    it('should redact sensitive tokens in incoming request body and attach vault to req', () => {
      const fakeJwt =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

      const middleware = createExpressMiddleware();

      const req: any = {
        body: {
          prompt: `Authenticate with ${fakeJwt}`,
          messages: [
            { role: 'user', content: `Also verify ${fakeJwt}` }
          ]
        }
      };

      let nextCalled = false;
      middleware(req, {}, () => {
        nextCalled = true;
      });

      expect(nextCalled).toBe(true);
      expect(req.body.prompt).toContain('[JWT_TOKEN_1]');
      expect(req.body.prompt).not.toContain(fakeJwt);
      expect(req.body.messages[0].content).toContain('[JWT_TOKEN_1]');
      expect(req.redact.hasLeaks).toBe(true);
      expect(req.redact.totalLeaks).toBe(2);
    });
  });
});

