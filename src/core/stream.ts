import { Transform, type TransformCallback } from 'node:stream';
import { redact } from './engine.js';
import type { RedactOptions, RedactResult } from './types.js';
import { Vault } from './vault.js';

export interface RedactStreamOptions extends RedactOptions {
  vault?: Vault;
  /**
   * Optional listener triggered whenever a line with secrets is processed.
   */
  onLineRedacted?: (result: RedactResult) => void;
}

/**
 * Node.js Transform Stream for memory-efficient O(1) continuous
 * stream redaction of large logs or piped inputs.
 */
export class RedactTransformStream extends Transform {
  private buffer = '';
  private options: RedactStreamOptions;
  public readonly vault: Vault;

  constructor(options: RedactStreamOptions = {}) {
    super({ objectMode: false });
    this.options = options;
    this.vault = options.vault ?? new Vault();
  }

  override _transform(
    chunk: Buffer | string,
    _encoding: BufferEncoding,
    callback: TransformCallback
  ): void {
    this.buffer += chunk.toString();
    const lines = this.buffer.split('\n');
    // Keep the trailing chunk until full newline
    this.buffer = lines.pop() ?? '';

    for (const line of lines) {
      const res = redact(line, {
        ...this.options,
        vault: this.vault
      });
      if (this.options.onLineRedacted && res.hasLeaks) {
        this.options.onLineRedacted(res);
      }
      this.push(res.text + '\n');
    }

    callback();
  }

  override _flush(callback: TransformCallback): void {
    if (this.buffer.length > 0) {
      const res = redact(this.buffer, {
        ...this.options,
        vault: this.vault
      });
      this.push(res.text);
    }
    callback();
  }
}

/**
 * Helper to create a new Transform stream instance.
 */
export function createRedactStream(options?: RedactStreamOptions): RedactTransformStream {
  return new RedactTransformStream(options);
}
