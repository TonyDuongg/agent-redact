import { Transform, type TransformCallback } from 'node:stream';
import { StringDecoder } from 'node:string_decoder';
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

const PEM_BEGIN_PATTERN = /-----BEGIN (?:(?:RSA |OPENSSH |DSA |EC |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/;
const PEM_END_PATTERN = /-----END (?:(?:RSA |OPENSSH |DSA |EC |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----(?:\r?\n)?/;

/**
 * Node.js Transform Stream for memory-efficient O(1) continuous
 * stream redaction of large logs or piped inputs.
 */
export class RedactTransformStream extends Transform {
  private buffer = '';
  private decoder = new StringDecoder('utf8');
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
    const text = typeof chunk === 'string' ? chunk : this.decoder.write(chunk);
    this.buffer += text;

    // Process all completed PEM blocks first
    let pemEndMatch = this.buffer.match(PEM_END_PATTERN);
    while (pemEndMatch && pemEndMatch.index !== undefined) {
      const pemEnd = pemEndMatch.index + pemEndMatch[0].length;
      const pemSlice = this.buffer.slice(0, pemEnd);
      this.buffer = this.buffer.slice(pemEnd);

      const res = redact(pemSlice, {
        ...this.options,
        vault: this.vault
      });
      if (this.options.onLineRedacted && res.hasLeaks) {
        this.options.onLineRedacted(res);
      }
      this.push(res.text);

      pemEndMatch = this.buffer.match(PEM_END_PATTERN);
    }

    // If buffer contains an incomplete private key PEM block, hold it until completed (up to 1MB)
    const lastBegin = this.buffer.search(PEM_BEGIN_PATTERN);
    if (lastBegin !== -1) {
      const remaining = this.buffer.slice(lastBegin);
      if (!PEM_END_PATTERN.test(remaining)) {
        if (this.buffer.length < 1048576) {
          callback();
          return;
        }
        // If an open PEM block exceeds 1MB without an END marker, redact the open block
        // so private key body lines are never leaked unredacted line by line
        const before = this.buffer.slice(0, lastBegin);
        const prefixRes = redact(before, { ...this.options, vault: this.vault });
        this.push(prefixRes.text + '[REDACTED_PRIVATE_KEY]\n');
        this.buffer = '';
        callback();
        return;
      }
    }

    const lines = this.buffer.split('\n');
    // Keep the trailing chunk until full newline arrives
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
    this.buffer += this.decoder.end();
    if (this.buffer.length > 0) {
      // Check for unclosed private key block at end of stream
      const lastBegin = this.buffer.search(PEM_BEGIN_PATTERN);
      if (lastBegin !== -1 && !PEM_END_PATTERN.test(this.buffer.slice(lastBegin))) {
        const before = this.buffer.slice(0, lastBegin);
        const prefixRes = redact(before, { ...this.options, vault: this.vault });
        this.push(prefixRes.text + '[REDACTED_PRIVATE_KEY]');
      } else {
        const res = redact(this.buffer, {
          ...this.options,
          vault: this.vault
        });
        this.push(res.text);
      }
      this.buffer = '';
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

