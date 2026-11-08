import { Transform, type TransformCallback } from 'node:stream';
import type { RedactOptions, RedactResult } from './types.js';
import { Vault } from './vault.js';
export interface RedactStreamOptions extends RedactOptions {
    vault?: Vault;
    /**
     * Optional listener triggered whenever a line with secrets is processed.
     */
    onLineRedacted?: (result: RedactResult) => void;
}
export declare class RedactTransformStream extends Transform {
    private buffer;
    /** True while discarding the body of an oversized private key block that has no END yet */
    private droppingOpenPem;
    private decoder;
    private options;
    readonly vault: Vault;
    constructor(options?: RedactStreamOptions);
    _transform(chunk: Buffer | string, _encoding: BufferEncoding, callback: TransformCallback): void;
    _flush(callback: TransformCallback): void;
}
/**
 * Helper to create a new Transform stream instance.
 */
export declare function createRedactStream(options?: RedactStreamOptions): RedactTransformStream;
