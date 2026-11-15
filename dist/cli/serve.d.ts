import type { Readable, Writable } from 'node:stream';
export declare function createHandler(): (method: string, params: Record<string, unknown>) => unknown;
/** Runs the worker until stdin ends. Returns the process exit code. */
export declare function runServe(args: string[], input?: Readable, output?: Writable, errors?: Writable): Promise<number>;
