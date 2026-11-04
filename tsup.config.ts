import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'patterns/index': 'src/patterns/index.ts',
    'cli/index': 'src/cli/index.ts',
    'mcp/index': 'src/mcp/index.ts',
    'action/index': 'src/action/index.ts'
  },
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  splitting: false,
  treeshake: true,
  minify: false,
  target: 'node20',
  banner: (ctx) => {
    if (
      ctx.entry === 'src/cli/index.ts' ||
      ctx.entry === 'cli/index' ||
      ctx.entry === 'src/mcp/index.ts' ||
      ctx.entry === 'mcp/index'
    ) {
      return { js: '#!/usr/bin/env node' };
    }
    return {};
  }
});

