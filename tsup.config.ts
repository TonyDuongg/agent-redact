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
  dts: false,
  clean: true,
  sourcemap: true,
  splitting: false,
  treeshake: true,
  minify: false,
  target: 'node22'
});

