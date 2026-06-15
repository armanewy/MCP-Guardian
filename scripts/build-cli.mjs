import { build } from 'esbuild';

const common = {
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node20',
  sourcemap: false,
  banner: { js: '#!/usr/bin/env node' },
  external: ['better-sqlite3', '@modelcontextprotocol/sdk/*', '@modelcontextprotocol/sdk'],
};

await Promise.all([
  build({
    ...common,
    entryPoints: ['src/cli/proxy.ts'],
    outfile: 'out/cli/proxy.js',
  }),
  build({
    ...common,
    entryPoints: ['src/cli/disabled.ts'],
    outfile: 'out/cli/disabled.js',
  }),
]);
