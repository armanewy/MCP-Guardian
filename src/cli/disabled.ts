#!/usr/bin/env node
import { getArg, parseArgs } from './args';
import { runDisabledServer } from '../node/proxyRuntime';

const args = parseArgs(process.argv.slice(2));

runDisabledServer(getArg(args, 'server-name', getArg(args, 'server-id', 'unknown'))).catch((error) => {
  console.error(error instanceof Error ? error.stack : String(error));
  process.exit(1);
});
