#!/usr/bin/env node
import { parseArgs, getArg, getArgs } from './args';
import { getDefaultDatabasePath } from '../node/database';
import { runProxyRuntime } from '../node/proxyRuntime';

const args = parseArgs(process.argv.slice(2));
const sourcePath = getArg(args, 'source-path');

runProxyRuntime({
  serverName: getArg(args, 'server-name', 'unknown'),
  sourcePath: sourcePath || undefined,
  dbPath: getArg(args, 'db-path', getDefaultDatabasePath()),
  upstreamCommand: getArg(args, 'upstream-command'),
  upstreamArgs: getArgs(args, 'upstream-arg'),
  approvalTimeoutMs: Number(getArg(args, 'approval-timeout-ms', '120000')),
}).catch((error) => {
  console.error(error instanceof Error ? error.stack : String(error));
  process.exit(1);
});
