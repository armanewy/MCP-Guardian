#!/usr/bin/env node
import { parseArgs, getArg } from './args';
import { getDefaultDatabasePath } from '../node/database';
import { runProxyRuntime } from '../node/proxyRuntime';

const args = parseArgs(process.argv.slice(2));
runProxyRuntime({
  serverId: getArg(args, 'server-id'),
  serverName: getArg(args, 'server-name', 'unknown'),
  backupId: getArg(args, 'backup-id') || undefined,
  dbPath: getArg(args, 'db-path', getDefaultDatabasePath()),
  approvalTimeoutMs: Number(getArg(args, 'approval-timeout-ms', '120000')),
}).catch((error) => {
  console.error(error instanceof Error ? error.stack : String(error));
  process.exit(1);
});
