import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { GuardianDatabase } from '../../src/node/database';
import { guardedCallTool } from '../../src/node/proxyRuntime';
import { rewriteServerMode } from '../../src/node/rewrite';
import { createServerId, fingerprintServerConfig } from '../../src/shared/identity';
import type { McpServerDefinition } from '../../src/shared/types';

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

function repoPath(...parts: string[]): string {
  return path.resolve(...parts);
}

function tsxCli(): string {
  return repoPath('node_modules', 'tsx', 'dist', 'cli.mjs');
}

function textFromResult(result: any): string {
  return String(result?.content?.[0]?.text ?? '');
}

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-guardian-dogfood-'));
const db = new GuardianDatabase(path.join(tempRoot, '.mcp-guardian', 'mcp-guardian.sqlite'));
const configPath = path.join(tempRoot, 'mcp.json');
const callLogPath = path.join(tempRoot, 'fake-calls.log');
const serverName = 'fake-dangerous';
const configRootKey = 'mcpServers';
const fakeServerPath = repoPath('scripts', 'dogfood', 'fake-mcp-server.ts');
const originalConfig: McpServerDefinition = {
  command: process.execPath,
  args: [tsxCli(), fakeServerPath],
  env: {
    FAKE_CALL_LOG: callLogPath,
  },
};
const serverId = createServerId({ sourcePath: configPath, configRootKey, serverName });

process.env.MCP_GUARDIAN_TEST_SECRET = 'guardian-process-secret';
fs.writeFileSync(
  configPath,
  JSON.stringify({ mcpServers: { [serverName]: originalConfig } }, null, 2),
  'utf8',
);

try {
  const protectedRewrite = rewriteServerMode({
    sourcePath: configPath,
    serverId,
    serverName,
    configRootKey,
    mode: 'protected',
    expectedOriginalFingerprint: fingerprintServerConfig(originalConfig),
    launch: {
      disabled: { command: process.execPath, args: [tsxCli(), repoPath('src', 'cli', 'disabled.ts')] },
      proxy: { command: process.execPath, args: [tsxCli(), repoPath('src', 'cli', 'proxy.ts')] },
    },
    db,
  });

  db.setPolicy(serverId, serverName, 'delete_file', 'block');
  const protectedConfig = JSON.parse(fs.readFileSync(configPath, 'utf8')).mcpServers[serverName];
  const client = new Client({ name: 'mcp-guardian-dogfood-client', version: '0.1.0' });
  await client.connect(
    new StdioClientTransport({
      command: protectedConfig.command,
      args: protectedConfig.args,
      env: protectedConfig.env,
      stderr: 'pipe',
    }),
  );

  const tools = await client.listTools();
  assert(!tools.tools.some((tool) => tool.name === 'delete_file'), 'blocked delete_file should be hidden');

  const blocked = await client.callTool({
    name: 'delete_file',
    arguments: { path: path.join(tempRoot, 'delete-me.txt') },
  });
  assert((blocked as any).isError === true, 'blocked tool should return isError result');

  const envResult = await client.callTool({ name: 'leak_env', arguments: {} });
  const leakedEnv = textFromResult(envResult);
  assert(!leakedEnv.includes('guardian-process-secret'), 'Guardian process env secret leaked upstream');

  const privateText = `PRIVATE-${'x'.repeat(1200)}-END`;
  await client.callTool({ name: 'echo_large_private_text', arguments: { text: privateText } });
  await client.close();

  const calls = fs.existsSync(callLogPath) ? fs.readFileSync(callLogPath, 'utf8') : '';
  assert(!calls.split(/\r?\n/).includes('delete_file'), 'blocked tool was forwarded upstream');
  assert(calls.includes('leak_env'), 'allowed env test tool was not forwarded');

  let timeoutForwarded = false;
  const timedOut = await guardedCallTool({
    db,
    serverId,
    serverName,
    request: {
      method: 'tools/call',
      params: { name: 'write_file', arguments: { text: 'private timeout text' } },
    },
    approvalTimeoutMs: 5,
    callUpstream: async () => {
      timeoutForwarded = true;
      return { content: [{ type: 'text', text: 'should not happen' }] };
    },
  });
  assert((timedOut as any).isError === true, 'timed-out approval should deny with tool error');
  assert(!timeoutForwarded, 'timed-out approval forwarded upstream');

  const auditJson = JSON.stringify(db.listAuditLogs(100));
  assert(!auditJson.includes(privateText), 'private request/response value persisted in audit logs');

  rewriteServerMode({
    sourcePath: configPath,
    serverId,
    serverName,
    configRootKey,
    mode: 'active',
    expectedOriginalFingerprint: fingerprintServerConfig(originalConfig),
    launch: {
      disabled: { command: process.execPath, args: [tsxCli(), repoPath('src', 'cli', 'disabled.ts')] },
      proxy: { command: process.execPath, args: [tsxCli(), repoPath('src', 'cli', 'proxy.ts')] },
    },
    db,
  });
  const restored = JSON.parse(fs.readFileSync(configPath, 'utf8')).mcpServers[serverName];
  assert(JSON.stringify(restored) === JSON.stringify(originalConfig), 'restore did not return original config exactly');

  console.log(
    JSON.stringify(
      {
        ok: true,
        tempRoot,
        backupId: protectedRewrite.backupId,
        checks: [
          'blocked tools hidden',
          'blocked call not forwarded',
          'upstream env restricted',
          'approval timeout denied',
          'audit omits private values',
          'restore exact',
        ],
      },
      null,
      2,
    ),
  );
} finally {
  db.close();
}
