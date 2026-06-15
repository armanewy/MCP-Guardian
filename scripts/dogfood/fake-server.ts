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

const useBuiltRuntime = process.argv.includes('--built');

function guardianCliLaunch(scriptName: 'proxy' | 'disabled'): { command: string; args: string[] } {
  if (useBuiltRuntime) {
    const built = repoPath('out', 'cli', `${scriptName}.js`);
    assert(fs.existsSync(built), `Built CLI missing at ${built}; run npm run build first`);
    return { command: process.execPath, args: [built] };
  }

  return {
    command: process.execPath,
    args: [tsxCli(), repoPath('src', 'cli', `${scriptName}.ts`)],
  };
}

function textFromResult(result: any): string {
  return String(result?.content?.[0]?.text ?? '');
}

function auditLog() {
  return db.listAuditLogs(200);
}

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-guardian-dogfood-'));
const db = new GuardianDatabase(path.join(tempRoot, '.mcp-guardian', 'mcp-guardian.sqlite'));
const configPath = path.join(tempRoot, 'mcp.json');
const callLogPath = path.join(tempRoot, 'fake-calls.log');
const serverName = 'fake-dangerous';
const configRootKey = 'mcpServers';
const fakeServerPath = repoPath('scripts', 'dogfood', 'fake-mcp-server.ts');
const sentinel = 'PRIVATE-SHOULD-NOT-PERSIST';
const privateRequestValue = `${sentinel}-REQUEST`;
const privateResponseValue = `${sentinel}-RESPONSE`;
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
      disabled: guardianCliLaunch('disabled'),
      proxy: guardianCliLaunch('proxy'),
    },
    db,
  });

  db.setPolicy(serverId, serverName, 'delete_file', 'block');
  db.setPolicy(serverId, serverName, 'echo_large_private_text', 'allow');
  db.setPolicy(serverId, serverName, 'leak_env', 'allow');
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

  await client.callTool({
    name: 'echo_large_private_text',
    arguments: { text: `${privateRequestValue}-${privateResponseValue}-${'x'.repeat(1200)}` },
  });
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

  const defaultSensitiveTools = ['write_file', 'run_shell_command', 'send_message'];
  for (const toolName of defaultSensitiveTools) {
    let forwarded = false;
    const defaultBlocked = await guardedCallTool({
      db,
      serverId,
      serverName,
      request: {
        method: 'tools/call',
        params: {
          name: toolName,
          arguments: { text: `default-deny-${toolName}`, command: 'echo default-deny' },
        },
      },
      approvalTimeoutMs: 5,
      callUpstream: async () => {
        forwarded = true;
        return { content: [{ type: 'text', text: 'should not happen' }] };
      },
    });
    assert((defaultBlocked as any).isError === true, `${toolName} should deny by default without approval`);
    assert(!forwarded, `${toolName} forwarded without approval`);
    assert(
      auditLog().some((entry) => entry.toolName === toolName && entry.decision === 'timeout_denied'),
      `${toolName} timeout_denied audit decision missing`,
    );
  }

  let approvalForwarded = false;
  const approvalPromise = guardedCallTool({
    db,
    serverId,
    serverName,
    request: {
      method: 'tools/call',
      params: { name: 'write_file', arguments: { text: 'approved dogfood write' } },
    },
    approvalTimeoutMs: 5_000,
    callUpstream: async () => {
      approvalForwarded = true;
      return { content: [{ type: 'text', text: 'approved write forwarded' }] };
    },
  });
  await new Promise((resolve) => setTimeout(resolve, 100));
  const pendingApproval = db.listPendingApprovals().find((approval) => approval.toolName === 'write_file');
  assert(pendingApproval, 'approval request was not created');
  db.resolveApproval(pendingApproval.id, 'approved', 'dogfood approval');
  const approved = await approvalPromise;
  assert((approved as any).isError !== true, 'approved call should not return an error result');
  assert(approvalForwarded, 'approved call was not forwarded upstream');
  assert(
    auditLog().some((entry) => entry.toolName === 'write_file' && entry.decision === 'asked_allowed'),
    'asked_allowed audit decision missing',
  );

  const auditJson = JSON.stringify(auditLog());
  assert(!auditJson.includes(sentinel), 'sentinel persisted in audit logs');
  assert(!auditJson.includes(privateRequestValue), 'private request value persisted in audit logs');
  assert(!auditJson.includes(privateResponseValue), 'private response prefix persisted in audit logs');

  rewriteServerMode({
    sourcePath: configPath,
    serverId,
    serverName,
    configRootKey,
    mode: 'active',
    expectedOriginalFingerprint: fingerprintServerConfig(originalConfig),
    launch: {
      disabled: guardianCliLaunch('disabled'),
      proxy: guardianCliLaunch('proxy'),
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
        runtime: useBuiltRuntime ? 'built' : 'source',
        checks: [
          'blocked tools hidden',
          'blocked call not forwarded',
          'upstream env restricted',
          'approval timeout denied',
          'default sensitive tools require approval',
          'approval allow forwards upstream',
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
