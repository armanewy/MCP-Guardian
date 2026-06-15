import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { GuardianDatabase } from '../node/database';
import { guardedCallTool } from '../node/proxyRuntime';
import { rewriteServerMode } from '../node/rewrite';
import { createServerId, fingerprintServerConfig } from '../shared/identity';
import { evaluatePolicy, filterVisibleTools } from '../shared/policy';
import type { McpServerDefinition, ToolInventoryItem } from '../shared/types';

const tempDirs: string[] = [];

function tempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-guardian-test-'));
  tempDirs.push(dir);
  return dir;
}

function writeConfig(configPath: string, serverConfig: McpServerDefinition): void {
  fs.writeFileSync(
    configPath,
    JSON.stringify({
      appSetting: true,
      mcpServers: {
        filesystem: serverConfig,
        other: {
          command: 'node',
          args: ['other.js'],
        },
      },
    }),
  );
}

function setupRewriteFixture(): {
  dir: string;
  configPath: string;
  db: GuardianDatabase;
  serverId: string;
  original: McpServerDefinition;
  launch: { disabled: { command: string; args: string[] }; proxy: { command: string; args: string[] } };
} {
  const dir = tempDir();
  const configPath = path.join(dir, 'config.json');
  const original = {
    command: 'npx',
    args: ['--dangerously-skip', '@modelcontextprotocol/server-filesystem', dir],
    env: { TOKEN: 'secret-value' },
  };
  writeConfig(configPath, original);
  return {
    dir,
    configPath,
    db: new GuardianDatabase(path.join(dir, 'guardian.sqlite')),
    serverId: createServerId({
      sourcePath: configPath,
      configRootKey: 'mcpServers',
      serverName: 'filesystem',
    }),
    original,
    launch: {
      disabled: { command: 'node', args: ['disabled.js'] },
      proxy: { command: 'node', args: ['proxy.js'] },
    },
  };
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('policy engine', () => {
  it('uses serverId so serverName collisions do not share policies', () => {
    const firstId = 'server-a';
    const secondId = 'server-b';
    const policies = [
      { serverId: firstId, serverName: 'filesystem', toolName: 'write_file', action: 'block' as const, updatedAt: 'now' },
    ];

    expect(
      evaluatePolicy({
        policies,
        serverId: firstId,
        serverName: 'filesystem',
        toolName: 'write_file',
        risk: 'high',
      }).action,
    ).toBe('block');

    expect(
      evaluatePolicy({
        policies,
        serverId: secondId,
        serverName: 'filesystem',
        toolName: 'write_file',
        risk: 'medium',
      }).action,
    ).toBe('allow');
  });
});

describe('config rewrite', () => {
  it('does not duplicate env secrets in mcpGuardian metadata', () => {
    const fixture = setupRewriteFixture();
    const result = rewriteServerMode({
      sourcePath: fixture.configPath,
      serverId: fixture.serverId,
      serverName: 'filesystem',
      configRootKey: 'mcpServers',
      mode: 'protected',
      expectedOriginalFingerprint: fingerprintServerConfig(fixture.original),
      launch: fixture.launch,
      db: fixture.db,
    });

    const rewritten = JSON.parse(fs.readFileSync(fixture.configPath, 'utf8'));
    const metadata = rewritten.mcpServers.filesystem.mcpGuardian;
    expect(fs.existsSync(result.backupPath)).toBe(true);
    expect(metadata.mode).toBe('protected');
    expect(metadata.backupId).toBeTruthy();
    expect(metadata.originalFingerprint).toBe(fingerprintServerConfig(fixture.original));
    expect(metadata).not.toHaveProperty('original');
    expect(JSON.stringify(metadata)).not.toContain('secret-value');
    expect(rewritten.mcpServers.filesystem.env.TOKEN).toBe('secret-value');
    fixture.db.close();
  });

  it('preserves upstream args beginning with "--" through backup lookup', () => {
    const fixture = setupRewriteFixture();
    rewriteServerMode({
      sourcePath: fixture.configPath,
      serverId: fixture.serverId,
      serverName: 'filesystem',
      configRootKey: 'mcpServers',
      mode: 'protected',
      expectedOriginalFingerprint: fingerprintServerConfig(fixture.original),
      launch: fixture.launch,
      db: fixture.db,
    });

    const rewritten = JSON.parse(fs.readFileSync(fixture.configPath, 'utf8'));
    expect(rewritten.mcpServers.filesystem.args).not.toContain('--upstream-arg');
    const backupId = rewritten.mcpServers.filesystem.mcpGuardian.backupId;
    expect(fixture.db.readServerConfigFromBackup(backupId).args).toEqual(fixture.original.args);
    fixture.db.close();
  });

  it('performs atomic rewrite while preserving unrelated config keys', () => {
    const fixture = setupRewriteFixture();
    rewriteServerMode({
      sourcePath: fixture.configPath,
      serverId: fixture.serverId,
      serverName: 'filesystem',
      configRootKey: 'mcpServers',
      mode: 'disabled',
      expectedOriginalFingerprint: fingerprintServerConfig(fixture.original),
      launch: fixture.launch,
      db: fixture.db,
    });

    const rewritten = JSON.parse(fs.readFileSync(fixture.configPath, 'utf8'));
    expect(rewritten.appSetting).toBe(true);
    expect(rewritten.mcpServers.other.command).toBe('node');
    expect(rewritten.mcpServers.filesystem.mcpGuardian).not.toHaveProperty('original');
    expect(fs.readdirSync(path.dirname(fixture.configPath)).some((name) => name.includes('.tmp'))).toBe(false);
    fixture.db.close();
  });

  it('restores server config from backupId instead of embedded metadata', () => {
    const fixture = setupRewriteFixture();
    rewriteServerMode({
      sourcePath: fixture.configPath,
      serverId: fixture.serverId,
      serverName: 'filesystem',
      configRootKey: 'mcpServers',
      mode: 'disabled',
      expectedOriginalFingerprint: fingerprintServerConfig(fixture.original),
      launch: fixture.launch,
      db: fixture.db,
    });

    rewriteServerMode({
      sourcePath: fixture.configPath,
      serverId: fixture.serverId,
      serverName: 'filesystem',
      configRootKey: 'mcpServers',
      mode: 'active',
      expectedOriginalFingerprint: fingerprintServerConfig(fixture.original),
      launch: fixture.launch,
      db: fixture.db,
    });

    const restored = JSON.parse(fs.readFileSync(fixture.configPath, 'utf8'));
    expect(restored.mcpServers.filesystem.command).toBe(fixture.original.command);
    expect(restored.mcpServers.filesystem.args).toEqual(fixture.original.args);
    expect(restored.mcpServers.filesystem.env.TOKEN).toBe('secret-value');
    fixture.db.close();
  });
});

describe('sqlite audit logging', () => {
  it('redacts secrets before writing capped audit rows', () => {
    const dir = tempDir();
    const db = new GuardianDatabase(path.join(dir, 'guardian.sqlite'));
    db.logAudit({
      serverId: 'server-a',
      serverName: 'fs',
      toolName: 'read_file',
      action: 'tools/call',
      decision: 'allowed',
      risk: 'medium',
      request: { API_KEY: 'abc123' },
    });

    const [entry] = db.listAuditLogs();
    expect(entry.requestJson).toContain('[REDACTED]');
    expect(entry.requestJson).not.toContain('abc123');
    db.close();
  });

  it('stores response summaries instead of full read_file output', () => {
    const dir = tempDir();
    const db = new GuardianDatabase(path.join(dir, 'guardian.sqlite'));
    const hugeText = `START-${'x'.repeat(1000)}-SECRET-END`;
    db.logAudit({
      serverId: 'server-a',
      serverName: 'fs',
      toolName: 'read_file',
      action: 'tools/call',
      decision: 'allowed',
      risk: 'medium',
      response: {
        content: [{ type: 'text', text: hugeText }],
        isError: false,
      },
    });

    const [entry] = db.listAuditLogs();
    expect(entry.responseSummaryJson).toBeTruthy();
    expect(entry.responseSummaryJson).toContain('byteLengthEstimate');
    expect(entry.responseSummaryJson).not.toContain('-SECRET-END');
    expect(entry).not.toHaveProperty('responseJson');
    db.close();
  });
});

describe('proxy policy behavior', () => {
  it('hides blocked tools from tools/list results by serverId', () => {
    const tools: ToolInventoryItem[] = [
      { serverId: 'server-a', serverName: 'fs', toolName: 'read_file', risk: 'medium', source: 'actual' },
      { serverId: 'server-a', serverName: 'fs', toolName: 'delete_file', risk: 'critical', source: 'actual' },
    ];

    const visible = filterVisibleTools(tools, [
      { serverId: 'server-a', serverName: 'fs', toolName: 'delete_file', action: 'block', updatedAt: 'now' },
    ]);

    expect(visible.map((tool) => tool.toolName)).toEqual(['read_file']);
  });

  it('returns blocked tool result without forwarding the call', async () => {
    const dir = tempDir();
    const db = new GuardianDatabase(path.join(dir, 'guardian.sqlite'));
    db.setPolicy('server-a', 'fs', 'delete_file', 'block');
    let forwarded = false;

    const result = await guardedCallTool({
      db,
      serverId: 'server-a',
      serverName: 'fs',
      request: {
        method: 'tools/call',
        params: {
          name: 'delete_file',
          arguments: { path: '/tmp/x' },
        },
      },
      approvalTimeoutMs: 1,
      callUpstream: async () => {
        forwarded = true;
        return { content: [] };
      },
    });

    expect(forwarded).toBe(false);
    expect(result).toMatchObject({ isError: true });
    expect(db.listAuditLogs()[0].decision).toBe('blocked');
    db.close();
  });
});
