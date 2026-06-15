import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { GuardianDatabase } from '../node/database';
import { buildUpstreamEnv, guardedCallTool } from '../node/proxyRuntime';
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

  it('writes backup files that are not world-readable on POSIX', () => {
    if (process.platform === 'win32') {
      return;
    }

    const fixture = setupRewriteFixture();
    const result = rewriteServerMode({
      sourcePath: fixture.configPath,
      serverId: fixture.serverId,
      serverName: 'filesystem',
      configRootKey: 'mcpServers',
      mode: 'disabled',
      expectedOriginalFingerprint: fingerprintServerConfig(fixture.original),
      launch: fixture.launch,
      db: fixture.db,
    });

    const backupMode = fs.statSync(result.backupPath).mode & 0o777;
    const backupDirMode = fs.statSync(path.dirname(result.backupPath)).mode & 0o777;
    expect(backupMode & 0o077).toBe(0);
    expect(backupDirMode & 0o077).toBe(0);
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

describe('database inventory settings', () => {
  it('persists custom config sources in SQLite settings', () => {
    const dir = tempDir();
    const dbPath = path.join(dir, 'guardian.sqlite');
    const configPath = path.join(dir, 'custom-mcp.json');
    let db = new GuardianDatabase(dbPath);

    db.addCustomConfigSource(configPath);
    db.addCustomConfigSource(configPath);
    expect(db.listCustomConfigSources()).toEqual([
      expect.objectContaining({
        client: 'Custom',
        path: path.resolve(configPath),
        parser: 'mcp-json',
        sourceKind: 'custom',
      }),
    ]);
    db.close();

    db = new GuardianDatabase(dbPath);
    expect(db.listCustomConfigSources()).toHaveLength(1);
    db.removeCustomConfigSource(db.listCustomConfigSources()[0].id);
    expect(db.listCustomConfigSources()).toHaveLength(0);
    db.close();
  });

  it('lists and deletes stale backup files', () => {
    const fixture = setupRewriteFixture();
    const result = rewriteServerMode({
      sourcePath: fixture.configPath,
      serverId: fixture.serverId,
      serverName: 'filesystem',
      configRootKey: 'mcpServers',
      mode: 'disabled',
      expectedOriginalFingerprint: fingerprintServerConfig(fixture.original),
      launch: fixture.launch,
      db: fixture.db,
    });

    expect(fixture.db.listBackups().map((backup) => backup.backupId)).toContain(result.backupId);
    fixture.db.deleteBackup(result.backupId ?? '');
    expect(fs.existsSync(result.backupPath)).toBe(false);
    expect(fixture.db.listBackups().map((backup) => backup.backupId)).not.toContain(result.backupId);
    fixture.db.close();
  });
});

describe('sqlite audit logging', () => {
  it('uses minimal request logging by default without value previews', () => {
    const dir = tempDir();
    const db = new GuardianDatabase(path.join(dir, 'guardian.sqlite'));
    db.logAudit({
      serverId: 'server-a',
      serverName: 'fs',
      toolName: 'read_file',
      action: 'tools/call',
      decision: 'allowed',
      risk: 'medium',
      request: {
        name: 'read_file',
        arguments: {
          path: '/tmp/private.txt',
          privateText: `VERY_PRIVATE_${'x'.repeat(600)}`,
        },
      },
    });

    const [entry] = db.listAuditLogs();
    expect(entry.requestJson).toContain('"detailLevel": "minimal"');
    expect(entry.requestJson).toContain('"privateText"');
    expect(entry.requestJson).toContain('"byteLengthEstimate"');
    expect(entry.requestJson).not.toContain('VERY_PRIVATE');
    expect(entry.requestJson).not.toContain('/tmp/private.txt');
    db.close();
  });

  it('supports opt-in redacted request previews', () => {
    const dir = tempDir();
    const db = new GuardianDatabase(path.join(dir, 'guardian.sqlite'));
    db.setAuditDetailLevel('redacted-preview');
    db.logAudit({
      serverId: 'server-a',
      serverName: 'fs',
      toolName: 'read_file',
      action: 'tools/call',
      decision: 'allowed',
      risk: 'medium',
      request: { name: 'read_file', arguments: { API_KEY: 'abc123' } },
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
    const summary = JSON.parse(entry.responseSummaryJson ?? '{}');
    expect(summary.preview).toBeNull();
    expect(summary.contentItemCount).toBe(1);
    expect(summary.contentTypes).toEqual(['text']);
    expect(summary.isError).toBe(false);
    expect(entry.responseSummaryJson).toContain('byteLengthEstimate');
    expect(entry.responseSummaryJson).not.toContain('START-');
    expect(entry.responseSummaryJson).not.toContain('-SECRET-END');
    expect(entry).not.toHaveProperty('responseJson');
    db.close();
  });

  it('stores response previews only when redacted-preview is enabled', () => {
    const dir = tempDir();
    const db = new GuardianDatabase(path.join(dir, 'guardian.sqlite'));
    db.setAuditDetailLevel('redacted-preview');
    db.logAudit({
      serverId: 'server-a',
      serverName: 'fs',
      toolName: 'read_file',
      action: 'tools/call',
      decision: 'allowed',
      risk: 'medium',
      response: {
        content: [{ type: 'text', text: 'visible debug response' }],
        isError: false,
      },
    });

    const [entry] = db.listAuditLogs();
    const summary = JSON.parse(entry.responseSummaryJson ?? '{}');
    expect(summary.preview).toContain('visible debug response');
    db.close();
  });
});

describe('proxy policy behavior', () => {
  it('does not pass Guardian process secrets upstream unless explicit in original env', () => {
    const baseEnv = {
      PATH: '/usr/bin',
      HOME: '/home/user',
      MCP_GUARDIAN_TEST_SECRET: 'do-not-pass',
    };

    expect(buildUpstreamEnv(undefined, baseEnv)).toEqual({
      PATH: '/usr/bin',
      HOME: '/home/user',
    });
    expect(
      buildUpstreamEnv(
        { MCP_GUARDIAN_TEST_SECRET: 'explicit-pass' },
        baseEnv,
      ).MCP_GUARDIAN_TEST_SECRET,
    ).toBe('explicit-pass');
  });

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
    expect(db.listAuditLogs()[0].decision).toBe('blocked_by_policy');
    db.close();
  });
});
