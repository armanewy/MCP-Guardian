import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { GuardianDatabase } from '../node/database';
import { rewriteServerMode } from '../node/rewrite';
import { evaluatePolicy, filterVisibleTools } from '../shared/policy';
import type { ToolInventoryItem } from '../shared/types';

const tempDirs: string[] = [];

function tempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-guardian-test-'));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('policy engine', () => {
  it('prefers exact policies and defaults high risk tools to ask', () => {
    expect(
      evaluatePolicy({
        policies: [{ serverName: 'fs', toolName: 'write_file', action: 'block', updatedAt: 'now' }],
        serverName: 'fs',
        toolName: 'write_file',
        risk: 'high',
      }).action,
    ).toBe('block');

    expect(
      evaluatePolicy({
        policies: [],
        serverName: 'fs',
        toolName: 'write_file',
        risk: 'high',
      }).action,
    ).toBe('ask');
  });
});

describe('config rewrite', () => {
  it('backs up, disables, protects, and restores a server config', () => {
    const dir = tempDir();
    const configPath = path.join(dir, 'config.json');
    fs.writeFileSync(
      configPath,
      JSON.stringify({
        mcpServers: {
          filesystem: {
            command: 'npx',
            args: ['-y', '@modelcontextprotocol/server-filesystem', dir],
            env: { TOKEN: 'secret' },
          },
        },
      }),
    );

    const launch = {
      disabled: { command: 'node', args: ['disabled.js'] },
      proxy: { command: 'node', args: ['proxy.js'] },
    };

    const disabled = rewriteServerMode({
      sourcePath: configPath,
      serverName: 'filesystem',
      configRootKey: 'mcpServers',
      mode: 'disabled',
      launch,
      dbPath: path.join(dir, 'db.sqlite'),
    });
    expect(fs.existsSync(disabled.backupPath)).toBe(true);
    expect(JSON.parse(fs.readFileSync(configPath, 'utf8')).mcpServers.filesystem.mcpGuardian.mode).toBe('disabled');

    rewriteServerMode({
      sourcePath: configPath,
      serverName: 'filesystem',
      configRootKey: 'mcpServers',
      mode: 'protected',
      launch,
      dbPath: path.join(dir, 'db.sqlite'),
    });
    const protectedJson = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    expect(protectedJson.mcpServers.filesystem.command).toBe('node');
    expect(protectedJson.mcpServers.filesystem.args).toContain('--upstream-command');
    expect(protectedJson.mcpServers.filesystem.mcpGuardian.original.command).toBe('npx');

    rewriteServerMode({
      sourcePath: configPath,
      serverName: 'filesystem',
      configRootKey: 'mcpServers',
      mode: 'active',
      launch,
      dbPath: path.join(dir, 'db.sqlite'),
    });
    expect(JSON.parse(fs.readFileSync(configPath, 'utf8')).mcpServers.filesystem.command).toBe('npx');
  });
});

describe('sqlite audit logging', () => {
  it('redacts secrets before writing audit rows', () => {
    const dir = tempDir();
    const db = new GuardianDatabase(path.join(dir, 'guardian.sqlite'));
    db.logAudit({
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
});

describe('proxy policy behavior', () => {
  it('hides blocked tools from tools/list results', () => {
    const tools: ToolInventoryItem[] = [
      { serverName: 'fs', toolName: 'read_file', risk: 'medium', source: 'actual' },
      { serverName: 'fs', toolName: 'delete_file', risk: 'critical', source: 'actual' },
    ];

    const visible = filterVisibleTools(tools, [
      { serverName: 'fs', toolName: 'delete_file', action: 'block', updatedAt: 'now' },
    ]);

    expect(visible.map((tool) => tool.toolName)).toEqual(['read_file']);
  });
});
