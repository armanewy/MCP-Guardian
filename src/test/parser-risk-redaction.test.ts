import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { candidateConfigSources } from '../shared/discovery';
import { createServerId, fingerprintServerConfig, normalizeSourcePath } from '../shared/identity';
import { parseMcpConfig } from '../shared/parser';
import { classifyServer, classifyTool } from '../shared/risk';
import { hasSecretMaterial, redactDeep } from '../shared/redaction';

const source = {
  id: 'test',
  client: 'Claude Desktop',
  path: '/tmp/claude_desktop_config.json',
  exists: true,
  parser: 'claude-desktop' as const,
};

describe('config parser', () => {
  it('parses Claude Desktop entries with stable serverId', () => {
    const parsed = parseMcpConfig(
      source,
      JSON.stringify({
        mcpServers: {
          filesystem: {
            command: 'npx',
            args: ['-y', '@modelcontextprotocol/server-filesystem', '/Users/me/Documents'],
            env: { API_TOKEN: 'secret-token' },
          },
        },
      }),
    );

    const expectedId = createServerId({
      sourcePath: source.path,
      configRootKey: 'mcpServers',
      serverName: 'filesystem',
    });

    expect(parsed.servers).toHaveLength(1);
    expect(parsed.servers[0].serverId).toBe(expectedId);
    expect(parsed.servers[0].id).toBe(expectedId);
    expect(parsed.servers[0].name).toBe('filesystem');
    expect(parsed.servers[0].transport).toBe('stdio');
    expect(parsed.servers[0].mode).toBe('active');
  });

  it('normalizes Windows source paths for stable server identity', () => {
    const first = createServerId({
      sourcePath: 'C:\\Users\\A\\.cursor\\mcp.json',
      configRootKey: 'mcpServers',
      serverName: 'filesystem',
      platform: 'win32',
    });
    const second = createServerId({
      sourcePath: 'c:/users/a/.cursor/mcp.json',
      configRootKey: 'mcpServers',
      serverName: 'filesystem',
      platform: 'win32',
    });

    expect(first).toBe(second);
    expect(normalizeSourcePath('C:\\Users\\A\\.cursor\\mcp.json', 'win32')).toBe(
      'c:/users/a/.cursor/mcp.json',
    );
  });

  it('parses hardened guardian metadata without embedded original config', () => {
    const originalFingerprint = fingerprintServerConfig({
      command: 'npx',
      args: ['--flag'],
    });
    const parsed = parseMcpConfig(
      source,
      JSON.stringify({
        mcpServers: {
          filesystem: {
            command: 'node',
            args: ['proxy.js', '--server-id', 'abc'],
            mcpGuardian: {
              mode: 'protected',
              backupId: 'backup-1',
              originalFingerprint,
              updatedAt: new Date().toISOString(),
            },
          },
        },
      }),
    );

    expect(parsed.servers[0].mode).toBe('protected');
    expect(parsed.servers[0].guardian?.backupId).toBe('backup-1');
    expect(parsed.servers[0].guardian).not.toHaveProperty('original');
    expect(parsed.servers[0].originalFingerprint).toBe(originalFingerprint);
  });
});

describe('config discovery', () => {
  it('includes workspace MCP JSON files for VS Code and Cursor', () => {
    const workspace = path.resolve('/workspace/project');
    const sources = candidateConfigSources({
      homeDir: '/home/tester',
      platform: 'linux',
      env: {},
      workspaceFolders: [workspace],
    });

    expect(sources).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          client: 'VS Code Workspace',
          path: path.join(workspace, '.vscode', 'mcp.json'),
          sourceKind: 'workspace',
        }),
        expect.objectContaining({
          client: 'Cursor Workspace',
          path: path.join(workspace, '.cursor', 'mcp.json'),
          sourceKind: 'workspace',
        }),
      ]),
    );
  });
});

describe('risk classifier', () => {
  it('classifies broad filesystem servers as critical', () => {
    const parsed = parseMcpConfig(
      source,
      JSON.stringify({
        mcpServers: {
          filesystem: {
            command: 'npx',
            args: ['-y', '@modelcontextprotocol/server-filesystem', '/'],
          },
        },
      }),
    );

    expect(classifyServer(parsed.servers[0]).level).toBe('critical');
  });

  it('classifies destructive tools as critical', () => {
    expect(classifyTool({ name: 'delete_repository', description: 'Remove repo' }).level).toBe('critical');
  });

  it('does not downgrade single high-risk write factors', () => {
    expect(classifyTool({ name: 'write_file', inputSchema: { path: 'x', text: 'y' } }).level).toBe('high');
  });
});

describe('redaction', () => {
  it('redacts secret keys and secret-looking values', () => {
    const redacted = redactDeep({
      env: {
        API_KEY: 'abc123',
        NORMAL: 'sk-abcdefghijklmnopqrstuvwxyz123456',
      },
    });

    expect(redacted).toEqual({
      env: {
        API_KEY: '[REDACTED]',
        NORMAL: '[REDACTED]',
      },
    });
    expect(hasSecretMaterial({ token: 'abc' })).toBe(true);
  });
});
