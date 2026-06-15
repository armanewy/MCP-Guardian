import { describe, expect, it } from 'vitest';
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
  it('parses Claude Desktop mcpServers entries', () => {
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

    expect(parsed.servers).toHaveLength(1);
    expect(parsed.servers[0].name).toBe('filesystem');
    expect(parsed.servers[0].transport).toBe('stdio');
    expect(parsed.servers[0].mode).toBe('active');
  });

  it('uses guardian original config for protected servers', () => {
    const parsed = parseMcpConfig(
      source,
      JSON.stringify({
        mcpServers: {
          filesystem: {
            command: 'node',
            args: ['proxy.js'],
            mcpGuardian: {
              mode: 'protected',
              updatedAt: new Date().toISOString(),
              original: {
                command: 'npx',
                args: ['-y', '@modelcontextprotocol/server-filesystem', '/'],
              },
            },
          },
        },
      }),
    );

    expect(parsed.servers[0].mode).toBe('protected');
    expect(parsed.servers[0].displayConfig.command).toBe('npx');
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
