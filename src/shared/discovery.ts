import path from 'node:path';
import type { ClientConfigSource } from './types';

export function candidateConfigSources(input: {
  homeDir: string;
  platform: NodeJS.Platform;
  env: NodeJS.ProcessEnv;
}): ClientConfigSource[] {
  const { homeDir, platform, env } = input;
  const appData = env.APPDATA ?? path.join(homeDir, 'AppData', 'Roaming');
  const configHome = env.XDG_CONFIG_HOME ?? path.join(homeDir, '.config');

  const candidates: ClientConfigSource[] = [];

  function add(client: string, filePath: string, parser: ClientConfigSource['parser']): void {
    candidates.push({
      id: `${client}:${filePath}`,
      client,
      path: filePath,
      exists: false,
      parser,
    });
  }

  if (platform === 'win32') {
    add('Claude Desktop', path.join(appData, 'Claude', 'claude_desktop_config.json'), 'claude-desktop');
    add('Cursor', path.join(homeDir, '.cursor', 'mcp.json'), 'mcp-json');
    add('Cursor', path.join(appData, 'Cursor', 'User', 'mcp.json'), 'mcp-json');
    add('VS Code', path.join(appData, 'Code', 'User', 'mcp.json'), 'mcp-json');
    add('VS Code', path.join(appData, 'Code', 'User', 'settings.json'), 'vscode-settings');
    add('Claude Code', path.join(homeDir, '.claude', 'mcp.json'), 'mcp-json');
  } else if (platform === 'darwin') {
    add(
      'Claude Desktop',
      path.join(homeDir, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
      'claude-desktop',
    );
    add('Cursor', path.join(homeDir, '.cursor', 'mcp.json'), 'mcp-json');
    add('VS Code', path.join(homeDir, 'Library', 'Application Support', 'Code', 'User', 'mcp.json'), 'mcp-json');
    add('VS Code', path.join(homeDir, 'Library', 'Application Support', 'Code', 'User', 'settings.json'), 'vscode-settings');
    add('Claude Code', path.join(homeDir, '.claude', 'mcp.json'), 'mcp-json');
  } else {
    add('Claude Desktop', path.join(configHome, 'Claude', 'claude_desktop_config.json'), 'claude-desktop');
    add('Cursor', path.join(homeDir, '.cursor', 'mcp.json'), 'mcp-json');
    add('VS Code', path.join(configHome, 'Code', 'User', 'mcp.json'), 'mcp-json');
    add('VS Code', path.join(configHome, 'Code', 'User', 'settings.json'), 'vscode-settings');
    add('Claude Code', path.join(homeDir, '.claude', 'mcp.json'), 'mcp-json');
  }

  return candidates;
}
