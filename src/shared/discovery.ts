import path from 'node:path';
import type { ClientConfigSource } from './types';

export function candidateConfigSources(input: {
  homeDir: string;
  platform: NodeJS.Platform;
  env: NodeJS.ProcessEnv;
  workspaceFolders?: string[];
  customSources?: ClientConfigSource[];
}): ClientConfigSource[] {
  const { homeDir, platform, env } = input;
  const appData = env.APPDATA ?? path.join(homeDir, 'AppData', 'Roaming');
  const configHome = env.XDG_CONFIG_HOME ?? path.join(homeDir, '.config');

  const candidates: ClientConfigSource[] = [];

  function add(
    client: string,
    filePath: string,
    parser: ClientConfigSource['parser'],
    sourceKind: ClientConfigSource['sourceKind'] = 'default',
  ): void {
    const resolved = path.resolve(filePath);
    candidates.push({
      id: `${sourceKind}:${client}:${resolved}`,
      client,
      path: resolved,
      exists: false,
      parser,
      sourceKind,
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

  for (const workspaceFolder of input.workspaceFolders ?? []) {
    const folder = path.resolve(workspaceFolder);
    add('VS Code Workspace', path.join(folder, '.vscode', 'mcp.json'), 'mcp-json', 'workspace');
    add('Cursor Workspace', path.join(folder, '.cursor', 'mcp.json'), 'mcp-json', 'workspace');
  }

  for (const source of input.customSources ?? []) {
    candidates.push({
      ...source,
      id: source.id || `custom:${path.resolve(source.path)}`,
      path: path.resolve(source.path),
      exists: false,
      parser: source.parser === 'unknown' ? 'mcp-json' : source.parser,
      sourceKind: 'custom',
    });
  }

  const seen = new Set<string>();
  return candidates.filter((source) => {
    const key = `${source.parser}:${platform === 'win32' ? source.path.toLowerCase() : source.path}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
