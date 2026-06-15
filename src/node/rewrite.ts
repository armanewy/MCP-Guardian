import fs from 'node:fs';
import path from 'node:path';
import type {
  GuardianMetadata,
  McpServerDefinition,
  RewriteLaunchConfig,
  RewriteResult,
  ServerMode,
} from '../shared/types';

function timestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function getRoot(json: any, rootKey: string): Record<string, any> {
  if (rootKey === 'mcpServers') return json.mcpServers;
  if (rootKey === 'servers') return json.servers;
  if (rootKey === 'mcp.servers') return json.mcp.servers;
  throw new Error(`Unsupported config root: ${rootKey}`);
}

function backupFile(sourcePath: string): string {
  const backupPath = `${sourcePath}.mcp-guardian-backup-${timestamp()}`;
  fs.copyFileSync(sourcePath, backupPath);
  return backupPath;
}

function originalFor(entry: McpServerDefinition & { mcpGuardian?: GuardianMetadata }): McpServerDefinition {
  return entry.mcpGuardian?.original ?? {
    ...entry,
    mcpGuardian: undefined,
  };
}

function stripGuardian(entry: McpServerDefinition): McpServerDefinition {
  const copy = { ...entry };
  delete copy.mcpGuardian;
  return copy;
}

function proxyArgs(input: {
  launch: RewriteLaunchConfig;
  serverName: string;
  sourcePath: string;
  dbPath: string;
  original: McpServerDefinition;
}): string[] {
  const args = [
    ...input.launch.proxy.args,
    '--server-name',
    input.serverName,
    '--source-path',
    input.sourcePath,
    '--db-path',
    input.dbPath,
    '--upstream-command',
    input.original.command ?? '',
  ];

  for (const arg of input.original.args ?? []) {
    args.push('--upstream-arg', arg);
  }

  return args;
}

export function rewriteServerMode(input: {
  sourcePath: string;
  serverName: string;
  configRootKey: string;
  mode: ServerMode;
  launch: RewriteLaunchConfig;
  dbPath: string;
}): RewriteResult {
  const raw = fs.readFileSync(input.sourcePath, 'utf8');
  const json = JSON.parse(raw);
  const root = getRoot(json, input.configRootKey);
  const entry = root[input.serverName] as McpServerDefinition & { mcpGuardian?: GuardianMetadata };

  if (!entry) {
    throw new Error(`Server ${input.serverName} not found in ${path.basename(input.sourcePath)}`);
  }

  const backupPath = backupFile(input.sourcePath);
  const original = stripGuardian(originalFor(entry));
  const updatedAt = new Date().toISOString();

  if (input.mode === 'active') {
    root[input.serverName] = original;
  } else if (input.mode === 'disabled') {
    root[input.serverName] = {
      command: input.launch.disabled.command,
      args: [...input.launch.disabled.args, '--server-name', input.serverName],
      env: {},
      mcpGuardian: {
        mode: 'disabled',
        original,
        updatedAt,
        note: 'Disabled by MCP Guardian. Restore from the app to re-enable the original server.',
      },
    };
  } else {
    if (!original.command) {
      throw new Error('Protect mode only supports stdio servers with a command in v0.1');
    }

    root[input.serverName] = {
      command: input.launch.proxy.command,
      args: proxyArgs({
        launch: input.launch,
        serverName: input.serverName,
        sourcePath: input.sourcePath,
        dbPath: input.dbPath,
        original,
      }),
      env: original.env ?? {},
      mcpGuardian: {
        mode: 'protected',
        original,
        updatedAt,
        note: 'Protected by MCP Guardian stdio proxy. Startup side effects are not sandboxed.',
      },
    };
  }

  fs.writeFileSync(input.sourcePath, `${JSON.stringify(json, null, 2)}\n`, 'utf8');

  return {
    backupPath,
    sourcePath: input.sourcePath,
    serverName: input.serverName,
    mode: input.mode,
  };
}
