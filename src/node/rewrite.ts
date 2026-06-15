import fs from 'node:fs';
import path from 'node:path';
import type {
  GuardianMetadata,
  McpServerDefinition,
  RewriteLaunchConfig,
  RewriteResult,
  ServerMode,
} from '../shared/types';
import { fingerprintServerConfig, stripGuardianMetadata } from '../shared/identity';
import { GuardianDatabase } from './database';

function getRoot(json: any, rootKey: string): Record<string, any> {
  if (rootKey === 'mcpServers') return json.mcpServers;
  if (rootKey === 'servers') return json.servers;
  if (rootKey === 'mcp.servers') return json.mcp.servers;
  throw new Error(`Unsupported config root: ${rootKey}`);
}

function atomicWriteJson(filePath: string, json: unknown): void {
  const dir = path.dirname(filePath);
  const tempPath = path.join(dir, `.${path.basename(filePath)}.mcp-guardian-${process.pid}-${Date.now()}.tmp`);
  const content = `${JSON.stringify(json, null, 2)}\n`;
  const fd = fs.openSync(tempPath, 'wx');

  try {
    fs.writeFileSync(fd, content, 'utf8');
    try {
      fs.fsyncSync(fd);
    } catch {
      // Some virtual filesystems do not support fsync. The temp+rename path still avoids torn JSON.
    }
  } finally {
    fs.closeSync(fd);
  }

  fs.renameSync(tempPath, filePath);
}

function readJsonConfig(sourcePath: string): { raw: string; json: any } {
  const raw = fs.readFileSync(sourcePath, 'utf8');
  return { raw, json: JSON.parse(raw) };
}

function existingGuardian(entry: McpServerDefinition & { mcpGuardian?: GuardianMetadata }): GuardianMetadata | undefined {
  return entry.mcpGuardian;
}

function metadataFor(input: {
  mode: Exclude<ServerMode, 'active'>;
  backupId: string;
  originalFingerprint: string;
}): GuardianMetadata {
  return {
    mode: input.mode,
    backupId: input.backupId,
    originalFingerprint: input.originalFingerprint,
    updatedAt: new Date().toISOString(),
    note:
      input.mode === 'protected'
        ? 'Protected by MCP Guardian stdio proxy. Startup side effects are not sandboxed.'
        : 'Disabled by MCP Guardian. Restore from the app to re-enable the original server.',
  };
}

function proxyArgs(input: {
  launch: RewriteLaunchConfig;
  serverId: string;
  serverName: string;
  dbPath: string;
  backupId: string;
}): string[] {
  return [
    ...input.launch.proxy.args,
    '--server-id',
    input.serverId,
    '--server-name',
    input.serverName,
    '--db-path',
    input.dbPath,
    '--backup-id',
    input.backupId,
  ];
}

function disabledArgs(input: { launch: RewriteLaunchConfig; serverId: string; serverName: string }): string[] {
  return [
    ...input.launch.disabled.args,
    '--server-id',
    input.serverId,
    '--server-name',
    input.serverName,
  ];
}

function resolveOriginal(input: {
  db: GuardianDatabase;
  entry: McpServerDefinition & { mcpGuardian?: GuardianMetadata };
}): { config: McpServerDefinition; backupId?: string; fingerprint: string } {
  const guardian = existingGuardian(input.entry);
  if (!guardian) {
    const config = stripGuardianMetadata(input.entry);
    return {
      config,
      fingerprint: fingerprintServerConfig(config),
    };
  }

  const config = stripGuardianMetadata(input.db.readServerConfigFromBackup(guardian.backupId));
  const fingerprint = fingerprintServerConfig(config);
  if (fingerprint !== guardian.originalFingerprint) {
    throw new Error('Registered backup does not match the stored original fingerprint');
  }

  return {
    config,
    backupId: guardian.backupId,
    fingerprint,
  };
}

export function rewriteServerMode(input: {
  sourcePath: string;
  serverId: string;
  serverName: string;
  configRootKey: string;
  mode: ServerMode;
  expectedOriginalFingerprint: string;
  launch: RewriteLaunchConfig;
  db: GuardianDatabase;
}): RewriteResult {
  const { raw, json } = readJsonConfig(input.sourcePath);
  const root = getRoot(json, input.configRootKey);
  const entry = root[input.serverName] as McpServerDefinition & { mcpGuardian?: GuardianMetadata };

  if (!entry) {
    throw new Error(`Server ${input.serverName} not found in ${path.basename(input.sourcePath)}`);
  }

  const original = resolveOriginal({ db: input.db, entry });
  if (original.fingerprint !== input.expectedOriginalFingerprint) {
    throw new Error('Config changed since last scan; rescan before applying mode changes');
  }

  const safetyBackup = input.db.createBackup({
    sourcePath: input.sourcePath,
    serverId: input.serverId,
    serverName: input.serverName,
    configRootKey: input.configRootKey,
    content: raw,
  });
  const originalBackupId = original.backupId ?? safetyBackup.backupId;

  if (input.mode === 'active') {
    if (!existingGuardian(entry)) {
      throw new Error(`${input.serverName} is already active`);
    }
    root[input.serverName] = original.config;
  } else if (input.mode === 'disabled') {
    root[input.serverName] = {
      command: input.launch.disabled.command,
      args: disabledArgs({
        launch: input.launch,
        serverId: input.serverId,
        serverName: input.serverName,
      }),
      mcpGuardian: metadataFor({
        mode: 'disabled',
        backupId: originalBackupId,
        originalFingerprint: original.fingerprint,
      }),
    };
  } else {
    if (!original.config.command) {
      throw new Error('Protect mode only supports stdio servers with a command in v0.1');
    }

    root[input.serverName] = {
      command: input.launch.proxy.command,
      args: proxyArgs({
        launch: input.launch,
        serverId: input.serverId,
        serverName: input.serverName,
        dbPath: input.db.path,
        backupId: originalBackupId,
      }),
      ...(original.config.env ? { env: original.config.env } : {}),
      mcpGuardian: metadataFor({
        mode: 'protected',
        backupId: originalBackupId,
        originalFingerprint: original.fingerprint,
      }),
    };
  }

  atomicWriteJson(input.sourcePath, json);

  return {
    backupId: safetyBackup.backupId,
    backupPath: safetyBackup.backupPath,
    sourcePath: input.sourcePath,
    serverId: input.serverId,
    serverName: input.serverName,
    mode: input.mode,
  };
}
