import { createHash } from 'node:crypto';
import path from 'node:path';
import type { McpServerDefinition } from './types';

export function sha256Hex(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

export function createServerId(input: {
  sourcePath: string;
  configRootKey: string;
  serverName: string;
  platform?: NodeJS.Platform;
}): string {
  return sha256Hex(
    `${normalizeSourcePath(input.sourcePath, input.platform)}::${input.configRootKey}::${input.serverName}`,
  );
}

export function normalizeSourcePath(sourcePath: string, platform: NodeJS.Platform = process.platform): string {
  const pathApi = platform === 'win32' ? path.win32 : path.posix;
  let normalized = pathApi.resolve(sourcePath).replace(/\\/g, '/');

  if (platform === 'win32') {
    normalized = normalized.toLowerCase();
  }

  return normalized;
}

function normalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(normalize);
  }

  if (value && typeof value === 'object') {
    const output: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const child = (value as Record<string, unknown>)[key];
      if (child !== undefined) {
        output[key] = normalize(child);
      }
    }
    return output;
  }

  return value;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalize(value));
}

export function stripGuardianMetadata<T extends McpServerDefinition>(config: T): McpServerDefinition {
  const output = { ...config };
  delete output.mcpGuardian;
  return output;
}

export function fingerprintServerConfig(config: McpServerDefinition): string {
  return sha256Hex(canonicalJson(stripGuardianMetadata(config)));
}
