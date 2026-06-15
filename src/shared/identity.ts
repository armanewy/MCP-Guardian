import { createHash } from 'node:crypto';
import type { McpServerDefinition } from './types';

export function sha256Hex(value: string | Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

export function createServerId(input: {
  sourcePath: string;
  configRootKey: string;
  serverName: string;
}): string {
  return sha256Hex(`${input.sourcePath}::${input.configRootKey}::${input.serverName}`);
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
