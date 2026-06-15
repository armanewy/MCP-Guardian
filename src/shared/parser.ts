import { z } from 'zod';
import type {
  ClientConfigSource,
  GuardianMetadata,
  McpServerDefinition,
  ParsedMcpServer,
  ServerMode,
  TransportKind,
} from './types';

const EnvSchema = z.record(z.string(), z.string()).optional();

const GuardianMetadataSchema: z.ZodType<GuardianMetadata> = z.object({
  mode: z.enum(['disabled', 'protected']),
  original: z
    .object({
      command: z.string().optional(),
      args: z.array(z.string()).optional(),
      env: EnvSchema,
      url: z.string().optional(),
      transport: z.enum(['stdio', 'http', 'unknown']).optional(),
    })
    .passthrough(),
  updatedAt: z.string(),
  note: z.string().optional(),
});

const ServerDefinitionSchema = z
  .object({
    command: z.string().optional(),
    args: z.array(z.string()).optional(),
    env: EnvSchema,
    url: z.string().optional(),
    transport: z.enum(['stdio', 'http', 'unknown']).optional(),
    mcpGuardian: GuardianMetadataSchema.optional(),
  })
  .passthrough();

export interface ParsedConfigFile {
  source: ClientConfigSource;
  servers: ParsedMcpServer[];
  warnings: string[];
}

function getServerRoot(json: any): { root: Record<string, unknown>; key: string } | undefined {
  if (json && typeof json === 'object') {
    if (json.mcpServers && typeof json.mcpServers === 'object') {
      return { root: json.mcpServers, key: 'mcpServers' };
    }
    if (json.servers && typeof json.servers === 'object') {
      return { root: json.servers, key: 'servers' };
    }
    if (json.mcp?.servers && typeof json.mcp.servers === 'object') {
      return { root: json.mcp.servers, key: 'mcp.servers' };
    }
  }

  return undefined;
}

function detectMode(config: McpServerDefinition & { mcpGuardian?: GuardianMetadata }): ServerMode {
  if (config.mcpGuardian?.mode === 'disabled') return 'disabled';
  if (config.mcpGuardian?.mode === 'protected') return 'protected';
  return 'active';
}

function detectTransport(config: McpServerDefinition): TransportKind {
  if (config.transport === 'http' || config.transport === 'stdio') return config.transport;
  if (config.url) return 'http';
  if (config.command) return 'stdio';
  return 'unknown';
}

export function parseMcpConfig(source: ClientConfigSource, content: string): ParsedConfigFile {
  const warnings: string[] = [];
  let json: unknown;

  try {
    json = JSON.parse(content);
  } catch (error) {
    return {
      source,
      servers: [],
      warnings: [`Invalid JSON: ${error instanceof Error ? error.message : String(error)}`],
    };
  }

  const root = getServerRoot(json);
  if (!root) {
    return {
      source,
      servers: [],
      warnings: ['No MCP server root found'],
    };
  }

  const servers: ParsedMcpServer[] = [];
  for (const [name, raw] of Object.entries(root.root)) {
    const parsed = ServerDefinitionSchema.safeParse(raw);
    if (!parsed.success) {
      warnings.push(`${name}: ${parsed.error.issues.map((issue) => issue.message).join(', ')}`);
      continue;
    }

    const currentConfig = parsed.data;
    const mode = detectMode(currentConfig);
    const displayConfig = currentConfig.mcpGuardian?.original ?? currentConfig;
    const transport = detectTransport(displayConfig);
    const parseWarnings: string[] = [];

    if (!displayConfig.command && !displayConfig.url) {
      parseWarnings.push('Server has neither command nor url');
    }
    if (transport === 'http') {
      parseWarnings.push('HTTP/SSE proxying is deferred in v0.1');
    }

    servers.push({
      id: `${source.path}::${name}`,
      name,
      source,
      mode,
      transport,
      configRootKey: root.key,
      displayConfig,
      currentConfig,
      guardian: currentConfig.mcpGuardian,
      parseWarnings,
    });
  }

  return { source, servers, warnings };
}
