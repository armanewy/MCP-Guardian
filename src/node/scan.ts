import fs from 'node:fs/promises';
import os from 'node:os';
import { candidateConfigSources } from '../shared/discovery';
import { parseMcpConfig } from '../shared/parser';
import { classifyServer, inferToolsForServer } from '../shared/risk';
import { redactDeep } from '../shared/redaction';
import type { ClientConfigSource, DashboardSnapshot, McpServerDefinition, ServerSummary, ToolInventoryItem, TransportKind } from '../shared/types';
import { GuardianDatabase, getDefaultDatabasePath, getDefaultGuardianHome } from './database';
import { stripGuardianMetadata } from '../shared/identity';

async function sourceExists(source: ClientConfigSource): Promise<ClientConfigSource> {
  try {
    await fs.access(source.path);
    return { ...source, exists: true };
  } catch {
    return { ...source, exists: false };
  }
}

function mergeTools(inferred: ToolInventoryItem[], actual: ToolInventoryItem[]): ToolInventoryItem[] {
  const merged = new Map<string, ToolInventoryItem>();
  for (const tool of inferred) {
    merged.set(`${tool.serverId}/${tool.toolName}`, tool);
  }
  for (const tool of actual) {
    merged.set(`${tool.serverId}/${tool.toolName}`, tool);
  }
  return [...merged.values()].sort((left, right) =>
    `${left.serverName}/${left.toolName}`.localeCompare(`${right.serverName}/${right.toolName}`),
  );
}

function detectTransport(config: McpServerDefinition): TransportKind {
  if (config.transport === 'http' || config.transport === 'stdio') return config.transport;
  if (config.url) return 'http';
  if (config.command) return 'stdio';
  return 'unknown';
}

export async function scanDashboard(db = new GuardianDatabase()): Promise<DashboardSnapshot> {
  const candidates = candidateConfigSources({
    homeDir: os.homedir(),
    platform: process.platform,
    env: process.env,
  });
  const sources = await Promise.all(candidates.map(sourceExists));
  const summaries: ServerSummary[] = [];

  for (const source of sources.filter((candidate) => candidate.exists)) {
    try {
      const content = await fs.readFile(source.path, 'utf8');
      const parsed = parseMcpConfig(source, content);
      for (const server of parsed.servers) {
        let displayConfig = server.displayConfig;
        const parseWarnings = [...server.parseWarnings];

        if (server.guardian?.backupId) {
          try {
            displayConfig = stripGuardianMetadata(db.readServerConfigFromBackup(server.guardian.backupId));
          } catch (error) {
            parseWarnings.push(
              `Unable to read registered backup ${server.guardian.backupId}: ${
                error instanceof Error ? error.message : String(error)
              }`,
            );
          }
        }

        const enriched = {
          ...server,
          displayConfig,
          transport: detectTransport(displayConfig),
          parseWarnings,
        };
        const risk = classifyServer(enriched);
        summaries.push({
          ...enriched,
          risk,
          redactedConfig: redactDeep(displayConfig),
          inferredTools: inferToolsForServer(enriched, risk),
        });
      }
    } catch (error) {
      source.error = error instanceof Error ? error.message : String(error);
    }
  }

  const inferredTools = summaries.flatMap((server) => server.inferredTools);
  const actualTools = db.listToolInventory();
  const tools = mergeTools(inferredTools, actualTools);

  return {
    generatedAt: new Date().toISOString(),
    guardianHome: getDefaultGuardianHome(),
    dbPath: getDefaultDatabasePath(),
    auditDetailLevel: db.getAuditDetailLevel(),
    sources,
    servers: summaries.sort((left, right) => left.name.localeCompare(right.name)),
    tools,
    policies: db.listPolicies(),
    audits: db.listAuditLogs(),
    pendingApprovals: db.listPendingApprovals(),
  };
}
