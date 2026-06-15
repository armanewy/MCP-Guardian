import fs from 'node:fs/promises';
import os from 'node:os';
import { candidateConfigSources } from '../shared/discovery';
import { parseMcpConfig } from '../shared/parser';
import { classifyServer, inferToolsForServer } from '../shared/risk';
import { redactDeep } from '../shared/redaction';
import type { ClientConfigSource, DashboardSnapshot, ServerSummary, ToolInventoryItem } from '../shared/types';
import { GuardianDatabase, getDefaultDatabasePath, getDefaultGuardianHome } from './database';

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
    merged.set(`${tool.serverName}/${tool.toolName}`, tool);
  }
  for (const tool of actual) {
    merged.set(`${tool.serverName}/${tool.toolName}`, tool);
  }
  return [...merged.values()].sort((left, right) =>
    `${left.serverName}/${left.toolName}`.localeCompare(`${right.serverName}/${right.toolName}`),
  );
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
        const risk = classifyServer(server);
        summaries.push({
          ...server,
          risk,
          redactedConfig: redactDeep(server.displayConfig),
          inferredTools: inferToolsForServer(server, risk),
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
    sources,
    servers: summaries.sort((left, right) => left.name.localeCompare(right.name)),
    tools,
    policies: db.listPolicies(),
    audits: db.listAuditLogs(),
    pendingApprovals: db.listPendingApprovals(),
  };
}
