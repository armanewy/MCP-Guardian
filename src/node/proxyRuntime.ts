import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema, type CallToolRequest } from '@modelcontextprotocol/sdk/types.js';
import { GuardianDatabase } from './database';
import { evaluatePolicy, filterVisibleTools } from '../shared/policy';
import { classifyTool } from '../shared/risk';
import { stripGuardianMetadata } from '../shared/identity';
import type { McpServerDefinition, PolicyEvaluation, ToolInventoryItem } from '../shared/types';

export interface ProxyRuntimeOptions {
  serverId: string;
  serverName: string;
  backupId?: string;
  dbPath: string;
  approvalTimeoutMs?: number;
}

const ALLOWED_UPSTREAM_ENV_KEYS = ['PATH', 'HOME', 'USERPROFILE', 'SystemRoot', 'TEMP', 'TMP', 'TMPDIR'];

export function minimalBaseEnv(sourceEnv: NodeJS.ProcessEnv = process.env): Record<string, string> {
  const output: Record<string, string> = {};
  for (const key of ALLOWED_UPSTREAM_ENV_KEYS) {
    const value = sourceEnv[key];
    if (typeof value === 'string') {
      output[key] = value;
    }
  }
  return output;
}

export function buildUpstreamEnv(
  originalConfigEnv: Record<string, string> | undefined,
  baseEnv: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  return {
    ...minimalBaseEnv(baseEnv),
    ...(originalConfigEnv ?? {}),
  };
}

function loadUpstreamConfig(db: GuardianDatabase, serverId: string, backupId?: string): McpServerDefinition {
  if (backupId) {
    return stripGuardianMetadata(db.readServerConfigFromBackup(backupId));
  }
  return stripGuardianMetadata(db.readLatestServerConfig(serverId).config);
}

async function enforcePolicy(input: {
  db: GuardianDatabase;
  serverId: string;
  serverName: string;
  toolName: string;
  risk: ToolInventoryItem['risk'];
  args: unknown;
  timeoutMs: number;
}): Promise<PolicyEvaluation> {
  const policy = evaluatePolicy({
    policies: input.db.listPolicies(),
    serverId: input.serverId,
    serverName: input.serverName,
    toolName: input.toolName,
    risk: input.risk,
  });

  if (policy.action !== 'ask') {
    return policy;
  }

  const approval = input.db.createPendingApproval({
    serverId: input.serverId,
    serverName: input.serverName,
    toolName: input.toolName,
    risk: input.risk,
    args: input.args,
    timeoutMs: input.timeoutMs,
  });
  const result = await input.db.waitForApproval(approval.id, input.timeoutMs);

  if (result === 'approved') {
    return { action: 'allow', source: 'approval-once', reason: `Approval ${approval.id} was approved` };
  }

  return {
    action: 'block',
    source: result === 'denied' ? 'approval-denied' : 'approval-timeout',
    reason: result === 'denied' ? `Approval ${approval.id} was denied` : `Approval ${approval.id} expired`,
  };
}

function allowedDecision(policy: PolicyEvaluation): string {
  if (policy.source === 'approval-once') return 'asked_allowed';
  if (policy.source === 'risk-default') return 'allowed_by_default';
  return 'allowed_by_policy';
}

function blockedDecision(policy: PolicyEvaluation): string {
  if (policy.source === 'approval-denied') return 'asked_denied';
  if (policy.source === 'approval-timeout') return 'timeout_denied';
  if (policy.source === 'risk-default') return 'blocked_by_default';
  return 'blocked_by_policy';
}

function blockedResult(toolName: string, reason: string): { content: Array<{ type: 'text'; text: string }>; isError: true } {
  return {
    content: [{ type: 'text', text: `MCP Guardian blocked ${toolName}: ${reason}` }],
    isError: true,
  };
}

export async function guardedCallTool(input: {
  db: GuardianDatabase;
  serverId: string;
  serverName: string;
  sourcePath?: string;
  request: CallToolRequest;
  approvalTimeoutMs: number;
  callUpstream: (params: CallToolRequest['params']) => Promise<unknown>;
}): Promise<any> {
  const toolName = input.request.params.name;
  const toolRisk = classifyTool({
    name: toolName,
    inputSchema: input.request.params.arguments,
  }).level;

  const policy = await enforcePolicy({
    db: input.db,
    serverId: input.serverId,
    serverName: input.serverName,
    toolName,
    risk: toolRisk,
    args: input.request.params.arguments,
    timeoutMs: input.approvalTimeoutMs,
  });

  if (policy.action === 'block') {
    const result = blockedResult(toolName, policy.reason);
    input.db.logAudit({
      serverId: input.serverId,
      serverName: input.serverName,
      toolName,
      action: 'tools/call',
      decision: blockedDecision(policy),
      risk: toolRisk,
      request: input.request.params,
      response: result,
      error: policy.reason,
      sourcePath: input.sourcePath,
    });
    return result;
  }

  try {
    const result = await input.callUpstream(input.request.params);
    input.db.logAudit({
      serverId: input.serverId,
      serverName: input.serverName,
      toolName,
      action: 'tools/call',
      decision: allowedDecision(policy),
      risk: toolRisk,
      request: input.request.params,
      response: result,
      sourcePath: input.sourcePath,
    });
    return result;
  } catch (error) {
    input.db.logAudit({
      serverId: input.serverId,
      serverName: input.serverName,
      toolName,
      action: 'tools/call',
      decision: 'errored',
      risk: toolRisk,
      request: input.request.params,
      error: error instanceof Error ? error.message : String(error),
      sourcePath: input.sourcePath,
    });
    throw error;
  }
}

export async function runProxyRuntime(options: ProxyRuntimeOptions): Promise<void> {
  const db = new GuardianDatabase(options.dbPath);
  let upstreamClient: Client | undefined;
  let sourcePath: string | undefined;

  async function getUpstreamClient(): Promise<Client> {
    if (upstreamClient) {
      return upstreamClient;
    }

    const backup = options.backupId ? db.getBackup(options.backupId) : db.getLatestBackupForServer(options.serverId);
    sourcePath = backup?.sourcePath;
    const upstreamConfig = loadUpstreamConfig(db, options.serverId, options.backupId);
    if (!upstreamConfig.command) {
      throw new Error(`No upstream command registered for ${options.serverName}`);
    }

    const transport = new StdioClientTransport({
      command: upstreamConfig.command,
      args: upstreamConfig.args ?? [],
      cwd: upstreamConfig.cwd,
      env: buildUpstreamEnv(upstreamConfig.env),
      stderr: 'inherit',
    });
    upstreamClient = new Client({ name: 'mcp-guardian-proxy-client', version: '0.1.0' });
    await upstreamClient.connect(transport);
    return upstreamClient;
  }

  const downstreamServer = new Server(
    { name: `mcp-guardian:${options.serverName}`, version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  downstreamServer.setRequestHandler(ListToolsRequestSchema, async (request) => {
    const client = await getUpstreamClient();
    const result = await client.listTools(request.params);
    const observedTools: ToolInventoryItem[] = result.tools.map((tool) => {
      const risk = classifyTool(tool).level;
      return {
        serverId: options.serverId,
        serverName: options.serverName,
        toolName: tool.name,
        description: tool.description,
        inputSchema: tool.inputSchema,
        risk,
        source: 'actual',
        lastSeen: new Date().toISOString(),
        hiddenWhenBlocked: true,
      };
    });

    for (const tool of observedTools) {
      db.upsertToolInventory(tool);
    }

    const visible = filterVisibleTools(observedTools, db.listPolicies());
    const visibleNames = new Set(visible.map((tool) => tool.toolName));
    const visibleTools = result.tools.filter((tool) => visibleNames.has(tool.name));
    db.logAudit({
      serverId: options.serverId,
      serverName: options.serverName,
      toolName: '*',
      action: 'tools/list',
      decision: 'listed',
      risk: 'low',
      request: request.params ?? {},
      responseSummary: {
        observedCount: result.tools.length,
        visibleCount: visibleTools.length,
        blockedCount: result.tools.length - visibleTools.length,
      },
      sourcePath,
    });

    return {
      ...result,
      tools: visibleTools,
    };
  });

  downstreamServer.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest) =>
    guardedCallTool({
      db,
      serverId: options.serverId,
      serverName: options.serverName,
      sourcePath,
      request,
      approvalTimeoutMs: options.approvalTimeoutMs ?? 120_000,
      callUpstream: async (params) => {
        const client = await getUpstreamClient();
        return client.callTool(params);
      },
    }),
  );

  await downstreamServer.connect(new StdioServerTransport());
}

export async function runDisabledServer(serverName: string): Promise<void> {
  const server = new Server(
    { name: `mcp-guardian-disabled:${serverName}`, version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [] }));
  server.setRequestHandler(CallToolRequestSchema, async (request) =>
    blockedResult(request.params.name, `${serverName} is disabled`),
  );

  await server.connect(new StdioServerTransport());
}
