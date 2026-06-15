import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
  type CallToolRequest,
} from '@modelcontextprotocol/sdk/types.js';
import { GuardianDatabase } from './database';
import { evaluatePolicy, filterVisibleTools } from '../shared/policy';
import { classifyTool } from '../shared/risk';
import type { PolicyEvaluation, ToolInventoryItem } from '../shared/types';

export interface ProxyRuntimeOptions {
  serverName: string;
  sourcePath?: string;
  dbPath: string;
  upstreamCommand: string;
  upstreamArgs: string[];
  approvalTimeoutMs?: number;
}

function processEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (typeof value === 'string') {
      env[key] = value;
    }
  }
  return env;
}

async function enforcePolicy(input: {
  db: GuardianDatabase;
  serverName: string;
  toolName: string;
  risk: ToolInventoryItem['risk'];
  args: unknown;
  timeoutMs: number;
}): Promise<PolicyEvaluation> {
  const policy = evaluatePolicy({
    policies: input.db.listPolicies(),
    serverName: input.serverName,
    toolName: input.toolName,
    risk: input.risk,
  });

  if (policy.action !== 'ask') {
    return policy;
  }

  const approval = input.db.createPendingApproval({
    serverName: input.serverName,
    toolName: input.toolName,
    risk: input.risk,
    args: input.args,
    timeoutMs: input.timeoutMs,
  });
  const result = await input.db.waitForApproval(approval.id, input.timeoutMs);

  if (result === 'approved') {
    return { action: 'allow', source: 'exact', reason: `Approval ${approval.id} was approved` };
  }

  return {
    action: 'block',
    source: 'risk-default',
    reason: result === 'denied' ? `Approval ${approval.id} was denied` : `Approval ${approval.id} expired`,
  };
}

export async function runProxyRuntime(options: ProxyRuntimeOptions): Promise<void> {
  if (!options.upstreamCommand) {
    throw new Error('Missing --upstream-command');
  }

  const db = new GuardianDatabase(options.dbPath);
  const upstreamTransport = new StdioClientTransport({
    command: options.upstreamCommand,
    args: options.upstreamArgs,
    env: processEnv(),
    stderr: 'inherit',
  });
  const upstreamClient = new Client({ name: 'mcp-guardian-proxy-client', version: '0.1.0' });
  await upstreamClient.connect(upstreamTransport);

  const downstreamServer = new Server(
    { name: `mcp-guardian:${options.serverName}`, version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  downstreamServer.setRequestHandler(ListToolsRequestSchema, async (request) => {
    const result = await upstreamClient.listTools(request.params);
    const observedTools: ToolInventoryItem[] = result.tools.map((tool) => {
      const risk = classifyTool(tool).level;
      return {
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
    return {
      ...result,
      tools: result.tools.filter((tool) => visibleNames.has(tool.name)),
    };
  });

  downstreamServer.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest) => {
    const toolName = request.params.name;
    const toolRisk = classifyTool({
      name: toolName,
      inputSchema: request.params.arguments,
    }).level;

    const policy = await enforcePolicy({
      db,
      serverName: options.serverName,
      toolName,
      risk: toolRisk,
      args: request.params.arguments,
      timeoutMs: options.approvalTimeoutMs ?? 120_000,
    });

    if (policy.action === 'block') {
      db.logAudit({
        serverName: options.serverName,
        toolName,
        action: 'tools/call',
        decision: 'blocked',
        risk: toolRisk,
        request: request.params,
        error: policy.reason,
        sourcePath: options.sourcePath,
      });
      throw new McpError(ErrorCode.InvalidRequest, `MCP Guardian blocked ${toolName}: ${policy.reason}`);
    }

    try {
      const result = await upstreamClient.callTool(request.params);
      db.logAudit({
        serverName: options.serverName,
        toolName,
        action: 'tools/call',
        decision: policy.source === 'exact' ? 'allowed-by-policy' : 'allowed',
        risk: toolRisk,
        request: request.params,
        response: result,
        sourcePath: options.sourcePath,
      });
      return result;
    } catch (error) {
      db.logAudit({
        serverName: options.serverName,
        toolName,
        action: 'tools/call',
        decision: 'errored',
        risk: toolRisk,
        request: request.params,
        error: error instanceof Error ? error.message : String(error),
        sourcePath: options.sourcePath,
      });
      throw error;
    }
  });

  await downstreamServer.connect(new StdioServerTransport());
}

export async function runDisabledServer(serverName: string): Promise<void> {
  const server = new Server(
    { name: `mcp-guardian-disabled:${serverName}`, version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [] }));
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    throw new McpError(
      ErrorCode.InvalidRequest,
      `MCP Guardian disabled ${serverName}; blocked ${request.params.name}`,
    );
  });

  await server.connect(new StdioServerTransport());
}
