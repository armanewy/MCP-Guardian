import type {
  McpServerDefinition,
  ParsedMcpServer,
  RiskFactor,
  RiskLevel,
  ServerRiskAssessment,
  ToolInventoryItem,
  ToolRiskAssessment,
} from './types';
import { hasSecretMaterial } from './redaction';

const LEVEL_SCORE: Record<RiskLevel, number> = {
  low: 1,
  medium: 3,
  high: 6,
  critical: 9,
};

const BROAD_PATH_PATTERNS = [
  /^\/$/,
  /^~$/,
  /^\/users\/?$/i,
  /^\/home\/?$/i,
  /^[a-z]:\\?$/i,
  /^[a-z]:\\users\\?$/i,
  /%userprofile%/i,
  /\$home/i,
];

const SHELL_COMMANDS = new Set(['bash', 'sh', 'zsh', 'fish', 'cmd', 'powershell', 'pwsh']);

function normalizeCommand(command = ''): string {
  const withoutQuotes = command.replace(/^["']|["']$/g, '');
  const normalized = withoutQuotes.split(/[\\/]/).pop() ?? withoutQuotes;
  return normalized.replace(/\.(exe|cmd|bat)$/i, '').toLowerCase();
}

function addFactor(factors: RiskFactor[], code: string, label: string, level: RiskLevel): void {
  if (!factors.some((factor) => factor.code === code)) {
    factors.push({ code, label, level });
  }
}

function levelFromScore(score: number): RiskLevel {
  if (score >= 12) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 3) return 'medium';
  return 'low';
}

function levelFromFactors(factors: RiskFactor[], score: number): RiskLevel {
  if (factors.some((factor) => factor.level === 'critical')) return 'critical';
  if (factors.some((factor) => factor.level === 'high')) return 'high';
  if (factors.some((factor) => factor.level === 'medium')) return levelFromScore(Math.max(score, LEVEL_SCORE.medium));
  return levelFromScore(score);
}

function textForServer(config: McpServerDefinition): string {
  return [config.command, ...(config.args ?? []), config.url].filter(Boolean).join(' ').toLowerCase();
}

function detectCapabilities(text: string): string[] {
  const capabilities = new Set<string>();

  if (/filesystem|file[-_ ]?system|read.*file|write.*file|directory|path/.test(text)) {
    capabilities.add('file access');
  }
  if (/shell|terminal|command|exec|bash|powershell|cmd\.exe|spawn/.test(text)) {
    capabilities.add('shell execution');
  }
  if (/git|github|gitlab|repo/.test(text)) {
    capabilities.add('repository access');
  }
  if (/postgres|mysql|sqlite|database|mongodb|redis|supabase|neon/.test(text)) {
    capabilities.add('database access');
  }
  if (/slack|discord|email|gmail|sendgrid|twilio|notion|linear|jira/.test(text)) {
    capabilities.add('third-party API access');
  }
  if (/browser|playwright|puppeteer|chrome/.test(text)) {
    capabilities.add('browser automation');
  }
  if (/http|https|sse/.test(text)) {
    capabilities.add('network access');
  }

  return [...capabilities];
}

export function classifyServer(server: Pick<ParsedMcpServer, 'displayConfig' | 'transport'>): ServerRiskAssessment {
  const factors: RiskFactor[] = [];
  const config = server.displayConfig;
  const command = normalizeCommand(config.command);
  const args = config.args ?? [];
  const text = textForServer(config);

  if (server.transport === 'http') {
    addFactor(factors, 'remote-transport', 'Remote MCP transport cannot be inspected by the stdio proxy', 'high');
  }

  if (command && SHELL_COMMANDS.has(command)) {
    addFactor(factors, 'shell-command', `Launches through ${command}`, 'critical');
  }

  if (/\b(npx|uvx|pipx|bunx)\b/.test(command)) {
    addFactor(factors, 'package-runner', `Uses package runner ${command}`, 'medium');
  }

  if (/server-filesystem|filesystem|file[-_ ]?system/.test(text)) {
    addFactor(factors, 'filesystem-server', 'Can expose local filesystem content', 'high');
  }

  if (/shell|terminal|exec|run[-_ ]?command/.test(text)) {
    addFactor(factors, 'command-execution', 'Appears able to execute local commands', 'critical');
  }

  if (/postgres|mysql|database|mongodb|redis|sqlite/.test(text)) {
    addFactor(factors, 'database-server', 'Can access databases or persisted records', 'high');
  }

  if (/browser|playwright|puppeteer|chrome/.test(text)) {
    addFactor(factors, 'browser-automation', 'Can control a browser session', 'high');
  }

  if (/slack|discord|email|gmail|sendgrid|twilio/.test(text)) {
    addFactor(factors, 'messaging-api', 'Can send messages through third-party services', 'high');
  }

  if (/github|gitlab|git\b/.test(text)) {
    addFactor(factors, 'repo-access', 'Can read or modify source repositories', 'medium');
  }

  for (const arg of args) {
    if (BROAD_PATH_PATTERNS.some((pattern) => pattern.test(arg))) {
      addFactor(factors, 'broad-path', `Broad path exposed: ${arg}`, 'critical');
    } else if (/[/\\](documents|desktop|downloads|repos|projects)\b/i.test(arg)) {
      addFactor(factors, 'user-data-path', `User data path exposed: ${arg}`, 'high');
    }
  }

  if (hasSecretMaterial(config.env ?? {})) {
    addFactor(factors, 'env-secrets', 'Environment includes likely secrets', 'medium');
  }

  if (config.url && !/^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(config.url)) {
    addFactor(factors, 'remote-url', 'Connects to a non-local URL', 'high');
  }

  const score = factors.reduce((sum, factor) => sum + LEVEL_SCORE[factor.level], 0);
  const capabilities = detectCapabilities(text);

  return {
    level: levelFromFactors(factors, score),
    score,
    factors,
    capabilities: capabilities.length > 0 ? capabilities : ['unknown MCP capabilities'],
  };
}

export function classifyTool(tool: {
  name: string;
  description?: string;
  inputSchema?: unknown;
  annotations?: {
    destructiveHint?: boolean;
    readOnlyHint?: boolean;
    openWorldHint?: boolean;
  };
}): ToolRiskAssessment {
  const factors: RiskFactor[] = [];
  const text = `${tool.name} ${tool.description ?? ''} ${JSON.stringify(tool.inputSchema ?? {})}`.toLowerCase();

  if (tool.annotations?.destructiveHint) {
    addFactor(factors, 'destructive-annotation', 'Tool declares destructive behavior', 'high');
  }
  if (tool.annotations?.openWorldHint) {
    addFactor(factors, 'open-world-annotation', 'Tool may act outside a closed data set', 'medium');
  }
  if (/delete|remove|destroy|drop|truncate|wipe|rm\b/.test(text)) {
    addFactor(factors, 'delete-action', 'Can delete or remove data', 'critical');
  }
  if (/write|create|update|edit|patch|commit|push|send|publish|post|insert/.test(text)) {
    addFactor(factors, 'write-action', 'Can modify data or send output', 'high');
  }
  if (/exec|shell|command|terminal|spawn|run_process|subprocess/.test(text)) {
    addFactor(factors, 'exec-action', 'Can execute commands', 'critical');
  }
  if (/password|secret|token|credential|private key/.test(text)) {
    addFactor(factors, 'secret-access', 'May handle secrets or credentials', 'high');
  }
  if (/read|list|search|get|fetch|query/.test(text) && !tool.annotations?.readOnlyHint) {
    addFactor(factors, 'read-access', 'Can inspect local or remote data', 'medium');
  }
  if (tool.annotations?.readOnlyHint && factors.length === 0) {
    addFactor(factors, 'readonly', 'Declared read-only', 'low');
  }

  const score = factors.reduce((sum, factor) => sum + LEVEL_SCORE[factor.level], 0);
  return {
    level: levelFromFactors(factors, score),
    score,
    factors: factors.length > 0 ? factors : [{ code: 'unknown-tool', label: 'Unclassified tool', level: 'medium' }],
  };
}

export function inferToolsForServer(server: ParsedMcpServer, risk: ServerRiskAssessment): ToolInventoryItem[] {
  const text = textForServer(server.displayConfig);
  const tools: ToolInventoryItem[] = [];

  function push(toolName: string, description: string): void {
    const assessment = classifyTool({ name: toolName, description });
    tools.push({
      serverId: server.serverId,
      serverName: server.name,
      toolName,
      description,
      risk: assessment.level,
      source: 'inferred',
    });
  }

  if (/filesystem|file[-_ ]?system/.test(text) || risk.capabilities.includes('file access')) {
    push('read_file', 'Read files from configured paths');
    push('write_file', 'Write files inside configured paths');
    push('list_directory', 'List configured directories');
  }

  if (risk.capabilities.includes('shell execution')) {
    push('run_command', 'Execute local shell commands');
  }

  if (risk.capabilities.includes('database access')) {
    push('query_database', 'Read records from a database');
    push('modify_database', 'Modify records in a database');
  }

  if (risk.capabilities.includes('repository access')) {
    push('repo_status', 'Inspect repository state');
    push('repo_write', 'Modify repository content or metadata');
  }

  if (risk.capabilities.includes('third-party API access')) {
    push('send_message', 'Send or publish content through an external service');
  }

  if (risk.capabilities.includes('browser automation')) {
    push('browser_action', 'Control a browser or inspect pages');
  }

  if (tools.length === 0) {
    push('unknown_tool_call', 'Actual tools appear after Protect mode observes tools/list');
  }

  return tools;
}
