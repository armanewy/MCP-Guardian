export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export type TransportKind = 'stdio' | 'http' | 'unknown';

export type ServerMode = 'active' | 'disabled' | 'protected';

export type PolicyAction = 'allow' | 'ask' | 'block';

export type ToolInventorySource = 'actual' | 'inferred';

export type AuditDetailLevel = 'minimal' | 'redacted-preview';

export interface ClientConfigSource {
  id: string;
  client: string;
  path: string;
  exists: boolean;
  parser: 'claude-desktop' | 'mcp-json' | 'vscode-settings' | 'unknown';
  error?: string;
}

export interface McpServerDefinition {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  url?: string;
  transport?: TransportKind;
  [key: string]: unknown;
}

export interface GuardianMetadata {
  mode: Exclude<ServerMode, 'active'>;
  backupId: string;
  originalFingerprint: string;
  updatedAt: string;
  note?: string;
}

export interface ParsedMcpServer {
  id: string;
  serverId: string;
  name: string;
  source: ClientConfigSource;
  mode: ServerMode;
  transport: TransportKind;
  configRootKey: string;
  originalFingerprint: string;
  displayConfig: McpServerDefinition;
  currentConfig: McpServerDefinition & { mcpGuardian?: GuardianMetadata };
  guardian?: GuardianMetadata;
  parseWarnings: string[];
}

export interface RiskFactor {
  code: string;
  label: string;
  level: RiskLevel;
}

export interface ServerRiskAssessment {
  level: RiskLevel;
  score: number;
  factors: RiskFactor[];
  capabilities: string[];
}

export interface ToolRiskAssessment {
  level: RiskLevel;
  score: number;
  factors: RiskFactor[];
}

export interface ServerSummary extends ParsedMcpServer {
  risk: ServerRiskAssessment;
  redactedConfig: McpServerDefinition;
  inferredTools: ToolInventoryItem[];
}

export interface ToolInventoryItem {
  serverId: string;
  serverName: string;
  toolName: string;
  description?: string;
  inputSchema?: unknown;
  risk: RiskLevel;
  source: ToolInventorySource;
  lastSeen?: string;
  hiddenWhenBlocked?: boolean;
}

export interface PolicyRecord {
  serverId: string;
  serverName?: string;
  toolName: string;
  action: PolicyAction;
  updatedAt: string;
}

export interface PolicyEvaluation {
  action: PolicyAction;
  source:
    | 'approval-once'
    | 'approval-denied'
    | 'approval-timeout'
    | 'exact'
    | 'server-default'
    | 'global-default'
    | 'risk-default';
  reason: string;
}

export interface AuditLogRecord {
  id: number;
  createdAt: string;
  serverId: string;
  serverName: string;
  toolName: string;
  action: string;
  decision: string;
  risk: RiskLevel;
  requestJson?: string;
  responseSummaryJson?: string;
  error?: string;
  sourcePath?: string;
}

export interface PendingApprovalRecord {
  id: number;
  createdAt: string;
  expiresAt: string;
  serverId: string;
  serverName: string;
  toolName: string;
  risk: RiskLevel;
  argsJson: string;
  status: 'pending' | 'approved' | 'denied' | 'expired';
  reason?: string;
}

export interface DashboardSnapshot {
  generatedAt: string;
  guardianHome: string;
  dbPath: string;
  auditDetailLevel: AuditDetailLevel;
  sources: ClientConfigSource[];
  servers: ServerSummary[];
  tools: ToolInventoryItem[];
  policies: PolicyRecord[];
  audits: AuditLogRecord[];
  pendingApprovals: PendingApprovalRecord[];
}

export interface RewriteLaunchConfig {
  disabled: {
    command: string;
    args: string[];
  };
  proxy: {
    command: string;
    args: string[];
  };
}

export interface RewriteResult {
  backupId?: string;
  backupPath: string;
  sourcePath: string;
  serverId: string;
  serverName: string;
  mode: ServerMode;
}

export interface BackupRecord {
  backupId: string;
  sourcePath: string;
  serverId: string;
  serverName: string;
  configRootKey: string;
  backupPath: string;
  sha256: string;
  createdAt: string;
}
