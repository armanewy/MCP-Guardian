import {
  AlertTriangle,
  Check,
  CircleSlash,
  ClipboardList,
  Database,
  FileJson,
  FolderOpen,
  Gauge,
  Lock,
  Plus,
  RefreshCw,
  ShieldCheck,
  Server,
  Shield,
  ShieldAlert,
  SlidersHorizontal,
  Trash2,
  Unlock,
  X,
} from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import type { ReactElement } from 'react';
import type {
  BackupRecord,
  DashboardSnapshot,
  PendingApprovalRecord,
  PolicyAction,
  PolicyRecord,
  RiskLevel,
  ServerMode,
  ServerSummary,
  ToolInventoryItem,
} from '../../shared/types';
import { evaluatePolicy } from '../../shared/policy';

type ViewKey = 'dashboard' | 'servers' | 'tools' | 'policies' | 'approvals' | 'audit' | 'backups' | 'safety';

const riskOrder: Record<RiskLevel, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function RiskBadge({ risk }: { risk: RiskLevel }): ReactElement {
  return <span className={`badge risk-${risk}`}>{risk}</span>;
}

function ModeBadge({ mode }: { mode: ServerMode }): ReactElement {
  return <span className={`badge mode-${mode}`}>{mode}</span>;
}

function formatDate(value?: string): string {
  if (!value) return 'Never';
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date(value));
}

const DECISION_LABELS: Record<string, string> = {
  asked_allowed: 'Allowed after approval',
  asked_denied: 'Denied after approval prompt',
  timeout_denied: 'Denied after timeout',
  allowed_by_policy: 'Allowed by policy',
  allowed_by_default: 'Allowed by default',
  blocked_by_policy: 'Blocked by policy',
  blocked_by_default: 'Blocked by default',
  listed: 'Listed tools',
  errored: 'Errored',
};

function decisionLabel(value: string): string {
  return DECISION_LABELS[value] ?? value.replaceAll('_', ' ');
}

function sortedServers(snapshot: DashboardSnapshot): ServerSummary[] {
  return [...snapshot.servers].sort((left, right) => {
    const riskDelta = riskOrder[right.risk.level] - riskOrder[left.risk.level];
    return riskDelta || left.name.localeCompare(right.name);
  });
}

function backupInUse(snapshot: DashboardSnapshot, backupId: string): boolean {
  return snapshot.servers.some((server) => server.guardian?.backupId === backupId);
}

function serverRecommendation(server: ServerSummary): string {
  if (server.transport === 'http') {
    return 'Scan only. HTTP/SSE protection is not implemented in v0.1.';
  }
  if (server.risk.factors.some((factor) => factor.code === 'shell-command' || factor.code === 'command-execution')) {
    return 'Disable if unknown. Protect only after verifying the server is trusted; startup code is not sandboxed.';
  }
  if (server.risk.factors.some((factor) => factor.code === 'package-runner')) {
    return 'Package runner detected. Protect trusted servers; disable unknown servers until reviewed.';
  }
  if (server.risk.level === 'critical' || server.risk.level === 'high') {
    return 'Protect trusted servers. Disable unknown high-risk servers.';
  }
  return 'Monitor or leave active. Protect if you want audit logs and policy enforcement.';
}

function safetyRows(snapshot: DashboardSnapshot): Array<{ label: string; value: string; state: 'ok' | 'warn' }> {
  return [
    { label: 'Backups', value: '0700 dirs and 0600 files where supported', state: 'ok' },
    { label: 'Renderer sandbox', value: 'enabled', state: 'ok' },
    { label: 'Audit detail', value: snapshot.auditDetailLevel, state: snapshot.auditDetailLevel === 'minimal' ? 'ok' : 'warn' },
    { label: 'Upstream environment', value: 'restricted to minimal base env plus explicit server env', state: 'ok' },
    { label: 'Full responses stored', value: 'no, summaries only', state: 'ok' },
    { label: 'Known limitation', value: 'not an OS sandbox; startup side effects can still happen', state: 'warn' },
  ];
}

function statCounts(snapshot: DashboardSnapshot): Record<RiskLevel, number> {
  return snapshot.servers.reduce(
    (counts, server) => {
      counts[server.risk.level] += 1;
      return counts;
    },
    { low: 0, medium: 0, high: 0, critical: 0 },
  );
}

function policyForTool(policies: PolicyRecord[], tool: ToolInventoryItem): PolicyRecord | undefined {
  return policies.find(
    (policy) => policy.serverId === tool.serverId && policy.toolName === tool.toolName,
  );
}

function IconButton({
  label,
  children,
  onClick,
  disabled,
}: {
  label: string;
  children: ReactElement;
  onClick?: () => void;
  disabled?: boolean;
}): ReactElement {
  return (
    <button className="icon-button" type="button" title={label} aria-label={label} onClick={onClick} disabled={disabled}>
      {children}
    </button>
  );
}

function Sidebar({
  view,
  onView,
  pendingCount,
}: {
  view: ViewKey;
  onView: (view: ViewKey) => void;
  pendingCount: number;
}): ReactElement {
  const items: Array<{ key: ViewKey; label: string; icon: ReactElement; count?: number }> = [
    { key: 'dashboard', label: 'Dashboard', icon: <Gauge size={18} /> },
    { key: 'servers', label: 'Servers', icon: <Server size={18} /> },
    { key: 'tools', label: 'Tools', icon: <Shield size={18} /> },
    { key: 'policies', label: 'Policies', icon: <SlidersHorizontal size={18} /> },
    { key: 'approvals', label: 'Approvals', icon: <ShieldAlert size={18} />, count: pendingCount },
    { key: 'audit', label: 'Audit', icon: <ClipboardList size={18} /> },
    { key: 'backups', label: 'Backups', icon: <Database size={18} /> },
    { key: 'safety', label: 'Safety', icon: <ShieldCheck size={18} /> },
  ];

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">
          <Shield size={24} />
        </div>
        <div>
          <h1>MCP Guardian</h1>
          <p>Local permission dashboard</p>
        </div>
      </div>
      <nav>
        {items.map((item) => (
          <button
            key={item.key}
            type="button"
            className={view === item.key ? 'nav-item active' : 'nav-item'}
            onClick={() => onView(item.key)}
          >
            {item.icon}
            <span>{item.label}</span>
            {item.count ? <strong>{item.count}</strong> : null}
          </button>
        ))}
      </nav>
    </aside>
  );
}

function TopBar({
  snapshot,
  refreshing,
  onRefresh,
}: {
  snapshot: DashboardSnapshot;
  refreshing: boolean;
  onRefresh: () => void;
}): ReactElement {
  return (
    <header className="topbar">
      <div>
        <div className="eyebrow">v0.1 local-first</div>
        <h2>MCP tool permissions, policies, and audit trail</h2>
      </div>
      <div className="topbar-actions">
        <span className="db-path" title={snapshot.dbPath}>
          <Database size={16} />
          {snapshot.guardianHome}
        </span>
        <button className="primary-button" type="button" onClick={onRefresh} disabled={refreshing}>
          <RefreshCw size={16} className={refreshing ? 'spin' : ''} />
          Rescan
        </button>
      </div>
    </header>
  );
}

function DashboardView({
  snapshot,
  onSelectServer,
}: {
  snapshot: DashboardSnapshot;
  onSelectServer: (serverId: string) => void;
}): ReactElement {
  const counts = statCounts(snapshot);
  const protectedCount = snapshot.servers.filter((server) => server.mode === 'protected').length;
  const disabledCount = snapshot.servers.filter((server) => server.mode === 'disabled').length;
  const recent = snapshot.audits.slice(0, 6);
  const triageServers = sortedServers(snapshot).filter((server) => server.risk.level === 'critical' || server.risk.level === 'high').slice(0, 5);

  return (
    <div className="view-stack">
      <section className="summary-grid">
        <article className="summary-tile">
          <span>Servers</span>
          <strong>{snapshot.servers.length}</strong>
          <p>{protectedCount} protected, {disabledCount} disabled</p>
        </article>
        <article className="summary-tile warning">
          <span>High risk</span>
          <strong>{counts.high + counts.critical}</strong>
          <p>{counts.critical} critical, {counts.high} high</p>
        </article>
        <article className="summary-tile">
          <span>Tools</span>
          <strong>{snapshot.tools.length}</strong>
          <p>{snapshot.tools.filter((tool) => tool.source === 'actual').length} observed</p>
        </article>
        <article className="summary-tile accent">
          <span>Pending</span>
          <strong>{snapshot.pendingApprovals.length}</strong>
          <p>Approval requests waiting</p>
        </article>
      </section>

      <section className="two-column">
        <div className="panel">
          <div className="panel-header">
            <h3>Recommended First Actions</h3>
          </div>
          <div className="row-list">
            {triageServers.map((server) => (
              <button className="server-row" type="button" key={server.id} onClick={() => onSelectServer(server.id)}>
                <div>
                  <strong>{server.name}</strong>
                  <span>{serverRecommendation(server)}</span>
                </div>
                <div className="row-badges">
                  <RiskBadge risk={server.risk.level} />
                </div>
              </button>
            ))}
            {triageServers.length === 0 ? <div className="empty-state">No high-risk servers need immediate action.</div> : null}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <h3>Riskiest Servers</h3>
          </div>
          <div className="row-list">
            {sortedServers(snapshot).slice(0, 8).map((server) => (
              <button className="server-row" type="button" key={server.id} onClick={() => onSelectServer(server.id)}>
                <div>
                  <strong>{server.name}</strong>
                  <span>{server.source.client}</span>
                </div>
                <div className="row-badges">
                  <ModeBadge mode={server.mode} />
                  <RiskBadge risk={server.risk.level} />
                </div>
              </button>
            ))}
            {snapshot.servers.length === 0 ? <div className="empty-state">No supported MCP config files found.</div> : null}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <h3>Recent Audit</h3>
          </div>
          <div className="audit-mini">
            {recent.map((audit) => (
              <div key={audit.id} className="audit-mini-row">
                <span>{formatDate(audit.createdAt)}</span>
                <strong>{audit.serverName}/{audit.toolName}</strong>
                <RiskBadge risk={audit.risk} />
                <em>{decisionLabel(audit.decision)}</em>
              </div>
            ))}
            {recent.length === 0 ? <div className="empty-state">No tool calls logged yet.</div> : null}
          </div>
        </div>
      </section>
    </div>
  );
}

function SourcesPanel({
  snapshot,
  onAddCustomSource,
  onRemoveCustomSource,
}: {
  snapshot: DashboardSnapshot;
  onAddCustomSource: () => void;
  onRemoveCustomSource: (id: string) => void;
}): ReactElement {
  return (
    <div className="panel">
      <div className="panel-header">
        <h3>Config Sources</h3>
        <button className="secondary-button" type="button" onClick={onAddCustomSource}>
          <Plus size={16} />
          Add JSON
        </button>
      </div>
      <div className="source-list">
        {snapshot.sources.map((source) => (
          <div key={source.id} className="source-row">
            <FileJson size={18} />
            <div>
              <strong>
                {source.client}
                {source.sourceKind ? ` (${source.sourceKind})` : ''}
              </strong>
              <span title={source.path}>{source.path}</span>
            </div>
            <span className={source.exists ? 'source-state found' : 'source-state'}>{source.exists ? 'found' : 'missing'}</span>
            {source.sourceKind === 'custom' ? (
              <IconButton label="Remove custom source" onClick={() => onRemoveCustomSource(source.id)}>
                <Trash2 size={16} />
              </IconButton>
            ) : null}
          </div>
        ))}
      </div>
    </div>
  );
}

function ServerDetail({
  server,
  busy,
  onMode,
}: {
  server?: ServerSummary;
  busy?: string;
  onMode: (server: ServerSummary, mode: ServerMode) => void;
}): ReactElement {
  if (!server) {
    return <div className="detail-empty">Select a server to inspect its permissions.</div>;
  }

  const canProtect = server.transport === 'stdio' && server.mode !== 'protected';
  const canRestore = server.mode !== 'active';
  const disableBusy = busy === `${server.id}:disabled`;
  const protectBusy = busy === `${server.id}:protected`;
  const restoreBusy = busy === `${server.id}:active`;

  return (
    <div className="detail-panel">
      <div className="detail-title">
        <div>
          <h3>{server.name}</h3>
          <p>{server.source.client}</p>
        </div>
        <div className="row-badges">
          <ModeBadge mode={server.mode} />
          <RiskBadge risk={server.risk.level} />
        </div>
      </div>

      <div className="warning-box">
        <AlertTriangle size={18} />
        <span>
          {serverRecommendation(server)} Protect mode proxies stdio calls and policies. It does not
          sandbox startup side effects, inspect all network traffic, or contain arbitrary child
          processes.
        </span>
      </div>

      <div className="action-row">
        <button className="secondary-button" type="button" onClick={() => onMode(server, 'disabled')} disabled={server.mode === 'disabled' || Boolean(busy)}>
          <CircleSlash size={16} />
          {disableBusy ? 'Disabling' : 'Disable'}
        </button>
        <button className="primary-button" type="button" onClick={() => onMode(server, 'protected')} disabled={!canProtect || Boolean(busy)}>
          <Lock size={16} />
          {protectBusy ? 'Protecting' : 'Protect'}
        </button>
        <button className="ghost-button" type="button" onClick={() => onMode(server, 'active')} disabled={!canRestore || Boolean(busy)}>
          <Unlock size={16} />
          {restoreBusy ? 'Restoring' : 'Restore'}
        </button>
      </div>

      <section className="detail-section">
        <h4>Risk Factors</h4>
        <div className="factor-list">
          {server.risk.factors.map((factor) => (
            <div key={factor.code} className="factor-row">
              <RiskBadge risk={factor.level} />
              <span>{factor.label}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="detail-section">
        <h4>Configuration</h4>
        <pre className="code-block">{JSON.stringify(server.redactedConfig, null, 2)}</pre>
      </section>

      <section className="detail-section">
        <h4>Inferred Tools</h4>
        <div className="compact-tools">
          {server.inferredTools.map((tool) => (
            <span key={tool.toolName}>
              {tool.toolName}
              <RiskBadge risk={tool.risk} />
            </span>
          ))}
        </div>
      </section>
    </div>
  );
}

function SafetyView({ snapshot }: { snapshot: DashboardSnapshot }): ReactElement {
  return (
    <div className="view-stack">
      <div className="panel">
        <div className="panel-header">
          <h3>Trust But Verify</h3>
        </div>
        <div className="safety-list">
          {safetyRows(snapshot).map((row) => (
            <div key={row.label} className="safety-row">
              <span className={`source-state ${row.state === 'ok' ? 'found' : ''}`}>{row.state}</span>
              <strong>{row.label}</strong>
              <span>{row.value}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="warning-box">
        <AlertTriangle size={18} />
        <span>
          Use local dogfooding with fake or disposable MCP servers first. Do not attach production
          credentials until CI, audit triage, fake-server E2E, and cross-platform testing remain
          stable.
        </span>
      </div>
    </div>
  );
}

function ServersView({
  snapshot,
  selectedServerId,
  setSelectedServerId,
  busy,
  onMode,
}: {
  snapshot: DashboardSnapshot;
  selectedServerId?: string;
  setSelectedServerId: (id: string) => void;
  busy?: string;
  onMode: (server: ServerSummary, mode: ServerMode) => void;
}): ReactElement {
  const servers = sortedServers(snapshot);
  const selected = servers.find((server) => server.id === selectedServerId) ?? servers[0];

  useEffect(() => {
    if (!selectedServerId && selected) {
      setSelectedServerId(selected.id);
    }
  }, [selected, selectedServerId, setSelectedServerId]);

  return (
    <section className="servers-layout">
      <div className="panel server-list-panel">
        <div className="panel-header">
          <h3>Servers</h3>
        </div>
        <div className="row-list">
          {servers.map((server) => (
            <button
              key={server.id}
              type="button"
              className={selected?.id === server.id ? 'server-row selected' : 'server-row'}
              onClick={() => setSelectedServerId(server.id)}
            >
              <div>
                <strong>{server.name}</strong>
                <span>{server.risk.capabilities.join(', ')}</span>
              </div>
              <div className="row-badges">
                <ModeBadge mode={server.mode} />
                <RiskBadge risk={server.risk.level} />
              </div>
            </button>
          ))}
          {servers.length === 0 ? <div className="empty-state">No MCP servers discovered.</div> : null}
        </div>
      </div>
      <ServerDetail server={selected} busy={busy} onMode={onMode} />
    </section>
  );
}

function ToolPolicySelect({
  tool,
  policies,
  onSet,
  onDelete,
}: {
  tool: ToolInventoryItem;
  policies: PolicyRecord[];
  onSet: (serverId: string, toolName: string, action: PolicyAction) => void;
  onDelete: (serverId: string, toolName: string) => void;
}): ReactElement {
  const exact = policyForTool(policies, tool);
  const evaluation = evaluatePolicy({
    policies,
    serverId: tool.serverId,
    serverName: tool.serverName,
    toolName: tool.toolName,
    risk: tool.risk,
  });

  return (
    <select
      value={exact?.action ?? ''}
      aria-label={`Policy for ${tool.serverName} ${tool.toolName}`}
      onChange={(event) => {
        const value = event.target.value as PolicyAction | '';
        if (value) {
          onSet(tool.serverId, tool.toolName, value);
        } else {
          onDelete(tool.serverId, tool.toolName);
        }
      }}
      title={evaluation.reason}
    >
      <option value="">Default: {evaluation.action}</option>
      <option value="allow">Allow</option>
      <option value="ask">Ask</option>
      <option value="block">Block</option>
    </select>
  );
}

function ToolsView({
  snapshot,
  onSetPolicy,
  onDeletePolicy,
}: {
  snapshot: DashboardSnapshot;
  onSetPolicy: (serverId: string, toolName: string, action: PolicyAction) => void;
  onDeletePolicy: (serverId: string, toolName: string) => void;
}): ReactElement {
  return (
    <div className="panel">
      <div className="panel-header">
        <h3>Tool Inventory</h3>
      </div>
      <div className="table">
        <div className="table-row table-head">
          <span>Server</span>
          <span>Tool</span>
          <span>Risk</span>
          <span>Source</span>
          <span>Policy</span>
        </div>
        {snapshot.tools.map((tool) => (
          <div className="table-row" key={`${tool.serverId}/${tool.toolName}`}>
            <span>{tool.serverName}</span>
            <span>
              <strong>{tool.toolName}</strong>
              {tool.description ? <em>{tool.description}</em> : null}
            </span>
            <span>
              <RiskBadge risk={tool.risk} />
            </span>
            <span>{tool.source}</span>
            <span>
              <ToolPolicySelect tool={tool} policies={snapshot.policies} onSet={onSetPolicy} onDelete={onDeletePolicy} />
            </span>
          </div>
        ))}
        {snapshot.tools.length === 0 ? <div className="empty-state">No tool inventory yet.</div> : null}
      </div>
    </div>
  );
}

function PoliciesView({
  snapshot,
  onSetPolicy,
  onDeletePolicy,
}: {
  snapshot: DashboardSnapshot;
  onSetPolicy: (serverId: string, toolName: string, action: PolicyAction) => void;
  onDeletePolicy: (serverId: string, toolName: string) => void;
}): ReactElement {
  const [serverId, setServerId] = useState('*');
  const [toolName, setToolName] = useState('*');
  const [action, setAction] = useState<PolicyAction>('ask');
  const serverOptions = [
    { serverId: '*', serverName: 'All servers' },
    ...snapshot.servers.map((server) => ({ serverId: server.serverId, serverName: server.name })),
  ];

  return (
    <div className="view-stack">
      <div className="panel">
        <div className="panel-header">
          <h3>Policy Editor</h3>
        </div>
        <div className="policy-form">
          <label>
            Server
            <select value={serverId} onChange={(event) => setServerId(event.target.value)}>
              {serverOptions.map((option) => (
                <option key={option.serverId} value={option.serverId}>
                  {option.serverName}
                </option>
              ))}
            </select>
          </label>
          <label>
            Tool
            <input value={toolName} onChange={(event) => setToolName(event.target.value || '*')} />
          </label>
          <div className="segmented" role="group" aria-label="Policy action">
            {(['allow', 'ask', 'block'] as PolicyAction[]).map((candidate) => (
              <button
                key={candidate}
                type="button"
                className={action === candidate ? 'active' : ''}
                onClick={() => setAction(candidate)}
              >
                {candidate}
              </button>
            ))}
          </div>
          <button className="primary-button" type="button" onClick={() => onSetPolicy(serverId, toolName || '*', action)}>
            <Check size={16} />
            Save
          </button>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>Active Policies</h3>
        </div>
        <div className="table compact">
          <div className="table-row table-head">
            <span>Server</span>
            <span>Tool</span>
            <span>Action</span>
            <span>Updated</span>
            <span></span>
          </div>
          {snapshot.policies.map((policy) => (
            <div className="table-row" key={`${policy.serverId}/${policy.toolName}`}>
              <span>{policy.serverId === '*' ? 'All servers' : policy.serverName ?? policy.serverId.slice(0, 12)}</span>
              <span>{policy.toolName}</span>
              <span className={`policy-action ${policy.action}`}>{policy.action}</span>
              <span>{formatDate(policy.updatedAt)}</span>
              <span>
                <IconButton label="Delete policy" onClick={() => onDeletePolicy(policy.serverId, policy.toolName)}>
                  <X size={16} />
                </IconButton>
              </span>
            </div>
          ))}
          {snapshot.policies.length === 0 ? <div className="empty-state">No explicit policies saved.</div> : null}
        </div>
      </div>
    </div>
  );
}

function ApprovalsView({
  approvals,
  onResolve,
}: {
  approvals: PendingApprovalRecord[];
  onResolve: (id: number, decision: 'approved' | 'denied') => void;
}): ReactElement {
  return (
    <div className="panel">
      <div className="panel-header">
        <h3>Pending Approvals</h3>
      </div>
      <div className="approval-list">
        {approvals.map((approval) => (
          <article key={approval.id} className="approval-item">
            <div className="approval-main">
              <div>
                <strong>{approval.serverName}/{approval.toolName}</strong>
                <span>Expires {formatDate(approval.expiresAt)}</span>
              </div>
              <RiskBadge risk={approval.risk} />
            </div>
            <pre className="code-block small">{approval.argsJson}</pre>
            <div className="action-row end">
              <button className="secondary-button" type="button" onClick={() => onResolve(approval.id, 'denied')}>
                <X size={16} />
                Deny
              </button>
              <button className="primary-button" type="button" onClick={() => onResolve(approval.id, 'approved')}>
                <Check size={16} />
                Approve
              </button>
            </div>
          </article>
        ))}
        {approvals.length === 0 ? <div className="empty-state">No pending approvals.</div> : null}
      </div>
    </div>
  );
}

function AuditView({ snapshot }: { snapshot: DashboardSnapshot }): ReactElement {
  return (
    <div className="panel">
      <div className="panel-header">
        <h3>Audit Log</h3>
      </div>
      <div className="table audit-table">
        <div className="table-row table-head">
          <span>Time</span>
          <span>Server</span>
          <span>Tool</span>
          <span>Decision</span>
          <span>Risk</span>
          <span>Error</span>
        </div>
        {snapshot.audits.map((audit) => (
          <div className="table-row" key={audit.id}>
            <span>{formatDate(audit.createdAt)}</span>
            <span>{audit.serverName}</span>
            <span>{audit.toolName}</span>
            <span>{decisionLabel(audit.decision)}</span>
            <span>
              <RiskBadge risk={audit.risk} />
            </span>
            <span title={audit.error}>{audit.error ?? ''}</span>
          </div>
        ))}
        {snapshot.audits.length === 0 ? <div className="empty-state">No audit entries yet.</div> : null}
      </div>
    </div>
  );
}

function BackupsView({
  snapshot,
  onOpenBackupFolder,
  onDeleteBackup,
}: {
  snapshot: DashboardSnapshot;
  onOpenBackupFolder: () => void;
  onDeleteBackup: (backup: BackupRecord) => void;
}): ReactElement {
  return (
    <div className="view-stack">
      <div className="warning-box">
        <AlertTriangle size={18} />
        <span>
          Backup files preserve MCP configs and may contain secrets. Delete only stale backups you no
          longer need for restore.
        </span>
      </div>
      <div className="panel">
        <div className="panel-header">
          <h3>Backup Inventory</h3>
          <button className="secondary-button" type="button" onClick={onOpenBackupFolder}>
            <FolderOpen size={16} />
            Open Folder
          </button>
        </div>
        <div className="table backup-table">
          <div className="table-row table-head">
            <span>Created</span>
            <span>Server</span>
            <span>Source</span>
            <span>Backup</span>
            <span>Status</span>
            <span></span>
          </div>
          {snapshot.backups.map((backup) => {
            const inUse = backupInUse(snapshot, backup.backupId);
            return (
              <div className="table-row" key={backup.backupId}>
                <span>{formatDate(backup.createdAt)}</span>
                <span>{backup.serverName}</span>
                <span title={backup.sourcePath}>{backup.sourcePath}</span>
                <span title={backup.backupPath}>{backup.backupPath}</span>
                <span className={inUse ? 'source-state found' : 'source-state'}>{inUse ? 'in use' : 'stale'}</span>
                <span>
                  <IconButton label="Delete backup" onClick={() => onDeleteBackup(backup)}>
                    <Trash2 size={16} />
                  </IconButton>
                </span>
              </div>
            );
          })}
          {snapshot.backups.length === 0 ? <div className="empty-state">No backups written yet.</div> : null}
        </div>
      </div>
    </div>
  );
}

export function App(): ReactElement {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | undefined>();
  const [view, setView] = useState<ViewKey>('dashboard');
  const [selectedServerId, setSelectedServerId] = useState<string | undefined>();
  const [refreshing, setRefreshing] = useState(false);
  const [busy, setBusy] = useState<string | undefined>();
  const [notice, setNotice] = useState<string | undefined>();
  const pendingCount = snapshot?.pendingApprovals.length ?? 0;

  const refresh = async (): Promise<void> => {
    setRefreshing(true);
    try {
      setSnapshot(await window.guardian.getSnapshot());
    } finally {
      setRefreshing(false);
    }
  };

  useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 5000);
    return () => window.clearInterval(timer);
  }, []);

  const selectedServer = useMemo(
    () => snapshot?.servers.find((server) => server.id === selectedServerId),
    [selectedServerId, snapshot],
  );

  const setPolicy = async (serverId: string, toolName: string, action: PolicyAction): Promise<void> => {
    setSnapshot(await window.guardian.setPolicy({ serverId, toolName, action }));
  };

  const deletePolicy = async (serverId: string, toolName: string): Promise<void> => {
    setSnapshot(await window.guardian.deletePolicy({ serverId, toolName }));
  };

  const applyMode = async (server: ServerSummary, mode: ServerMode): Promise<void> => {
    const busyKey = `${server.id}:${mode}`;
    setBusy(busyKey);
    setNotice(undefined);
    try {
      const response = await window.guardian.applyMode({
        serverId: server.serverId,
        mode,
      });
      setSnapshot(response.snapshot);
      setNotice(`Backup written: ${response.result.backupPath}`);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(undefined);
    }
  };

  const resolveApproval = async (id: number, decision: 'approved' | 'denied'): Promise<void> => {
    setSnapshot(await window.guardian.resolveApproval({ id, decision }));
  };

  const addCustomSource = async (): Promise<void> => {
    setSnapshot(await window.guardian.addCustomSource());
  };

  const removeCustomSource = async (id: string): Promise<void> => {
    setSnapshot(await window.guardian.removeCustomSource({ id }));
  };

  const openBackupFolder = async (): Promise<void> => {
    const result = await window.guardian.openBackupFolder();
    if (result) {
      setNotice(result);
    }
  };

  const deleteBackup = async (backup: BackupRecord): Promise<void> => {
    const inUse = snapshot ? backupInUse(snapshot, backup.backupId) : false;
    const confirmed =
      !inUse ||
      window.confirm(
        'This backup is used by a currently protected or disabled server. Delete it only if you have another restore path.',
      );
    if (!confirmed) return;
    setSnapshot(await window.guardian.deleteBackup({ backupId: backup.backupId, confirmed: inUse }));
  };

  if (!snapshot) {
    return (
      <div className="loading-screen">
        <Shield size={36} />
        <span>Loading MCP Guardian</span>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <Sidebar view={view} onView={setView} pendingCount={pendingCount} />
      <main className="content">
        <TopBar snapshot={snapshot} refreshing={refreshing} onRefresh={refresh} />
        {notice ? <div className="notice">{notice}</div> : null}
        {view === 'dashboard' ? (
          <DashboardView
            snapshot={snapshot}
            onSelectServer={(id) => {
              setSelectedServerId(id);
              setView('servers');
            }}
          />
        ) : null}
        {view === 'servers' ? (
          <div className="view-stack">
            <ServersView
              snapshot={snapshot}
              selectedServerId={selectedServer?.id ?? selectedServerId}
              setSelectedServerId={setSelectedServerId}
              busy={busy}
              onMode={applyMode}
            />
            <SourcesPanel
              snapshot={snapshot}
              onAddCustomSource={addCustomSource}
              onRemoveCustomSource={removeCustomSource}
            />
          </div>
        ) : null}
        {view === 'tools' ? (
          <ToolsView snapshot={snapshot} onSetPolicy={setPolicy} onDeletePolicy={deletePolicy} />
        ) : null}
        {view === 'policies' ? (
          <PoliciesView snapshot={snapshot} onSetPolicy={setPolicy} onDeletePolicy={deletePolicy} />
        ) : null}
        {view === 'approvals' ? (
          <ApprovalsView approvals={snapshot.pendingApprovals} onResolve={resolveApproval} />
        ) : null}
        {view === 'audit' ? <AuditView snapshot={snapshot} /> : null}
        {view === 'backups' ? (
          <BackupsView snapshot={snapshot} onOpenBackupFolder={openBackupFolder} onDeleteBackup={deleteBackup} />
        ) : null}
        {view === 'safety' ? <SafetyView snapshot={snapshot} /> : null}
      </main>
    </div>
  );
}
