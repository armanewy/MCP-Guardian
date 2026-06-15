import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import type {
  AuditLogRecord,
  PendingApprovalRecord,
  PolicyAction,
  PolicyRecord,
  RiskLevel,
  ToolInventoryItem,
} from '../shared/types';
import { coercePolicyAction } from '../shared/policy';
import { redactDeep, safeJson } from '../shared/redaction';

type SqliteDatabase = Database.Database;

export function getDefaultGuardianHome(env: NodeJS.ProcessEnv = process.env): string {
  return env.MCP_GUARDIAN_HOME || path.join(os.homedir(), '.mcp-guardian');
}

export function getDefaultDatabasePath(env: NodeJS.ProcessEnv = process.env): string {
  return path.join(getDefaultGuardianHome(env), 'mcp-guardian.sqlite');
}

function ensureParentDir(filePath: string): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function nowIso(): string {
  return new Date().toISOString();
}

function toRiskLevel(value: string): RiskLevel {
  if (value === 'low' || value === 'medium' || value === 'high' || value === 'critical') {
    return value;
  }
  return 'medium';
}

export class GuardianDatabase {
  readonly db: SqliteDatabase;
  readonly path: string;

  constructor(dbPath = getDefaultDatabasePath()) {
    this.path = dbPath;
    ensureParentDir(dbPath);
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.migrate();
  }

  close(): void {
    this.db.close();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS policies (
        server_name TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        action TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (server_name, tool_name)
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        server_name TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        action TEXT NOT NULL,
        decision TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        request_json TEXT,
        response_json TEXT,
        error TEXT,
        source_path TEXT
      );

      CREATE TABLE IF NOT EXISTS pending_approvals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        server_name TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        args_json TEXT NOT NULL,
        status TEXT NOT NULL,
        reason TEXT
      );

      CREATE TABLE IF NOT EXISTS tool_inventory (
        server_name TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        description TEXT,
        input_schema_json TEXT,
        risk_level TEXT NOT NULL,
        source TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        hidden_when_blocked INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (server_name, tool_name)
      );
    `);
  }

  listPolicies(): PolicyRecord[] {
    const rows = this.db
      .prepare('SELECT server_name, tool_name, action, updated_at FROM policies ORDER BY server_name, tool_name')
      .all() as Array<Record<string, string>>;

    return rows.map((row) => ({
      serverName: row.server_name,
      toolName: row.tool_name,
      action: coercePolicyAction(row.action),
      updatedAt: row.updated_at,
    }));
  }

  setPolicy(serverName: string, toolName: string, action: PolicyAction): PolicyRecord {
    const updatedAt = nowIso();
    this.db
      .prepare(
        `
        INSERT INTO policies (server_name, tool_name, action, updated_at)
        VALUES (@serverName, @toolName, @action, @updatedAt)
        ON CONFLICT(server_name, tool_name) DO UPDATE SET
          action = excluded.action,
          updated_at = excluded.updated_at
      `,
      )
      .run({ serverName, toolName, action, updatedAt });

    return { serverName, toolName, action, updatedAt };
  }

  deletePolicy(serverName: string, toolName: string): void {
    this.db
      .prepare('DELETE FROM policies WHERE server_name = ? AND tool_name = ?')
      .run(serverName, toolName);
  }

  upsertToolInventory(tool: ToolInventoryItem): void {
    this.db
      .prepare(
        `
        INSERT INTO tool_inventory (
          server_name,
          tool_name,
          description,
          input_schema_json,
          risk_level,
          source,
          last_seen,
          hidden_when_blocked
        )
        VALUES (@serverName, @toolName, @description, @inputSchemaJson, @risk, @source, @lastSeen, @hiddenWhenBlocked)
        ON CONFLICT(server_name, tool_name) DO UPDATE SET
          description = excluded.description,
          input_schema_json = excluded.input_schema_json,
          risk_level = excluded.risk_level,
          source = excluded.source,
          last_seen = excluded.last_seen,
          hidden_when_blocked = excluded.hidden_when_blocked
      `,
      )
      .run({
        serverName: tool.serverName,
        toolName: tool.toolName,
        description: tool.description ?? null,
        inputSchemaJson: tool.inputSchema ? safeJson(tool.inputSchema) : null,
        risk: tool.risk,
        source: tool.source,
        lastSeen: tool.lastSeen ?? nowIso(),
        hiddenWhenBlocked: tool.hiddenWhenBlocked === false ? 0 : 1,
      });
  }

  listToolInventory(): ToolInventoryItem[] {
    const rows = this.db
      .prepare(
        `
        SELECT server_name, tool_name, description, input_schema_json, risk_level, source, last_seen, hidden_when_blocked
        FROM tool_inventory
        ORDER BY server_name, tool_name
      `,
      )
      .all() as Array<Record<string, string | number | null>>;

    return rows.map((row) => ({
      serverName: String(row.server_name),
      toolName: String(row.tool_name),
      description: row.description ? String(row.description) : undefined,
      inputSchema: row.input_schema_json ? JSON.parse(String(row.input_schema_json)) : undefined,
      risk: toRiskLevel(String(row.risk_level)),
      source: row.source === 'actual' ? 'actual' : 'inferred',
      lastSeen: String(row.last_seen),
      hiddenWhenBlocked: Number(row.hidden_when_blocked) === 1,
    }));
  }

  logAudit(input: {
    serverName: string;
    toolName: string;
    action: string;
    decision: string;
    risk: RiskLevel;
    request?: unknown;
    response?: unknown;
    error?: string;
    sourcePath?: string;
  }): void {
    this.db
      .prepare(
        `
        INSERT INTO audit_logs (
          created_at,
          server_name,
          tool_name,
          action,
          decision,
          risk_level,
          request_json,
          response_json,
          error,
          source_path
        )
        VALUES (@createdAt, @serverName, @toolName, @action, @decision, @risk, @requestJson, @responseJson, @error, @sourcePath)
      `,
      )
      .run({
        createdAt: nowIso(),
        serverName: input.serverName,
        toolName: input.toolName,
        action: input.action,
        decision: input.decision,
        risk: input.risk,
        requestJson: input.request === undefined ? null : safeJson(input.request),
        responseJson: input.response === undefined ? null : safeJson(input.response),
        error: input.error ?? null,
        sourcePath: input.sourcePath ?? null,
      });
  }

  listAuditLogs(limit = 200): AuditLogRecord[] {
    const rows = this.db
      .prepare(
        `
        SELECT id, created_at, server_name, tool_name, action, decision, risk_level, request_json, response_json, error, source_path
        FROM audit_logs
        ORDER BY id DESC
        LIMIT ?
      `,
      )
      .all(limit) as Array<Record<string, string | number | null>>;

    return rows.map((row) => ({
      id: Number(row.id),
      createdAt: String(row.created_at),
      serverName: String(row.server_name),
      toolName: String(row.tool_name),
      action: String(row.action),
      decision: String(row.decision),
      risk: toRiskLevel(String(row.risk_level)),
      requestJson: row.request_json ? String(row.request_json) : undefined,
      responseJson: row.response_json ? String(row.response_json) : undefined,
      error: row.error ? String(row.error) : undefined,
      sourcePath: row.source_path ? String(row.source_path) : undefined,
    }));
  }

  createPendingApproval(input: {
    serverName: string;
    toolName: string;
    risk: RiskLevel;
    args: unknown;
    timeoutMs: number;
  }): PendingApprovalRecord {
    const createdAt = nowIso();
    const expiresAt = new Date(Date.now() + input.timeoutMs).toISOString();
    const result = this.db
      .prepare(
        `
        INSERT INTO pending_approvals (
          created_at,
          expires_at,
          server_name,
          tool_name,
          risk_level,
          args_json,
          status
        )
        VALUES (@createdAt, @expiresAt, @serverName, @toolName, @risk, @argsJson, 'pending')
      `,
      )
      .run({
        createdAt,
        expiresAt,
        serverName: input.serverName,
        toolName: input.toolName,
        risk: input.risk,
        argsJson: safeJson(input.args),
      });

    return {
      id: Number(result.lastInsertRowid),
      createdAt,
      expiresAt,
      serverName: input.serverName,
      toolName: input.toolName,
      risk: input.risk,
      argsJson: safeJson(input.args),
      status: 'pending',
    };
  }

  listPendingApprovals(includeResolved = false): PendingApprovalRecord[] {
    this.expireStaleApprovals();
    const rows = this.db
      .prepare(
        `
        SELECT id, created_at, expires_at, server_name, tool_name, risk_level, args_json, status, reason
        FROM pending_approvals
        ${includeResolved ? '' : "WHERE status = 'pending'"}
        ORDER BY id DESC
        LIMIT 100
      `,
      )
      .all() as Array<Record<string, string | number | null>>;

    return rows.map((row) => ({
      id: Number(row.id),
      createdAt: String(row.created_at),
      expiresAt: String(row.expires_at),
      serverName: String(row.server_name),
      toolName: String(row.tool_name),
      risk: toRiskLevel(String(row.risk_level)),
      argsJson: String(row.args_json),
      status:
        row.status === 'approved' || row.status === 'denied' || row.status === 'expired'
          ? row.status
          : 'pending',
      reason: row.reason ? String(row.reason) : undefined,
    }));
  }

  getPendingApproval(id: number): PendingApprovalRecord | undefined {
    const row = this.db
      .prepare(
        `
        SELECT id, created_at, expires_at, server_name, tool_name, risk_level, args_json, status, reason
        FROM pending_approvals
        WHERE id = ?
      `,
      )
      .get(id) as Record<string, string | number | null> | undefined;

    if (!row) return undefined;
    return {
      id: Number(row.id),
      createdAt: String(row.created_at),
      expiresAt: String(row.expires_at),
      serverName: String(row.server_name),
      toolName: String(row.tool_name),
      risk: toRiskLevel(String(row.risk_level)),
      argsJson: String(row.args_json),
      status:
        row.status === 'approved' || row.status === 'denied' || row.status === 'expired'
          ? row.status
          : 'pending',
      reason: row.reason ? String(row.reason) : undefined,
    };
  }

  resolveApproval(id: number, decision: 'approved' | 'denied', reason?: string): void {
    this.db
      .prepare(
        `
        UPDATE pending_approvals
        SET status = ?, reason = ?
        WHERE id = ? AND status = 'pending'
      `,
      )
      .run(decision, reason ?? null, id);
  }

  expireStaleApprovals(): void {
    this.db
      .prepare(
        `
        UPDATE pending_approvals
        SET status = 'expired', reason = 'Timed out'
        WHERE status = 'pending' AND expires_at < ?
      `,
      )
      .run(nowIso());
  }

  async waitForApproval(id: number, timeoutMs: number, pollMs = 750): Promise<'approved' | 'denied' | 'expired'> {
    const started = Date.now();
    while (Date.now() - started < timeoutMs) {
      this.expireStaleApprovals();
      const approval = this.getPendingApproval(id);
      if (!approval || approval.status === 'expired') return 'expired';
      if (approval.status === 'approved' || approval.status === 'denied') return approval.status;
      await new Promise((resolve) => setTimeout(resolve, pollMs));
    }

    this.expireStaleApprovals();
    return 'expired';
  }

  redacted(value: unknown): unknown {
    return redactDeep(value);
  }
}
