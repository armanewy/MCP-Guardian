import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import Database from 'better-sqlite3';
import type {
  AuditLogRecord,
  BackupRecord,
  AuditDetailLevel,
  McpServerDefinition,
  PendingApprovalRecord,
  PolicyAction,
  PolicyRecord,
  RiskLevel,
  ToolInventoryItem,
} from '../shared/types';
import { coercePolicyAction } from '../shared/policy';
import { redactDeep } from '../shared/redaction';
import { sha256Hex } from '../shared/identity';

type SqliteDatabase = Database.Database;

const RESPONSE_PREVIEW_LIMIT = 200;
const PRIVATE_DIR_MODE = 0o700;
const PRIVATE_FILE_MODE = 0o600;

export function getDefaultGuardianHome(env: NodeJS.ProcessEnv = process.env): string {
  return env.MCP_GUARDIAN_HOME || path.join(os.homedir(), '.mcp-guardian');
}

export function getDefaultDatabasePath(env: NodeJS.ProcessEnv = process.env): string {
  return path.join(getDefaultGuardianHome(env), 'mcp-guardian.sqlite');
}

export function getDefaultBackupDir(env: NodeJS.ProcessEnv = process.env): string {
  return path.join(getDefaultGuardianHome(env), 'backups');
}

function chmodIfSupported(targetPath: string, mode: number): void {
  try {
    fs.chmodSync(targetPath, mode);
  } catch {
    // chmod is not consistently meaningful on Windows and some virtual filesystems.
  }
}

function ensurePrivateDir(dirPath: string): void {
  fs.mkdirSync(dirPath, { recursive: true, mode: PRIVATE_DIR_MODE });
  chmodIfSupported(dirPath, PRIVATE_DIR_MODE);
}

function ensurePrivateParentDir(filePath: string): void {
  ensurePrivateDir(path.dirname(filePath));
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

function getRoot(json: any, rootKey: string): Record<string, unknown> {
  if (rootKey === 'mcpServers') return json.mcpServers;
  if (rootKey === 'servers') return json.servers;
  if (rootKey === 'mcp.servers') return json.mcp.servers;
  throw new Error(`Unsupported config root: ${rootKey}`);
}

function cappedRedactedJson(value: unknown, limit = 4_000): string {
  const redacted = redactDeep(value);
  const json = JSON.stringify(redacted, null, 2);
  if (json.length <= limit) {
    return json;
  }

  return JSON.stringify(
    {
      truncated: true,
      byteLengthEstimate: Buffer.byteLength(json, 'utf8'),
      preview: json.slice(0, limit),
    },
    null,
    2,
  );
}

function objectKeys(value: unknown): string[] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return [];
  }
  return Object.keys(value as Record<string, unknown>).sort();
}

function summarizeRequestMinimal(value: unknown): string {
  const serialized = JSON.stringify(redactDeep(value));
  const request = value as { arguments?: unknown; name?: unknown } | undefined;
  return JSON.stringify(
    {
      detailLevel: 'minimal',
      byteLengthEstimate: Buffer.byteLength(serialized, 'utf8'),
      toolName: typeof request?.name === 'string' ? request.name : undefined,
      argKeys: objectKeys(request?.arguments),
    },
    null,
    2,
  );
}

function coerceAuditDetailLevel(value: string | undefined): AuditDetailLevel {
  return value === 'redacted-preview' ? 'redacted-preview' : 'minimal';
}

export function summarizeToolResponse(response: unknown): Record<string, unknown> {
  const redacted = redactDeep(response) as any;
  const content = Array.isArray(redacted?.content) ? redacted.content : [];
  const serialized = JSON.stringify(redacted);
  return {
    contentItemCount: content.length,
    contentTypes: [...new Set(content.map((item: any) => String(item?.type ?? 'unknown')))],
    isError: Boolean(redacted?.isError),
    byteLengthEstimate: Buffer.byteLength(serialized, 'utf8'),
    preview: serialized.slice(0, RESPONSE_PREVIEW_LIMIT),
  };
}

function tableColumns(db: SqliteDatabase, tableName: string): Set<string> {
  const rows = db.prepare(`PRAGMA table_info(${tableName})`).all() as Array<{ name: string }>;
  return new Set(rows.map((row) => row.name));
}

function ensureColumn(db: SqliteDatabase, tableName: string, columnName: string, ddl: string): void {
  if (!tableColumns(db, tableName).has(columnName)) {
    db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${ddl}`);
  }
}

export class GuardianDatabase {
  readonly db: SqliteDatabase;
  readonly path: string;
  readonly backupDir: string;

  constructor(dbPath = getDefaultDatabasePath()) {
    this.path = dbPath;
    this.backupDir = path.join(path.dirname(dbPath), 'backups');
    ensurePrivateParentDir(dbPath);
    ensurePrivateDir(this.backupDir);
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
        server_id TEXT NOT NULL,
        server_name TEXT,
        tool_name TEXT NOT NULL,
        action TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (server_id, tool_name)
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        server_id TEXT NOT NULL,
        server_name TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        action TEXT NOT NULL,
        decision TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        request_json TEXT,
        response_summary_json TEXT,
        error TEXT,
        source_path TEXT
      );

      CREATE TABLE IF NOT EXISTS pending_approvals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        server_id TEXT NOT NULL,
        server_name TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        args_json TEXT NOT NULL,
        status TEXT NOT NULL,
        reason TEXT
      );

      CREATE TABLE IF NOT EXISTS tool_inventory (
        server_id TEXT NOT NULL,
        server_name TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        description TEXT,
        input_schema_json TEXT,
        risk_level TEXT NOT NULL,
        source TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        hidden_when_blocked INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (server_id, tool_name)
      );

      CREATE TABLE IF NOT EXISTS backups (
        backup_id TEXT PRIMARY KEY,
        source_path TEXT NOT NULL,
        server_id TEXT NOT NULL,
        server_name TEXT NOT NULL,
        config_root_key TEXT NOT NULL,
        backup_path TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
    `);

    ensureColumn(this.db, 'policies', 'server_id', "server_id TEXT NOT NULL DEFAULT ''");
    ensureColumn(this.db, 'policies', 'server_name', 'server_name TEXT');
    this.db.exec("UPDATE policies SET server_id = server_name WHERE server_id = '' AND server_name IS NOT NULL");
    this.db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_server_tool ON policies(server_id, tool_name)');

    ensureColumn(this.db, 'audit_logs', 'server_id', "server_id TEXT NOT NULL DEFAULT ''");
    ensureColumn(this.db, 'audit_logs', 'response_summary_json', 'response_summary_json TEXT');
    this.db.exec("UPDATE audit_logs SET server_id = server_name WHERE server_id = '' AND server_name IS NOT NULL");

    ensureColumn(this.db, 'pending_approvals', 'server_id', "server_id TEXT NOT NULL DEFAULT ''");
    this.db.exec(
      "UPDATE pending_approvals SET server_id = server_name WHERE server_id = '' AND server_name IS NOT NULL",
    );

    ensureColumn(this.db, 'tool_inventory', 'server_id', "server_id TEXT NOT NULL DEFAULT ''");
    this.db.exec("UPDATE tool_inventory SET server_id = server_name WHERE server_id = '' AND server_name IS NOT NULL");
    this.db.exec(
      'CREATE UNIQUE INDEX IF NOT EXISTS idx_tool_inventory_server_tool ON tool_inventory(server_id, tool_name)',
    );
  }

  getAuditDetailLevel(): AuditDetailLevel {
    const row = this.db.prepare("SELECT value FROM settings WHERE key = 'auditDetailLevel'").get() as
      | { value: string }
      | undefined;
    return coerceAuditDetailLevel(row?.value);
  }

  setAuditDetailLevel(level: AuditDetailLevel): void {
    this.db
      .prepare(
        `
        INSERT INTO settings (key, value, updated_at)
        VALUES ('auditDetailLevel', @level, @updatedAt)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
      `,
      )
      .run({ level, updatedAt: nowIso() });
  }

  listPolicies(): PolicyRecord[] {
    const rows = this.db
      .prepare(
        'SELECT server_id, server_name, tool_name, action, updated_at FROM policies ORDER BY server_name, tool_name',
      )
      .all() as Array<Record<string, string | null>>;

    return rows.map((row) => ({
      serverId: String(row.server_id),
      serverName: row.server_name ? String(row.server_name) : undefined,
      toolName: String(row.tool_name),
      action: coercePolicyAction(String(row.action)),
      updatedAt: String(row.updated_at),
    }));
  }

  setPolicy(serverId: string, serverName: string | undefined, toolName: string, action: PolicyAction): PolicyRecord {
    const updatedAt = nowIso();
    const displayServerName = serverName ?? serverId;
    this.db
      .prepare(
        `
        INSERT INTO policies (server_id, server_name, tool_name, action, updated_at)
        VALUES (@serverId, @serverName, @toolName, @action, @updatedAt)
        ON CONFLICT(server_id, tool_name) DO UPDATE SET
          server_name = excluded.server_name,
          action = excluded.action,
          updated_at = excluded.updated_at
      `,
      )
      .run({ serverId, serverName: displayServerName, toolName, action, updatedAt });

    return { serverId, serverName: displayServerName, toolName, action, updatedAt };
  }

  deletePolicy(serverId: string, toolName: string): void {
    this.db.prepare('DELETE FROM policies WHERE server_id = ? AND tool_name = ?').run(serverId, toolName);
  }

  upsertToolInventory(tool: ToolInventoryItem): void {
    this.db
      .prepare(
        `
        INSERT INTO tool_inventory (
          server_id,
          server_name,
          tool_name,
          description,
          input_schema_json,
          risk_level,
          source,
          last_seen,
          hidden_when_blocked
        )
        VALUES (@serverId, @serverName, @toolName, @description, @inputSchemaJson, @risk, @source, @lastSeen, @hiddenWhenBlocked)
        ON CONFLICT(server_id, tool_name) DO UPDATE SET
          server_name = excluded.server_name,
          description = excluded.description,
          input_schema_json = excluded.input_schema_json,
          risk_level = excluded.risk_level,
          source = excluded.source,
          last_seen = excluded.last_seen,
          hidden_when_blocked = excluded.hidden_when_blocked
      `,
      )
      .run({
        serverId: tool.serverId,
        serverName: tool.serverName,
        toolName: tool.toolName,
        description: tool.description ?? null,
        inputSchemaJson: tool.inputSchema ? cappedRedactedJson(tool.inputSchema) : null,
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
        SELECT server_id, server_name, tool_name, description, input_schema_json, risk_level, source, last_seen, hidden_when_blocked
        FROM tool_inventory
        ORDER BY server_name, tool_name
      `,
      )
      .all() as Array<Record<string, string | number | null>>;

    return rows.map((row) => ({
      serverId: String(row.server_id),
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

  createBackup(input: {
    sourcePath: string;
    serverId: string;
    serverName: string;
    configRootKey: string;
    content: string;
  }): BackupRecord {
    const createdAt = nowIso();
    const backupId = `${createdAt.replace(/[:.]/g, '-')}-${input.serverId.slice(0, 12)}-${randomBytes(6).toString('hex')}`;
    const backupPath = path.join(this.backupDir, `${backupId}.json`);
    const sha256 = sha256Hex(input.content);

    const fd = fs.openSync(backupPath, 'wx', PRIVATE_FILE_MODE);
    try {
      fs.writeFileSync(fd, input.content, 'utf8');
      try {
        fs.fsyncSync(fd);
      } catch {
        // Backup still exists with restrictive mode; fsync support varies by filesystem.
      }
    } finally {
      fs.closeSync(fd);
    }
    chmodIfSupported(backupPath, PRIVATE_FILE_MODE);
    this.db
      .prepare(
        `
        INSERT INTO backups (backup_id, source_path, server_id, server_name, config_root_key, backup_path, sha256, created_at)
        VALUES (@backupId, @sourcePath, @serverId, @serverName, @configRootKey, @backupPath, @sha256, @createdAt)
      `,
      )
      .run({
        backupId,
        sourcePath: input.sourcePath,
        serverId: input.serverId,
        serverName: input.serverName,
        configRootKey: input.configRootKey,
        backupPath,
        sha256,
        createdAt,
      });

    return {
      backupId,
      sourcePath: input.sourcePath,
      serverId: input.serverId,
      serverName: input.serverName,
      configRootKey: input.configRootKey,
      backupPath,
      sha256,
      createdAt,
    };
  }

  getBackup(backupId: string): BackupRecord | undefined {
    const row = this.db
      .prepare(
        `
        SELECT backup_id, source_path, server_id, server_name, config_root_key, backup_path, sha256, created_at
        FROM backups
        WHERE backup_id = ?
      `,
      )
      .get(backupId) as Record<string, string> | undefined;

    if (!row) return undefined;
    return {
      backupId: row.backup_id,
      sourcePath: row.source_path,
      serverId: row.server_id,
      serverName: row.server_name,
      configRootKey: row.config_root_key,
      backupPath: row.backup_path,
      sha256: row.sha256,
      createdAt: row.created_at,
    };
  }

  getLatestBackupForServer(serverId: string): BackupRecord | undefined {
    const row = this.db
      .prepare(
        `
        SELECT backup_id, source_path, server_id, server_name, config_root_key, backup_path, sha256, created_at
        FROM backups
        WHERE server_id = ?
        ORDER BY created_at DESC
        LIMIT 1
      `,
      )
      .get(serverId) as Record<string, string> | undefined;

    return row ? this.getBackup(row.backup_id) : undefined;
  }

  readBackupConfig(backupId: string): unknown {
    const backup = this.getBackup(backupId);
    if (!backup) {
      throw new Error(`Backup ${backupId} not found`);
    }

    const content = fs.readFileSync(backup.backupPath, 'utf8');
    const actualSha = sha256Hex(content);
    if (actualSha !== backup.sha256) {
      throw new Error(`Backup ${backupId} checksum mismatch`);
    }

    return JSON.parse(content);
  }

  readServerConfigFromBackup(backupId: string): McpServerDefinition {
    const backup = this.getBackup(backupId);
    if (!backup) {
      throw new Error(`Backup ${backupId} not found`);
    }

    const json = this.readBackupConfig(backupId);
    const root = getRoot(json, backup.configRootKey);
    const entry = root[backup.serverName];
    if (!entry || typeof entry !== 'object') {
      throw new Error(`Server ${backup.serverName} missing from backup ${backupId}`);
    }

    return entry as McpServerDefinition;
  }

  readLatestServerConfig(serverId: string): { backup: BackupRecord; config: McpServerDefinition } {
    const backup = this.getLatestBackupForServer(serverId);
    if (!backup) {
      throw new Error(`No backup registered for server ${serverId}`);
    }

    return {
      backup,
      config: this.readServerConfigFromBackup(backup.backupId),
    };
  }

  logAudit(input: {
    serverId: string;
    serverName: string;
    toolName: string;
    action: string;
    decision: string;
    risk: RiskLevel;
    request?: unknown;
    response?: unknown;
    responseSummary?: unknown;
    error?: string;
    sourcePath?: string;
  }): void {
    const responseSummary =
      input.responseSummary ?? (input.response === undefined ? undefined : summarizeToolResponse(input.response));

    this.db
      .prepare(
        `
        INSERT INTO audit_logs (
          created_at,
          server_id,
          server_name,
          tool_name,
          action,
          decision,
          risk_level,
          request_json,
          response_summary_json,
          error,
          source_path
        )
        VALUES (@createdAt, @serverId, @serverName, @toolName, @action, @decision, @risk, @requestJson, @responseSummaryJson, @error, @sourcePath)
      `,
      )
      .run({
        createdAt: nowIso(),
        serverId: input.serverId,
        serverName: input.serverName,
        toolName: input.toolName,
        action: input.action,
        decision: input.decision,
        risk: input.risk,
        requestJson:
          input.request === undefined
            ? null
            : this.getAuditDetailLevel() === 'redacted-preview'
              ? cappedRedactedJson(input.request)
              : summarizeRequestMinimal(input.request),
        responseSummaryJson: responseSummary === undefined ? null : cappedRedactedJson(responseSummary, 1_000),
        error: input.error ?? null,
        sourcePath: input.sourcePath ?? null,
      });
  }

  listAuditLogs(limit = 200): AuditLogRecord[] {
    const rows = this.db
      .prepare(
        `
        SELECT id, created_at, server_id, server_name, tool_name, action, decision, risk_level, request_json, response_summary_json, error, source_path
        FROM audit_logs
        ORDER BY id DESC
        LIMIT ?
      `,
      )
      .all(limit) as Array<Record<string, string | number | null>>;

    return rows.map((row) => ({
      id: Number(row.id),
      createdAt: String(row.created_at),
      serverId: String(row.server_id),
      serverName: String(row.server_name),
      toolName: String(row.tool_name),
      action: String(row.action),
      decision: String(row.decision),
      risk: toRiskLevel(String(row.risk_level)),
      requestJson: row.request_json ? String(row.request_json) : undefined,
      responseSummaryJson: row.response_summary_json ? String(row.response_summary_json) : undefined,
      error: row.error ? String(row.error) : undefined,
      sourcePath: row.source_path ? String(row.source_path) : undefined,
    }));
  }

  createPendingApproval(input: {
    serverId: string;
    serverName: string;
    toolName: string;
    risk: RiskLevel;
    args: unknown;
    timeoutMs: number;
  }): PendingApprovalRecord {
    const createdAt = nowIso();
    const expiresAt = new Date(Date.now() + input.timeoutMs).toISOString();
    const argsJson = cappedRedactedJson(input.args);
    const result = this.db
      .prepare(
        `
        INSERT INTO pending_approvals (
          created_at,
          expires_at,
          server_id,
          server_name,
          tool_name,
          risk_level,
          args_json,
          status
        )
        VALUES (@createdAt, @expiresAt, @serverId, @serverName, @toolName, @risk, @argsJson, 'pending')
      `,
      )
      .run({
        createdAt,
        expiresAt,
        serverId: input.serverId,
        serverName: input.serverName,
        toolName: input.toolName,
        risk: input.risk,
        argsJson,
      });

    return {
      id: Number(result.lastInsertRowid),
      createdAt,
      expiresAt,
      serverId: input.serverId,
      serverName: input.serverName,
      toolName: input.toolName,
      risk: input.risk,
      argsJson,
      status: 'pending',
    };
  }

  listPendingApprovals(includeResolved = false): PendingApprovalRecord[] {
    this.expireStaleApprovals();
    const rows = this.db
      .prepare(
        `
        SELECT id, created_at, expires_at, server_id, server_name, tool_name, risk_level, args_json, status, reason
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
      serverId: String(row.server_id),
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
        SELECT id, created_at, expires_at, server_id, server_name, tool_name, risk_level, args_json, status, reason
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
      serverId: String(row.server_id),
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
