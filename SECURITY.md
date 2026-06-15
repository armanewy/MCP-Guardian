# Security Notes

MCP Guardian is designed for local dogfooding and defense-in-depth around MCP configuration and stdio tool calls. It is not a full sandbox.

## Supported Versions

| Version | Support |
| --- | --- |
| `main` / `0.1.x` private alpha | Security fixes accepted for local dogfooding only |

Do not use private-alpha builds as a production security boundary.

## Vulnerability Reporting

Please report suspected vulnerabilities privately before opening public issues or pull requests. Include:

- affected commit or release;
- operating system and MCP client config path;
- reproduction steps with a fake or disposable MCP server when possible;
- whether backups, audit logs, policy decisions, or rewritten config files exposed sensitive data.

Use GitHub private vulnerability reporting if it is enabled for the repository. If it is not enabled, contact the repository owner privately and avoid posting secrets, backup files, or exploit details in public trackers.

## Current Protections

- Stable server identity uses SHA-256 over normalized source path, config root, and server name.
- Config rewrites verify the original fingerprint before writing.
- Rewrites create registry-backed backups before changing config files.
- Config writes use a temp file and rename instead of direct writes to the original path.
- Backup directories are created with `0700` where supported.
- Backup files are written with `0600` where supported.
- Guarded stdio servers are launched through a local MCP proxy.
- The proxy lazy-connects upstream servers only on first `tools/list` or `tools/call`.
- Upstream server environment is restricted to a minimal base env plus the original server config env.
- Custom MCP config files are selected through the native file picker in normal use; renderer-supplied paths are accepted only in smoke/test mode.
- Backup inventory shows file existence, checksum status, and latest-per-server status.
- Backup deletion requires explicit confirmation for backups used by guarded/disabled servers, latest-per-server backups, missing files, or checksum mismatches.
- Request and response audit logging defaults to minimal metadata only.
- Tool responses are summarized and never stored in full.
- Electron renderer uses `nodeIntegration: false`, `contextIsolation: true`, and `sandbox: true`.

## Known Limits

- Startup side effects can still occur when the upstream MCP server is launched.
- A malicious MCP server can perform local side effects after launch if the allowed tool call reaches it.
- HTTP/SSE MCP proxying is not implemented in v0.1.
- Network traffic is not inspected.
- Operating system sandboxing is not implemented.
- Windows filesystem permission hardening depends on filesystem ACLs; POSIX mode bits are applied where supported.

## Audit Privacy

The default audit detail level is `minimal`. It stores argument keys and byte-length estimates, not argument values. Minimal mode also stores no response text preview; response summaries set `preview: null`.

`redacted-preview` mode is opt-in for local debugging and should be treated as sensitive. It may store short redacted request previews and the first 200 redacted serialized characters of response summaries.

Responses are always summarized with:

- content item count;
- content types;
- `isError`;
- byte-length estimate;
- `preview: null` in minimal mode;
- first 200 redacted serialized characters only in `redacted-preview` mode.

Full tool responses are never intentionally stored.

Run `npm run dogfood:fake-server` before pointing Guardian at real MCP servers. The fake server harness verifies default sensitive tools require approval, blocked calls are not forwarded, approved calls do forward, upstream environment handling stays minimal, audit logs omit private values in minimal mode, and restore remains exact.

## Backup Handling

Backup files may contain secrets because they preserve MCP configs. Treat `~/.mcp-guardian/backups` as sensitive local data.

Manual restore steps are documented in `README.md`.

## Dependency Audit

Current npm audit triage is tracked in `SECURITY_AUDIT.md`. Do not run `npm audit fix --force` without reviewing runtime impact and Electron/Vite compatibility.
