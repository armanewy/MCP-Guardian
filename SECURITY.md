# Security Notes

MCP Guardian is designed for local dogfooding and defense-in-depth around MCP configuration and stdio tool calls. It is not a full sandbox.

## Current Protections

- Stable server identity uses SHA-256 over normalized source path, config root, and server name.
- Config rewrites verify the original fingerprint before writing.
- Rewrites create registry-backed backups before changing config files.
- Config writes use a temp file and rename instead of direct writes to the original path.
- Backup directories are created with `0700` where supported.
- Backup files are written with `0600` where supported.
- Protected stdio servers are launched through a local MCP proxy.
- The proxy lazy-connects upstream servers only on first `tools/list` or `tools/call`.
- Upstream server environment is restricted to a minimal base env plus the original server config env.
- Request audit logging defaults to minimal metadata only.
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

The default audit detail level is `minimal`. It stores argument keys and byte-length estimates, not argument values. A future UI may expose `redacted-preview` mode for local debugging, but that mode should be treated as more sensitive.

Responses are always summarized with:

- content item count;
- content types;
- `isError`;
- byte-length estimate;
- first 200 redacted serialized characters.

Full tool responses are never intentionally stored.

## Backup Handling

Backup files may contain secrets because they preserve MCP configs. Treat `~/.mcp-guardian/backups` as sensitive local data.

Manual restore steps are documented in `README.md`.
