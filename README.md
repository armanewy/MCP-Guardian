# MCP Guardian

[![CI](https://github.com/armanewy/MCP-Guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/armanewy/MCP-Guardian/actions/workflows/ci.yml)

MCP Guardian is a local-first Electron dashboard for inspecting and controlling MCP server access. It scans supported local MCP client configs, classifies server and tool risk, can disable or guard stdio MCP servers with a proxy, and keeps a local SQLite audit trail.

## What It Protects

- Discovers Claude Desktop-style, Cursor, VS Code, and Claude Code MCP config files.
- Shows installed MCP servers, inferred/observed tools, risk factors, policies, pending approvals, and audit events.
- Rewrites stdio MCP server config entries to a Guardian proxy for policy enforcement.
- Hides blocked tools from `tools/list`.
- Blocks or asks before sensitive `tools/call` requests.
- Stores backups before config rewrites and restores from the backup registry.
- Redacts secrets and defaults to minimal audit argument logging.

## What It Cannot Protect

- It is not an OS sandbox.
- It cannot stop side effects that happen when an MCP server starts.
- It does not inspect all network traffic.
- It does not sandbox arbitrary child processes.
- It does not make remote HTTP/SSE MCP servers safe.
- It does not replace enterprise policy management.

## Local Data

By default Guardian stores local data in:

```text
~/.mcp-guardian/
```

Backups are stored in:

```text
~/.mcp-guardian/backups/
```

On POSIX systems Guardian attempts to create those directories with `0700` permissions and backup files with `0600` permissions. On Windows, filesystem ACL behavior depends on the host filesystem and user profile configuration.

The SQLite database stores:

- policies keyed by stable `serverId`;
- observed tool inventory;
- pending approvals;
- backup registry metadata;
- audit events with minimal request summaries by default;
- response summaries, not full tool responses.

Minimal audit mode stores argument keys and byte-length estimates only. It does not store argument values or response text previews. `redacted-preview` is an opt-in debugging mode and should be treated as sensitive because it may store short redacted request and response previews.

## Manual Restore

If the app cannot start, restore manually:

1. Open `~/.mcp-guardian/mcp-guardian.sqlite`.
2. Find the relevant row in the `backups` table.
3. Verify the backup file at `backup_path` still hashes to `sha256`.
4. Copy the server entry from the backup JSON back into the original `source_path`.
5. Remove the rewritten `mcpGuardian` proxy entry for that server.

The backup file contains the whole config file as it existed before Guardian rewrote it.

## Emergency Disable Or Restore

To disable a problematic guarded server quickly, edit the MCP client config and remove that server entry or point it at the disabled Guardian shim.

To restore original behavior, copy the original server config from the registered backup file back into the MCP config. Then restart the MCP client.

## Development

```bash
npm ci
npm run typecheck
npm run lint
npm test
npm run build
npm run dogfood:fake-server:built
npm run smoke:electron
```

Use `npm run dev` to launch the Electron app during development.

For controlled private-alpha testing, use [PRIVATE_ALPHA.md](PRIVATE_ALPHA.md).

## Dogfood Harness

Run the fake dangerous MCP server harness before testing real servers. Passing this harness is required before real server dogfooding:

```bash
npm run dogfood:fake-server
```

The harness creates a temporary MCP config, guards a fake server with the proxy, verifies blocked calls are not forwarded, checks default sensitive tools require approval, exercises an approved call that forwards upstream, checks upstream env isolation, verifies minimal audit logs do not persist private request or response values, and restores the original config exactly.

After `npm run build`, run `npm run dogfood:fake-server:built` to exercise the compiled `out/cli/proxy.js` and `out/cli/disabled.js` runtime. Run `npm run smoke:electron` to launch the built Electron app in smoke-test mode and verify the renderer, snapshot IPC, and Safety screen.
