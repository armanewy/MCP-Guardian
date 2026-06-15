# MCP Guardian Private Alpha Guide

MCP Guardian is ready for a tiny private alpha with technical users who understand that it is not an OS sandbox. Treat it as a local visibility, guarded-proxy, approval, audit, and restore experiment.

## Safe Test Setup

- Start with fake or disposable MCP servers.
- Avoid production tokens, production databases, and full home-directory filesystem servers.
- Use throwaway repositories and throwaway API keys when testing GitHub or messaging MCP servers.
- Run `npm run dogfood:fake-server`, `npm run build`, `npm run dogfood:fake-server:built`, and `npm run smoke:electron` before real MCP testing.
- Keep minimal audit mode enabled unless you are deliberately debugging audit previews.

## Disposable Server Flow

1. Add a fake MCP JSON config through the Config Sources file picker.
2. Rescan and confirm the server appears.
3. Use **Guard with proxy** on the fake server.
4. Block a destructive tool such as `delete_file`.
5. Trigger a write-like tool and approve it once.
6. Confirm audit entries show decisions without request or response values in minimal mode.
7. Restore the server and verify the original config returns.

## What To Send If Something Breaks

- OS and MCP client.
- The MCP config path.
- The server name and whether it was active, disabled, or guarded with proxy.
- The visible error message.
- The relevant audit decision names.
- The backup ID and backup path.

Do not send production tokens, full backup files, or private tool arguments in public issues. Use private vulnerability reporting for security-sensitive failures.

## Manual Restore

1. Open the Backups screen.
2. Check that the backup is `verified`.
3. Export the backup before deleting or editing anything.
4. Open the source MCP config.
5. Copy the original server entry from the backup JSON back into the source config.
6. Restart the MCP client.

If the app cannot start, use `~/.mcp-guardian/mcp-guardian.sqlite` to find the backup row and restore from the `backup_path` manually.

## Demo Outline

Use [DEMO.md](DEMO.md) for the full 60-90 second private-alpha demo script. The short flow is:

1. Scan local MCP config sources.
2. Select a high-risk fake server.
3. Guard it with proxy.
4. Block `delete_file`.
5. Trigger and approve `write_file`.
6. Show the minimal audit entry.
7. Open the backup inventory and restore the original config.
