# MCP Guardian Demo Script

Use this for a 60-90 second private-alpha demo. Keep the narration concrete: this is a local MCP visibility and guarded-proxy experiment, not an OS sandbox.

## Preflight

- Run `npm run dogfood:fake-server`.
- Run `npm run build`.
- Run `npm run dogfood:fake-server:built`.
- Run `npm run smoke:electron`.
- Use a fake or disposable MCP config and avoid production credentials.

## Recording Flow

1. **0-10s: Scan**
   Open MCP Guardian and show discovered config sources and servers.
   Narration: “Guardian scans local MCP configs and classifies server/tool risk locally.”

2. **10-25s: Identify Risk**
   Select a high-risk fake server and show risk factors.
   Narration: “This server can expose local files and destructive tools, so I don’t want it running unguarded.”

3. **25-40s: Guard With Proxy**
   Click **Guard with proxy** and show the backup notice.
   Narration: “Guardian rewrites the stdio server to a local proxy and stores a restore backup.”

4. **40-55s: Block Destructive Tool**
   Set `delete_file` to `block`, trigger the fake call, and show the denied result.
   Narration: “Blocked calls return an MCP error result and are not forwarded upstream.”

5. **55-70s: Approve Write**
   Trigger a write-like call, approve it once, and show it forwards.
   Narration: “Sensitive tools require approval by default; one approved call is audited as `asked_allowed`.”

6. **70-82s: Minimal Audit**
   Open Audit and show a decision row.
   Narration: “Minimal audit mode stores metadata, not request values or response previews.”

7. **82-90s: Restore**
   Open Backups, show `verified` status, then restore the server.
   Narration: “Backups can be exported and used to restore the original config.”

## What Not To Show

- Production API tokens.
- Real private file contents.
- Full backup JSON from a real user profile.
- Redacted-preview audit mode unless the demo is specifically about debugging.
