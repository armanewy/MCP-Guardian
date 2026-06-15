# Security Audit Triage

Last local triage: 2026-06-15.

Command:

```bash
npm audit --json
```

Result summary:

```text
3 high severity findings
0 critical findings
```

## Findings

| Package | Introduced Via | Runtime? | Reachable From Untrusted Input? | Fix Available | Breaking? | Decision |
| --- | --- | --- | --- | --- | --- | --- |
| `esbuild` | direct dev dependency; also via `vite` | No, build/dev tooling only | Not in packaged runtime; dev server exposure only during local development | `esbuild@0.28.1` | Yes for current toolchain compatibility | Track; do not force-upgrade blindly |
| `vite` | direct dev dependency | No, renderer build/dev tooling only | Dev server only; app runtime loads built assets | `vite@8.0.16` | Yes; incompatible with current `electron-vite@5` peer range | Track until `electron-vite` supports Vite 8 |
| `electron-vite` | direct dev dependency | No, build/dev launcher only | No packaged runtime exposure identified | Downgrade to `electron-vite@1.0.20` | Yes and regressive | Do not downgrade; track upstream |

## Notes

- The reported chain is build/dev-server related, not part of the Guardian proxy runtime or Electron renderer runtime after build.
- The current app should not expose the Vite dev server during real dogfooding.
- `npm audit fix --force` would perform major-version changes or downgrade tooling and may break the Electron/Vite build.

## Follow-Up

- Re-check after `electron-vite` publishes compatibility with a Vite/esbuild chain that clears these advisories.
- Keep CI on `npm ci` with pinned versions so drift is explicit.
- Revisit before any public release.
