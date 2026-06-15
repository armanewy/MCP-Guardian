import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const electronPath = require('electron') as string;
const electronVersion = String(require('electron/package.json').version);
const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-guardian-electron-smoke-'));
const npmCli = process.env.npm_execpath;

function rebuildNative(runtime: 'electron' | 'node', target: string): void {
  const command = npmCli ? process.execPath : process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const args = npmCli ? [npmCli, 'rebuild', 'better-sqlite3'] : ['rebuild', 'better-sqlite3'];
  const rebuildEnv = {
    ...process.env,
    npm_config_runtime: runtime,
    npm_config_target: target,
    npm_config_loglevel: 'error',
  };
  if (runtime === 'electron') {
    rebuildEnv.npm_config_disturl = 'https://electronjs.org/headers';
  } else {
    delete rebuildEnv.npm_config_disturl;
  }
  const result = spawnSync(command, args, {
    cwd: path.resolve(),
    env: rebuildEnv,
    stdio: 'inherit',
    windowsHide: true,
  });

  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`Failed to rebuild better-sqlite3 for ${runtime} ${target}`);
  }
}

rebuildNative('electron', electronVersion);

const env = {
  ...process.env,
  MCP_GUARDIAN_SMOKE_TEST: '1',
  MCP_GUARDIAN_HOME: path.join(tempRoot, '.mcp-guardian'),
  MCP_GUARDIAN_SCAN_CWD: '0',
  ELECTRON_DISABLE_SECURITY_WARNINGS: 'true',
};

const useXvfb = process.platform === 'linux' && !process.env.DISPLAY;
const command = useXvfb ? 'xvfb-run' : electronPath;
const args = useXvfb ? ['-a', electronPath, '.'] : ['.'];
const child = spawn(command, args, {
  cwd: path.resolve(),
  env,
  stdio: ['ignore', 'pipe', 'pipe'],
  windowsHide: true,
});

let stdout = '';
let stderr = '';
let completed = false;

const timeout = setTimeout(() => {
  if (completed) return;
  child.kill('SIGTERM');
  console.error('Electron smoke test timed out');
  console.error(stderr);
  rebuildNative('node', process.versions.node);
  process.exit(1);
}, 30_000);

child.stdout.setEncoding('utf8');
child.stderr.setEncoding('utf8');
child.stdout.on('data', (chunk: string) => {
  stdout += chunk;
  process.stdout.write(chunk);
});
child.stderr.on('data', (chunk: string) => {
  stderr += chunk;
  process.stderr.write(chunk);
});
child.on('error', (error) => {
  clearTimeout(timeout);
  completed = true;
  console.error(error);
  rebuildNative('node', process.versions.node);
  process.exit(1);
});
child.on('exit', (code) => {
  clearTimeout(timeout);
  completed = true;
  fs.rmSync(tempRoot, { recursive: true, force: true });
  rebuildNative('node', process.versions.node);
  if (code === 0 && stdout.includes('MCP_GUARDIAN_SMOKE_OK')) {
    process.exit(0);
  }

  console.error(`Electron smoke test failed with exit code ${code ?? 'unknown'}`);
  if (!stdout.includes('MCP_GUARDIAN_SMOKE_OK')) {
    console.error('Smoke success marker was not printed');
  }
  process.exit(1);
});
