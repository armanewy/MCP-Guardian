import { app, BrowserWindow, ipcMain, shell } from 'electron';
import Store from 'electron-store';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { GuardianDatabase, getDefaultDatabasePath } from '../node/database';
import { rewriteServerMode } from '../node/rewrite';
import { scanDashboard } from '../node/scan';
import type { PolicyAction, ServerMode } from '../shared/types';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const preferences = new Store<{
  windowBounds?: { width: number; height: number };
}>({ name: 'preferences' });

let mainWindow: BrowserWindow | undefined;
let db: GuardianDatabase | undefined;

function getDb(): GuardianDatabase {
  db ??= new GuardianDatabase(getDefaultDatabasePath());
  return db;
}

function resolveProjectRoot(): string {
  const appPath = app.getAppPath();
  if (fs.existsSync(path.join(appPath, 'package.json'))) {
    return appPath;
  }
  return path.resolve(__dirname, '..', '..');
}

function cliLaunch(scriptName: 'proxy' | 'disabled'): { command: string; args: string[] } {
  const root = resolveProjectRoot();
  const built = path.join(root, 'out', 'cli', `${scriptName}.js`);
  if (fs.existsSync(built)) {
    return { command: 'node', args: [built] };
  }

  const source = path.join(root, 'src', 'cli', `${scriptName}.ts`);
  const tsxCli = path.join(root, 'node_modules', 'tsx', 'dist', 'cli.mjs');
  return { command: 'node', args: [tsxCli, source] };
}

async function createWindow(): Promise<void> {
  const bounds = preferences.get('windowBounds') ?? { width: 1280, height: 820 };
  mainWindow = new BrowserWindow({
    width: bounds.width,
    height: bounds.height,
    minWidth: 980,
    minHeight: 680,
    title: 'MCP Guardian',
    backgroundColor: '#f7f8fb',
    webPreferences: {
      preload: path.join(__dirname, '../preload/index.js'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false,
    },
  });

  mainWindow.on('resize', () => {
    if (!mainWindow) return;
    const [width, height] = mainWindow.getSize();
    preferences.set('windowBounds', { width, height });
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  if (process.env.ELECTRON_RENDERER_URL) {
    await mainWindow.loadURL(process.env.ELECTRON_RENDERER_URL);
  } else {
    await mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));
  }
}

function registerIpc(): void {
  ipcMain.handle('guardian:snapshot', async () => scanDashboard(getDb()));

  ipcMain.handle(
    'guardian:set-policy',
    async (_event, input: { serverId: string; toolName: string; action: PolicyAction }) => {
      const snapshot = await scanDashboard(getDb());
      const server = snapshot.servers.find((candidate) => candidate.serverId === input.serverId);
      const serverName =
        input.serverId === '*'
          ? undefined
          : server?.name ??
            snapshot.tools.find((tool) => tool.serverId === input.serverId)?.serverName ??
            undefined;
      getDb().setPolicy(input.serverId, serverName, input.toolName, input.action);
      return scanDashboard(getDb());
    },
  );

  ipcMain.handle(
    'guardian:delete-policy',
    async (_event, input: { serverId: string; toolName: string }) => {
      getDb().deletePolicy(input.serverId, input.toolName);
      return scanDashboard(getDb());
    },
  );

  ipcMain.handle(
    'guardian:resolve-approval',
    async (_event, input: { id: number; decision: 'approved' | 'denied'; reason?: string }) => {
      getDb().resolveApproval(input.id, input.decision, input.reason);
      return scanDashboard(getDb());
    },
  );

  ipcMain.handle(
    'guardian:apply-mode',
    async (
      _event,
      input: {
        serverId: string;
        mode: ServerMode;
      },
    ) => {
      const snapshot = await scanDashboard(getDb());
      const server = snapshot.servers.find((candidate) => candidate.serverId === input.serverId);
      if (!server) {
        throw new Error('Unknown or unavailable MCP server; rescan before applying mode changes');
      }

      const result = rewriteServerMode({
        sourcePath: server.source.path,
        serverId: server.serverId,
        serverName: server.name,
        configRootKey: server.configRootKey,
        mode: input.mode,
        expectedOriginalFingerprint: server.originalFingerprint,
        launch: {
          disabled: cliLaunch('disabled'),
          proxy: cliLaunch('proxy'),
        },
        db: getDb(),
      });
      return {
        result,
        snapshot: await scanDashboard(getDb()),
      };
    },
  );
}

app.whenReady().then(async () => {
  app.setName('MCP Guardian');
  registerIpc();
  await createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => {
  db?.close();
});
