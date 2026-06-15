import { app, BrowserWindow, dialog, ipcMain, shell } from 'electron';
import Store from 'electron-store';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { GuardianDatabase, getDefaultDatabasePath } from '../node/database';
import { rewriteServerMode } from '../node/rewrite';
import { scanDashboard } from '../node/scan';
import type { PolicyAction, ServerMode } from '../shared/types';
import type { OpenDialogOptions } from 'electron';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const preferences = new Store<{
  windowBounds?: { width: number; height: number };
}>({ name: 'preferences' });

let mainWindow: BrowserWindow | undefined;
let db: GuardianDatabase | undefined;
const isSmokeTest = process.env.MCP_GUARDIAN_SMOKE_TEST === '1';
const allowsRendererSuppliedPaths =
  isSmokeTest || process.env.NODE_ENV === 'test' || process.env.MCP_GUARDIAN_ALLOW_RENDERER_FILE_PATHS === '1';

if (isSmokeTest) {
  app.commandLine.appendSwitch('disable-gpu');
}

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

function preloadScriptPath(): string {
  const built = path.join(__dirname, '../preload/index.js');
  if (fs.existsSync(built)) {
    return built;
  }
  return path.join(__dirname, '../preload/index.mjs');
}

function backupDeletionWarnings(snapshot: Awaited<ReturnType<typeof scanDashboard>>, backupId: string): string[] {
  const backup = snapshot.backups.find((candidate) => candidate.backupId === backupId);
  if (!backup) {
    throw new Error(`Backup ${backupId} not found`);
  }

  const warnings: string[] = [];
  if (snapshot.servers.some((server) => server.guardian?.backupId === backupId)) {
    warnings.push('used by a currently protected or disabled server');
  }
  if (backup.latestForServer) {
    warnings.push('latest backup for this server');
  }
  if (backup.fileExists === false) {
    warnings.push('backup file is missing');
  } else if (backup.checksumMatches === false) {
    warnings.push('backup checksum does not match registry');
  }
  return warnings;
}

async function createWindow(): Promise<void> {
  const bounds = isSmokeTest ? { width: 1100, height: 760 } : preferences.get('windowBounds') ?? { width: 1280, height: 820 };
  mainWindow = new BrowserWindow({
    width: bounds.width,
    height: bounds.height,
    minWidth: 980,
    minHeight: 680,
    title: 'MCP Guardian',
    backgroundColor: '#f7f8fb',
    show: !isSmokeTest,
    webPreferences: {
      preload: preloadScriptPath(),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
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

async function runSmokeTest(): Promise<void> {
  if (!mainWindow) {
    throw new Error('Smoke test window was not created');
  }

  const timeout = setTimeout(() => {
    console.error('MCP_GUARDIAN_SMOKE_FAIL timed out');
    app.exit(1);
  }, 20_000);

  try {
    const result = await mainWindow.webContents.executeJavaScript(`
      (async () => {
        const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
        const waitFor = async (predicate, label) => {
          for (let attempt = 0; attempt < 120; attempt += 1) {
            if (predicate()) return;
            await sleep(50);
          }
          throw new Error(label + ' did not become ready');
        };

        await waitFor(() => window.guardian && window.guardian.getSnapshot, 'guardian preload API');
        await waitFor(() => document.body && document.body.innerText.includes('MCP Guardian'), 'renderer');

        const snapshot = await window.guardian.getSnapshot();
        if (!snapshot || !snapshot.generatedAt || !Array.isArray(snapshot.sources)) {
          throw new Error('guardian:snapshot returned an invalid payload');
        }

        await waitFor(
          () => Array.from(document.querySelectorAll('button')).some((button) =>
            button.textContent && button.textContent.includes('Safety')
          ),
          'Safety navigation'
        );
        const safetyButton = Array.from(document.querySelectorAll('button')).find((button) =>
          button.textContent && button.textContent.includes('Safety')
        );
        if (!safetyButton) {
          throw new Error('Safety navigation button was not rendered');
        }
        safetyButton.click();
        await waitFor(() => document.body.innerText.includes('Trust But Verify'), 'Safety screen');

        return { generatedAt: snapshot.generatedAt, sources: snapshot.sources.length, safetyRendered: true };
      })();
    `);
    clearTimeout(timeout);
    console.log(`MCP_GUARDIAN_SMOKE_OK ${JSON.stringify(result)}`);
    app.exit(0);
  } catch (error) {
    clearTimeout(timeout);
    console.error(`MCP_GUARDIAN_SMOKE_FAIL ${error instanceof Error ? error.stack : String(error)}`);
    app.exit(1);
  }
}

function registerIpc(): void {
  ipcMain.handle('guardian:snapshot', async () => scanDashboard(getDb()));

  ipcMain.handle('guardian:add-custom-source', async (_event, input?: { filePath?: string }) => {
    let filePath = input?.filePath;
    if (filePath && !allowsRendererSuppliedPaths) {
      throw new Error('Renderer-supplied custom source paths are only allowed in smoke/test mode. Use the file picker.');
    }
    if (!filePath) {
      const dialogOptions: OpenDialogOptions = {
        title: 'Select MCP JSON config',
        properties: ['openFile'],
        filters: [{ name: 'JSON config', extensions: ['json'] }],
      };
      const result = mainWindow
        ? await dialog.showOpenDialog(mainWindow, dialogOptions)
        : await dialog.showOpenDialog(dialogOptions);
      if (result.canceled || result.filePaths.length === 0) {
        return scanDashboard(getDb());
      }
      filePath = result.filePaths[0];
    }

    getDb().addCustomConfigSource(filePath);
    return scanDashboard(getDb());
  });

  ipcMain.handle('guardian:remove-custom-source', async (_event, input: { id: string }) => {
    getDb().removeCustomConfigSource(input.id);
    return scanDashboard(getDb());
  });

  ipcMain.handle('guardian:open-backup-folder', async () => shell.openPath(getDb().backupDir));

  ipcMain.handle('guardian:export-backup', async (_event, input: { backupId: string }) => {
    const backup = getDb().listBackups().find((candidate) => candidate.backupId === input.backupId);
    if (!backup) {
      throw new Error(`Backup ${input.backupId} not found`);
    }
    if (!backup.fileExists) {
      throw new Error('Backup file is missing and cannot be exported.');
    }

    const dialogOptions = {
      title: 'Export MCP Guardian backup',
      defaultPath: path.basename(backup.backupPath),
      filters: [{ name: 'JSON backup', extensions: ['json'] }],
    };
    const result = mainWindow
      ? await dialog.showSaveDialog(mainWindow, dialogOptions)
      : await dialog.showSaveDialog(dialogOptions);
    if (result.canceled || !result.filePath) {
      return '';
    }

    fs.copyFileSync(backup.backupPath, result.filePath);
    return result.filePath;
  });

  ipcMain.handle('guardian:delete-backup', async (_event, input: { backupId: string; confirmed?: boolean }) => {
    const snapshot = await scanDashboard(getDb());
    const warnings = backupDeletionWarnings(snapshot, input.backupId);
    if (warnings.length > 0 && !input.confirmed) {
      throw new Error(`Backup requires confirmation before delete: ${warnings.join(', ')}.`);
    }

    getDb().deleteBackup(input.backupId);
    return scanDashboard(getDb());
  });

  ipcMain.handle('guardian:delete-old-backups', async (_event, input: { days: number }) => {
    const days = Number(input.days);
    if (!Number.isFinite(days) || days < 1) {
      throw new Error('Backup age must be at least 1 day');
    }

    const snapshot = await scanDashboard(getDb());
    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
    let deletedCount = 0;
    let skippedCount = 0;

    for (const backup of snapshot.backups) {
      if (new Date(backup.createdAt).getTime() >= cutoff) {
        continue;
      }

      const warnings = backupDeletionWarnings(snapshot, backup.backupId);
      if (warnings.length > 0) {
        skippedCount += 1;
        continue;
      }

      try {
        getDb().deleteBackup(backup.backupId);
        deletedCount += 1;
      } catch {
        skippedCount += 1;
      }
    }

    return {
      snapshot: await scanDashboard(getDb()),
      deletedCount,
      skippedCount,
    };
  });

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

  if (isSmokeTest) {
    await runSmokeTest();
    return;
  }

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
