import { contextBridge, ipcRenderer } from 'electron';
import type { DashboardSnapshot, PolicyAction, ServerMode } from '../shared/types';

const api = {
  getSnapshot: (): Promise<DashboardSnapshot> => ipcRenderer.invoke('guardian:snapshot'),
  setPolicy: (input: {
    serverId: string;
    toolName: string;
    action: PolicyAction;
  }): Promise<DashboardSnapshot> => ipcRenderer.invoke('guardian:set-policy', input),
  deletePolicy: (input: { serverId: string; toolName: string }): Promise<DashboardSnapshot> =>
    ipcRenderer.invoke('guardian:delete-policy', input),
  resolveApproval: (input: {
    id: number;
    decision: 'approved' | 'denied';
    reason?: string;
  }): Promise<DashboardSnapshot> => ipcRenderer.invoke('guardian:resolve-approval', input),
  applyMode: (input: {
    serverId: string;
    mode: ServerMode;
  }): Promise<{
    result: { backupPath: string; sourcePath: string; serverId: string; serverName: string; mode: ServerMode };
    snapshot: DashboardSnapshot;
  }> => ipcRenderer.invoke('guardian:apply-mode', input),
};

contextBridge.exposeInMainWorld('guardian', api);

export type GuardianApi = typeof api;
