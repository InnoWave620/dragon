import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('electronAPI', {
  // Database API
  db: {
    getAssets: () => ipcRenderer.invoke('db:get-assets'),
    addAsset: (asset: any) => ipcRenderer.invoke('db:add-asset', asset),
    deleteAsset: (id: string) => ipcRenderer.invoke('db:delete-asset', id),
    getScans: () => ipcRenderer.invoke('db:get-scans'),
    getFindings: () => ipcRenderer.invoke('db:get-findings'),
    updateFinding: (finding: any) => ipcRenderer.invoke('db:update-finding', finding),
  },
  
  // Scanning Engine API
  scan: {
    startScan: (assetId: string, modules: string[]) => ipcRenderer.invoke('scan:start', assetId, modules),
    cancelScan: (scanId: string) => ipcRenderer.invoke('scan:cancel', scanId),
    onLog: (callback: (logLine: string) => void) => {
      const subscription = (_event: any, value: string) => callback(value);
      ipcRenderer.on('scan:log', subscription);
      return () => ipcRenderer.removeListener('scan:log', subscription);
    },
    onProgress: (callback: (scan: any) => void) => {
      const subscription = (_event: any, value: any) => callback(value);
      ipcRenderer.on('scan:progress', subscription);
      return () => ipcRenderer.removeListener('scan:progress', subscription);
    },
    onComplete: (callback: (scan: any) => void) => {
      const subscription = (_event: any, value: any) => callback(value);
      ipcRenderer.on('scan:complete', subscription);
      return () => ipcRenderer.removeListener('scan:complete', subscription);
    }
  },

  // Reporting API
  reports: {
    exportReport: (scanId: string, format: 'pdf' | 'html' | 'json' | 'csv', defaultPath: string) => 
      ipcRenderer.invoke('report:export', scanId, format, defaultPath),
    selectSavePath: (title: string, defaultName: string, filters: any[]) => 
      ipcRenderer.invoke('dialog:save-path', title, defaultName, filters)
  },

  // AI Assistant API
  ai: {
    chat: (message: string, contextFinding?: any) => ipcRenderer.invoke('ai:chat', message, contextFinding)
  }
});
