import { BrowserWindow } from 'electron';
import { dbService } from './db';

export interface SyncStatus {
  isSyncing: boolean;
  lastSyncedAt?: string;
  lastError?: string | null;
  lastSyncSuccess?: boolean;
}

class SyncManager {
  private syncInterval: NodeJS.Timeout | null = null;
  private isSyncing = false;
  private lastError: string | null = null;
  private lastSyncSuccess = false;

  constructor() {
    // Start background sync interval
    this.startAutoSync();
  }

  private sendStatusToRenderer() {
    const settings = dbService.getSyncSettings();
    const status: SyncStatus = {
      isSyncing: this.isSyncing,
      lastSyncedAt: settings.lastSyncedAt,
      lastError: this.lastError,
      lastSyncSuccess: this.lastSyncSuccess
    };
    
    const windows = BrowserWindow.getAllWindows();
    for (const win of windows) {
      if (!win.isDestroyed()) {
        win.webContents.send('sync:status-changed', status);
      }
    }
  }

  getSyncStatus(): SyncStatus {
    const settings = dbService.getSyncSettings();
    return {
      isSyncing: this.isSyncing,
      lastSyncedAt: settings.lastSyncedAt,
      lastError: this.lastError,
      lastSyncSuccess: this.lastSyncSuccess
    };
  }

  startAutoSync() {
    if (this.syncInterval) clearInterval(this.syncInterval);
    // Poll every 60 seconds
    this.syncInterval = setInterval(() => {
      this.sync().catch(err => console.error('Background sync failed:', err));
    }, 60000);
  }

  stopAutoSync() {
    if (this.syncInterval) {
      clearInterval(this.syncInterval);
      this.syncInterval = null;
    }
  }

  async sync(): Promise<SyncStatus> {
    if (this.isSyncing) {
      return this.getSyncStatus();
    }

    const settings = dbService.getSyncSettings();
    if (!settings.workerUrl || !settings.token) {
      // Not configured, skip silently
      return this.getSyncStatus();
    }

    this.isSyncing = true;
    this.lastError = null;
    this.sendStatusToRenderer();

    const syncStartTime = new Date().toISOString();
    // Default to epoch if never synced
    const lastSyncedAt = settings.lastSyncedAt || '1970-01-01T00:00:00.000Z';

    try {
      const data = dbService.getRawData();

      // Filter local updates
      const updatedAssets = data.assets.filter(a => a.updatedAt > lastSyncedAt);
      const updatedScans = data.scans.filter(s => s.updatedAt > lastSyncedAt);
      const updatedFindings = data.findings.filter(f => (f.updatedAt || f.createdAt) > lastSyncedAt);
      const updatedDevelopers = data.developers.filter(d => d.updatedAt > lastSyncedAt);
      
      // Get all deleted items recorded in log
      const deletedItems = dbService.getDeletedItems();

      // Only perform network request if there is something to sync
      if (
        updatedAssets.length > 0 ||
        updatedScans.length > 0 ||
        updatedFindings.length > 0 ||
        updatedDevelopers.length > 0 ||
        deletedItems.length > 0
      ) {
        const payload = {
          assets: updatedAssets,
          scans: updatedScans,
          findings: updatedFindings,
          developers: updatedDevelopers,
          deleted: deletedItems.map(d => ({ table: d.table, id: d.id }))
        };

        const targetUrl = settings.workerUrl.replace(/\/$/, '') + '/api/sync';
        
        console.log(`[*] Syncing data to ${targetUrl}...`);
        console.log(`    - Assets: ${updatedAssets.length}`);
        console.log(`    - Scans: ${updatedScans.length}`);
        console.log(`    - Findings: ${updatedFindings.length}`);
        console.log(`    - Developers: ${updatedDevelopers.length}`);
        console.log(`    - Deleted items: ${deletedItems.length}`);

        const response = await fetch(targetUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${settings.token}`
          },
          body: JSON.stringify(payload)
        });

        if (!response.ok) {
          let errMsg = `Server returned status ${response.status}`;
          try {
            const errBody = await response.json() as any;
            if (errBody && errBody.error) {
              errMsg = errBody.error;
            }
          } catch (_) {}
          throw new Error(errMsg);
        }

        // Sync succeeded! Clear deletion logs up to syncStartTime
        dbService.clearDeletedItems(syncStartTime);
      }

      // Update sync time
      dbService.saveSyncSettings({
        ...settings,
        lastSyncedAt: syncStartTime
      });

      this.lastSyncSuccess = true;
      this.lastError = null;
    } catch (err: any) {
      console.error('[!] Sync Error:', err.message);
      this.lastSyncSuccess = false;
      this.lastError = err.message || 'Failed to connect to sync server';
    } finally {
      this.isSyncing = false;
      this.sendStatusToRenderer();
    }

    return this.getSyncStatus();
  }
}

export const syncManager = new SyncManager();
