import React, { useState, useEffect } from 'react';
import { 
  Database, 
  CloudLightning, 
  RefreshCw, 
  CheckCircle2, 
  XCircle, 
  Key, 
  Globe,
  HelpCircle
} from 'lucide-react';

interface SettingsProps {
  onRefresh: () => void;
}

export default function Settings({ onRefresh }: SettingsProps) {
  const [workerUrl, setWorkerUrl] = useState('');
  const [token, setToken] = useState('');
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [syncStatus, setSyncStatus] = useState<any>({
    isSyncing: false,
    lastSyncedAt: '',
    lastError: null,
    lastSyncSuccess: false
  });

  // Load settings on mount
  useEffect(() => {
    const loadSettings = async () => {
      try {
        const settings = await window.electronAPI.settings.getSyncSettings();
        if (settings) {
          setWorkerUrl(settings.workerUrl || '');
          setToken(settings.token || '');
        }

        const status = await window.electronAPI.sync.getStatus();
        setSyncStatus(status);
      } catch (err) {
        console.error('Failed to load settings:', err);
      }
    };

    loadSettings();

    // Listen to live sync status changes
    const unsubscribeSync = window.electronAPI.sync.onStatusChanged((status: any) => {
      setSyncStatus(status);
      if (status.lastSyncSuccess) {
        onRefresh();
      }
    });

    return () => {
      unsubscribeSync();
    };
  }, []);

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaveSuccess(false);

    try {
      await window.electronAPI.settings.saveSyncSettings({
        workerUrl: workerUrl.trim(),
        token: token.trim(),
        lastSyncedAt: syncStatus.lastSyncedAt // Preserve sync history
      });

      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);

      // Trigger a sync check/run immediately
      await window.electronAPI.sync.syncNow();
    } catch (err) {
      console.error('Failed to save settings:', err);
      await window.electronAPI.dialog.alert('Failed to save sync settings.');
    }
  };

  const handleManualSync = async () => {
    if (syncStatus.isSyncing) return;
    if (!workerUrl || !token) {
      await window.electronAPI.dialog.alert('Please configure and save your Worker URL and Token first.', 'warning');
      return;
    }

    try {
      const res = await window.electronAPI.sync.syncNow();
      setSyncStatus(res);
      onRefresh();
    } catch (err) {
      console.error('Manual sync failed:', err);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h2 className="text-2xl font-bold tracking-tight text-white">Database & Cloud Synchronization</h2>
        <p className="text-gray-400 text-sm mt-1">Configure and manage cloud backup and replication parameters for D1 database integration.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        
        {/* Left Column: Config Forms */}
        <div className="md:col-span-2 space-y-6">
          <div className="glass-card p-6 space-y-4">
            <h3 className="text-lg font-bold text-white flex items-center space-x-2 pb-2 border-b border-dark-border">
              <Database className="w-5 h-5 text-cyber-cyan" />
              <span>Cloudflare Worker Configuration</span>
            </h3>

            <form onSubmit={handleSaveSettings} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs text-gray-400 font-semibold uppercase tracking-wider flex items-center justify-between">
                  <span>Worker Proxy Endpoint URL</span>
                  <Globe className="w-3.5 h-3.5 text-gray-500" />
                </label>
                <input
                  type="url"
                  value={workerUrl}
                  onChange={(e) => setWorkerUrl(e.target.value)}
                  placeholder="https://dragon-api-gateway.your-subdomain.workers.dev"
                  className="input-cyber"
                  required
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs text-gray-400 font-semibold uppercase tracking-wider flex items-center justify-between">
                  <span>API Bearer Token</span>
                  <Key className="w-3.5 h-3.5 text-gray-500" />
                </label>
                <input
                  type="password"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  placeholder="••••••••••••••••••••••••••••••••"
                  className="input-cyber font-mono"
                  required
                />
              </div>

              <div className="flex items-center justify-between pt-2">
                <button
                  type="submit"
                  className="btn-cyber-cyan flex items-center space-x-2"
                >
                  <span>Save settings</span>
                </button>

                {saveSuccess && (
                  <span className="text-xs text-cyber-emerald font-semibold flex items-center space-x-1.5">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Settings Saved Successfully!</span>
                  </span>
                )}
              </div>
            </form>
          </div>

          {/* Sync Status/Logger panel */}
          <div className="glass-card p-6 space-y-4">
            <h3 className="text-lg font-bold text-white flex items-center justify-between pb-2 border-b border-dark-border">
              <span className="flex items-center space-x-2">
                <CloudLightning className="w-5 h-5 text-cyber-cyan" />
                <span>Replication Status & Actions</span>
              </span>
              
              <button
                onClick={handleManualSync}
                disabled={syncStatus.isSyncing}
                className={`btn-cyber-cyan text-xs py-1.5 px-3 flex items-center space-x-2 ${
                  syncStatus.isSyncing ? 'opacity-50 cursor-not-allowed' : ''
                }`}
              >
                <RefreshCw className={`w-3.5 h-3.5 ${syncStatus.isSyncing ? 'animate-spin' : ''}`} />
                <span>{syncStatus.isSyncing ? 'Syncing...' : 'Sync Now'}</span>
              </button>
            </h3>

            <div className="grid grid-cols-2 gap-4">
              <div className="p-4 bg-dark-surface/50 border border-dark-border rounded-lg space-y-1">
                <span className="block text-[10px] text-gray-500 font-bold uppercase tracking-wider">Sync State</span>
                <span className="font-semibold text-sm flex items-center space-x-2 mt-1">
                  <span className={`w-2.5 h-2.5 rounded-full ${
                    syncStatus.isSyncing 
                      ? 'bg-cyber-cyan animate-pulse' 
                      : syncStatus.lastError 
                        ? 'bg-cyber-rose' 
                        : syncStatus.lastSyncedAt 
                          ? 'bg-cyber-emerald' 
                          : 'bg-gray-600'
                  }`} />
                  <span className="text-white">
                    {syncStatus.isSyncing 
                      ? 'Synchronizing...' 
                      : syncStatus.lastError 
                        ? 'Error / Offline' 
                        : syncStatus.lastSyncedAt 
                          ? 'Operational (Synced)' 
                          : 'Offline (Not configured)'}
                  </span>
                </span>
              </div>

              <div className="p-4 bg-dark-surface/50 border border-dark-border rounded-lg space-y-1">
                <span className="block text-[10px] text-gray-500 font-bold uppercase tracking-wider">Last Sync Occurrence</span>
                <span className="font-semibold text-sm text-white block mt-1">
                  {syncStatus.lastSyncedAt 
                    ? new Date(syncStatus.lastSyncedAt).toLocaleString() 
                    : 'Never Synced'}
                </span>
              </div>
            </div>

            {syncStatus.lastError && (
              <div className="p-4 bg-cyber-rose/10 border border-cyber-rose/30 text-cyber-rose rounded-lg space-y-1.5">
                <div className="flex items-center space-x-2 text-xs font-bold uppercase tracking-wider">
                  <XCircle className="w-4 h-4" />
                  <span>Connection / Sync Failure Details</span>
                </div>
                <p className="text-xs font-medium pl-6">{syncStatus.lastError}</p>
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Integration Documentation */}
        <div className="md:col-span-1">
          <div className="glass-card p-6 space-y-4 h-full text-xs">
            <h3 className="text-sm font-bold text-white flex items-center space-x-2 pb-2 border-b border-dark-border">
              <HelpCircle className="w-4.5 h-4.5 text-cyber-cyan" />
              <span>Hybrid Sync Model Help</span>
            </h3>

            <div className="space-y-3 text-gray-400 leading-relaxed">
              <p>
                Dragon operates on an <strong>Offline-First / Hybrid Sync</strong> architecture. 
                All scan reports, assets, finding modifications, and team assignments are committed locally to your encrypted JSON storage first.
              </p>
              <p>
                When online and configured with a <strong>Cloudflare Worker Proxy</strong>, the app will replicate local insertions, updates, and deletion tracking arrays securely in batches.
              </p>
              <p className="text-[10px] border-t border-dark-border/50 pt-3">
                <strong>Deployment tip:</strong> Use Wrangler to deploy <code>api-worker</code> and link a Cloudflare D1 database. Set the <code>API_TOKEN</code> secret in Wrangler to secure your proxy endpoint.
              </p>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
