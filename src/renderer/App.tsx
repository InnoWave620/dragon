import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  LayoutDashboard, 
  FolderGit2, 
  Play, 
  AlertTriangle, 
  FileDown, 
  MessageSquareCode, 
  Moon, 
  Sun,
  Activity
} from 'lucide-react';

// Import views
import Dashboard from './components/Dashboard';
import AssetManager from './components/AssetManager';
import ScanWizard from './components/ScanWizard';
import VulnerabilityExplorer from './components/VulnerabilityExplorer';
import ReportCenter from './components/ReportCenter';
import AIAssistant from './components/AIAssistant';

// Extend window interface for Electron API exposed by preload
declare global {
  interface Window {
    electronAPI: {
      db: {
        getAssets: () => Promise<any[]>;
        addAsset: (asset: any) => Promise<any>;
        deleteAsset: (id: string) => Promise<boolean>;
        getScans: () => Promise<any[]>;
        getFindings: () => Promise<any[]>;
        updateFinding: (finding: any) => Promise<any>;
        deleteFinding: (id: string) => Promise<boolean>;
        clearFindings: () => Promise<void>;
      };
      scan: {
        startScan: (assetId: string, modules: string[]) => Promise<{ success: boolean; scanId: string; error?: string }>;
        cancelScan: (scanId: string) => Promise<boolean>;
        onLog: (callback: (logLine: string) => void) => () => void;
        onProgress: (callback: (scan: any) => void) => () => void;
        onComplete: (callback: (scan: any) => void) => () => void;
      };
      reports: {
        exportReport: (scanId: string, format: string, filePath: string, reportType?: 'audit' | 'compliance') => Promise<boolean>;
        selectSavePath: (title: string, defaultName: string, filters: any[]) => Promise<string | null>;
      };
      ai: {
        chat: (message: string, contextFinding?: any) => Promise<{ answer: string; codeSnippet?: string; language?: string }>;
      };
    };
  }
}

type TabType = 'dashboard' | 'assets' | 'scan' | 'findings' | 'reports' | 'ai';

export default function App() {
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [isDarkMode, setIsDarkMode] = useState(true);
  const [assets, setAssets] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [activeScan, setActiveScan] = useState<any>(null);

  // Fetch initial data from SQLite/JSON db service via Electron IPC
  const refreshData = async () => {
    try {
      const dbAssets = await window.electronAPI.db.getAssets();
      const dbScans = await window.electronAPI.db.getScans();
      const dbFindings = await window.electronAPI.db.getFindings();
      
      setAssets(dbAssets);
      setScans(dbScans);
      setFindings(dbFindings);

      // Check if any scan is running currently
      const running = dbScans.find(s => s.status === 'running');
      if (running) {
        setActiveScan(running);
      } else {
        setActiveScan(null);
      }
    } catch (e) {
      console.error('Failed to load database values:', e);
    }
  };

  useEffect(() => {
    refreshData();
    // Refresh database variables every 5 seconds
    const interval = setInterval(refreshData, 5000);
    return () => clearInterval(interval);
  }, []);

  // Listen to active scan updates in background
  useEffect(() => {
    const unsubscribeProgress = window.electronAPI.scan.onProgress((updatedScan: any) => {
      setActiveScan(updatedScan);
      setScans(prev => prev.map(s => s.id === updatedScan.id ? updatedScan : s));
    });

    const unsubscribeComplete = window.electronAPI.scan.onComplete((completedScan: any) => {
      setActiveScan(null);
      refreshData();
    });

    return () => {
      unsubscribeProgress();
      unsubscribeComplete();
    };
  }, []);

  // Compute stats
  const totalFindings = findings.length;
  const openFindings = findings.filter(f => f.status === 'open');
  const criticalCount = openFindings.filter(f => f.severity === 'critical').length;
  const highCount = openFindings.filter(f => f.severity === 'high').length;
  const mediumCount = openFindings.filter(f => f.severity === 'medium').length;

  // Simple Risk Score Formulation
  // Critical = 10, High = 7, Medium = 4, Low = 1
  const riskIndex = Math.min(100, Math.floor(
    (criticalCount * 25 + highCount * 12 + mediumCount * 5 + openFindings.filter(f => f.severity === 'low').length * 1)
  ));

  const toggleDarkMode = () => {
    setIsDarkMode(!isDarkMode);
    const html = document.documentElement;
    if (isDarkMode) {
      html.classList.remove('dark');
    } else {
      html.classList.add('dark');
    }
  };

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'assets', label: 'Asset Manager', icon: FolderGit2 },
    { id: 'scan', label: 'Scan Wizard', icon: Play },
    { id: 'findings', label: 'Vulnerability Explorer', icon: AlertTriangle, count: openFindings.length },
    { id: 'reports', label: 'Report Center', icon: FileDown },
    { id: 'ai', label: 'AI Remediation', icon: MessageSquareCode },
  ];

  return (
    <div className="flex h-screen overflow-hidden bg-dark-bg text-gray-200">
      
      {/* SIDEBAR */}
      <aside className="w-64 bg-dark-surface border-r border-dark-border flex flex-col justify-between shrink-0">
        <div>
          {/* Logo Area */}
          <div className="p-6 flex items-center space-x-3 border-b border-dark-border">
            <div className="p-2 bg-cyber-cyan/10 border border-cyber-cyan/40 rounded-lg text-cyber-cyan shadow-glow-cyan">
              <Shield className="w-6 h-6 animate-pulse-subtle" />
            </div>
            <div>
              <h1 className="font-extrabold text-lg tracking-wider text-white">DRAGON</h1>
              <p className="text-[10px] text-gray-500 font-semibold tracking-widest uppercase">SEC PLATFORM</p>
            </div>
          </div>

          {/* Navigation Items */}
          <nav className="p-4 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id as TabType)}
                  className={`w-full flex items-center justify-between px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 group ${
                    isActive 
                      ? 'bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan shadow-glow-cyan/5' 
                      : 'text-gray-400 hover:bg-gray-800/40 hover:text-gray-200'
                  }`}
                >
                  <div className="flex items-center space-x-3">
                    <Icon className={`w-4 h-4 transition-transform duration-300 ${isActive ? 'scale-110 text-cyber-cyan' : 'group-hover:scale-110'}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.count !== undefined && item.count > 0 && (
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                      isActive 
                        ? 'bg-cyber-cyan text-dark-bg' 
                        : 'bg-dark-border text-gray-400'
                    }`}>
                      {item.count}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Sidebar Footer */}
        <div className="p-4 border-t border-dark-border flex items-center justify-between text-xs text-gray-500">
          <span className="font-semibold">v1.0.0 (MVP)</span>
          <button 
            onClick={toggleDarkMode}
            className="p-1.5 rounded-lg border border-dark-border hover:bg-gray-800 text-gray-400 hover:text-white transition-colors"
          >
            {isDarkMode ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
          </button>
        </div>
      </aside>

      {/* MAIN CONTAINER */}
      <div className="flex-1 flex flex-col overflow-hidden">
        
        {/* HEADER */}
        <header className="h-16 bg-dark-surface border-b border-dark-border flex items-center justify-between px-8 shrink-0">
          {/* Left panel: Activity indicators */}
          <div className="flex items-center space-x-6">
            {activeScan ? (
              <div className="flex items-center space-x-3 bg-cyber-cyan/5 border border-cyber-cyan/20 px-3 py-1.5 rounded-full">
                <Activity className="w-4 h-4 text-cyber-cyan animate-spin" />
                <span className="text-xs text-cyber-cyan font-medium">
                  Scan running: {activeScan.assetName} ({activeScan.progress}%)
                </span>
              </div>
            ) : (
              <div className="flex items-center space-x-2 text-gray-500 text-xs font-medium">
                <div className="w-2 h-2 rounded-full bg-cyber-emerald animate-pulse" />
                <span>Ready for Security Scan</span>
              </div>
            )}
          </div>

          {/* Right panel: Global Summary Index */}
          <div className="flex items-center space-x-6">
            <div className="flex items-center space-x-4 border-r border-dark-border pr-6">
              <div className="text-right">
                <span className="block text-[10px] text-gray-500 font-bold uppercase tracking-wider">Risk Index</span>
                <span className={`text-base font-bold ${
                  riskIndex > 60 ? 'text-cyber-rose' : riskIndex > 20 ? 'text-cyber-amber' : 'text-cyber-emerald'
                }`}>{riskIndex} / 100</span>
              </div>
              <div className="text-right">
                <span className="block text-[10px] text-gray-500 font-bold uppercase tracking-wider">Open Risks</span>
                <span className="text-base font-bold text-white">{openFindings.length}</span>
              </div>
            </div>

            <div className="flex space-x-1">
              {criticalCount > 0 && <span className="badge-critical">Critical: {criticalCount}</span>}
              {highCount > 0 && <span className="badge-high">High: {highCount}</span>}
            </div>
          </div>
        </header>

        {/* WORKSPACE CONTENT AREA */}
        <main className="flex-1 overflow-y-auto p-8 bg-dark-bg">
          {activeTab === 'dashboard' && (
            <Dashboard 
              assets={assets} 
              scans={scans} 
              findings={findings} 
              riskIndex={riskIndex} 
              onNavigate={(tab) => setActiveTab(tab as TabType)} 
            />
          )}
          {activeTab === 'assets' && (
            <AssetManager 
              assets={assets} 
              onRefresh={refreshData} 
            />
          )}
          {activeTab === 'scan' && (
            <ScanWizard 
              assets={assets} 
              activeScan={activeScan}
              onScanStarted={refreshData}
            />
          )}
          {activeTab === 'findings' && (
            <VulnerabilityExplorer 
              findings={findings} 
              onRefresh={refreshData} 
              onNavigateToAI={() => setActiveTab('ai')}
            />
          )}
          {activeTab === 'reports' && (
            <ReportCenter 
              scans={scans} 
            />
          )}
          {activeTab === 'ai' && (
            <AIAssistant 
              findings={findings}
            />
          )}
        </main>
      </div>

    </div>
  );
}
