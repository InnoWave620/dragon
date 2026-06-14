import React, { useState, useEffect, useRef } from 'react';
import { 
  Play, 
  StopCircle, 
  Terminal, 
  CheckCircle, 
  AlertTriangle,
  Layers, 
  Settings, 
  FileText,
  Loader
} from 'lucide-react';

interface Asset {
  id: string;
  name: string;
  target: string;
  type: 'website' | 'localhost' | 'folder' | 'api' | 'docker';
}

interface ScanWizardProps {
  assets: Asset[];
  activeScan: any;
  onScanStarted: () => void;
}

export default function ScanWizard({ assets, activeScan, onScanStarted }: ScanWizardProps) {
  const [selectedAssetId, setSelectedAssetId] = useState('');
  const [useCrawler, setUseCrawler] = useState(true);
  const [useSecrets, setUseSecrets] = useState(false);
  const [useDependencies, setUseDependencies] = useState(false);
  const [useSast, setUseSast] = useState(false);
  const [useApi, setUseApi] = useState(false);
  const [useDocker, setUseDocker] = useState(false);
  
  const [logs, setLogs] = useState<string[]>([]);
  const [progress, setProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState<'idle' | 'running' | 'completed' | 'failed'>('idle');
  const [runningScanId, setRunningScanId] = useState<string | null>(null);

  const consoleEndRef = useRef<HTMLDivElement>(null);

  // Auto-configure modules when asset selection changes
  useEffect(() => {
    const asset = assets.find(a => a.id === selectedAssetId);
    if (asset) {
      if (asset.type === 'folder') {
        setUseCrawler(false);
        setUseSecrets(true);
        setUseDependencies(true);
        setUseSast(true);
        setUseDocker(true);
        setUseApi(true);
      } else if (asset.type === 'api') {
        setUseCrawler(false);
        setUseSecrets(false);
        setUseDependencies(false);
        setUseSast(false);
        setUseDocker(false);
        setUseApi(true);
      } else if (asset.type === 'docker') {
        setUseCrawler(false);
        setUseSecrets(false);
        setUseDependencies(false);
        setUseSast(false);
        setUseDocker(true);
        setUseApi(false);
      } else {
        setUseCrawler(true);
        setUseSecrets(false);
        setUseDependencies(false);
        setUseSast(false);
        setUseDocker(false);
        setUseApi(false);
      }
    }
  }, [selectedAssetId, assets]);

  // Handle activeScan loaded from global state
  useEffect(() => {
    if (activeScan) {
      setScanStatus(activeScan.status);
      setProgress(activeScan.progress);
      setRunningScanId(activeScan.id);
      setLogs(activeScan.logs || []);
    } else if (scanStatus === 'running') {
      setScanStatus('completed');
      setProgress(100);
    }
  }, [activeScan]);

  // Keep logs scrolled down
  useEffect(() => {
    if (consoleEndRef.current) {
      consoleEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  // Listen to IPC scanning logs
  useEffect(() => {
    const unsubscribeLog = window.electronAPI.scan.onLog((logLine: string) => {
      setLogs(prev => [...prev, logLine]);
    });

    const unsubscribeProgress = window.electronAPI.scan.onProgress((pScan: any) => {
      setProgress(pScan.progress);
      setScanStatus(pScan.status);
    });

    const unsubscribeComplete = window.electronAPI.scan.onComplete((cScan: any) => {
      setProgress(100);
      setScanStatus(cScan.status);
      setRunningScanId(null);
    });

    return () => {
      unsubscribeLog();
      unsubscribeProgress();
      unsubscribeComplete();
    };
  }, []);

  const handleStartScan = async () => {
    if (!selectedAssetId) return;
    
    const modules: string[] = [];
    if (useCrawler) modules.push('website_security');
    if (useSecrets) modules.push('secret_detection');
    if (useDependencies) modules.push('dependency_scanning');
    if (useSast) modules.push('source_code_sast');
    if (useApi) modules.push('api_security');
    if (useDocker) modules.push('docker_security');

    if (modules.length === 0) {
      alert('Please select at least one scan module to execute.');
      return;
    }

    setLogs([
      "         ,           ,",
      "        /             \\",
      "       ((__-^^-,-^^-__))",
      "        `-_---' `---_-'",
      "         <__`--------'>",
      "          ) `--------' (",
      "          /            \\",
      "",
      "[*] Dragon Security Assessment Engine Init...",
      "[*] Target Scope Initialized."
    ]);
    setProgress(5);
    setScanStatus('running');

    try {
      const res = await window.electronAPI.scan.startScan(selectedAssetId, modules);
      if (res.success) {
        setRunningScanId(res.scanId);
        onScanStarted();
      } else {
        setLogs(prev => [...prev, `[!] Failed to start scan: ${res.error}`]);
        setScanStatus('failed');
      }
    } catch (err: any) {
      setLogs(prev => [...prev, `[!] Error starting scan: ${err.message}`]);
      setScanStatus('failed');
    }
  };

  const handleCancelScan = async () => {
    if (!runningScanId) return;
    try {
      await window.electronAPI.scan.cancelScan(runningScanId);
      setScanStatus('failed');
      setRunningScanId(null);
    } catch (err) {
      console.error(err);
    }
  };

  const selectedAsset = assets.find(a => a.id === selectedAssetId);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-white tracking-wide">Dynamic Scanning Engine</h2>
        <p className="text-sm text-gray-500">Configure audit parameters and review real-time security events.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* CONFIGURATION COLUMN (1/3 Width) */}
        <div className="space-y-6">
          
          {/* Target Select */}
          <div className="glass-card p-6 space-y-4">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
              <Layers className="w-4 h-4 text-cyber-cyan" />
              <span>Scope Configuration</span>
            </h3>

            <div className="space-y-1">
              <label className="text-xs text-gray-500 font-semibold uppercase">Select Target Asset</label>
              <select 
                value={selectedAssetId}
                onChange={(e) => setSelectedAssetId(e.target.value)}
                disabled={scanStatus === 'running'}
                className="input-cyber text-sm"
              >
                <option value="">-- Choose Asset --</option>
                {assets.map(a => (
                  <option key={a.id} value={a.id}>{a.name} ({a.type})</option>
                ))}
              </select>
            </div>

            {selectedAsset && (
              <div className="p-3 bg-dark-surface/60 border border-dark-border rounded-lg text-xs space-y-1">
                <span className="block font-semibold text-white">Target URI/Path:</span>
                <span className="block font-mono text-cyber-cyan truncate">{selectedAsset.target}</span>
              </div>
            )}
          </div>

          {/* Module Toggles */}
          <div className="glass-card p-6 space-y-4">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
              <Settings className="w-4 h-4 text-cyber-purple" />
              <span>Assessment Modules</span>
            </h3>

            <div className="space-y-3">
              {/* Web Crawler Module */}
              <label className="flex items-start space-x-3 cursor-pointer group">
                <input 
                  type="checkbox" 
                  checked={useCrawler}
                  onChange={(e) => setUseCrawler(e.target.checked)}
                  disabled={scanStatus === 'running' || (selectedAsset && selectedAsset.type === 'folder')}
                  className="mt-1 rounded bg-dark-surface border-dark-border text-cyber-cyan focus:ring-0 w-4 h-4"
                />
                <div>
                  <span className="text-xs font-semibold text-gray-200 group-hover:text-white block">
                    Website Crawler & Headers
                  </span>
                  <span className="text-[10px] text-gray-500 block">
                    Audit security directives, XSS headers, cookies, and detect framework techs.
                  </span>
                </div>
              </label>

              {/* Secrets Detection Module */}
              <label className="flex items-start space-x-3 cursor-pointer group">
                <input 
                  type="checkbox" 
                  checked={useSecrets}
                  onChange={(e) => setUseSecrets(e.target.checked)}
                  disabled={scanStatus === 'running' || (selectedAsset && selectedAsset.type !== 'folder')}
                  className="mt-1 rounded bg-dark-surface border-dark-border text-cyber-cyan focus:ring-0 w-4 h-4"
                />
                <div>
                  <span className="text-xs font-semibold text-gray-200 group-hover:text-white block">
                    Hardcoded Secrets Detection
                  </span>
                  <span className="text-[10px] text-gray-500 block">
                    Regex check for committed AWS keys, Slack tokens, private certificates, and config database passwords.
                  </span>
                </div>
              </label>

              {/* Dependency Audit Module */}
              <label className="flex items-start space-x-3 cursor-pointer group">
                <input 
                  type="checkbox" 
                  checked={useDependencies}
                  onChange={(e) => setUseDependencies(e.target.checked)}
                  disabled={scanStatus === 'running' || (selectedAsset && selectedAsset.type !== 'folder')}
                  className="mt-1 rounded bg-dark-surface border-dark-border text-cyber-cyan focus:ring-0 w-4 h-4"
                />
                <div>
                  <span className="text-xs font-semibold text-gray-200 group-hover:text-white block">
                    Software Dependency Auditor
                  </span>
                  <span className="text-[10px] text-gray-500 block">
                    Inspect package.json or requirements.txt for outdated, vulnerable library modules.
                  </span>
                </div>
              </label>

              {/* Source Code SAST Module */}
              <label className="flex items-start space-x-3 cursor-pointer group">
                <input 
                  type="checkbox" 
                  checked={useSast}
                  onChange={(e) => setUseSast(e.target.checked)}
                  disabled={scanStatus === 'running' || (selectedAsset && selectedAsset.type !== 'folder')}
                  className="mt-1 rounded bg-dark-surface border-dark-border text-cyber-cyan focus:ring-0 w-4 h-4"
                />
                <div>
                  <span className="text-xs font-semibold text-gray-200 group-hover:text-white block">
                    Source Code SAST Auditor
                  </span>
                  <span className="text-[10px] text-gray-500 block">
                    Regex-based SAST scanning for SQL Injection, Command Injection, and dangerous functions.
                  </span>
                </div>
              </label>

              {/* API Security Audit Module */}
              <label className="flex items-start space-x-3 cursor-pointer group">
                <input 
                  type="checkbox" 
                  checked={useApi}
                  onChange={(e) => setUseApi(e.target.checked)}
                  disabled={scanStatus === 'running' || (selectedAsset && (selectedAsset.type !== 'folder' && selectedAsset.type !== 'api' && selectedAsset.type !== 'localhost' && selectedAsset.type !== 'website'))}
                  className="mt-1 rounded bg-dark-surface border-dark-border text-cyber-cyan focus:ring-0 w-4 h-4"
                />
                <div>
                  <span className="text-xs font-semibold text-gray-200 group-hover:text-white block">
                    API Security Auditor
                  </span>
                  <span className="text-[10px] text-gray-500 block">
                    Parse OpenAPI/Swagger specs to audit unauthenticated routes and parameter constraints.
                  </span>
                </div>
              </label>

              {/* Docker Security Audit Module */}
              <label className="flex items-start space-x-3 cursor-pointer group">
                <input 
                  type="checkbox" 
                  checked={useDocker}
                  onChange={(e) => setUseDocker(e.target.checked)}
                  disabled={scanStatus === 'running' || (selectedAsset && (selectedAsset.type !== 'folder' && selectedAsset.type !== 'docker'))}
                  className="mt-1 rounded bg-dark-surface border-dark-border text-cyber-cyan focus:ring-0 w-4 h-4"
                />
                <div>
                  <span className="text-xs font-semibold text-gray-200 group-hover:text-white block">
                    Container Security Auditor
                  </span>
                  <span className="text-[10px] text-gray-500 block">
                    Audit Dockerfile and docker-compose settings for root users, port mappings, and secrets.
                  </span>
                </div>
              </label>
            </div>
          </div>

          {/* Action Trigger */}
          {scanStatus === 'running' ? (
            <button 
              onClick={handleCancelScan}
              className="w-full btn-cyber-rose flex items-center justify-center space-x-2 text-sm py-3"
            >
              <StopCircle className="w-5 h-5" />
              <span>Abort Assessment</span>
            </button>
          ) : (
            <button 
              onClick={handleStartScan}
              disabled={!selectedAssetId}
              className="w-full btn-cyber-cyan flex items-center justify-center space-x-2 text-sm py-3 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <Play className="w-5 h-5" />
              <span>Execute Assessment</span>
            </button>
          )}

        </div>

        {/* TERMINAL CONSOLE COLUMN (2/3 Width) */}
        <div className="lg:col-span-2 flex flex-col space-y-6">
          <div className="glass-card flex-1 p-6 flex flex-col justify-between min-h-[400px]">
            {/* Header */}
            <div className="flex items-center justify-between border-b border-dark-border pb-4 mb-4">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-cyber-cyan" />
                <span>Console Log Output</span>
              </h3>
              <div className="flex items-center space-x-2">
                {scanStatus === 'running' && (
                  <span className="flex items-center space-x-1.5 text-xs text-cyber-cyan font-medium">
                    <Loader className="w-3.5 h-3.5 animate-spin" />
                    <span>Processing {progress}%</span>
                  </span>
                )}
                {scanStatus === 'completed' && (
                  <span className="text-xs text-cyber-emerald font-semibold flex items-center space-x-1">
                    <CheckCircle className="w-3.5 h-3.5" />
                    <span>Finished</span>
                  </span>
                )}
                {scanStatus === 'failed' && (
                  <span className="text-xs text-cyber-rose font-semibold flex items-center space-x-1">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Aborted</span>
                  </span>
                )}
              </div>
            </div>

            {/* Log Panel */}
            <div className="flex-1 bg-dark-bg/60 border border-dark-border rounded-lg p-4 font-mono text-[11px] text-gray-400 overflow-y-auto max-h-[350px] space-y-1.5">
              {logs.length > 0 ? (
                logs.map((log, index) => {
                  let logColor = 'text-gray-400';
                  if (log.startsWith('[+]')) logColor = 'text-cyber-emerald font-semibold';
                  else if (log.startsWith('[!]')) logColor = 'text-cyber-rose font-semibold';
                  else if (log.startsWith('[~]')) logColor = 'text-cyber-cyan';
                  else if (log.startsWith('[-]')) logColor = 'text-cyber-amber';

                  return (
                    <div key={index} className={logColor}>
                      {log}
                    </div>
                  );
                })
              ) : (
                <div className="w-full h-full flex flex-col items-center justify-center py-6 text-gray-500 font-sans select-none">
                  <pre className="font-mono text-cyber-cyan/50 text-[10px] leading-tight mb-4 text-center">
{`         ,           ,
        /             \\
       ((__-^^-,-^^-__))
        \`-_---' \`---_-'
         <__\`--------'>
          ) \`--------' (
          /            \\`}
                  </pre>
                  <span className="text-xs font-semibold text-gray-400 block tracking-wider">DRAGON SECURITY TERMINAL IDLE</span>
                  <span className="text-[10px] text-gray-600 mt-1">Select an asset and execute an assessment to stream real-time logs.</span>
                </div>
              )}
              <div ref={consoleEndRef} />
            </div>

            {/* Progress Bar Container */}
            <div className="mt-4 space-y-1.5">
              <div className="flex justify-between text-[10px] text-gray-500 font-bold uppercase tracking-wider">
                <span>Scan progress</span>
                <span>{progress}%</span>
              </div>
              <div className="w-full h-2 bg-dark-border rounded-full overflow-hidden">
                <div 
                  className="h-full bg-cyber-cyan transition-all duration-300 shadow-glow-cyan"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
