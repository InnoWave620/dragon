import React, { useState } from 'react';
import { 
  FileDown, 
  FileText, 
  Code, 
  Table, 
  FileCode,
  ShieldCheck, 
  Download,
  AlertCircle
} from 'lucide-react';

interface Scan {
  id: string;
  assetId: string;
  assetName: string;
  status: 'idle' | 'running' | 'completed' | 'failed';
  modules: string[];
  progress: number;
  stats: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  startedAt: string;
  completedAt?: string;
  compliance?: {
    owaspScore: number;
    cisScore: number;
    details: {
      category: string;
      status: 'pass' | 'fail';
      control: string;
      description: string;
    }[];
  };
}

interface ReportCenterProps {
  scans: Scan[];
}

type FormatType = 'pdf' | 'html' | 'json' | 'csv';

export default function ReportCenter({ scans }: ReportCenterProps) {
  const [selectedScanId, setSelectedScanId] = useState('');
  const [exportFormat, setExportFormat] = useState<FormatType>('pdf');
  const [reportType, setReportType] = useState<'audit' | 'compliance'>('audit');
  const [isExporting, setIsExporting] = useState(false);
  const [exportMessage, setExportMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null);

  const completedScans = scans.filter(s => s.status === 'completed');

  const handleExportReport = async () => {
    if (!selectedScanId) return;
    const scan = completedScans.find(s => s.id === selectedScanId);
    if (!scan) return;

    setExportMessage(null);
    setIsExporting(true);

    try {
      // Configure save dialog properties based on format
      let title = 'Save PDF Report';
      let defaultName = `Dragon_Report_${scan.assetName.replace(/\s+/g, '_')}_${scan.id}.pdf`;
      let filters = [{ name: 'PDF Document', extensions: ['pdf'] }];

      if (exportFormat === 'html') {
        title = 'Save HTML Report';
        defaultName = defaultName.replace('.pdf', '.html');
        filters = [{ name: 'HTML Webpage', extensions: ['html'] }];
      } else if (exportFormat === 'json') {
        title = 'Export JSON Dataset';
        defaultName = defaultName.replace('.pdf', '.json');
        filters = [{ name: 'JSON Data', extensions: ['json'] }];
      } else if (exportFormat === 'csv') {
        title = 'Export CSV Spreadsheet';
        defaultName = defaultName.replace('.pdf', '.csv');
        filters = [{ name: 'CSV File', extensions: ['csv'] }];
      }

      // 1. Ask user for file save destination path via native save dialog
      const savePath = await window.electronAPI.reports.selectSavePath(title, defaultName, filters);
      if (!savePath) {
        setIsExporting(false);
        return; // User cancelled save dialog
      }

      // 2. Call main process to generate and write the report to disk
      const success = await window.electronAPI.reports.exportReport(scan.id, exportFormat, savePath, reportType);
      
      if (success) {
        setExportMessage({
          type: 'success',
          text: `Report successfully exported to: ${savePath}`
        });
      } else {
        setExportMessage({
          type: 'error',
          text: 'Failed to generate report file. Please verify write permissions.'
        });
      }
    } catch (err: any) {
      setExportMessage({
        type: 'error',
        text: `Error exporting report: ${err.message}`
      });
    } finally {
      setIsExporting(false);
    }
  };

  const handleQuickExport = async (scanId: string, format: FormatType) => {
    const scan = completedScans.find(s => s.id === scanId);
    if (!scan) return;

    try {
      let defaultName = `Dragon_Report_${scan.assetName.replace(/\s+/g, '_')}_${scan.id}.${format}`;
      let filters = [{ name: `${format.toUpperCase()} Document`, extensions: [format] }];
      
      const savePath = await window.electronAPI.reports.selectSavePath(`Save ${format.toUpperCase()} Report`, defaultName, filters);
      if (!savePath) return;

      const success = await window.electronAPI.reports.exportReport(scan.id, format, savePath);
      if (success) {
        await window.electronAPI.dialog.alert(`Successfully exported report to: ${savePath}`, 'info');
      } else {
        await window.electronAPI.dialog.alert('Failed to export report.', 'error');
      }
    } catch (e: any) {
      await window.electronAPI.dialog.alert(`Export error: ${e.message}`, 'error');
    }
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h2 className="text-2xl font-bold text-white tracking-wide">Security Report Center</h2>
        <p className="text-sm text-gray-500">Generate executive briefs, developer remediation logs, or raw JSON data.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* REPORT EXPORTER WIDGET (1/3 Width) */}
        <div className="glass-card p-6 space-y-6">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
            <FileDown className="w-4 h-4 text-cyber-cyan" />
            <span>Generate Custom Report</span>
          </h3>

          <div className="space-y-4">
            {/* Scan dropdown */}
            <div className="space-y-1">
              <label className="text-xs text-gray-500 font-semibold uppercase">Select Completed Scan</label>
              <select 
                value={selectedScanId}
                onChange={(e) => setSelectedScanId(e.target.value)}
                disabled={isExporting}
                className="input-cyber text-sm"
              >
                <option value="">-- Choose Scan Record --</option>
                {completedScans.map(s => (
                  <option key={s.id} value={s.id}>
                    {s.assetName} - {new Date(s.startedAt).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}
                  </option>
                ))}
              </select>
            </div>

            {/* Report Type choice */}
            <div className="space-y-1">
              <label className="text-xs text-gray-500 font-semibold uppercase">Report Type</label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => setReportType('audit')}
                  disabled={isExporting}
                  className={`flex items-center justify-center p-2 rounded-lg border text-[11px] font-semibold transition-all ${
                    reportType === 'audit'
                      ? 'bg-cyber-cyan/15 border-cyber-cyan text-cyber-cyan'
                      : 'bg-dark-surface border-dark-border text-gray-400 hover:bg-gray-800 hover:text-white'
                  }`}
                >
                  Vuln Audit
                </button>
                <button
                  type="button"
                  onClick={() => setReportType('compliance')}
                  disabled={isExporting}
                  className={`flex items-center justify-center p-2 rounded-lg border text-[11px] font-semibold transition-all ${
                    reportType === 'compliance'
                      ? 'bg-cyber-purple/15 border-cyber-purple text-cyber-purple'
                      : 'bg-dark-surface border-dark-border text-gray-400 hover:bg-gray-800 hover:text-white'
                  }`}
                >
                  Compliance
                </button>
              </div>
            </div>

            {/* Format choice grid */}
            <div className="space-y-2">
              <label className="text-xs text-gray-500 font-semibold uppercase">Export Format</label>
              <div className="grid grid-cols-2 gap-2">
                {[
                  { id: 'pdf', label: 'PDF Brief', icon: FileText },
                  { id: 'html', label: 'HTML Page', icon: FileCode },
                  { id: 'json', label: 'JSON Dataset', icon: Code },
                  { id: 'csv', label: 'CSV Sheet', icon: Table }
                ].map(opt => (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => setExportFormat(opt.id as FormatType)}
                    disabled={isExporting}
                    className={`flex items-center space-x-2 p-2.5 rounded-lg border text-xs font-semibold transition-all ${
                      exportFormat === opt.id 
                        ? 'bg-cyber-cyan/15 border-cyber-cyan text-cyber-cyan shadow-glow-cyan/5' 
                        : 'bg-dark-surface border-dark-border text-gray-400 hover:bg-gray-800 hover:text-white'
                    }`}
                  >
                    <opt.icon className="w-4 h-4" />
                    <span>{opt.label}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Action Trigger */}
            <button 
              onClick={handleExportReport}
              disabled={!selectedScanId || isExporting}
              className="w-full btn-cyber-cyan flex items-center justify-center space-x-2 text-xs py-3 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <Download className="w-4 h-4" />
              <span>{isExporting ? 'Generating Document...' : 'Compile and Save'}</span>
            </button>

            {/* Message alert feedback */}
            {exportMessage && (
              <div className={`p-3 rounded-lg border flex items-start space-x-2.5 text-xs ${
                exportMessage.type === 'success' 
                  ? 'bg-cyber-emerald/5 border-cyber-emerald/30 text-cyber-emerald' 
                  : 'bg-cyber-rose/5 border-cyber-rose/30 text-cyber-rose'
              }`}>
                {exportMessage.type === 'success' ? <ShieldCheck className="w-4 h-4 shrink-0 mt-0.5" /> : <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />}
                <p className="leading-normal">{exportMessage.text}</p>
              </div>
            )}

          </div>
        </div>

        {/* SCAN ASSESSMENT LOG TABLE (2/3 Width) */}
        <div className="lg:col-span-2 glass-card p-6 space-y-4">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider">Historical Assessment Runs</h3>
          
          {completedScans.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[11px] border-collapse">
                <thead>
                  <tr className="bg-dark-surface border-b border-dark-border text-gray-500 font-bold uppercase tracking-wider">
                    <th className="p-3">Asset</th>
                    <th className="p-3">Completed On</th>
                    <th className="p-3">Severity Findings</th>
                    <th className="p-3 text-center">Compliance</th>
                    <th className="p-3 text-center">Quick Export</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-dark-border/40">
                  {completedScans.map(scan => (
                    <tr key={scan.id} className="hover:bg-dark-surface/40 transition-colors">
                      <td className="p-3">
                        <span className="font-semibold text-white block">{scan.assetName}</span>
                        <span className="text-[9px] text-gray-500 font-mono">{scan.id}</span>
                      </td>
                      <td className="p-3 text-gray-400 font-medium">
                        {new Date(scan.completedAt || scan.startedAt).toLocaleString()}
                      </td>
                      <td className="p-3">
                        <div className="flex space-x-1.5 font-bold">
                          {scan.stats.critical > 0 && <span className="text-cyber-rose">C:{scan.stats.critical}</span>}
                          {scan.stats.high > 0 && <span className="text-cyber-purple">H:{scan.stats.high}</span>}
                          {scan.stats.medium > 0 && <span className="text-cyber-amber">M:{scan.stats.medium}</span>}
                          {scan.stats.low > 0 && <span className="text-cyber-blue">L:{scan.stats.low}</span>}
                          {scan.stats.critical + scan.stats.high + scan.stats.medium + scan.stats.low === 0 && (
                            <span className="text-cyber-emerald font-semibold uppercase text-[9px] tracking-wider">Clean</span>
                          )}
                        </div>
                      </td>
                      <td className="p-3 text-center">
                        {scan.compliance ? (
                          <div className="space-y-0.5 font-bold">
                            <span className="text-cyber-cyan block">OWASP: {scan.compliance.owaspScore}%</span>
                            <span className="text-cyber-purple block">CIS: {scan.compliance.cisScore}%</span>
                          </div>
                        ) : (
                          <span className="text-gray-600 font-medium">N/A</span>
                        )}
                      </td>
                      <td className="p-3">
                        <div className="flex items-center justify-center space-x-1">
                          <button 
                            onClick={() => handleQuickExport(scan.id, 'pdf')}
                            className="px-2 py-1 bg-dark-bg border border-dark-border hover:border-cyber-cyan text-gray-400 hover:text-white rounded transition-colors text-[9px] font-bold uppercase"
                          >
                            PDF
                          </button>
                          <button 
                            onClick={() => handleQuickExport(scan.id, 'json')}
                            className="px-2 py-1 bg-dark-bg border border-dark-border hover:border-cyber-cyan text-gray-400 hover:text-white rounded transition-colors text-[9px] font-bold uppercase"
                          >
                            JSON
                          </button>
                          <button 
                            onClick={() => handleQuickExport(scan.id, 'csv')}
                            className="px-2 py-1 bg-dark-bg border border-dark-border hover:border-cyber-cyan text-gray-400 hover:text-white rounded transition-colors text-[9px] font-bold uppercase"
                          >
                            CSV
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-12 text-gray-500 text-xs">
              No completed scan history detected. Reports will unlock once a scan is successfully finished.
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
