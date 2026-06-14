import React from 'react';
import { 
  ShieldAlert, 
  Folder, 
  Activity, 
  CheckCircle2, 
  Clock, 
  ArrowRight,
  TrendingUp,
  Database
} from 'lucide-react';

interface DashboardProps {
  assets: any[];
  scans: any[];
  findings: any[];
  riskIndex: number;
  onNavigate: (tab: string) => void;
}

export default function Dashboard({ assets, scans, findings, riskIndex, onNavigate }: DashboardProps) {
  const openFindings = findings.filter(f => f.status === 'open');
  const totalFindings = openFindings.length;
  
  const counts = {
    critical: openFindings.filter(f => f.severity === 'critical').length,
    high: openFindings.filter(f => f.severity === 'high').length,
    medium: openFindings.filter(f => f.severity === 'medium').length,
    low: openFindings.filter(f => f.severity === 'low').length,
    info: openFindings.filter(f => f.severity === 'info').length
  };

  const activeScansCount = scans.filter(s => s.status === 'running').length;
  const recentScans = [...scans].sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime()).slice(0, 4);
  const recentFindings = [...openFindings].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()).slice(0, 4);

  // SVG Trend Chart Data
  // We will plot the last 6 scans to show vulnerability trends
  const completedScans = [...scans]
    .filter(s => s.status === 'completed')
    .sort((a, b) => new Date(a.startedAt).getTime() - new Date(b.startedAt).getTime())
    .slice(-6);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-cyber-rose bg-cyber-rose/10 border-cyber-rose/30';
      case 'high': return 'text-cyber-purple bg-cyber-purple/10 border-cyber-purple/30';
      case 'medium': return 'text-cyber-amber bg-cyber-amber/10 border-cyber-amber/30';
      case 'low': return 'text-cyber-blue bg-cyber-blue/10 border-cyber-blue/30';
      default: return 'text-gray-400 bg-gray-700/30 border-gray-600/30';
    }
  };

  return (
    <div className="space-y-8">
      {/* Title Header */}
      <div>
        <h2 className="text-2xl font-bold text-white tracking-wide">Security Operations Center</h2>
        <p className="text-sm text-gray-500">Real-time posture assessment and threat overview.</p>
      </div>

      {/* STAT CARDS */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        
        {/* Assets Card */}
        <div className="glass-card glass-card-hover p-6 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs text-gray-500 font-bold uppercase tracking-wider">Monitored Assets</span>
            <h3 className="text-3xl font-extrabold text-white">{assets.length}</h3>
          </div>
          <div className="p-3 bg-cyber-blue/10 border border-cyber-blue/30 text-cyber-blue rounded-lg">
            <Folder className="w-6 h-6" />
          </div>
        </div>

        {/* Total Scans Card */}
        <div className="glass-card glass-card-hover p-6 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs text-gray-500 font-bold uppercase tracking-wider">Total Scans Run</span>
            <h3 className="text-3xl font-extrabold text-white">{scans.length}</h3>
          </div>
          <div className="p-3 bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan rounded-lg">
            <Activity className="w-6 h-6" />
          </div>
        </div>

        {/* Active Scans Card */}
        <div className="glass-card glass-card-hover p-6 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs text-gray-500 font-bold uppercase tracking-wider">Active Operations</span>
            <h3 className="text-3xl font-extrabold text-white">{activeScansCount}</h3>
          </div>
          <div className="p-3 bg-cyber-emerald/10 border border-cyber-emerald/30 text-cyber-emerald rounded-lg">
            <CheckCircle2 className="w-6 h-6" />
          </div>
        </div>

        {/* Risk score radial indicator */}
        <div className="glass-card glass-card-hover p-6 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs text-gray-500 font-bold uppercase tracking-wider">Average Risk Score</span>
            <h3 className="text-3xl font-extrabold text-white">{riskIndex}%</h3>
          </div>
          <div className="relative w-12 h-12 flex items-center justify-center">
            {/* SVG circle track */}
            <svg className="w-full h-full -rotate-90">
              <circle cx="24" cy="24" r="20" className="stroke-dark-border" strokeWidth="4" fill="none" />
              <circle 
                cx="24" 
                cy="24" 
                r="20" 
                className={riskIndex > 60 ? 'stroke-cyber-rose' : riskIndex > 20 ? 'stroke-cyber-amber' : 'stroke-cyber-emerald'} 
                strokeWidth="4" 
                fill="none"
                strokeDasharray={`${2 * Math.PI * 20}`}
                strokeDashoffset={`${2 * Math.PI * 20 * (1 - riskIndex / 100)}`}
                strokeLinecap="round"
              />
            </svg>
            <span className="absolute text-[10px] font-bold">{riskIndex}</span>
          </div>
        </div>

      </div>

      {/* VULNERABILITY COUNTS GRID */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[
          { label: 'Critical', value: counts.critical, color: 'text-cyber-rose bg-cyber-rose/5 border-cyber-rose/20' },
          { label: 'High', value: counts.high, color: 'text-cyber-purple bg-cyber-purple/5 border-cyber-purple/20' },
          { label: 'Medium', value: counts.medium, color: 'text-cyber-amber bg-cyber-amber/5 border-cyber-amber/20' },
          { label: 'Low', value: counts.low, color: 'text-cyber-blue bg-cyber-blue/5 border-cyber-blue/20' },
          { label: 'Informational', value: counts.info, color: 'text-gray-400 bg-gray-500/5 border-gray-500/10' }
        ].map(item => (
          <div key={item.label} className={`glass-card p-4 border flex flex-col items-center justify-center ${item.color}`}>
            <span className="text-[10px] font-extrabold uppercase tracking-wider opacity-80">{item.label}</span>
            <span className="text-2xl font-black mt-1">{item.value}</span>
          </div>
        ))}
      </div>

      {/* CHARTS & ANALYTICS AREA */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Trend Area Chart (2/3 width) */}
        <div className="glass-card p-6 lg:col-span-2 space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <TrendingUp className="w-4 h-4 text-cyber-cyan" />
              <h3 className="text-sm font-semibold text-white uppercase tracking-wider">Vulnerability Severity Trends</h3>
            </div>
            <span className="text-xs text-gray-500 font-medium">Last 6 Assessments</span>
          </div>

          {/* SVG Line/Area Chart */}
          <div className="w-full h-56 relative">
            {completedScans.length >= 2 ? (
              <svg className="w-full h-full" viewBox="0 0 600 220">
                <defs>
                  <linearGradient id="chartGlow" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#00f0ff" stopOpacity="0.25"/>
                    <stop offset="100%" stopColor="#00f0ff" stopOpacity="0"/>
                  </linearGradient>
                </defs>
                {/* Horizontal lines */}
                <line x1="40" y1="20" x2="580" y2="20" className="stroke-dark-border" strokeDasharray="3 3" />
                <line x1="40" y1="70" x2="580" y2="70" className="stroke-dark-border" strokeDasharray="3 3" />
                <line x1="40" y1="120" x2="580" y2="120" className="stroke-dark-border" strokeDasharray="3 3" />
                <line x1="40" y1="170" x2="580" y2="170" className="stroke-dark-border" strokeDasharray="3 3" />
                
                {/* Generate Points */}
                {(() => {
                  const maxVal = Math.max(10, ...completedScans.map(s => s.stats.critical + s.stats.high + s.stats.medium + s.stats.low));
                  const points = completedScans.map((s, idx) => {
                    const total = s.stats.critical + s.stats.high + s.stats.medium + s.stats.low;
                    const x = 40 + (idx / (completedScans.length - 1)) * 540;
                    const y = 170 - (total / maxVal) * 140;
                    return { x, y, name: s.assetName.substring(0, 8), total };
                  });

                  const dPath = `M ${points.map(p => `${p.x} ${p.y}`).join(' L ')}`;
                  const fillPath = `${dPath} L ${points[points.length - 1].x} 170 L ${points[0].x} 170 Z`;

                  return (
                    <>
                      {/* Area Fill */}
                      <path d={fillPath} fill="url(#chartGlow)" />
                      {/* Border Line */}
                      <path d={dPath} fill="none" stroke="#00f0ff" strokeWidth="2.5" />
                      {/* Nodes */}
                      {points.map((p, i) => (
                        <g key={i}>
                          <circle cx={p.x} cy={p.y} r="5" fill="#0a0b0d" stroke="#00f0ff" strokeWidth="2" />
                          {/* Label below axis */}
                          <text x={p.x} y="195" textAnchor="middle" fill="#64748b" fontSize="10">{p.name}</text>
                          {/* Value above node */}
                          <text x={p.x} y={p.y - 10} textAnchor="middle" fill="#e2e8f0" fontSize="10" fontWeight="bold">{p.total}</text>
                        </g>
                      ))}
                    </>
                  );
                })()}
              </svg>
            ) : (
              <div className="w-full h-full flex flex-col items-center justify-center text-xs text-gray-500 border border-dashed border-dark-border rounded-lg">
                <ShieldAlert className="w-8 h-8 mb-2 opacity-50" />
                <span>Run at least 2 scans to unlock vulnerability trending graphics.</span>
              </div>
            )}
          </div>
        </div>

        {/* Severity distribution progress block (1/3 width) */}
        <div className="glass-card p-6 space-y-6">
          <div className="flex items-center space-x-2">
            <Database className="w-4 h-4 text-cyber-purple" />
            <h3 className="text-sm font-semibold text-white uppercase tracking-wider">Severity Distribution</h3>
          </div>

          <div className="space-y-4">
            {[
              { label: 'Critical', count: counts.critical, pct: totalFindings ? (counts.critical / totalFindings) * 100 : 0, color: 'bg-cyber-rose' },
              { label: 'High Priority', count: counts.high, pct: totalFindings ? (counts.high / totalFindings) * 100 : 0, color: 'bg-cyber-purple' },
              { label: 'Medium Priority', count: counts.medium, pct: totalFindings ? (counts.medium / totalFindings) * 100 : 0, color: 'bg-cyber-amber' },
              { label: 'Low Severity', count: counts.low, pct: totalFindings ? (counts.low / totalFindings) * 100 : 0, color: 'bg-cyber-blue' },
              { label: 'Informational', count: counts.info, pct: totalFindings ? (counts.info / totalFindings) * 100 : 0, color: 'bg-gray-500' }
            ].map(item => (
              <div key={item.label} className="space-y-1">
                <div className="flex justify-between text-xs font-semibold">
                  <span className="text-gray-400">{item.label}</span>
                  <span className="text-white">{item.count} ({Math.round(item.pct)}%)</span>
                </div>
                <div className="w-full h-2 bg-dark-border rounded-full overflow-hidden">
                  <div className={`h-full ${item.color}`} style={{ width: `${item.pct}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>

      {/* RECENT SCAN & RECENT FINDINGS ROWS */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Recent Operations */}
        <div className="glass-card p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Clock className="w-4 h-4 text-cyber-cyan" />
              <h3 className="text-sm font-semibold text-white uppercase tracking-wider">Recent Scans</h3>
            </div>
            <button 
              onClick={() => onNavigate('scan')} 
              className="text-xs text-cyber-cyan hover:underline flex items-center space-x-1"
            >
              <span>View all</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-2">
            {recentScans.length > 0 ? (
              recentScans.map(scan => (
                <div key={scan.id} className="p-3 bg-dark-surface border border-dark-border rounded-lg flex items-center justify-between text-xs">
                  <div>
                    <span className="font-semibold text-white block">{scan.assetName}</span>
                    <span className="text-[10px] text-gray-500 font-semibold uppercase">{scan.modules.join(', ')}</span>
                  </div>
                  <div className="flex items-center space-x-4">
                    <span className="text-gray-400">{new Date(scan.startedAt).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}</span>
                    <span className={`px-2 py-0.5 rounded font-bold uppercase ${
                      scan.status === 'completed' 
                        ? 'bg-cyber-emerald/10 text-cyber-emerald' 
                        : scan.status === 'running' 
                          ? 'bg-cyber-cyan/10 text-cyber-cyan animate-pulse'
                          : 'bg-cyber-rose/10 text-cyber-rose'
                    }`}>
                      {scan.status}
                    </span>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-6 text-gray-500 text-xs">
                No scan history recorded. Go to the Scan Wizard to launch your first assessment.
              </div>
            )}
          </div>
        </div>

        {/* Recent Vulnerabilities */}
        <div className="glass-card p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-cyber-rose" />
              <h3 className="text-sm font-semibold text-white uppercase tracking-wider">Recent Vulnerabilities</h3>
            </div>
            <button 
              onClick={() => onNavigate('findings')} 
              className="text-xs text-cyber-cyan hover:underline flex items-center space-x-1"
            >
              <span>Explore</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-2">
            {recentFindings.length > 0 ? (
              recentFindings.map(finding => (
                <div key={finding.id} className="p-3 bg-dark-surface border border-dark-border rounded-lg flex items-center justify-between text-xs">
                  <div>
                    <span className="font-semibold text-white block truncate w-64">{finding.title}</span>
                    <span className="text-[10px] text-gray-500">{finding.evidence?.split('\n')[0] || 'Web audit'}</span>
                  </div>
                  <span className={`badge border ${getSeverityColor(finding.severity)}`}>
                    {finding.severity}
                  </span>
                </div>
              ))
            ) : (
              <div className="text-center py-6 text-gray-500 text-xs">
                No active vulnerabilities found. Everything is fully secured!
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
