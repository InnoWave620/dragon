import { app } from 'electron';
import fs from 'node:fs';
import path from 'node:path';

export interface Asset {
  id: string;
  name: string;
  target: string;
  type: 'website' | 'localhost' | 'folder' | 'api' | 'docker';
  environment: 'production' | 'staging' | 'development';
  owner: string;
  criticality: 'critical' | 'high' | 'medium' | 'low';
  createdAt: string;
}

export interface Scan {
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
  logs: string[];
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

export interface Finding {
  id: string;
  scanId: string;
  assetId: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  evidence: string;
  impact: string;
  riskScore: number;
  remediation: string;
  references: string[];
  status: 'open' | 'fixed' | 'ignored';
  assignedTo?: string;
  notes?: string;
  createdAt: string;
}

interface DBData {
  assets: Asset[];
  scans: Scan[];
  findings: Finding[];
}

class DatabaseService {
  private dbPath: string;
  private data: DBData = { assets: [], scans: [], findings: [] };

  constructor() {
    // Determine path in userData directory
    const userDataPath = app ? app.getPath('userData') : process.cwd();
    this.dbPath = path.join(userDataPath, 'dragon_db.json');
    this.init();
  }

  private init() {
    try {
      if (fs.existsSync(this.dbPath)) {
        const rawData = fs.readFileSync(this.dbPath, 'utf-8');
        this.data = JSON.parse(rawData);
        // Ensure arrays exist
        this.data.assets = this.data.assets || [];
        this.data.scans = this.data.scans || [];
        this.data.findings = this.data.findings || [];

        // Clean up orphaned "running" scans on startup
        let dirty = false;
        this.data.scans.forEach(scan => {
          if (scan.status === 'running') {
            scan.status = 'failed';
            scan.progress = 100;
            scan.logs.push('[!] Scan interrupted due to application restart.');
            dirty = true;
          }
        });
        if (dirty) {
          this.save();
        }
      } else {
        this.save();
      }
    } catch (error) {
      console.error('Failed to initialize database:', error);
      // Fallback to default empty data
      this.data = { assets: [], scans: [], findings: [] };
    }
  }

  private save() {
    try {
      fs.writeFileSync(this.dbPath, JSON.stringify(this.data, null, 2), 'utf-8');
    } catch (error) {
      console.error('Failed to write database file:', error);
    }
  }

  // --- Asset Management ---
  getAssets(): Asset[] {
    this.init();
    return this.data.assets;
  }

  addAsset(asset: Omit<Asset, 'id' | 'createdAt'>): Asset {
    const newAsset: Asset = {
      ...asset,
      id: 'ast_' + Math.random().toString(36).substr(2, 9),
      createdAt: new Date().toISOString()
    };
    this.data.assets.push(newAsset);
    this.save();
    return newAsset;
  }

  deleteAsset(id: string): boolean {
    const initialLength = this.data.assets.length;
    this.data.assets = this.data.assets.filter(a => a.id !== id);
    if (this.data.assets.length !== initialLength) {
      this.save();
      return true;
    }
    return false;
  }

  // --- Scan Management ---
  getScans(): Scan[] {
    this.init();
    return this.data.scans;
  }

  addScan(scan: Omit<Scan, 'id' | 'status' | 'progress' | 'stats' | 'startedAt' | 'logs'> & { id?: string }): Scan {
    const newScan: Scan = {
      id: scan.id || 'scn_' + Math.random().toString(36).substr(2, 9),
      assetId: scan.assetId,
      assetName: scan.assetName,
      status: 'idle',
      modules: scan.modules,
      progress: 0,
      stats: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      startedAt: new Date().toISOString(),
      logs: ['Scan record initialized']
    };
    this.data.scans.push(newScan);
    this.save();
    return newScan;
  }

  updateScan(updatedScan: Scan): Scan {
    const idx = this.data.scans.findIndex(s => s.id === updatedScan.id);
    if (idx !== -1) {
      this.data.scans[idx] = updatedScan;
      this.save();
    }
    return updatedScan;
  }

  getScan(id: string): Scan | undefined {
    this.init();
    return this.data.scans.find(s => s.id === id);
  }

  deleteScan(id: string): boolean {
    const initialLength = this.data.scans.length;
    this.data.scans = this.data.scans.filter(s => s.id !== id);
    if (this.data.scans.length !== initialLength) {
      this.deleteFindingsForScan(id);
      this.save();
      return true;
    }
    return false;
  }

  clearScans() {
    this.data.scans = [];
    this.data.findings = [];
    this.save();
  }

  // --- Finding Management ---
  getFindings(): Finding[] {
    this.init();
    return this.data.findings;
  }

  addFindings(findings: Omit<Finding, 'id' | 'status' | 'createdAt'>[]): Finding[] {
    const newFindings = findings.map(f => ({
      ...f,
      id: 'fnd_' + Math.random().toString(36).substr(2, 9),
      status: 'open' as const,
      createdAt: new Date().toISOString()
    }));
    this.data.findings.push(...newFindings);
    this.save();
    return newFindings;
  }

  updateFinding(updatedFinding: Finding): Finding {
    const idx = this.data.findings.findIndex(f => f.id === updatedFinding.id);
    if (idx !== -1) {
      this.data.findings[idx] = updatedFinding;
      this.save();
    }
    return updatedFinding;
  }

  deleteFindingsForScan(scanId: string) {
    this.data.findings = this.data.findings.filter(f => f.scanId !== scanId);
    this.save();
  }

  deleteFinding(id: string): boolean {
    const initialLength = this.data.findings.length;
    this.data.findings = this.data.findings.filter(f => f.id !== id);
    if (this.data.findings.length !== initialLength) {
      this.save();
      return true;
    }
    return false;
  }

  deleteFindings(ids: string[]): boolean {
    const initialLength = this.data.findings.length;
    this.data.findings = this.data.findings.filter(f => !ids.includes(f.id));
    if (this.data.findings.length !== initialLength) {
      this.save();
      return true;
    }
    return false;
  }

  clearFindings() {
    this.data.findings = [];
    this.save();
  }
}

export const dbService = new DatabaseService();
