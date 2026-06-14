import { app, BrowserWindow, dialog } from 'electron';
import fs from 'node:fs';
import path from 'node:path';
import { dbService, Finding, Scan } from './db';

export class ReportService {
  
  // HTML template generator
  generateHtmlReport(scan: Scan, findings: Finding[], reportType: 'audit' | 'compliance' = 'audit'): string {
    const severityColors = {
      critical: '#f43f5e',
      high: '#8b5cf6',
      medium: '#f59e0b',
      low: '#3b82f6',
      info: '#9ca3af'
    };

    const severityCount = {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      info: findings.filter(f => f.severity === 'info').length
    };

    const totalFindings = findings.length;
    const dateStr = new Date(scan.startedAt).toLocaleDateString() + ' ' + new Date(scan.startedAt).toLocaleTimeString();

    // Map findings to HTML rows
    const findingsHtml = findings.map((f, i) => `
      <div class="finding-card card-severity-${f.severity}">
        <div class="finding-header">
          <span class="finding-index">#${i + 1}</span>
          <span class="finding-title">${f.title}</span>
          <span class="badge badge-${f.severity}">${f.severity.toUpperCase()}</span>
          <span class="finding-score">Risk Score: ${f.riskScore}</span>
        </div>
        <div class="finding-body">
          <div class="finding-section">
            <h4>Description</h4>
            <p>${f.description}</p>
          </div>
          <div class="finding-section">
            <h4>Impact</h4>
            <p>${f.impact}</p>
          </div>
          ${f.evidence ? `
          <div class="finding-section">
            <h4>Evidence</h4>
            <pre><code>${f.evidence}</code></pre>
          </div>` : ''}
          <div class="finding-section">
            <h4>Remediation</h4>
            <p>${f.remediation.replace(/\n/g, '<br>')}</p>
          </div>
          ${f.references && f.references.length > 0 ? `
          <div class="finding-section">
            <h4>References</h4>
            <ul>
              ${f.references.map(ref => `<li><a href="${ref}" target="_blank">${ref}</a></li>`).join('')}
            </ul>
          </div>` : ''}
        </div>
      </div>
    `).join('');

    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Dragon Security Report - ${scan.assetName}</title>
      <style>
        body {
          font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
          background-color: #0d0f14;
          color: #e2e8f0;
          margin: 0;
          padding: 40px;
        }
        .container {
          max-width: 1000px;
          margin: 0 auto;
        }
        .header {
          border-bottom: 2px solid #1f2937;
          padding-bottom: 20px;
          margin-bottom: 30px;
        }
        .title-area {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        .logo {
          font-size: 28px;
          font-weight: bold;
          color: #00f0ff;
          letter-spacing: 1.5px;
        }
        .report-subtitle {
          color: #94a3b8;
          font-size: 14px;
        }
        .summary-grid {
          display: grid;
          grid-template-columns: 2fr 1fr;
          gap: 20px;
          margin-bottom: 40px;
        }
        .card {
          background-color: #151821;
          border: 1px solid #1f2430;
          border-radius: 8px;
          padding: 20px;
        }
        .stat-grid {
          display: grid;
          grid-template-columns: repeat(5, 1fr);
          gap: 10px;
          text-align: center;
          margin-top: 15px;
        }
        .stat-box {
          border-radius: 6px;
          padding: 10px 5px;
          font-weight: bold;
        }
        .stat-val {
          font-size: 24px;
          display: block;
        }
        .stat-lbl {
          font-size: 10px;
          text-transform: uppercase;
          opacity: 0.8;
        }
        .bg-critical { background-color: rgba(244, 63, 94, 0.15); color: #f43f5e; border: 1px solid rgba(244, 63, 94, 0.3); }
        .bg-high { background-color: rgba(139, 92, 246, 0.15); color: #8b5cf6; border: 1px solid rgba(139, 92, 246, 0.3); }
        .bg-medium { background-color: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.3); }
        .bg-low { background-color: rgba(59, 130, 246, 0.15); color: #3b82f6; border: 1px solid rgba(59, 130, 246, 0.3); }
        .bg-info { background-color: rgba(156, 163, 175, 0.15); color: #9ca3af; border: 1px solid rgba(156, 163, 175, 0.3); }
        
        .finding-card {
          background-color: #151821;
          border: 1px solid #1f2430;
          border-radius: 8px;
          margin-bottom: 25px;
          overflow: hidden;
          page-break-inside: avoid;
        }
        .finding-header {
          padding: 15px 20px;
          background-color: #1b1f2e;
          display: flex;
          align-items: center;
          border-bottom: 1px solid #1f2430;
        }
        .finding-index {
          font-weight: bold;
          color: #94a3b8;
          margin-right: 15px;
        }
        .finding-title {
          font-weight: bold;
          font-size: 16px;
          flex-grow: 1;
        }
        .badge {
          padding: 4px 10px;
          font-size: 11px;
          font-weight: bold;
          border-radius: 4px;
          margin-right: 15px;
        }
        .badge-critical { background-color: #f43f5e; color: white; }
        .badge-high { background-color: #8b5cf6; color: white; }
        .badge-medium { background-color: #f59e0b; color: white; }
        .badge-low { background-color: #3b82f6; color: white; }
        .badge-info { background-color: #9ca3af; color: white; }
        
        .finding-score {
          font-weight: bold;
          color: #00f0ff;
          font-size: 13px;
        }
        .finding-body {
          padding: 20px;
        }
        .finding-section {
          margin-bottom: 15px;
        }
        .finding-section:last-child {
          margin-bottom: 0;
        }
        .finding-section h4 {
          margin: 0 0 5px 0;
          font-size: 13px;
          color: #94a3b8;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .finding-section p {
          margin: 0;
          font-size: 14px;
          line-height: 1.5;
        }
        pre {
          background-color: #0a0b0d;
          padding: 12px;
          border-radius: 6px;
          border: 1px solid #1f2430;
          overflow-x: auto;
          margin: 5px 0 0 0;
        }
        code {
          font-family: 'Fira Code', 'Courier New', monospace;
          font-size: 13px;
          color: #38bdf8;
        }
        ul {
          margin: 5px 0 0 0;
          padding-left: 20px;
        }
        li {
          font-size: 13px;
          margin-bottom: 3px;
        }
        a {
          color: #00f0ff;
          text-decoration: none;
        }
        a:hover {
          text-decoration: underline;
        }
        
        @media print {
          body {
            background-color: white;
            color: black;
            padding: 20px;
          }
          .card, .finding-card {
            border: 1px solid #d1d5db;
            background-color: white;
            color: black;
          }
          .finding-header {
            background-color: #f3f4f6;
            border-bottom: 1px solid #d1d5db;
          }
          pre {
            background-color: #f9fafb;
            border: 1px solid #d1d5db;
          }
          code {
            color: #0369a1;
          }
          a {
            color: #0284c7;
          }
          .logo {
            color: #0284c7;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <div class="title-area">
            <div class="logo">DRAGON SECURITY PLATFORM</div>
            <div class="report-subtitle">EXECUTIVE ASSESSMENT REPORT</div>
          </div>
        </div>

        <div class="summary-grid">
          <div class="card">
            <h3>Assessment Metadata</h3>
            <table style="width: 100%; font-size: 14px; border-collapse: collapse;">
              <tr>
                <td style="padding: 6px 0; font-weight: bold; color: #94a3b8; width: 150px;">Asset Name:</td>
                <td style="padding: 6px 0;">${scan.assetName}</td>
              </tr>
              <tr>
                <td style="padding: 6px 0; font-weight: bold; color: #94a3b8;">Target URI:</td>
                <td style="padding: 6px 0; font-family: monospace; color: #00f0ff;">${scan.assetId}</td>
              </tr>
              <tr>
                <td style="padding: 6px 0; font-weight: bold; color: #94a3b8;">Scan Date:</td>
                <td style="padding: 6px 0;">${dateStr}</td>
              </tr>
              <tr>
                <td style="padding: 6px 0; font-weight: bold; color: #94a3b8;">Scope Modules:</td>
                <td style="padding: 6px 0;">${scan.modules.join(', ')}</td>
              </tr>
            </table>
          </div>
          
          <div class="card">
            <h3>Vulnerability Stats</h3>
            <div class="stat-grid">
              <div class="stat-box bg-critical">
                <span class="stat-val">${severityCount.critical}</span>
                <span class="stat-lbl">Crit</span>
              </div>
              <div class="stat-box bg-high">
                <span class="stat-val">${severityCount.high}</span>
                <span class="stat-lbl">High</span>
              </div>
              <div class="stat-box bg-medium">
                <span class="stat-val">${severityCount.medium}</span>
                <span class="stat-lbl">Med</span>
              </div>
              <div class="stat-box bg-low">
                <span class="stat-val">${severityCount.low}</span>
                <span class="stat-lbl">Low</span>
              </div>
              <div class="stat-box bg-info">
                <span class="stat-val">${severityCount.info}</span>
                <span class="stat-lbl">Info</span>
              </div>
            </div>
            <div style="margin-top: 15px; text-align: center; font-size: 13px;">
              Total Issues Identified: <strong>${totalFindings}</strong>
            </div>
          </div>
        </div>

        ${(() => {
          let complianceSectionHtml = '';
          if (scan.compliance) {
            const detailsRows = scan.compliance.details.map(d => `
              <tr style="border-bottom: 1px solid #1f2430; font-size: 12px;">
                <td style="padding: 10px; font-weight: bold; color: #e2e8f0;">${d.category}</td>
                <td style="padding: 10px; font-family: monospace; color: #94a3b8;">${d.control}</td>
                <td style="padding: 10px; color: #94a3b8;">${d.description}</td>
                <td style="padding: 10px; text-align: center;">
                  <span class="badge" style="background-color: ${d.status === 'pass' ? '#10b981' : '#f43f5e'}; color: white; display: inline-block; margin: 0; min-width: 60px; text-align: center;">
                    ${d.status.toUpperCase()}
                  </span>
                </td>
              </tr>
            `).join('');

            complianceSectionHtml = `
              <div class="card" style="margin-top: 30px; margin-bottom: 40px; page-break-inside: avoid;">
                <h3 style="color: #00f0ff; margin-top: 0;">Compliance Evaluation Matrices</h3>
                <div style="display: flex; gap: 40px; margin-bottom: 25px; align-items: center; justify-content: space-around;">
                  <div style="text-align: center;">
                    <span style="font-size: 12px; text-transform: uppercase; color: #94a3b8; display: block; margin-bottom: 5px;">OWASP ASVS Score</span>
                    <div style="font-size: 36px; font-weight: 900; color: #00f0ff;">${scan.compliance.owaspScore}%</div>
                  </div>
                  <div style="text-align: center;">
                    <span style="font-size: 12px; text-transform: uppercase; color: #94a3b8; display: block; margin-bottom: 5px;">CIS Container Score</span>
                    <div style="font-size: 36px; font-weight: 900; color: #8b5cf6;">${scan.compliance.cisScore}%</div>
                  </div>
                </div>
                <table style="width: 100%; border-collapse: collapse; text-align: left; margin-top: 15px;">
                  <thead>
                    <tr style="background-color: #1b1f2e; border-bottom: 2px solid #1f2430; color: #94a3b8; font-size: 10px; text-transform: uppercase;">
                      <th style="padding: 10px;">Category</th>
                      <th style="padding: 10px;">Control</th>
                      <th style="padding: 10px;">Requirement Description</th>
                      <th style="padding: 10px; text-align: center; width: 80px;">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${detailsRows}
                  </tbody>
                </table>
              </div>
            `;
          }

          if (reportType === 'compliance') {
            return `
              <h2>Compliance Assessment Summary</h2>
              ${complianceSectionHtml || `
                <div class="card" style="text-align: center; padding: 40px;">
                  <p style="font-size: 14px; margin: 0; color: #94a3b8;">No compliance metrics recorded for this scan.</p>
                </div>
              `}
              
              <h2 style="margin-top: 40px;">Supporting Security Findings</h2>
              ${totalFindings === 0 ? `
                <div class="card" style="text-align: center; padding: 40px;">
                  <p style="font-size: 16px; margin: 0; color: #10b981;">[+] No supporting vulnerabilities were detected during this security scan.</p>
                </div>
              ` : findingsHtml}
            `;
          } else {
            return `
              <h2>Detailed Vulnerability Analysis</h2>
              ${totalFindings === 0 ? `
                <div class="card" style="text-align: center; padding: 40px;">
                  <p style="font-size: 16px; margin: 0; color: #10b981;">[+] No vulnerabilities were detected during this security scan.</p>
                </div>
              ` : findingsHtml}
              
              ${scan.compliance ? `
                <h2 style="margin-top: 40px;">Compliance Evaluation Matrices</h2>
                ${complianceSectionHtml}
              ` : ''}
            `;
          }
        })()}
      </div>
    </body>
    </html>
    `;
  }

  // Exports report to HTML file
  exportHtml(scan: Scan, filePath: string, reportType?: 'audit' | 'compliance'): boolean {
    try {
      const findings = dbService.getFindings().filter(f => f.scanId === scan.id);
      const html = this.generateHtmlReport(scan, findings, reportType);
      fs.writeFileSync(filePath, html, 'utf-8');
      return true;
    } catch (e) {
      console.error('HTML report generation failed:', e);
      return false;
    }
  }

  // Exports report to JSON file
  exportJson(scan: Scan, filePath: string): boolean {
    try {
      const findings = dbService.getFindings().filter(f => f.scanId === scan.id);
      const output = {
        scanId: scan.id,
        assetId: scan.assetId,
        assetName: scan.assetName,
        date: scan.startedAt,
        summary: scan.stats,
        findings: findings.map(f => ({
          title: f.title,
          severity: f.severity,
          riskScore: f.riskScore,
          description: f.description,
          impact: f.impact,
          remediation: f.remediation,
          evidence: f.evidence,
          references: f.references
        }))
      };
      fs.writeFileSync(filePath, JSON.stringify(output, null, 2), 'utf-8');
      return true;
    } catch (e) {
      console.error('JSON report generation failed:', e);
      return false;
    }
  }

  // Exports report to CSV file
  exportCsv(scan: Scan, filePath: string): boolean {
    try {
      const findings = dbService.getFindings().filter(f => f.scanId === scan.id);
      const escape = (val: string) => `"${val.replace(/"/g, '""')}"`;
      
      let csvContent = 'Index,Title,Severity,Risk Score,Description,Impact,Remediation,Evidence\n';
      findings.forEach((f, i) => {
        csvContent += [
          i + 1,
          escape(f.title),
          escape(f.severity),
          f.riskScore,
          escape(f.description),
          escape(f.impact),
          escape(f.remediation),
          escape(f.evidence)
        ].join(',') + '\n';
      });
      
      fs.writeFileSync(filePath, csvContent, 'utf-8');
      return true;
    } catch (e) {
      console.error('CSV report generation failed:', e);
      return false;
    }
  }

  // Electron printToPDF runner
  async exportPdf(scan: Scan, filePath: string, reportType?: 'audit' | 'compliance'): Promise<boolean> {
    return new Promise(async (resolve) => {
      try {
        const findings = dbService.getFindings().filter(f => f.scanId === scan.id);
        const html = this.generateHtmlReport(scan, findings, reportType);
        
        // Write HTML to a temporary file
        const tmpHtmlPath = path.join(app.getPath('temp'), `dragon_pdf_report_${scan.id}.html`);
        fs.writeFileSync(tmpHtmlPath, html, 'utf-8');
        
        // Spawn hidden browser window
        const win = new BrowserWindow({
          show: false,
          webPreferences: {
            nodeIntegration: false
          }
        });
        
        win.loadFile(tmpHtmlPath);
        
        win.webContents.on('did-finish-load', async () => {
          try {
            const pdfBuffer = await win.webContents.printToPDF({
              printBackground: true,
              margins: {
                top: 0.5,
                bottom: 0.5,
                left: 0.5,
                right: 0.5
              },
              pageSize: 'A4'
            });
            
            fs.writeFileSync(filePath, pdfBuffer);
            win.close();
            // Cleanup temp html file
            try { fs.unlinkSync(tmpHtmlPath); } catch (e) {}
            resolve(true);
          } catch (pdfErr) {
            console.error('PrintToPDF failed:', pdfErr);
            win.close();
            resolve(false);
          }
        });
      } catch (err) {
        console.error('PDF generation lifecycle failed:', err);
        resolve(false);
      }
    });
  }
}

export const reportService = new ReportService();
