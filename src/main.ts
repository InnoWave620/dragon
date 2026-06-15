import { app, BrowserWindow, ipcMain, dialog } from 'electron';
import path from 'node:path';
import started from 'electron-squirrel-startup';
import { dbService } from './main/db';
import { scannerEngine } from './main/scanner';
import { reportService } from './main/reporter';
import { aiService } from './main/ai';

// Declare global constants from Vite
declare const MAIN_WINDOW_VITE_DEV_SERVER_URL: string;
declare const MAIN_WINDOW_VITE_NAME: string;

// Handle creating/removing shortcuts on Windows when installing/uninstalling.
if (started) {
  app.quit();
}

let mainWindow: BrowserWindow | null = null;

const createWindow = () => {
  // Create the browser window.
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 1024,
    minHeight: 720,
    title: 'Dragon Security Assessment Platform',
    icon: path.join(__dirname, '../../dragon-logo.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true
    },
  });

  // and load the index.html of the app.
  if (MAIN_WINDOW_VITE_DEV_SERVER_URL) {
    mainWindow.loadURL(MAIN_WINDOW_VITE_DEV_SERVER_URL);
  } else {
    mainWindow.loadFile(
      path.join(__dirname, `../renderer/${MAIN_WINDOW_VITE_NAME}/index.html`),
    );
  }

  // Set menu to null or design a custom one
  mainWindow.setMenuBarVisibility(false);
};

// Electron ready hook
app.on('ready', () => {
  setupIpcHandlers();
  createWindow();
});

// Quit when all windows are closed
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

// --- REGISTER IPC HANDLERS ---
function setupIpcHandlers() {
  
  // Database Handlers
  ipcMain.handle('db:get-assets', () => {
    return dbService.getAssets();
  });

  ipcMain.handle('db:add-asset', (_event, asset) => {
    return dbService.addAsset(asset);
  });

  ipcMain.handle('db:delete-asset', (_event, id) => {
    return dbService.deleteAsset(id);
  });

  ipcMain.handle('db:get-scans', () => {
    return dbService.getScans();
  });

  ipcMain.handle('db:delete-scan', (_event, id) => {
    return dbService.deleteScan(id);
  });

  ipcMain.handle('db:clear-scans', () => {
    return dbService.clearScans();
  });

  ipcMain.handle('db:get-findings', () => {
    return dbService.getFindings();
  });

  ipcMain.handle('db:update-finding', (_event, finding) => {
    return dbService.updateFinding(finding);
  });

  ipcMain.handle('db:delete-finding', (_event, id) => {
    return dbService.deleteFinding(id);
  });

  ipcMain.handle('db:delete-findings', (_event, ids) => {
    return dbService.deleteFindings(ids);
  });

  ipcMain.handle('db:clear-findings', () => {
    return dbService.clearFindings();
  });

  // Scanning Engine Handlers
  ipcMain.handle('scan:start', (event, assetId, modules) => {
    const scanId = 'scn_' + Math.random().toString(36).substr(2, 9);
    
    // Print dragon design to terminal console
    const dragonLogo = [
      "    ██████╗ ██████╗  █████╗  ██████╗  ██████╗ ███╗   ██╗",
      "    ██╔══██╗██╔══██╗██╔══██╗██╔════╝ ██╔═══██╗████╗  ██║",
      "    ██║  ██║██████╔╝███████║██║  ███╗██║   ██║██╔██╗ ██║",
      "    ██║  ██║██╔══██╗██╔══██║██║   ██║██║   ██║██║╚██╗██║",
      "    ██████╔╝██║  ██║██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║",
      "    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝"
    ];
    console.log("\n==================================================");
    dragonLogo.forEach(line => console.log(line));
    console.log("[*] Dragon Security Validation & Controlled Simulation Engine Init...");
    console.log("[*] Scan target: " + assetId + " | Modules: " + modules.join(', '));
    console.log("==================================================\n");

    // Call scanner engine
    try {
      scannerEngine.startScan(
        scanId,
        assetId,
        modules,
        (progressScan) => {
          if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('scan:progress', progressScan);
          }
        },
        (logLine) => {
          console.log(logLine);
          if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('scan:log', logLine);
          }
        },
        (completedScan) => {
          console.log(`\n[+] Scan ${scanId} completed with status: ${completedScan.status}\n`);
          if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('scan:complete', completedScan);
          }
        }
      );
      return { success: true, scanId };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle('scan:cancel', (_event, scanId) => {
    scannerEngine.cancelScan(scanId);
    return true;
  });

  // Dialog Handler to select save path
  ipcMain.handle('dialog:save-path', async (_event, title, defaultName, filters) => {
    if (!mainWindow) return null;
    const { filePath } = await dialog.showSaveDialog(mainWindow, {
      title,
      defaultPath: path.join(app.getPath('downloads'), defaultName),
      filters
    });
    return filePath;
  });

  // Report Export Handler
  ipcMain.handle('report:export', async (_event, scanId, format, filePath, reportType) => {
    const scan = dbService.getScan(scanId);
    if (!scan) return false;
    
    if (format === 'html') {
      return reportService.exportHtml(scan, filePath, reportType);
    } else if (format === 'json') {
      return reportService.exportJson(scan, filePath);
    } else if (format === 'csv') {
      return reportService.exportCsv(scan, filePath);
    } else if (format === 'pdf') {
      return await reportService.exportPdf(scan, filePath, reportType);
    }
    
    return false;
  });

  ipcMain.handle('dialog:alert', async (_event, message, type = 'info') => {
    if (!mainWindow) return;
    await dialog.showMessageBox(mainWindow, {
      type: type as any,
      message,
      buttons: ['OK'],
      title: 'Dragon Platform'
    });
  });

  ipcMain.handle('dialog:confirm', async (_event, message, type = 'question') => {
    if (!mainWindow) return false;
    const result = await dialog.showMessageBox(mainWindow, {
      type: type as any,
      message,
      buttons: ['Yes', 'No'],
      defaultId: 1,
      cancelId: 1,
      title: 'Dragon Platform'
    });
    return result.response === 0;
  });

  // AI Assistant Chat Handler
  ipcMain.handle('ai:chat', (_event, message, contextFinding) => {
    return aiService.processChat(message, contextFinding);
  });
}
