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

  ipcMain.handle('db:get-findings', () => {
    return dbService.getFindings();
  });

  ipcMain.handle('db:update-finding', (_event, finding) => {
    return dbService.updateFinding(finding);
  });

  // Scanning Engine Handlers
  ipcMain.handle('scan:start', (event, assetId, modules) => {
    const scanId = 'scn_' + Math.random().toString(36).substr(2, 9);
    
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
          if (mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('scan:log', logLine);
          }
        },
        (completedScan) => {
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
  ipcMain.handle('report:export', async (_event, scanId, format, filePath) => {
    const scan = dbService.getScan(scanId);
    if (!scan) return false;
    
    if (format === 'html') {
      return reportService.exportHtml(scan, filePath);
    } else if (format === 'json') {
      return reportService.exportJson(scan, filePath);
    } else if (format === 'csv') {
      return reportService.exportCsv(scan, filePath);
    } else if (format === 'pdf') {
      return await reportService.exportPdf(scan, filePath);
    }
    
    return false;
  });

  // AI Assistant Chat Handler
  ipcMain.handle('ai:chat', (_event, message, contextFinding) => {
    return aiService.processChat(message, contextFinding);
  });
}
