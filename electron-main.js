const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { startServer } = require('./server');

// Chromium switches for uncapped 120+ FPS high refresh rate
app.commandLine.appendSwitch('disable-frame-rate-limit');
app.commandLine.appendSwitch('enable-gpu-rasterization');
app.commandLine.appendSwitch('enable-zero-copy');
app.commandLine.appendSwitch('ignore-gpu-blocklist');

let mainWindow = null;

async function createWindow(port) {
  mainWindow = new BrowserWindow({
    width: 1560,
    height: 980,
    minWidth: 1080,
    minHeight: 720,
    title: 'REA Studio - Reverse Engineering Anything',
    backgroundColor: '#090d16',
    autoHideMenuBar: true,
    show: true,
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#0a0f1e',
      symbolColor: '#e2e8f0',
      height: 42
    },
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      backgroundThrottling: false
    }
  });

  mainWindow.loadURL(`http://localhost:${port}`);

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    mainWindow.focus();
    mainWindow.setAlwaysOnTop(true);
    setTimeout(() => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.setAlwaysOnTop(false);
        mainWindow.focus();
      }
    }, 250);
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Native dialog handler for Folder, Binary, or Custom Background Image Picker
ipcMain.handle('dialog:openTarget', async (event, mode = 'folder') => {
  if (!mainWindow) return null;
  const isImage = mode === 'image';
  const isFile = mode === 'file' || isImage;
  
  let title = 'Select Application Folder to Analyze with REA';
  let filters;
  
  if (isImage) {
    title = 'Select Custom Background Image (JPG, PNG, GIF, WEBP)';
    filters = [
      { name: 'Images', extensions: ['jpg', 'jpeg', 'png', 'gif', 'webp'] },
      { name: 'All Files', extensions: ['*'] }
    ];
  } else if (isFile) {
    title = 'Select Binary or Package Archive (.asar, .exe, .dll, .js, .zip)';
    filters = [
      { name: 'Supported Targets', extensions: ['asar', 'exe', 'dll', 'js', 'json', 'bin', 'zip'] },
      { name: 'All Files', extensions: ['*'] }
    ];
  }

  const result = await dialog.showOpenDialog(mainWindow, {
    title,
    properties: isFile ? ['openFile', 'dontAddToRecent'] : ['openDirectory', 'dontAddToRecent'],
    filters
  });
  if (result.canceled || !result.filePaths || result.filePaths.length === 0) {
    return null;
  }
  return result.filePaths[0];
});

// Backward compatibility alias
ipcMain.handle('dialog:openFolder', async (event) => {
  return await ipcMain.emit('dialog:openTarget', event, 'folder') || null;
});

app.whenReady().then(async () => {
  try {
    const port = await startServer();
    await createWindow(port);

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        createWindow(port);
      }
    });
  } catch (err) {
    console.error('Failed to initialize REA Studio Desktop:', err);
    dialog.showErrorBox('REA Studio Startup Error', err.message);
    app.quit();
  }
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
