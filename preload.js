const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  isElectron: true,
  openFolder: () => ipcRenderer.invoke('dialog:openTarget', 'folder'),
  openTarget: (mode = 'folder') => ipcRenderer.invoke('dialog:openTarget', mode),
  openImage: () => ipcRenderer.invoke('dialog:openTarget', 'image'),
  openExtract: () => ipcRenderer.invoke('dialog:openTarget', 'file')
});
