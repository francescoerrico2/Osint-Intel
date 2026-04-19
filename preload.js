// Preload script for Electron
// Provides secure context isolation

const { contextBridge } = require('electron');

// Expose protected methods that allow the renderer process to use
// selected node modules without exposing the entire node environment
contextBridge.exposeInMainWorld('electronAPI', {
  platform: process.platform,
  isElectron: true
});
