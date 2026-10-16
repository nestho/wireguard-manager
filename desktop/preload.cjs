const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("wgm", Object.freeze({
  request: (input) => ipcRenderer.invoke("wgm:request", input),
  openDocs: (baseUrl) => ipcRenderer.invoke("wgm:open-docs", baseUrl),
  closeApp: () => ipcRenderer.invoke("wgm:close"),
}));
