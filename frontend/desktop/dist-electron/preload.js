"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const electron_1 = require("electron");
electron_1.contextBridge.exposeInMainWorld('desktop', {
    platform: process.platform, version: process.versions.electron,
    openExternal: (url) => electron_1.ipcRenderer.invoke('app:open-external', url),
    localSecurity: {
        chooseExecutable: () => electron_1.ipcRenderer.invoke('local:choose'),
        readForCloud: (filePath, expectedSha256) => electron_1.ipcRenderer.invoke('local:read-for-cloud', filePath, expectedSha256),
        quarantine: (filePath) => electron_1.ipcRenderer.invoke('local:quarantine', filePath),
        getDownloadGuardSettings: () => electron_1.ipcRenderer.invoke('local:download-guard-settings'),
        setDownloadGuard: (enabled) => electron_1.ipcRenderer.invoke('local:set-download-guard-settings', enabled),
        onAutoQuarantined: (listener) => {
            const callback = (_event, result) => listener(result);
            electron_1.ipcRenderer.on('local:auto-quarantined', callback);
            return () => electron_1.ipcRenderer.removeListener('local:auto-quarantined', callback);
        },
        sandboxStatus: () => electron_1.ipcRenderer.invoke('local:sandbox-status'),
        openSandbox: (filePath) => electron_1.ipcRenderer.invoke('local:open-sandbox', filePath),
    },
});
