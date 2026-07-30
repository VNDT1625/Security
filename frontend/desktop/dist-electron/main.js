"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const electron_1 = require("electron");
const node_path_1 = __importDefault(require("node:path"));
const promises_1 = __importDefault(require("node:fs/promises"));
const node_fs_1 = __importDefault(require("node:fs"));
const node_os_1 = __importDefault(require("node:os"));
const node_crypto_1 = __importDefault(require("node:crypto"));
const node_child_process_1 = require("node:child_process");
const allowedExtensions = new Set(['.exe', '.msi', '.bat', '.cmd', '.com', '.scr', '.ps1']);
const pendingDownloadInspections = new Set();
const approvedLocalFiles = new Set();
const MAX_CLOUD_SAMPLE_BYTES = 10 * 1024 * 1024;
let downloadsWatcher;
function ps(script, args = []) {
    return new Promise((resolve, reject) => (0, node_child_process_1.execFile)('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script, ...args], { windowsHide: true, timeout: 15000 }, (error, output, stderr) => error
        ? reject(new Error(String(stderr || error.message)))
        : resolve(String(output).trim())));
}
function isExecutable(filePath) {
    return allowedExtensions.has(node_path_1.default.extname(filePath).toLowerCase());
}
function approveLocalFile(filePath) {
    const resolved = node_path_1.default.resolve(filePath);
    approvedLocalFiles.add(resolved);
    // Keep the capability set bounded during long-running desktop sessions.
    if (approvedLocalFiles.size > 32) {
        const oldest = approvedLocalFiles.values().next().value;
        if (oldest)
            approvedLocalFiles.delete(oldest);
    }
    return resolved;
}
function guardSettingsPath() {
    return node_path_1.default.join(electron_1.app.getPath('userData'), 'download-guard.json');
}
async function readDownloadGuardSettings() {
    try {
        const raw = await promises_1.default.readFile(guardSettingsPath(), 'utf8');
        const parsed = JSON.parse(raw);
        return { autoQuarantineDownloads: parsed.autoQuarantineDownloads === true };
    }
    catch {
        return { autoQuarantineDownloads: false };
    }
}
async function writeDownloadGuardSettings(patch) {
    await promises_1.default.mkdir(electron_1.app.getPath('userData'), { recursive: true });
    await promises_1.default.writeFile(guardSettingsPath(), JSON.stringify(patch, null, 2), 'utf8');
    return patch;
}
async function hashFile(filePath) {
    const hash = node_crypto_1.default.createHash('sha256');
    const stream = node_fs_1.default.createReadStream(filePath);
    for await (const chunk of stream)
        hash.update(chunk);
    return hash.digest('hex');
}
async function inspectExecutable(filePath) {
    const stat = await promises_1.default.stat(filePath);
    if (!isExecutable(filePath)) {
        throw new Error('Định dạng này không thuộc nhóm tệp thực thi được hỗ trợ.');
    }
    let signature = { status: 'Unknown', signer: '' };
    try {
        const raw = await ps("$s=Get-AuthenticodeSignature -LiteralPath $args[0]; [pscustomobject]@{status=$s.Status.ToString();signer=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{''}}|ConvertTo-Json -Compress", [filePath]);
        signature = JSON.parse(raw);
    }
    catch {
        // Keep the conservative Unknown verdict if Authenticode is unavailable.
    }
    const suspicious = signature.status !== 'Valid';
    return {
        path: filePath,
        name: node_path_1.default.basename(filePath),
        size: stat.size,
        modifiedAt: stat.mtime.toISOString(),
        sha256: await hashFile(filePath),
        signatureStatus: signature.status,
        signer: signature.signer,
        risk: suspicious ? 'unknown' : 'trusted',
        reasons: suspicious
            ? ['Tệp không có chữ ký số hợp lệ', 'Chưa chạy tệp; cần kiểm tra trong môi trường cô lập']
            : ['Chữ ký Authenticode hợp lệ', 'Danh tính nhà phát hành đã được Windows xác minh'],
    };
}
function vaultDirectory() {
    return node_path_1.default.join(electron_1.app.getPath('userData'), 'quarantine');
}
async function uniqueVaultPath(fileName) {
    const dir = vaultDirectory();
    await promises_1.default.mkdir(dir, { recursive: true });
    return node_path_1.default.join(dir, `${Date.now()}-${fileName}.quarantine`);
}
async function writeVaultMetadata(target, originalPath, report) {
    const metadata = {
        originalPath,
        quarantinedAt: new Date().toISOString(),
        report,
    };
    await promises_1.default.writeFile(`${target}.json`, JSON.stringify(metadata, null, 2), 'utf8');
}
async function moveToQuarantine(sourcePath, report) {
    const source = node_path_1.default.resolve(sourcePath);
    await promises_1.default.access(source);
    const target = await uniqueVaultPath(node_path_1.default.basename(source));
    try {
        await promises_1.default.rename(source, target);
    }
    catch (error) {
        if (error.code !== 'EXDEV')
            throw error;
        await promises_1.default.copyFile(source, target);
        await promises_1.default.unlink(source);
    }
    await promises_1.default.chmod(target, 0o400).catch(() => { });
    await writeVaultMetadata(target, source, report);
    return {
        ok: true,
        path: target,
        originalPath: source,
        report,
        note: 'Đã chuyển bản gốc vào kho cô lập. Không chạy file này ngoài Windows Sandbox.',
    };
}
async function copyToQuarantine(sourcePath) {
    const source = node_path_1.default.resolve(sourcePath);
    await promises_1.default.access(source);
    const target = await uniqueVaultPath(node_path_1.default.basename(source));
    await promises_1.default.copyFile(source, target);
    await promises_1.default.chmod(target, 0o400).catch(() => { });
    await writeVaultMetadata(target, source);
    return {
        ok: true,
        path: target,
        originalPath: source,
        note: 'Đã sao chép vào kho cô lập. Bản gốc chưa bị xóa để tránh mất dữ liệu.',
    };
}
async function waitForCompletedDownload(filePath) {
    let previousSize = -1;
    let previousMtime = -1;
    let stableChecks = 0;
    for (let attempt = 0; attempt < 20; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        try {
            const stat = await promises_1.default.stat(filePath);
            if (!stat.isFile() || stat.size === 0)
                continue;
            if (stat.size === previousSize && stat.mtimeMs === previousMtime) {
                stableChecks += 1;
                if (stableChecks >= 2)
                    return true;
            }
            else {
                stableChecks = 0;
                previousSize = stat.size;
                previousMtime = stat.mtimeMs;
            }
        }
        catch {
            return false;
        }
    }
    return false;
}
function notifyAutoQuarantine(result) {
    for (const window of electron_1.BrowserWindow.getAllWindows()) {
        window.webContents.send('local:auto-quarantined', result);
    }
}
async function inspectNewDownload(filePath) {
    const resolved = node_path_1.default.resolve(filePath);
    if (!isExecutable(resolved) || pendingDownloadInspections.has(resolved))
        return;
    pendingDownloadInspections.add(resolved);
    try {
        const settings = await readDownloadGuardSettings();
        if (!settings.autoQuarantineDownloads || !(await waitForCompletedDownload(resolved)))
            return;
        const report = await inspectExecutable(resolved);
        if (report.risk !== 'unknown')
            return;
        notifyAutoQuarantine(await moveToQuarantine(resolved, report));
    }
    catch {
        // A browser can rename/delete a partial download while we are waiting.
    }
    finally {
        pendingDownloadInspections.delete(resolved);
    }
}
function startDownloadsMonitor() {
    if (process.platform !== 'win32' || downloadsWatcher)
        return;
    const downloads = electron_1.app.getPath('downloads');
    try {
        downloadsWatcher = node_fs_1.default.watch(downloads, (_event, filename) => {
            if (!filename)
                return;
            const name = filename.toString();
            if (name.endsWith('.crdownload') || name.endsWith('.tmp'))
                return;
            void inspectNewDownload(node_path_1.default.join(downloads, name));
        });
    }
    catch {
        // The user can still use manual Local Shield if Downloads is unavailable.
    }
}
async function sandboxStatus() {
    if (process.platform !== 'win32')
        return { available: false, reason: 'Chỉ hỗ trợ Windows.' };
    const executable = node_path_1.default.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsSandbox.exe');
    try {
        await promises_1.default.access(executable);
        return { available: true, reason: 'Windows Sandbox đã sẵn sàng.' };
    }
    catch {
        return { available: false, reason: 'Windows Sandbox chưa được bật hoặc phiên bản Windows không hỗ trợ.' };
    }
}
function registerIpc() {
    electron_1.ipcMain.handle('app:open-external', async (_event, value) => {
        const url = new URL(value);
        if (url.protocol !== 'https:' && url.protocol !== 'http:')
            throw new Error('Chỉ cho phép mở liên kết HTTP/HTTPS.');
        await electron_1.shell.openExternal(url.toString());
        return { ok: true };
    });
    electron_1.ipcMain.handle('local:choose', async () => {
        const result = await electron_1.dialog.showOpenDialog({
            title: 'Chọn tệp thực thi để kiểm tra',
            properties: ['openFile'],
            filters: [{ name: 'Tệp thực thi', extensions: ['exe', 'msi', 'bat', 'cmd', 'com', 'scr', 'ps1'] }],
        });
        if (result.canceled)
            return null;
        const source = node_path_1.default.resolve(result.filePaths[0]);
        const report = await inspectExecutable(source);
        approveLocalFile(source);
        return report;
    });
    electron_1.ipcMain.handle('local:read-for-cloud', async (_event, filePath, expectedSha256) => {
        const source = node_path_1.default.resolve(filePath);
        if (!approvedLocalFiles.has(source)) {
            throw new Error('Tệp chưa được người dùng chọn trong Local Shield.');
        }
        if (!isExecutable(source)) {
            throw new Error('Chỉ cho phép gửi tệp thực thi Windows đã được kiểm tra.');
        }
        const stat = await promises_1.default.stat(source);
        if (!stat.isFile() || stat.size === 0)
            throw new Error('Tệp không hợp lệ hoặc đã bị di chuyển.');
        if (stat.size > MAX_CLOUD_SAMPLE_BYTES) {
            throw new Error('Tệp vượt giới hạn 10 MB của Cloud Lab.');
        }
        const currentSha256 = await hashFile(source);
        if (!expectedSha256 || currentSha256 !== expectedSha256.toLowerCase()) {
            approvedLocalFiles.delete(source);
            throw new Error('Tệp đã thay đổi sau lần kiểm tra tĩnh. Hãy chọn và kiểm tra lại.');
        }
        const bytes = await promises_1.default.readFile(source);
        return {
            filename: node_path_1.default.basename(source),
            sha256: currentSha256,
            data: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
        };
    });
    electron_1.ipcMain.handle('local:quarantine', async (_event, filePath) => copyToQuarantine(filePath));
    electron_1.ipcMain.handle('local:download-guard-settings', readDownloadGuardSettings);
    electron_1.ipcMain.handle('local:set-download-guard-settings', async (_event, enabled) => {
        return writeDownloadGuardSettings({ autoQuarantineDownloads: enabled === true });
    });
    electron_1.ipcMain.handle('local:sandbox-status', sandboxStatus);
    electron_1.ipcMain.handle('local:open-sandbox', async (_event, filePath) => {
        const status = await sandboxStatus();
        if (!status.available)
            throw new Error(status.reason);
        const source = node_path_1.default.resolve(filePath);
        await promises_1.default.access(source);
        const directory = await promises_1.default.mkdtemp(node_path_1.default.join(node_os_1.default.tmpdir(), 'armor-sandbox-'));
        const sample = node_path_1.default.join(directory, node_path_1.default.basename(source));
        await promises_1.default.copyFile(source, sample);
        const config = node_path_1.default.join(directory, 'AI-Security-Armor.wsb');
        const escaped = directory.replace(/&/g, '&amp;');
        await promises_1.default.writeFile(config, `<Configuration><Networking>Disable</Networking><ClipboardRedirection>Disable</ClipboardRedirection><PrinterRedirection>Disable</PrinterRedirection><MappedFolders><MappedFolder><HostFolder>${escaped}</HostFolder><SandboxFolder>C:\\ArmorSample</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder></MappedFolders><LogonCommand><Command>explorer.exe C:\\ArmorSample</Command></LogonCommand></Configuration>`);
        (0, node_child_process_1.spawn)(node_path_1.default.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsSandbox.exe'), [config], { detached: true, stdio: 'ignore', windowsHide: false }).unref();
        return { ok: true, note: 'Đã mở Windows Sandbox: mạng, clipboard và máy in đều bị tắt. Tệp chưa tự động chạy.' };
    });
}
function createWindow() {
    const window = new electron_1.BrowserWindow({
        width: 1440,
        height: 900,
        minWidth: 1050,
        minHeight: 680,
        backgroundColor: '#070b12',
        title: 'AI Security Armor',
        webPreferences: {
            preload: node_path_1.default.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: true,
        },
    });
    window.removeMenu();
    window.webContents.setWindowOpenHandler(({ url }) => {
        if (url.startsWith('https://'))
            electron_1.shell.openExternal(url);
        return { action: 'deny' };
    });
    const devUrl = process.env.VITE_DEV_SERVER_URL;
    if (devUrl)
        window.loadURL(devUrl);
    else
        window.loadFile(node_path_1.default.join(__dirname, '..', 'dist', 'index.html'));
}
electron_1.app.whenReady().then(() => {
    registerIpc();
    startDownloadsMonitor();
    createWindow();
    electron_1.app.on('activate', () => {
        if (electron_1.BrowserWindow.getAllWindows().length === 0)
            createWindow();
    });
});
electron_1.app.on('window-all-closed', () => {
    if (process.platform !== 'darwin')
        electron_1.app.quit();
});
electron_1.app.on('before-quit', () => downloadsWatcher?.close());
