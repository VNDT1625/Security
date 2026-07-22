import { app, BrowserWindow, dialog, ipcMain, shell } from 'electron';
import path from 'node:path';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFile, spawn } from 'node:child_process';

const allowedExtensions = new Set(['.exe', '.msi', '.bat', '.cmd', '.com', '.scr', '.ps1']);
const pendingDownloadInspections = new Set<string>();
const approvedLocalFiles = new Set<string>();
const MAX_CLOUD_SAMPLE_BYTES = 10 * 1024 * 1024;
let downloadsWatcher: fsSync.FSWatcher | undefined;

type DownloadGuardSettings = { autoQuarantineDownloads: boolean };
type QuarantineResult = {
  ok: true;
  path: string;
  originalPath: string;
  note: string;
  report?: LocalFileReport;
};
type LocalFileReport = {
  path: string;
  name: string;
  size: number;
  modifiedAt: string;
  sha256: string;
  signatureStatus: string;
  signer: string;
  risk: 'trusted' | 'unknown';
  reasons: string[];
};

function ps(script: string, args: string[] = []): Promise<string> {
  return new Promise((resolve, reject) => execFile(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script, ...args],
    { windowsHide: true, timeout: 15_000 },
    (error, output, stderr) => error
      ? reject(new Error(String(stderr || error.message)))
      : resolve(String(output).trim()),
  ));
}

function isExecutable(filePath: string) {
  return allowedExtensions.has(path.extname(filePath).toLowerCase());
}

function approveLocalFile(filePath: string) {
  const resolved = path.resolve(filePath);
  approvedLocalFiles.add(resolved);
  // Keep the capability set bounded during long-running desktop sessions.
  if (approvedLocalFiles.size > 32) {
    const oldest = approvedLocalFiles.values().next().value as string | undefined;
    if (oldest) approvedLocalFiles.delete(oldest);
  }
  return resolved;
}

function guardSettingsPath() {
  return path.join(app.getPath('userData'), 'download-guard.json');
}

async function readDownloadGuardSettings(): Promise<DownloadGuardSettings> {
  try {
    const raw = await fs.readFile(guardSettingsPath(), 'utf8');
    const parsed = JSON.parse(raw) as Partial<DownloadGuardSettings>;
    return { autoQuarantineDownloads: parsed.autoQuarantineDownloads === true };
  } catch {
    return { autoQuarantineDownloads: false };
  }
}

async function writeDownloadGuardSettings(
  patch: DownloadGuardSettings,
): Promise<DownloadGuardSettings> {
  await fs.mkdir(app.getPath('userData'), { recursive: true });
  await fs.writeFile(guardSettingsPath(), JSON.stringify(patch, null, 2), 'utf8');
  return patch;
}

async function hashFile(filePath: string) {
  const hash = crypto.createHash('sha256');
  const stream = fsSync.createReadStream(filePath);
  for await (const chunk of stream) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

async function inspectExecutable(filePath: string): Promise<LocalFileReport> {
  const stat = await fs.stat(filePath);
  if (!isExecutable(filePath)) {
    throw new Error('Định dạng này không thuộc nhóm tệp thực thi được hỗ trợ.');
  }
  let signature = { status: 'Unknown', signer: '' };
  try {
    const raw = await ps(
      "$s=Get-AuthenticodeSignature -LiteralPath $args[0]; [pscustomobject]@{status=$s.Status.ToString();signer=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{''}}|ConvertTo-Json -Compress",
      [filePath],
    );
    signature = JSON.parse(raw) as typeof signature;
  } catch {
    // Keep the conservative Unknown verdict if Authenticode is unavailable.
  }
  const suspicious = signature.status !== 'Valid';
  return {
    path: filePath,
    name: path.basename(filePath),
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
  return path.join(app.getPath('userData'), 'quarantine');
}

async function uniqueVaultPath(fileName: string) {
  const dir = vaultDirectory();
  await fs.mkdir(dir, { recursive: true });
  return path.join(dir, `${Date.now()}-${fileName}.quarantine`);
}

async function writeVaultMetadata(target: string, originalPath: string, report?: LocalFileReport) {
  const metadata = {
    originalPath,
    quarantinedAt: new Date().toISOString(),
    report,
  };
  await fs.writeFile(`${target}.json`, JSON.stringify(metadata, null, 2), 'utf8');
}

async function moveToQuarantine(
  sourcePath: string,
  report?: LocalFileReport,
): Promise<QuarantineResult> {
  const source = path.resolve(sourcePath);
  await fs.access(source);
  const target = await uniqueVaultPath(path.basename(source));
  try {
    await fs.rename(source, target);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EXDEV') throw error;
    await fs.copyFile(source, target);
    await fs.unlink(source);
  }
  await fs.chmod(target, 0o400).catch(() => {});
  await writeVaultMetadata(target, source, report);
  return {
    ok: true,
    path: target,
    originalPath: source,
    report,
    note: 'Đã chuyển bản gốc vào kho cô lập. Không chạy file này ngoài Windows Sandbox.',
  };
}

async function copyToQuarantine(sourcePath: string): Promise<QuarantineResult> {
  const source = path.resolve(sourcePath);
  await fs.access(source);
  const target = await uniqueVaultPath(path.basename(source));
  await fs.copyFile(source, target);
  await fs.chmod(target, 0o400).catch(() => {});
  await writeVaultMetadata(target, source);
  return {
    ok: true,
    path: target,
    originalPath: source,
    note: 'Đã sao chép vào kho cô lập. Bản gốc chưa bị xóa để tránh mất dữ liệu.',
  };
}

async function waitForCompletedDownload(filePath: string): Promise<boolean> {
  let previousSize = -1;
  let previousMtime = -1;
  let stableChecks = 0;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 1_000));
    try {
      const stat = await fs.stat(filePath);
      if (!stat.isFile() || stat.size === 0) continue;
      if (stat.size === previousSize && stat.mtimeMs === previousMtime) {
        stableChecks += 1;
        if (stableChecks >= 2) return true;
      } else {
        stableChecks = 0;
        previousSize = stat.size;
        previousMtime = stat.mtimeMs;
      }
    } catch {
      return false;
    }
  }
  return false;
}

function notifyAutoQuarantine(result: QuarantineResult) {
  for (const window of BrowserWindow.getAllWindows()) {
    window.webContents.send('local:auto-quarantined', result);
  }
}

async function inspectNewDownload(filePath: string) {
  const resolved = path.resolve(filePath);
  if (!isExecutable(resolved) || pendingDownloadInspections.has(resolved)) return;
  pendingDownloadInspections.add(resolved);
  try {
    const settings = await readDownloadGuardSettings();
    if (!settings.autoQuarantineDownloads || !(await waitForCompletedDownload(resolved))) return;
    const report = await inspectExecutable(resolved);
    if (report.risk !== 'unknown') return;
    notifyAutoQuarantine(await moveToQuarantine(resolved, report));
  } catch {
    // A browser can rename/delete a partial download while we are waiting.
  } finally {
    pendingDownloadInspections.delete(resolved);
  }
}

function startDownloadsMonitor() {
  if (process.platform !== 'win32' || downloadsWatcher) return;
  const downloads = app.getPath('downloads');
  try {
    downloadsWatcher = fsSync.watch(downloads, (_event, filename) => {
      if (!filename) return;
      const name = filename.toString();
      if (name.endsWith('.crdownload') || name.endsWith('.tmp')) return;
      void inspectNewDownload(path.join(downloads, name));
    });
  } catch {
    // The user can still use manual Local Shield if Downloads is unavailable.
  }
}

async function sandboxStatus() {
  if (process.platform !== 'win32') return { available: false, reason: 'Chỉ hỗ trợ Windows.' };
  const executable = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsSandbox.exe');
  try {
    await fs.access(executable);
    return { available: true, reason: 'Windows Sandbox đã sẵn sàng.' };
  } catch {
    return { available: false, reason: 'Windows Sandbox chưa được bật hoặc phiên bản Windows không hỗ trợ.' };
  }
}

function registerIpc() {
  ipcMain.handle('app:open-external', async (_event, value: string) => {
    const url = new URL(value);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('Chỉ cho phép mở liên kết HTTP/HTTPS.');
    await shell.openExternal(url.toString());
    return { ok: true };
  });
  ipcMain.handle('local:choose', async () => {
    const result = await dialog.showOpenDialog({
      title: 'Chọn tệp thực thi để kiểm tra',
      properties: ['openFile'],
      filters: [{ name: 'Tệp thực thi', extensions: ['exe', 'msi', 'bat', 'cmd', 'com', 'scr', 'ps1'] }],
    });
    if (result.canceled) return null;
    const source = path.resolve(result.filePaths[0]);
    const report = await inspectExecutable(source);
    approveLocalFile(source);
    return report;
  });
  ipcMain.handle(
    'local:read-for-cloud',
    async (_event, filePath: string, expectedSha256: string) => {
      const source = path.resolve(filePath);
      if (!approvedLocalFiles.has(source)) {
        throw new Error('Tệp chưa được người dùng chọn trong Local Shield.');
      }
      if (!isExecutable(source)) {
        throw new Error('Chỉ cho phép gửi tệp thực thi Windows đã được kiểm tra.');
      }
      const stat = await fs.stat(source);
      if (!stat.isFile() || stat.size === 0) throw new Error('Tệp không hợp lệ hoặc đã bị di chuyển.');
      if (stat.size > MAX_CLOUD_SAMPLE_BYTES) {
        throw new Error('Tệp vượt giới hạn 10 MB của Cloud Lab.');
      }
      const currentSha256 = await hashFile(source);
      if (!expectedSha256 || currentSha256 !== expectedSha256.toLowerCase()) {
        approvedLocalFiles.delete(source);
        throw new Error('Tệp đã thay đổi sau lần kiểm tra tĩnh. Hãy chọn và kiểm tra lại.');
      }
      const bytes = await fs.readFile(source);
      return {
        filename: path.basename(source),
        sha256: currentSha256,
        data: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
      };
    },
  );
  ipcMain.handle('local:quarantine', async (_event, filePath: string) => copyToQuarantine(filePath));
  ipcMain.handle('local:download-guard-settings', readDownloadGuardSettings);
  ipcMain.handle('local:set-download-guard-settings', async (_event, enabled: boolean) => {
    return writeDownloadGuardSettings({ autoQuarantineDownloads: enabled === true });
  });
  ipcMain.handle('local:sandbox-status', sandboxStatus);
  ipcMain.handle('local:open-sandbox', async (_event, filePath: string) => {
    const status = await sandboxStatus();
    if (!status.available) throw new Error(status.reason);
    const source = path.resolve(filePath);
    await fs.access(source);
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'armor-sandbox-'));
    const sample = path.join(directory, path.basename(source));
    await fs.copyFile(source, sample);
    const config = path.join(directory, 'AI-Security-Armor.wsb');
    const escaped = directory.replace(/&/g, '&amp;');
    await fs.writeFile(config, `<Configuration><Networking>Disable</Networking><ClipboardRedirection>Disable</ClipboardRedirection><PrinterRedirection>Disable</PrinterRedirection><MappedFolders><MappedFolder><HostFolder>${escaped}</HostFolder><SandboxFolder>C:\\ArmorSample</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder></MappedFolders><LogonCommand><Command>explorer.exe C:\\ArmorSample</Command></LogonCommand></Configuration>`);
    spawn(path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsSandbox.exe'), [config], { detached: true, stdio: 'ignore', windowsHide: false }).unref();
    return { ok: true, note: 'Đã mở Windows Sandbox: mạng, clipboard và máy in đều bị tắt. Tệp chưa tự động chạy.' };
  });
}

function createWindow() {
  const window = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1050,
    minHeight: 680,
    backgroundColor: '#070b12',
    title: 'AI Security Armor',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  window.removeMenu();
  window.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://')) shell.openExternal(url);
    return { action: 'deny' };
  });
  const devUrl = process.env.VITE_DEV_SERVER_URL;
  if (devUrl) window.loadURL(devUrl);
  else window.loadFile(path.join(__dirname, '..', 'dist', 'index.html'));
}

app.whenReady().then(() => {
  registerIpc();
  startDownloadsMonitor();
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
app.on('before-quit', () => downloadsWatcher?.close());
