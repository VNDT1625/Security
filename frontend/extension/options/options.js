const $ = (id) => document.getElementById(id);
const DEFAULT_GATEWAY = "http://localhost:8000";
const DEFAULT_THRESHOLD = 60;
const normalizedGateway = () => $("gateway").value.trim().replace(/\/$/, "");

function showAccount(activation) {
  const element = $("account-info");
  if (!activation?.valid) { element.hidden = true; return; }
  element.hidden = false;
  const limit = activation.quota.dailyScanLimit >= 999999 ? "Không giới hạn" : activation.quota.dailyScanLimit;
  element.textContent = `${activation.user.displayName} · ${activation.user.email} · Gói ${activation.plan.label} · Đã dùng ${activation.quota.usedToday}/${limit} lượt hôm nay`;
}

function showThreshold(value) { $("threshold-value").textContent = `${value}/100`; }

async function send(message) {
  return new Promise((resolve, reject) => chrome.runtime.sendMessage(message, (response) => {
    const error = chrome.runtime.lastError;
    error ? reject(new Error(error.message)) : resolve(response);
  }));
}

async function load() {
  const settings = await chrome.storage.local.get({
    apiBaseUrl: DEFAULT_GATEWAY,
    extensionApiKey: "",
    extensionActivation: null,
    websiteProtection: true,
    gmailProtection: true,
    warningThreshold: DEFAULT_THRESHOLD,
  });
  $("gateway").value = settings.apiBaseUrl;
  $("api-key").value = settings.extensionApiKey;
  $("website-protection").checked = settings.websiteProtection;
  $("gmail-protection").checked = settings.gmailProtection;
  $("warning-threshold").value = settings.warningThreshold;
  showThreshold(settings.warningThreshold);
  showAccount(settings.extensionActivation);
}

$("warning-threshold").addEventListener("input", (event) => showThreshold(event.target.value));

$("verify-key").addEventListener("click", async () => {
  const key = $("api-key").value.trim();
  const output = $("key-result");
  if (!key) { output.className = "hint bad"; output.textContent = "Vui lòng nhập API key."; return; }
  if (!/^pw_live_[A-Za-z0-9_-]{30,}$/.test(key) || key.includes("*") || key.includes("•")) {
    output.className = "hint bad";
    output.textContent = "Đây không phải secret key đầy đủ. Trên Web App hãy chọn ‘Tạo lại key’, xác nhận, rồi sao chép key mới ngay khi nó xuất hiện.";
    return;
  }
  await chrome.storage.local.set({ extensionApiKey: key, extensionActivation: null, protectionEnabled: false });
  output.className = "hint";
  output.textContent = "Đang xác minh…";
  try {
    const response = await send({ type: "VERIFY_API_KEY" });
    if (response?.error) throw new Error(response.error.status === 401
      ? "Key không khớp dữ liệu máy chủ. Hãy tạo lại key trên Web App và sao chép secret mới ngay sau khi tạo."
      : response.error.message);
    output.className = "hint ok";
    output.textContent = "Xác minh thành công. Extension đã sẵn sàng để bật bảo vệ.";
    showAccount(response.activation);
  } catch (error) {
    await chrome.storage.local.set({ extensionActivation: null, protectionEnabled: false });
    output.className = "hint bad";
    output.textContent = error.message;
    showAccount(null);
  }
});

$("save").addEventListener("click", async () => {
  let gateway;
  try {
    gateway = new URL(normalizedGateway());
    if (!/^https?:$/.test(gateway.protocol)) throw new Error("invalid_protocol");
  } catch {
    $("saved").textContent = "Địa chỉ Gateway không hợp lệ.";
    return;
  }
  await chrome.storage.local.set({
    apiBaseUrl: gateway.toString().replace(/\/$/, ""),
    websiteProtection: $("website-protection").checked,
    gmailProtection: $("gmail-protection").checked,
    warningThreshold: Number($("warning-threshold").value),
  });
  $("saved").textContent = "Đã lưu. Các tab đang mở sẽ dùng cấu hình mới.";
  setTimeout(() => { $("saved").textContent = ""; }, 2200);
});

$("reset").addEventListener("click", async () => {
  $("gateway").value = DEFAULT_GATEWAY;
  $("api-key").value = "";
  $("website-protection").checked = true;
  $("gmail-protection").checked = true;
  $("warning-threshold").value = DEFAULT_THRESHOLD;
  showThreshold(DEFAULT_THRESHOLD);
  showAccount(null);
  await chrome.storage.local.set({
    apiBaseUrl: DEFAULT_GATEWAY,
    extensionApiKey: "",
    extensionActivation: null,
    protectionEnabled: false,
    websiteProtection: true,
    gmailProtection: true,
    warningThreshold: DEFAULT_THRESHOLD,
  });
  $("saved").textContent = "Đã khôi phục mặc định và tắt bảo vệ.";
});

$("test").addEventListener("click", async () => {
  const output = $("test-result");
  output.className = "hint";
  output.textContent = "Đang kiểm tra…";
  const startedAt = performance.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    const response = await fetch(`${normalizedGateway()}/v1/health`, { signal: controller.signal });
    clearTimeout(timer);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    output.className = "hint ok";
    output.textContent = `Kết nối thành công (${Math.round(performance.now() - startedAt)} ms).`;
  } catch (error) {
    output.className = "hint bad";
    output.textContent = error.name === "AbortError" ? "Gateway không phản hồi trong 4 giây." : `Không thể kết nối: ${error.message}`;
  }
});

void load();
