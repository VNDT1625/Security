(() => {
  "use strict";

  const TTL = 30 * 60 * 1000;
  const MAX_EMAIL_CHARS = 20000;
  const MAX_EXE_BYTES = 8 * 1024 * 1024;
  const DEFAULT_THRESHOLD = 60;
  const completed = new Map();
  const inFlight = new Set();
  const rendered = new Map();
  let enabled = false;
  let warningThreshold = DEFAULT_THRESHOLD;
  let timer = null;
  let activeMessageKey = "";
  let scanSequence = 0;
  let preferredMessageRoot = null;

  function runtimeAvailable() {
    try { return Boolean(chrome.runtime?.id && chrome.runtime.sendMessage); } catch { return false; }
  }

  function send(message, timeoutMs = 22000) {
    return new Promise((resolve, reject) => {
      if (!runtimeAvailable()) return reject(new Error("context_invalid"));
      let settled = false;
      const timerId = setTimeout(() => {
        if (!settled) { settled = true; reject(new Error("timeout")); }
      }, timeoutMs);
      try {
        chrome.runtime.sendMessage(message, (response) => {
          if (settled) return;
          settled = true;
          clearTimeout(timerId);
          const error = chrome.runtime.lastError;
          error ? reject(new Error(error.message)) : resolve(response);
        });
      } catch (error) {
        clearTimeout(timerId);
        reject(error);
      }
    });
  }

  function visibleBody() {
    const preferred = preferredMessageRoot?.isConnected
      ? [...preferredMessageRoot.querySelectorAll("div.a3s")]
        .filter((element) => element.offsetParent !== null && element.innerText.trim())
        .at(-1)
      : null;
    if (preferred) return preferred;
    return [...document.querySelectorAll("div.a3s")]
      .filter((element) => element.isConnected && element.offsetParent !== null && element.innerText.trim())
      .at(-1) || null;
  }

  function messageRoot(body) {
    return body.closest(".adn")
      || body.closest("[role=listitem]")
      || body.closest("[data-legacy-message-id], [data-message-id]")
      || body.parentElement;
  }

  function identifyMessage(body) {
    const root = messageRoot(body);
    const sender = root?.querySelector("span.gD")?.getAttribute("email") || "";
    const subject = document.querySelector("h2.hP")?.textContent?.trim() || "";
    const messageId = root?.getAttribute("data-legacy-message-id")
      || root?.getAttribute("data-message-id")
      || root?.querySelector("[data-legacy-message-id]")?.getAttribute("data-legacy-message-id")
      || root?.querySelector("[data-message-id]")?.getAttribute("data-message-id")
      || "";
    return {
      key: messageId || `${location.hash}|${sender}|${subject}|${body.innerText.length}`,
      sender,
      subject,
      root,
    };
  }

  function cachedFinding(key) {
    const entry = completed.get(key);
    if (!entry) return null;
    if (Date.now() - entry.completedAt < TTL) return entry.finding;
    completed.delete(key);
    return null;
  }

  function removeRendered() {
    rendered.forEach((host) => host.remove());
    rendered.clear();
  }

  function renderFinding(key, target, { score, kind, filename = "", reasons = [], loading = false }) {
    if (!target?.isConnected) return;
    rendered.get(key)?.remove();

    const numericScore = Number(score || 0);
    const danger = !loading && numericScore >= 70;
    const warning = !loading && numericScore > warningThreshold;
    const host = document.createElement("div");
    host.dataset.aiArmorFinding = "1";
    host.dataset.aiArmorScore = String(score);
    host.style.cssText = "display:block;margin:8px 0;max-width:100%";
    const shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      *{box-sizing:border-box}.notice{display:grid;grid-template-columns:auto 1fr auto;align-items:start;gap:11px;padding:11px 12px;border:1px solid var(--border);border-left:4px solid var(--accent);border-radius:7px;background:var(--background);color:#1f2937;font:13px/1.45 Roboto,Arial,sans-serif}.score{display:grid;place-items:center;min-width:42px;height:42px;border-radius:6px;background:var(--accent);color:#fff;font-size:16px;font-weight:700}.score small{display:block;margin-top:-7px;font-size:8px;font-weight:600}.title{font-weight:700;color:#111827}.meta{margin-top:1px;color:#4b5563;font-size:11px;overflow-wrap:anywhere}.reasons{margin:6px 0 0;padding:0;list-style:none;color:#374151;font-size:11px}.reasons li+li{margin-top:2px}.reasons li::before{content:"•";margin-right:5px;color:var(--accent)}button{width:26px;height:26px;border:0;border-radius:5px;background:transparent;color:#6b7280;font-size:18px;line-height:1;cursor:pointer}button:hover{background:rgba(15,23,42,.08);color:#111827}button:focus-visible{outline:2px solid #2563eb;outline-offset:2px}
    `;
    const notice = document.createElement("section");
    notice.className = "notice";
    notice.style.setProperty("--accent", loading ? "#2563eb" : danger ? "#b91c1c" : warning ? "#b7791f" : "#15803d");
    notice.style.setProperty("--border", loading ? "#bfdbfe" : danger ? "#fecaca" : warning ? "#fde68a" : "#bbf7d0");
    notice.style.setProperty("--background", loading ? "#eff6ff" : danger ? "#fff7f7" : warning ? "#fffbeb" : "#f0fdf4");
    notice.setAttribute("role", loading ? "status" : "alert");

    const scoreBox = document.createElement("div");
    scoreBox.className = "score";
    scoreBox.append(document.createTextNode(loading ? "…" : String(numericScore)));
    const unit = document.createElement("small");
    unit.textContent = loading ? "AI" : "/100";
    scoreBox.append(unit);

    const copy = document.createElement("div");
    const title = document.createElement("div");
    title.className = "title";
    title.textContent = loading
      ? "AI Security Armor đang kiểm tra email này…"
      : kind === "exe"
      ? `${danger ? "Tệp EXE nguy hiểm" : warning ? "Tệp EXE đáng ngờ" : "Không phát hiện rủi ro trong tệp EXE"}: ${filename}`
      : danger ? "Email này có rủi ro cao" : warning ? "Email này cần được kiểm tra kỹ" : "Email này an toàn";
    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = loading
      ? "Kết quả sẽ tự động xuất hiện tại đây, không cần bấm biểu tượng extension."
      : kind === "exe"
      ? "AI Security Armor đã kiểm tra tĩnh tệp đính kèm, không thực thi tệp."
      : "AI Security Armor chỉ phân tích email bạn đang mở.";
    const reasonList = document.createElement("ul");
    reasonList.className = "reasons";
    reasons.slice(0, 3).forEach((reason) => {
      const item = document.createElement("li");
      item.textContent = reason;
      reasonList.append(item);
    });
    copy.append(title, meta);
    if (reasonList.children.length) copy.append(reasonList);

    const close = document.createElement("button");
    close.type = "button";
    close.textContent = "×";
    close.setAttribute("aria-label", "Ẩn cảnh báo này");
    close.addEventListener("click", () => { host.remove(); rendered.delete(key); });
    notice.append(scoreBox, copy, close);
    shadow.append(style, notice);

    target.parentElement?.insertBefore(host, target);
    if (host.isConnected) rendered.set(key, host);
  }

  function filenameFrom(element) {
    const labels = [
      element.getAttribute?.("download"),
      element.getAttribute?.("data-tooltip"),
      element.getAttribute?.("aria-label"),
      element.getAttribute?.("title"),
      element.querySelector?.(".aV3")?.textContent,
      element.matches?.(".aV3") ? element.textContent : "",
    ].filter(Boolean);
    for (const label of labels) {
      const match = String(label).match(/([^\\/:*?"<>|\r\n]+\.exe)\b/i);
      if (match) return match[1].trim();
    }
    return "";
  }

  // Only Google's own attachment endpoints may be fetched with the user's
  // cookies. Without this an attacker-authored email could point the scanner at
  // any https origin: the extension holds broad host permissions, so the fetch
  // would be CORS-exempt, carry the victim's session, and stream any response
  // beginning with "MZ" to the gateway.
  const GMAIL_ATTACHMENT_HOSTS = new Set([
    "mail.google.com",
    "mail-attachment.googleusercontent.com",
    "drive.google.com",
  ]);

  function downloadUrlFrom(element) {
    // A real Gmail attachment always carries download_url on its chip. Anchors
    // written by the message body do not, and must never be followed.
    const holder = element.closest?.("[download_url]") || element.querySelector?.("[download_url]");
    const encoded = holder?.getAttribute?.("download_url") || "";
    const urlIndex = encoded.search(/https?:\/\//i);
    if (urlIndex < 0) return "";
    try {
      const parsed = new URL(encoded.slice(urlIndex));
      if (parsed.protocol !== "https:") return "";
      if (!GMAIL_ATTACHMENT_HOSTS.has(parsed.hostname)) return "";
      return parsed.href;
    } catch {
      return "";
    }
  }

  function executableAttachments(root) {
    if (!root) return [];
    const records = [];
    const seen = new Set();
    const candidates = root.querySelectorAll("[download_url], [download_url] .aV3, [download_url] [download$='.exe' i]");
    candidates.forEach((candidate) => {
      const filename = filenameFrom(candidate);
      if (!filename) return;
      const block = candidate.closest(".aQH, .aQy, .aZp, [download_url]") || candidate.parentElement || candidate;
      const url = downloadUrlFrom(block) || downloadUrlFrom(candidate);
      if (!url) return;
      const identity = `${filename}|${url}`;
      if (seen.has(identity)) return;
      seen.add(identity);
      records.push({ filename, url, target: block });
    });
    return records;
  }

  function bytesToBase64(bytes) {
    let binary = "";
    const chunkSize = 0x8000;
    for (let index = 0; index < bytes.length; index += chunkSize) {
      binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
    }
    return btoa(binary);
  }

  async function downloadExecutable(attachment) {
    // Re-check at the point of use: the URL travelled through caches and message
    // objects since it was validated, and this is the only credentialed fetch.
    let parsed;
    try {
      parsed = new URL(attachment.url);
    } catch {
      throw new Error("invalid_attachment_url");
    }
    if (parsed.protocol !== "https:" || !GMAIL_ATTACHMENT_HOSTS.has(parsed.hostname)) {
      throw new Error("untrusted_attachment_host");
    }
    const response = await fetch(parsed.href, { credentials: "include", cache: "no-store" });
    if (!response.ok) throw new Error(`download_${response.status}`);
    const declaredSize = Number(response.headers.get("Content-Length")) || 0;
    if (declaredSize > MAX_EXE_BYTES) throw new Error("file_too_large");
    const buffer = await response.arrayBuffer();
    if (buffer.byteLength > MAX_EXE_BYTES) throw new Error("file_too_large");
    const bytes = new Uint8Array(buffer);
    if (bytes.length < 2 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) throw new Error("invalid_exe");
    return bytes;
  }

  async function scanExecutable(message, attachment, sequence) {
    const cacheKey = `exe:${message.key}:${attachment.filename}:${attachment.url}`;
    const previous = cachedFinding(cacheKey);
    if (previous) {
      if (sequence === scanSequence && message.key === activeMessageKey) renderFinding(cacheKey, attachment.target, previous);
      return;
    }
    if (inFlight.has(cacheKey)) return;
    inFlight.add(cacheKey);
    try {
      const bytes = await downloadExecutable(attachment);
      if (sequence !== scanSequence || message.key !== activeMessageKey) return;
      const response = await send({
        type: "ASSESS_EXE_ATTACHMENT",
        filename: attachment.filename,
        mimeType: "application/vnd.microsoft.portable-executable",
        dataBase64: bytesToBase64(bytes),
      });
      const score = Math.round(Math.max(0, Math.min(100, Number(response?.result?.risk_score || 0))));
      if (response?.error || !response?.result) return;
      const finding = {
        score,
        kind: "exe",
        filename: attachment.filename,
        reasons: response.result?.issues || [],
      };
      completed.set(cacheKey, { completedAt: Date.now(), finding });
      if (sequence !== scanSequence || message.key !== activeMessageKey) return;
      renderFinding(cacheKey, attachment.target, finding);
    } catch {
      // Download/API failures remain silent; only actionable bad results are injected into Gmail.
    } finally {
      inFlight.delete(cacheKey);
    }
  }

  async function scanEmail(message, body, sequence) {
    const cacheKey = `email:${message.key}`;
    const previous = cachedFinding(cacheKey);
    if (previous) {
      if (sequence === scanSequence && message.key === activeMessageKey) renderFinding(cacheKey, body, previous);
      return;
    }
    if (inFlight.has(cacheKey)) return;
    inFlight.add(cacheKey);
    renderFinding(cacheKey, body, { score: 0, kind: "email", loading: true });
    try {
      const response = await send({
        type: "ASSESS_TEXT",
        text: body.innerText.slice(0, MAX_EMAIL_CHARS),
        modality: "email",
        metadata: { sender: message.sender, subject: message.subject },
      }, 10000);
      const score = Math.round(Math.max(0, Math.min(1, Number(response?.result?.risk_score || 0))) * 100);
      if (response?.error || !response?.result) return;
      const finding = {
        score,
        kind: "email",
        reasons: response.result?.reasons || [],
      };
      completed.set(cacheKey, { completedAt: Date.now(), finding });
      if (sequence !== scanSequence || message.key !== activeMessageKey) return;
      renderFinding(cacheKey, body, finding);
    } catch {
      rendered.get(cacheKey)?.remove();
      rendered.delete(cacheKey);
    } finally {
      inFlight.delete(cacheKey);
    }
  }

  async function scanOpenMessage() {
    if (!enabled || document.visibilityState !== "visible" || !runtimeAvailable()) return;
    const body = visibleBody();
    if (!body) return;
    const message = identifyMessage(body);
    if (!message.key) return;
    if (message.key !== activeMessageKey) {
      activeMessageKey = message.key;
      scanSequence += 1;
    }
    const sequence = scanSequence;
    await scanEmail(message, body, sequence);
    if (sequence !== scanSequence || message.key !== activeMessageKey) return;
    for (const attachment of executableAttachments(message.root)) {
      await scanExecutable(message, attachment, sequence);
      if (sequence !== scanSequence || message.key !== activeMessageKey) break;
    }
  }

  function schedule(delay = 700) {
    clearTimeout(timer);
    timer = setTimeout(() => void scanOpenMessage(), delay);
  }

  async function refreshSettings() {
    try {
      const settings = await send({ type: "GET_SETTINGS" }, 2500);
      enabled = settings?.protectionEnabled === true
        && settings?.gmailProtection === true
        && settings?.activated === true;
      warningThreshold = Number.isFinite(settings?.warningThreshold) ? settings.warningThreshold : DEFAULT_THRESHOLD;
      if (!enabled) removeRendered();
      else schedule(100);
    } catch {
      enabled = false;
      removeRendered();
    }
  }

  const observer = new MutationObserver(() => { if (enabled) schedule(); });
  observer.observe(document.documentElement, { childList: true, subtree: true });
  document.addEventListener("click", (event) => {
    const candidate = event.target?.closest?.(".adn, [role=listitem], [data-legacy-message-id], [data-message-id]");
    if (candidate) preferredMessageRoot = candidate.closest?.(".adn") || candidate;
    if (enabled) schedule(450);
  }, true);
  document.addEventListener("visibilitychange", () => schedule(100));
  addEventListener("hashchange", () => schedule(100));
  if (runtimeAvailable() && chrome.storage?.onChanged) {
    chrome.storage.onChanged.addListener((changes) => {
      if (changes.protectionEnabled || changes.gmailProtection || changes.extensionActivation || changes.warningThreshold) {
        if (changes.warningThreshold) {
          removeRendered();
        }
        void refreshSettings();
      }
    });
  }
  void refreshSettings();
})();
