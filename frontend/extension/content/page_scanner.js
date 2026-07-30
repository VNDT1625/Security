(() => {
  "use strict";

  const DEFAULT_THRESHOLD = 60;
  let contextAlive = true;
  let protectionEnabled = false;
  let websiteProtection = true;
  let warningThreshold = DEFAULT_THRESHOLD;
  let currentUrl = location.href;
  let scanToken = 0;
  let warningHost = null;
  let warningGuard = null;
  const dismissedUrls = new Set();

  function isGmail() {
    return location.hostname === "mail.google.com";
  }

  function runtimeAvailable() {
    try {
      return contextAlive && Boolean(chrome.runtime?.id) && typeof chrome.runtime.sendMessage === "function";
    } catch {
      return false;
    }
  }

  function disableStaleContext() {
    contextAlive = false;
    clearWarning();
  }

  function send(message, timeoutMs = 65000) {
    return new Promise((resolve, reject) => {
      if (!runtimeAvailable()) {
        disableStaleContext();
        reject(new Error("context_invalid"));
        return;
      }
      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          reject(new Error("timeout"));
        }
      }, timeoutMs);
      try {
        chrome.runtime.sendMessage(message, (response) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          const error = chrome.runtime.lastError;
          if (error) {
            if (/context invalidated|receiving end/i.test(error.message || "")) disableStaleContext();
            reject(new Error(error.message));
          } else resolve(response);
        });
      } catch (error) {
        clearTimeout(timer);
        disableStaleContext();
        reject(error);
      }
    });
  }

  // The background strips credential-bearing query parameters and the fragment
  // before scanning, so a returned entry.url is not byte-identical to
  // location.href. Identity for "is this result about the page I am on" is
  // therefore origin + path, which is also what the verdict was based on.
  function samePage(a, b) {
    try {
      const left = new URL(a);
      const right = new URL(b);
      return left.origin === right.origin && left.pathname === right.pathname;
    } catch {
      return a === b;
    }
  }

  function clearWarning() {
    warningGuard?.disconnect();
    warningGuard = null;
    warningHost?.remove();
    warningHost = null;
  }

  function riskCopy(level) {
    if (level === "danger") return {
      label: "RỦI RO CAO",
      title: "Trang này có dấu hiệu nguy hiểm",
      accent: "#dc2626",
      background: "#3b0d12",
    };
    return {
      label: "CẦN THẬN TRỌNG",
      title: "Trang này có nhiều dấu hiệu đáng ngờ",
      accent: "#f59e0b",
      background: "#36230a",
    };
  }

  function showWarning(entry) {
    const score = Number(entry?.score || 0);
    const level = entry?.level || "safe";
    if (
      !protectionEnabled
      || !websiteProtection
      || entry?.status !== "complete"
      || !samePage(entry.url, location.href)
      || level === "safe"
      || (!entry?.result?.decision && score <= warningThreshold)
      || dismissedUrls.has(entry.url)
    ) {
      clearWarning();
      return;
    }

    clearWarning();
    const copy = riskCopy(level);
    const host = document.createElement("div");
    // Deliberately unlabelled. The shadow root is closed, but the host element
    // lives in the page's light DOM, so a stable marker attribute let the very
    // page being warned about find and delete the banner:
    //   new MutationObserver(() => document
    //     .querySelectorAll('[data-ai-armor-page-warning]')
    //     .forEach((n) => n.remove())).observe(document.documentElement, ...)
    host.style.cssText = "position:fixed;top:12px;left:50%;z-index:2147483647;width:min(860px,calc(100vw - 24px));transform:translateX(-50%);pointer-events:none";
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      *{box-sizing:border-box}.bar{display:grid;grid-template-columns:auto 1fr auto;gap:12px;align-items:start;padding:13px 14px;border:1px solid color-mix(in srgb,var(--accent) 55%,#334155);border-radius:10px;background:var(--background);box-shadow:0 12px 32px rgba(2,6,23,.34);color:#f8fafc;pointer-events:auto;font:13px/1.45 Inter,system-ui,-apple-system,"Segoe UI",sans-serif}.score{display:grid;place-items:center;min-width:50px;height:50px;border:1px solid var(--accent);border-radius:8px;background:rgba(2,6,23,.35);color:#fff;font-size:19px;font-weight:750}.score small{display:block;margin-top:-8px;color:#cbd5e1;font-size:9px;font-weight:600}.copy{min-width:0}.label{color:var(--accent);font-size:10px;font-weight:800;letter-spacing:.1em}.title{margin:2px 0 0;font-size:14px;font-weight:700}.host{margin-top:2px;color:#cbd5e1;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.reasons{display:flex;flex-wrap:wrap;gap:5px 12px;margin:7px 0 0;padding:0;list-style:none;color:#e2e8f0;font-size:11px}.reasons li::before{content:"•";margin-right:5px;color:var(--accent)}button{display:grid;place-items:center;width:30px;height:30px;border:0;border-radius:6px;background:transparent;color:#cbd5e1;font:20px/1 system-ui;cursor:pointer}button:hover{background:rgba(255,255,255,.1);color:#fff}button:focus-visible{outline:2px solid #93c5fd;outline-offset:2px}@media(max-width:560px){.bar{grid-template-columns:auto 1fr}.close{position:absolute;right:6px;top:6px}.score{min-width:44px;height:44px}.reasons{display:none}.title{padding-right:24px}}
    `;
    const bar = document.createElement("section");
    bar.className = "bar";
    bar.style.setProperty("--accent", copy.accent);
    bar.style.setProperty("--background", copy.background);
    bar.setAttribute("role", "alert");
    bar.setAttribute("aria-label", `AI Security Armor cảnh báo: ${copy.label}`);

    const scoreBox = document.createElement("div");
    scoreBox.className = "score";
    scoreBox.append(document.createTextNode(level === "danger" ? "⛔" : "⚠"));

    const content = document.createElement("div");
    content.className = "copy";
    const label = document.createElement("div");
    label.className = "label";
    label.textContent = `AI SECURITY ARMOR · ${copy.label}`;
    const title = document.createElement("div");
    title.className = "title";
    title.textContent = copy.title;
    const pageHost = document.createElement("div");
    pageHost.className = "host";
    pageHost.textContent = location.hostname;
    const reasons = document.createElement("ul");
    reasons.className = "reasons";
    (entry.result?.reasons || []).slice(0, 3).forEach((reason) => {
      const item = document.createElement("li");
      item.textContent = reason;
      reasons.append(item);
    });
    content.append(label, title, pageHost);
    if (reasons.children.length) content.append(reasons);

    const close = document.createElement("button");
    close.className = "close";
    close.type = "button";
    close.setAttribute("aria-label", "Ẩn cảnh báo cho trang này");
    close.textContent = "×";
    close.addEventListener("click", () => {
      dismissedUrls.add(entry.url);
      clearWarning();
    });

    bar.append(scoreBox, content, close);
    root.append(style, bar);
    (document.documentElement || document.body).append(host);
    warningHost = host;
    // Re-assert the banner if page script removes it. Only the user's close
    // button (which sets warningHost = null via clearWarning) may retire it.
    warningGuard?.disconnect();
    warningGuard = new MutationObserver(() => {
      if (warningHost === host && !host.isConnected) {
        (document.documentElement || document.body).append(host);
      }
    });
    warningGuard.observe(document.documentElement, { childList: true, subtree: true });
  }

  async function scan(url = location.href, force = false) {
    // Gmail has its own message-level scanner. Never assess the inbox/thread
    // shell as a website and never place a page warning over Gmail.
    if (isGmail() || !protectionEnabled || !websiteProtection || !/^https?:\/\//i.test(url) || !runtimeAvailable()) {
      clearWarning();
      return;
    }
    const token = ++scanToken;
    try {
      const entry = await send({ type: "ASSESS_URL", url, force });
      if (token === scanToken && samePage(url, location.href)) showWarning(entry);
    } catch {
      // Background/offline failures stay silent on the page. The toolbar popup exposes diagnostics.
    }
  }

  async function initialize() {
    try {
      const settings = await send({ type: "GET_SETTINGS" }, 2500);
      protectionEnabled = settings?.protectionEnabled === true;
      websiteProtection = settings?.websiteProtection !== false;
      warningThreshold = Number.isFinite(settings?.warningThreshold) ? settings.warningThreshold : DEFAULT_THRESHOLD;
      if (!isGmail()) await scan();
    } catch {
      // A stale extension context is cleaned up by send().
    }
  }

  function detectNavigation() {
    if (location.href === currentUrl) return;
    currentUrl = location.href;
    scanToken += 1;
    clearWarning();
    void scan(currentUrl);
  }

  if (runtimeAvailable()) {
    chrome.runtime.onMessage.addListener((message) => {
      if (message?.type === "TAB_ASSESSMENT_UPDATED") {
        if (Number.isFinite(message.warningThreshold)) warningThreshold = message.warningThreshold;
        if (typeof message.websiteProtection === "boolean") websiteProtection = message.websiteProtection;
        showWarning(message.entry);
      }
      if (message?.type === "PROTECTION_STATE_CHANGED") {
        protectionEnabled = message.enabled === true;
        websiteProtection = message.websiteProtection !== false;
        if (Number.isFinite(message.warningThreshold)) warningThreshold = message.warningThreshold;
        if (!protectionEnabled || !websiteProtection) clearWarning();
        else void scan(location.href, true);
      }
    });
    chrome.storage.onChanged.addListener((changes) => {
      if (changes.protectionEnabled) protectionEnabled = changes.protectionEnabled.newValue === true;
      if (changes.websiteProtection) websiteProtection = changes.websiteProtection.newValue !== false;
      if (changes.warningThreshold && Number.isFinite(changes.warningThreshold.newValue)) warningThreshold = changes.warningThreshold.newValue;
      if (!protectionEnabled || !websiteProtection) clearWarning();
      else if (changes.warningThreshold || changes.websiteProtection || changes.protectionEnabled) void scan(location.href);
    });
  }

  addEventListener("popstate", detectNavigation);
  addEventListener("hashchange", detectNavigation);
  setInterval(detectNavigation, 1000);
  void initialize();
})();
