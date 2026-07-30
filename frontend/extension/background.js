import { assessUrl, assessText, assessAction, assessExecutable, verifyExtensionKey } from "./shared/api.js";
import { getRiskLevel, toDisplayScore } from "./shared/risk.js";

const tabResults = new Map();
const urlCache = new Map();
const inFlight = new Map();
const CACHE_TTL = 5 * 60 * 1000;
// V3 invalidates scores saved before the extension started using the
// authoritative Risk Core final score from the balanced Web App pipeline.
const CACHE_STORAGE_KEY = "urlAssessmentCacheV4";
const MAX_CACHED_URLS = 100;
const DEFAULT_WARNING_THRESHOLD = 60;
const MAX_ATTACHMENT_BYTES = 12 * 1024 * 1024;
let requestSequence = 0;
let rateLimitedUntil = 0;
let rateLimitTimer = null;

const cacheReady = (async () => {
  try {
    const stored = await chrome.storage.local.get(CACHE_STORAGE_KEY);
    const entries = Object.entries(stored[CACHE_STORAGE_KEY] || {});
    const now = Date.now();
    for (const [url, entry] of entries) {
      if (entry?.status === "complete" && entry.url === url && now - entry.completedAt < CACHE_TTL) urlCache.set(url, entry);
    }
  } catch { /* The in-memory cache still works if storage is unavailable. */ }
})();
async function persistUrlCache() {
  const now = Date.now();
  const entries = [...urlCache.entries()]
    .filter(([, entry]) => entry?.status === "complete" && now - entry.completedAt < CACHE_TTL)
    .sort(([, a], [, b]) => b.completedAt - a.completedAt)
    .slice(0, MAX_CACHED_URLS);
  urlCache.clear(); entries.forEach(([url, entry]) => urlCache.set(url, entry));
  try { await chrome.storage.local.set({ [CACHE_STORAGE_KEY]: Object.fromEntries(entries) }); } catch { /* Cache persistence is an optimization. */ }
}

async function settings() {
  return chrome.storage.local.get({
    protectionEnabled: false,
    websiteProtection: true,
    gmailProtection: true,
    warningThreshold: DEFAULT_WARNING_THRESHOLD,
  });
}
function errorInfo(error) {
  return { type: error?.type || "unknown", message: error?.message || "Đã xảy ra lỗi không xác định.", status: error?.status ?? null, retryAfter: error?.retryAfter || 0 };
}
function clearBadge(tabId) {
  if (tabId == null) return;
  chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
  chrome.action.setTitle({ tabId, title: "AI Security Armor" }).catch(() => {});
}
function setBadge(tabId, entry, threshold = DEFAULT_WARNING_THRESHOLD) {
  if (tabId == null) return;
  const level = getRiskLevel(entry?.score || 0, entry?.result?.decision);
  const legacyBelowThreshold = !entry?.result?.decision && Number(entry?.score || 0) <= threshold;
  if (entry?.status === "loading" || entry?.error || level.key === "safe" || legacyBelowThreshold) { clearBadge(tabId); return; }
  chrome.action.setBadgeText({ tabId, text: level.key === "danger" ? "X" : "!" });
  chrome.action.setBadgeBackgroundColor({ tabId, color: level.color });
  chrome.action.setTitle({ tabId, title: `AI Security Armor — ${level.label}` });
}
function notifyTab(tabId, entry, current) {
  if (tabId == null) return;
  chrome.tabs.sendMessage(tabId, {
    type: "TAB_ASSESSMENT_UPDATED",
    entry,
    warningThreshold: current.warningThreshold,
    websiteProtection: current.websiteProtection,
  }).catch(() => null);
}
function decodeBase64(value) {
  const binary = atob(value);
  if (binary.length > MAX_ATTACHMENT_BYTES) throw new Error("Tệp EXE vượt quá giới hạn quét nhanh 12 MB.");
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}
function cached(url) {
  const hit = urlCache.get(url);
  if (hit && Date.now() - hit.completedAt < CACHE_TTL) return hit;
  if (hit) urlCache.delete(url);
  return null;
}
function beginCooldown(retryAfter) {
  rateLimitedUntil = Date.now() + Math.max(1, retryAfter || 60) * 1000;
  clearTimeout(rateLimitTimer);
  rateLimitTimer = setTimeout(async () => {
    rateLimitedUntil = 0;
    const tabs = await chrome.tabs.query({});
    await Promise.all(tabs.filter((tab) => tab.id != null).map((tab) => chrome.action.setBadgeText({ tabId: tab.id, text: "" }).catch(() => {})));
  }, Math.max(1, rateLimitedUntil - Date.now()));
}
// Query parameters and fragments routinely carry live single-use credentials:
// password-reset links, OAuth ?code= / #access_token= callbacks, magic links and
// pre-signed object URLs. None of them contribute to a phishing verdict, and
// sending them would put working credentials into gateway logs and into the
// on-disk cache. The host and path stay: that is where the phishing signal is.
const SENSITIVE_QUERY_PARAM = /(^|[_-])(token|code|key|secret|password|passwd|pwd|session|sid|auth|jwt|sig|signature|credential|otp|access|refresh)([_-]|$)/i;

function scanTarget(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    parsed.hash = "";
    for (const name of [...parsed.searchParams.keys()]) {
      if (SENSITIVE_QUERY_PARAM.test(name)) parsed.searchParams.delete(name);
    }
    return parsed.toString();
  } catch {
    return rawUrl;
  }
}

async function handleAssessUrl(rawUrl, tabId, force = false) {
  const current = await settings();
  if (!current.protectionEnabled || !current.websiteProtection) return { disabled: true };
  if (!/^https?:\/\//i.test(rawUrl || "")) return { unsupported: true };
  const url = scanTarget(rawUrl);
  await cacheReady;
  if (Date.now() < rateLimitedUntil) {
    clearBadge(tabId);
    return { status: "cooldown", url, error: { type: "http", status: 429, message: "Gateway đang tạm giới hạn lượt quét.", retryAfter: Math.ceil((rateLimitedUntil - Date.now()) / 1000) } };
  }
  if (!force) {
    const hit = cached(url);
    if (hit) { if (tabId != null) { tabResults.set(tabId, hit); setBadge(tabId, hit, current.warningThreshold); notifyTab(tabId, hit, current); } return hit; }
    if (inFlight.has(url)) {
      const shared = await inFlight.get(url);
      if (tabId != null && shared?.status === "complete") {
        tabResults.set(tabId, shared);
        setBadge(tabId, shared, current.warningThreshold);
        notifyTab(tabId, shared, current);
      }
      return shared;
    }
  }
  const requestId = ++requestSequence;
  const startedAt = Date.now();
  const loading = { status: "loading", url, requestId, startedAt };
  if (tabId != null) { tabResults.set(tabId, loading); setBadge(tabId, loading, current.warningThreshold); }
  const promise = (async () => {
    try {
      const result = await assessUrl(url);
      const level = getRiskLevel(toDisplayScore(result.risk_score), result.decision);
      const entry = { status: "complete", url, score: toDisplayScore(result.risk_score), level: level.key, result, requestId, startedAt, completedAt: Date.now(), latencyMs: Date.now() - startedAt };
      urlCache.set(url, entry);
      await persistUrlCache();
      if (tabId != null && tabResults.get(tabId)?.requestId === requestId) {
        tabResults.set(tabId, entry);
        setBadge(tabId, entry, current.warningThreshold);
        notifyTab(tabId, entry, current);
      }
      return entry;
    } catch (error) {
      const info = errorInfo(error);
      const entry = { status: "error", url, error: info, requestId, startedAt, completedAt: Date.now(), latencyMs: Date.now() - startedAt };
      if (info.status === 429) beginCooldown(info.retryAfter);
      if (tabId != null && tabResults.get(tabId)?.requestId === requestId) {
        tabResults.set(tabId, entry);
        clearBadge(tabId);
        notifyTab(tabId, entry, current);
      }
      return entry;
    } finally { if (inFlight.get(url) === promise) inFlight.delete(url); }
  })();
  inFlight.set(url, promise);
  return promise;
}

chrome.runtime.onInstalled.addListener(async () => {
  const stored = await chrome.storage.local.get(["protectionEnabled", "websiteProtection", "linkProtection", "gmailProtection", "warningThreshold"]);
  await chrome.storage.local.set({
    protectionEnabled: typeof stored.protectionEnabled === "boolean" ? stored.protectionEnabled : false,
    websiteProtection: typeof stored.websiteProtection === "boolean" ? stored.websiteProtection : stored.linkProtection !== false,
    gmailProtection: typeof stored.gmailProtection === "boolean" ? stored.gmailProtection : true,
    warningThreshold: Number.isFinite(stored.warningThreshold) ? Math.max(40, Math.min(90, stored.warningThreshold)) : DEFAULT_WARNING_THRESHOLD,
  });
  await chrome.storage.local.remove("linkProtection");
  const tabs = await chrome.tabs.query({}); tabs.forEach((tab) => clearBadge(tab.id));
});
chrome.runtime.onStartup.addListener(async () => { const tabs = await chrome.tabs.query({}); tabs.forEach((tab) => clearBadge(tab.id)); });
// Operations that change protection state, verify the account key, or read
// another tab's result belong to the popup and options pages. Content scripts
// run on every site, so a single compromised one must not reach them, and must
// not be able to claim an arbitrary tab identity via message.tabId.
const EXTENSION_PAGE_ONLY = new Set(["SET_PROTECTION_STATE", "VERIFY_API_KEY", "GET_TAB_RESULT"]);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return false;
  const fromExtensionPage = !sender.tab;
  const tabId = sender.tab?.id ?? (fromExtensionPage ? message.tabId : null);
  (async () => {
    try {
      if (EXTENSION_PAGE_ONLY.has(message.type) && !fromExtensionPage) {
        return sendResponse({ error: { type: "forbidden", message: "Không được phép." } });
      }
      switch (message.type) {
        case "ASSESS_URL": return sendResponse(await handleAssessUrl(message.url, tabId, message.force));
        case "GET_PROTECTION_STATE": { const current = await settings(); return sendResponse({ enabled: current.protectionEnabled === true, websiteProtection: current.websiteProtection, gmailProtection: current.gmailProtection, warningThreshold: current.warningThreshold }); }
        case "SET_PROTECTION_STATE": {
          if (message.enabled === true) {
            try {
              const activation = await verifyExtensionKey();
              await chrome.storage.local.set({ extensionActivation: activation });
            } catch (error) {
              await chrome.storage.local.set({ protectionEnabled: false });
              return sendResponse({ enabled: false, error: { ...errorInfo(error), message: error?.status === 401 ? "API key không hợp lệ hoặc đã bị thu hồi." : error?.message } });
            }
          }
          await chrome.storage.local.set({ protectionEnabled: message.enabled === true });
          const current = await settings(); const tabs = await chrome.tabs.query({});
          await Promise.all(tabs.filter((tab) => tab.id != null).map((tab) => chrome.tabs.sendMessage(tab.id, { type: "PROTECTION_STATE_CHANGED", enabled: current.protectionEnabled, websiteProtection: current.websiteProtection, gmailProtection: current.gmailProtection, warningThreshold: current.warningThreshold }).catch(() => null)));
          if (!message.enabled) { tabResults.clear(); urlCache.clear(); await chrome.storage.local.remove(CACHE_STORAGE_KEY); rateLimitedUntil = 0; clearTimeout(rateLimitTimer); tabs.forEach((tab) => clearBadge(tab.id)); }
          else {
            const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (activeTab?.id != null && /^https?:/.test(activeTab.url || "")) void handleAssessUrl(activeTab.url, activeTab.id, true);
          }
          return sendResponse({ enabled: message.enabled === true });
        }
        case "ASSESS_TEXT": {
          const current = await settings(); if (!current.protectionEnabled || !current.gmailProtection) return sendResponse({ disabled: true });
          try { return sendResponse({ result: await assessText(message.text, message.modality || "email", message.metadata), offline: false }); } catch (error) { return sendResponse({ error: errorInfo(error) }); }
        }
        case "ASSESS_EXE_ATTACHMENT": {
          const current = await settings();
          if (!current.protectionEnabled || !current.gmailProtection) return sendResponse({ disabled: true });
          if (!/\.exe$/i.test(message.filename || "")) return sendResponse({ error: { type: "invalid_file", message: "Chỉ hỗ trợ quét nhanh tệp .exe." } });
          try {
            const bytes = decodeBase64(message.dataBase64 || "");
            return sendResponse({ result: await assessExecutable(message.filename, bytes, message.mimeType), offline: false });
          } catch (error) { return sendResponse({ error: errorInfo(error) }); }
        }
        case "ASSESS_ACTION": try { return sendResponse({ result: await assessAction(message.actionType, message.targetUrl, message.dataTypes) }); } catch (error) { return sendResponse({ error: errorInfo(error) }); }
        case "GET_TAB_RESULT": { const entry = tabResults.get(message.tabId); return sendResponse(entry?.url === scanTarget(message.url) ? entry : null); }
        case "VERIFY_API_KEY": try { const activation = await verifyExtensionKey(); await chrome.storage.local.set({ extensionActivation: activation }); return sendResponse({ activation }); } catch (error) { return sendResponse({ error: errorInfo(error) }); }
        case "GET_SETTINGS": { const current = await settings(); const stored = await chrome.storage.local.get(["extensionApiKey", "extensionActivation"]); return sendResponse({ ...current, activated: Boolean(stored.extensionApiKey && stored.extensionActivation?.valid), activation: stored.extensionActivation || null, rateLimited: Date.now() < rateLimitedUntil, retryAfter: Math.max(0, Math.ceil((rateLimitedUntil - Date.now()) / 1000)) }); }
        default: return sendResponse({ error: { type: "unknown_message", message: "Thông điệp không được hỗ trợ." } });
      }
    } catch (error) { sendResponse({ error: errorInfo(error) }); }
  })();
  return true;
});
chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "loading") { tabResults.delete(tabId); clearBadge(tabId); }
  if (info.status === "complete" && /^https?:/.test(tab.url || "") && Date.now() >= rateLimitedUntil) settings().then((current) => current.protectionEnabled && handleAssessUrl(tab.url, tabId));
});
chrome.tabs.onRemoved.addListener((tabId) => tabResults.delete(tabId));
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || (!changes.protectionEnabled && !changes.websiteProtection && !changes.warningThreshold)) return;
  settings().then((current) => {
    for (const [tabId, entry] of tabResults) {
      if (!current.protectionEnabled || !current.websiteProtection) clearBadge(tabId);
      else setBadge(tabId, entry, current.warningThreshold);
      notifyTab(tabId, entry, current);
    }
  }).catch(() => {});
});
