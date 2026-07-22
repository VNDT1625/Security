# AI Security Armor — Chrome Extension (Manifest V3)

Primary browser protection client. It assesses every opened HTTP(S) page in the
background and injects a compact top-of-page warning only when the score is
above the configured threshold (60/100 by default). In Gmail it assesses only
the currently opened message and performs a static quick scan of `.exe`
attachments belonging to that message. Safe results do not add page UI.

## Package and validate

From the repository root:

```powershell
python scripts/package_extension.py --check
python scripts/package_extension.py
```

The second command writes the Chrome Web Store-ready, reproducible ZIP to
`artifacts/`. See `docs/release-packaging.md` for permissions, checksums, and
release signing guidance.

## Load (development)

1. Start the gateway: `uvicorn backend.main:app --port 8000` (from repo root).
2. Chrome → `chrome://extensions` → enable **Developer mode**.
3. **Load unpacked** → select `frontend/extension/`.
4. The checked-in manifest references the generated PNG icons in `icons/`.

## Architecture

- `background.js` — service worker; brokers URL, email, and EXE quick-scan calls,
  caches per-tab results, and degrades gracefully when the gateway is offline.
- `content/page_scanner.js` — automatically assesses the current URL and injects
  a non-modal Shadow-DOM warning at the top of risky pages.
- `content/gmail_scanner.js` — extracts only the open email, assesses its text,
  and scans `.exe` attachments without executing or externally sharing them.
- `popup/` — shows the current tab's badge, reasons, and evidence.
- `shared/risk.js` — single source of truth for the 0-100 color scale (mirrors web `lib/risk.ts`).
- `shared/api.js` — gateway client (base URL configurable via `chrome.storage.local`).

## Manual test checklist (test-plan.md §7)

- [ ] Load unpacked — no console errors.
- [ ] Open a phishing sample page → warning appears at the top without clicking the icon.
- [ ] Open a safe page → no page UI is injected.
- [ ] Open one scam email in Gmail → warning appears above that email only.
- [ ] Open an email with a suspicious EXE → warning appears beside that attachment.
- [ ] Click the icon → popup shows evidence, layout intact (Shadow DOM).
- [ ] Stop the gateway → popup shows "offline", no crash.
