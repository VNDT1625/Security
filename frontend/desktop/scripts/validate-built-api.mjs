import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const expected = (
  process.env.VITE_API_BASE_URL?.trim() || "https://api.prewise.site"
).replace(/\/$/, "");
const endpoint = new URL(expected);
const localHosts = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0"]);

if (endpoint.protocol !== "https:" || localHosts.has(endpoint.hostname.toLowerCase())) {
  throw new Error("Production desktop bundle must target a non-local HTTPS Core API.");
}

const desktopRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const assetsDirectory = path.join(desktopRoot, "dist", "assets");
const assets = (await readdir(assetsDirectory))
  .filter((name) => name.endsWith(".js"))
  .map((name) => path.join(assetsDirectory, name));
if (!assets.length) {
  throw new Error("Desktop build produced no JavaScript assets.");
}

const bundled = (await Promise.all(assets.map((file) => readFile(file, "utf8")))).join("\n");
if (!bundled.includes(expected)) {
  throw new Error(`Desktop bundle does not contain the expected Core API origin: ${expected}`);
}
if (
  bundled.includes("http://localhost:8000") ||
  bundled.includes("http://127.0.0.1:8000")
) {
  throw new Error("Desktop production bundle still contains a localhost Core API fallback.");
}

console.log(`Desktop bundle Core API verified: ${expected}`);
