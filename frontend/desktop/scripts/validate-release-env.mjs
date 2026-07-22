const raw = process.env.VITE_API_BASE_URL?.trim();

if (!raw) {
  console.error("Release bị chặn: phải đặt VITE_API_BASE_URL tới Core API production HTTPS.");
  process.exit(1);
}

let endpoint;
try {
  endpoint = new URL(raw);
} catch {
  console.error("Release bị chặn: VITE_API_BASE_URL không phải URL hợp lệ.");
  process.exit(1);
}

const host = endpoint.hostname.toLowerCase();
const localHosts = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0"]);
if (endpoint.protocol !== "https:" || localHosts.has(host)) {
  console.error("Release bị chặn: VITE_API_BASE_URL phải là endpoint HTTPS production, không phải localhost.");
  process.exit(1);
}
if (endpoint.username || endpoint.password) {
  console.error("Release bị chặn: không được nhúng credentials vào VITE_API_BASE_URL.");
  process.exit(1);
}

console.log(`Release Core API: ${endpoint.origin}`);
