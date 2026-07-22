/** @type {import('next').NextConfig} */
const path = require("node:path");
const { PHASE_DEVELOPMENT_SERVER } = require("next/constants");

/** @param {string} phase */
module.exports = (phase) => {
    const isDevelopment = phase === PHASE_DEVELOPMENT_SERVER;
    const contentSecurityPolicy = [
        "default-src 'self'",
        `script-src 'self' 'unsafe-inline'${isDevelopment ? " 'unsafe-eval'" : ""}`,
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: blob: https:",
        "font-src 'self' data:",
        "connect-src 'self' https: wss: http://127.0.0.1:* http://localhost:* ws://127.0.0.1:* ws://localhost:*",
        "media-src 'self' blob:",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ].join("; ");

    return ({
    reactStrictMode: true,
    // Tách cache của từng dev server để manifest/chunk không ghi đè lẫn nhau.
    // Production vẫn dùng thư mục .next ổn định.
    distDir: process.env.NEXT_DIST_DIR || (phase === PHASE_DEVELOPMENT_SERVER ? `.next-dev-${process.pid}` : ".next"),
    outputFileTracingRoot: path.resolve(__dirname, "../.."),
    env: {
        // Chế độ API client: "mock" (demo standalone) hoặc "real" (gọi Security Gateway)
        NEXT_PUBLIC_API_MODE: process.env.NEXT_PUBLIC_API_MODE || "real",
        // A production build must never silently compile localhost into the
        // browser bundle when the deploy platform forgot its build arguments.
        NEXT_PUBLIC_API_BASE_URL: process.env.NEXT_PUBLIC_API_BASE_URL
            || (isDevelopment ? "http://localhost:8000" : "https://api.prewise.site"),
        NEXT_PUBLIC_WS_BASE_URL: process.env.NEXT_PUBLIC_WS_BASE_URL
            || (isDevelopment ? "ws://localhost:8000" : "wss://api.prewise.site"),
    },
    async headers() {
        return [{
            // Never cache route HTML across releases. A stale App Router
            // document can otherwise reference chunks removed by the next deploy.
            source: "/:path((?!_next/static|_next/image|favicon.ico).*)",
            headers: [{key: "Cache-Control", value: "no-store, max-age=0, must-revalidate"}],
        }, {
            source: "/:path*",
            headers: [
                {key: "Content-Security-Policy", value: contentSecurityPolicy},
                {key: "Referrer-Policy", value: "strict-origin-when-cross-origin"},
                {key: "X-Content-Type-Options", value: "nosniff"},
                {key: "X-Frame-Options", value: "DENY"},
                {key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=()"},
                ...(!isDevelopment ? [{key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains"}] : []),
            ],
        }];
    },
});
};
