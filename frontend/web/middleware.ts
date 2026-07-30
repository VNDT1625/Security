import { NextResponse, type NextRequest } from "next/server";

/**
 * Route documents must never outlive their release's hashed JavaScript chunks.
 * Static assets remain excluded and keep Next/nginx immutable caching.
 */
export function middleware(_request: NextRequest): NextResponse {
    const response = NextResponse.next();
    response.headers.set(
        "Cache-Control",
        "no-store, max-age=0, must-revalidate",
    );
    return response;
}

export const config = {
    matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
