import type { Session } from "@/lib/types";

export const SESSION_STORAGE_KEY = "aisec:session";
export const SESSION_INVALID_EVENT = "aisec:session-invalid";

export function readStoredAccessToken(): string | null {
    if (
        typeof window === "undefined" ||
        typeof window.localStorage === "undefined"
    ) {
        return null;
    }

    try {
        const raw = window.localStorage.getItem(SESSION_STORAGE_KEY);
        if (!raw) return null;

        const session = JSON.parse(raw) as Partial<Session>;
        return typeof session.token === "string" && session.token.length > 0
            ? session.token
            : null;
    } catch {
        return null;
    }
}

export function invalidateStoredSession(): void {
    if (typeof window === "undefined") return;
    try {
        window.localStorage?.removeItem(SESSION_STORAGE_KEY);
    } catch {
        // Storage may be blocked; the in-memory auth context is still notified.
    }
    window.dispatchEvent(new Event(SESSION_INVALID_EVENT));
}

/**
 * Public assessment endpoints accept anonymous traffic. If a stale browser
 * session turns an otherwise valid request into a 401, revoke that stale
 * session and retry exactly once without Authorization.
 */
export async function fetchWithAnonymousSessionFallback(
    input: RequestInfo | URL,
    init: RequestInit = {},
): Promise<Response> {
    const token = readStoredAccessToken();
    const authenticatedHeaders = new Headers(init.headers);
    if (token) authenticatedHeaders.set("Authorization", `Bearer ${token}`);

    let response = await fetch(input, { ...init, headers: authenticatedHeaders });
    if (response.status !== 401 || !token) return response;

    invalidateStoredSession();
    const anonymousHeaders = new Headers(init.headers);
    anonymousHeaders.delete("Authorization");
    response = await fetch(input, { ...init, headers: anonymousHeaders });
    return response;
}
