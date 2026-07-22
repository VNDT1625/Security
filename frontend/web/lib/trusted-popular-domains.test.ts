import { describe, expect, it } from "vitest";

import {
    TRUSTED_POPULAR_DOMAINS,
    trustedPopularDomain,
    trustedPopularResult,
} from "@/lib/trusted-popular-domains";

describe("trusted popular domains", () => {
    it("contains exactly 100 unique entries", () => {
        expect(TRUSTED_POPULAR_DOMAINS).toHaveLength(100);
        expect(new Set(TRUSTED_POPULAR_DOMAINS).size).toBe(100);
    });

    it("matches real subdomains but rejects lookalikes", () => {
        expect(trustedPopularDomain("https://mail.google.com/mail/u/0/")).toBe("google.com");
        expect(trustedPopularDomain("https://youtube.com.attacker.example/")).toBeNull();
        expect(trustedPopularDomain("https://notyoutube.com/")).toBeNull();
    });

    it("returns the immediate safe Web App result", () => {
        const result = trustedPopularResult("https://chatgpt.com/");
        expect(result).toMatchObject({
            score: 0,
            riskLevel: "safe",
            confidence: 1,
            latencyMs: 0,
            modelVersion: "trusted-popular-domains-v1",
        });
    });
});
