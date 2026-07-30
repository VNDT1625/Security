import { canUseApiKeyMcp, canUseProAI } from "./entitlements";

describe("plan entitlements", () => {
    it("allows Pro AI only for paid plans", () => {
        expect(canUseProAI(undefined)).toBe(false);
        expect(canUseProAI(null)).toBe(false);
        expect(canUseProAI("free")).toBe(false);
        expect(canUseProAI("pro")).toBe(true);
        expect(canUseProAI("team")).toBe(true);
        expect(canUseProAI("enterprise")).toBe(true);
    });

    it("allows API key and MCP only for Team or Enterprise", () => {
        expect(canUseApiKeyMcp(undefined)).toBe(false);
        expect(canUseApiKeyMcp("free")).toBe(false);
        expect(canUseApiKeyMcp("pro")).toBe(false);
        expect(canUseApiKeyMcp("team")).toBe(true);
        expect(canUseApiKeyMcp("enterprise")).toBe(true);
    });
});
