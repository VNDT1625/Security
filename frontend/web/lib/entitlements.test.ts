import { canUseProAI } from "./entitlements";

describe("plan entitlements", () => {
    it("allows Pro AI only for paid plans", () => {
        expect(canUseProAI(undefined)).toBe(false);
        expect(canUseProAI(null)).toBe(false);
        expect(canUseProAI("free")).toBe(false);
        expect(canUseProAI("pro")).toBe(true);
        expect(canUseProAI("team")).toBe(true);
        expect(canUseProAI("enterprise")).toBe(true);
    });
});
