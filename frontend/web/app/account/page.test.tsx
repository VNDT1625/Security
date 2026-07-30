import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useAuth } from "@/context/AuthContext";
import { getApiClient } from "@/lib/api";
import type { UserProfile } from "@/lib/types";
import Account from "./page";

vi.mock("@/context/AuthContext", () => ({ useAuth: vi.fn() }));
vi.mock("@/lib/api", () => ({ getApiClient: vi.fn() }));

const persistedProfile: UserProfile = {
    id: "user-1",
    email: "owner@prewise.site",
    displayName: "Nguyễn An",
    organizationName: "Prewise Security",
    jobTitle: "Security Analyst",
    countryCode: "VN",
    locale: "vi",
    timezone: "Asia/Ho_Chi_Minh",
    emailVerified: false,
    status: "active",
    createdAt: "2026-07-01T08:00:00Z",
    updatedAt: "2026-07-20T08:00:00Z",
    lastLoginAt: "2026-07-31T08:00:00Z",
    role: "user",
};

const plan = {
    tier: "pro" as const,
    label: "PRO",
    dailyScanLimit: 1000,
    aiCreditDailyLimit: 100,
    deepScanDailyLimit: 10,
    chatFollowupLimit: 20,
    autoMessageContext: true,
    autoWebContext: true,
};

describe("account profile", () => {
    const setSession = vi.fn();

    beforeEach(() => {
        vi.clearAllMocks();
        vi.mocked(useAuth).mockReturnValue({
            session: {
                token: "token",
                user: { ...persistedProfile, organizationName: null, jobTitle: null },
                plan,
            },
            isHydrated: true,
            setSession,
        } as never);
    });

    it("loads persisted details and shows a truthful verification state", async () => {
        vi.mocked(getApiClient).mockReturnValue({
            getProfile: vi.fn().mockResolvedValue(persistedProfile),
        } as never);

        render(<Account />);

        expect(await screen.findByDisplayValue("Prewise Security")).toBeInTheDocument();
        expect(screen.getByDisplayValue("Security Analyst")).toBeInTheDocument();
        expect(screen.getByText("EMAIL CHƯA XÁC MINH")).toBeInTheDocument();
        expect(screen.queryByText(/^VERIFIED$/)).not.toBeInTheDocument();
        expect(screen.getByText("PRO")).toBeInTheDocument();
    });

    it("saves the complete profile contract and refreshes the session", async () => {
        const updated = {
            ...persistedProfile,
            organizationName: "Prewise Labs",
            updatedAt: "2026-07-31T09:00:00Z",
        };
        const api = {
            getProfile: vi.fn().mockResolvedValue(persistedProfile),
            updateProfile: vi.fn().mockResolvedValue(updated),
        };
        vi.mocked(getApiClient).mockReturnValue(api as never);
        render(<Account />);

        const organization = await screen.findByDisplayValue("Prewise Security");
        fireEvent.change(organization, { target: { value: "Prewise Labs" } });
        fireEvent.click(screen.getByRole("button", { name: /lưu thay đổi/i }));

        await waitFor(() =>
            expect(api.updateProfile).toHaveBeenCalledWith({
                displayName: "Nguyễn An",
                organizationName: "Prewise Labs",
                jobTitle: "Security Analyst",
                countryCode: "VN",
                locale: "vi",
                timezone: "Asia/Ho_Chi_Minh",
            }),
        );
        expect(await screen.findByText(/hồ sơ đã được lưu/i)).toBeInTheDocument();
        expect(setSession).toHaveBeenLastCalledWith(
            expect.objectContaining({
                user: expect.objectContaining({ organizationName: "Prewise Labs" }),
            }),
        );
    });
});
