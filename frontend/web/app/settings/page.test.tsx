import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Settings from "./page";
import { useAuth } from "@/context/AuthContext";
import { getApiClient } from "@/lib/api";

vi.mock("@/context/AuthContext", () => ({ useAuth: vi.fn() }));
vi.mock("@/context/LanguageContext", () => ({
  useLanguage: () => ({ language: "vi", setLanguage: vi.fn() }),
}));
vi.mock("@/components/PrewiseUI", () => ({
  PrewiseShell: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));
vi.mock("@/lib/api", () => ({ getApiClient: vi.fn() }));
vi.mock("@/lib/result-storage", () => ({ clearResultHistory: vi.fn() }));

const baseSettings = {
  provider: "local" as const,
  baseUrl: "http://127.0.0.1:11434/v1",
  model: "allowed-model",
  apiKeyConfigured: false,
  configured: true,
  source: "account" as const,
  percent: 10,
  minPercent: 10,
  maxPercent: 40,
  weightPercent: 20,
  weightEligible: true,
  weightSource: "account" as const,
  allowedProviders: ["auto", "local"] as const,
  allowedModels: ["allowed-model"],
};

function api(settings = baseSettings) {
  return {
    getAISettings: vi.fn().mockResolvedValue(settings),
    updateAISettings: vi.fn().mockImplementation(async input => ({ ...settings, ...input })),
    testAISettings: vi.fn().mockResolvedValue({ ok: true, modelAvailable: true, modelsCount: 1 }),
  };
}

describe("personal AI settings", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(useAuth).mockReturnValue({
      session: { token: "token", user: { id: "u1" }, plan: { tier: "pro" } },
      isHydrated: true,
    } as never);
  });

  it("shows and saves the admin-bounded weight for Pro", async () => {
    const client = api();
    vi.mocked(getApiClient).mockReturnValue(client as never);
    render(<Settings />);

    const slider = await screen.findByRole("slider", { name: /trọng số ai cá nhân/i });
    expect(slider).toHaveAttribute("min", "10");
    expect(slider).toHaveAttribute("max", "40");
    fireEvent.change(slider, { target: { value: "35" } });
    fireEvent.click(screen.getByRole("button", { name: /lưu cho tài khoản/i }));

    await waitFor(() => expect(client.updateAISettings).toHaveBeenCalledWith(
      expect.objectContaining({ weightPercent: 35, model: "allowed-model" }),
    ));
  });

  it("does not render or submit a personal weight for Free", async () => {
    const freeSettings = { ...baseSettings, weightEligible: false, weightPercent: 0 };
    const client = api(freeSettings);
    vi.mocked(getApiClient).mockReturnValue(client as never);
    render(<Settings />);

    await screen.findByText("Model và chế độ AI");
    expect(screen.queryByRole("slider", { name: /trọng số ai cá nhân/i })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /lưu cho tài khoản/i }));
    await waitFor(() => expect(client.updateAISettings).toHaveBeenCalled());
    expect(client.updateAISettings.mock.calls[0][0]).not.toHaveProperty("weightPercent");
  });
});
