import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Settings from "./page";
import { useAuth } from "@/context/AuthContext";
import { getApiClient } from "@/lib/api";
import type { UserAISettings } from "@/lib/types";

vi.mock("@/context/AuthContext", () => ({ useAuth: vi.fn() }));
const languageMocks = vi.hoisted(() => ({ setLanguage: vi.fn() }));
vi.mock("@/context/LanguageContext", () => ({
  useLanguage: () => ({ language: "vi", setLanguage: languageMocks.setLanguage }),
}));
vi.mock("@/components/PrewiseUI", () => ({
  PrewiseShell: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));
vi.mock("@/lib/api", () => ({ getApiClient: vi.fn() }));
vi.mock("@/lib/result-storage", () => ({ clearResultHistory: vi.fn() }));

const baseSettings: UserAISettings = {
  provider: "endpoint" as const,
  baseUrl: "https://api.example.com/v1",
  model: "allowed-model",
  apiKeyConfigured: true,
  configured: true,
  source: "account" as const,
  percent: 10,
  minPercent: 10,
  maxPercent: 40,
  weightPercent: 20,
  weightEligible: true,
  weightSource: "account" as const,
  allowedProviders: ["adapter", "local", "endpoint"] as const,
  allowedModels: ["allowed-model"],
};

function api(settings: UserAISettings = baseSettings) {
  return {
    getAISettings: vi.fn().mockResolvedValue(settings),
    updateAISettings: vi.fn().mockImplementation(async input => ({ ...settings, ...input })),
    testAISettings: vi.fn().mockResolvedValue({ ok: true, modelAvailable: true, modelsCount: 1 }),
  };
}

describe("personal AI settings", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    sessionStorage.clear();
    delete document.documentElement.dataset.motion;
    delete document.documentElement.dataset.density;
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

  it("shows only AI modes that can run from the hosted web backend", async () => {
    vi.mocked(getApiClient).mockReturnValue(api() as never);
    render(<Settings />);

    const mode = await screen.findByRole("combobox", { name: /chế độ ai/i });
    expect([...mode.querySelectorAll("option")].map(option => option.value)).toEqual(["adapter", "endpoint"]);
    expect(screen.queryByRole("option", { name: /local/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/mặc định admin/i)).not.toBeInTheDocument();
  });

  it("falls back from a legacy auto response to the first admin-allowed mode", async () => {
    const client = api({
      ...baseSettings,
      provider: "auto",
      source: "database",
      configured: false,
      allowedProviders: ["endpoint", "local"],
    });
    vi.mocked(getApiClient).mockReturnValue(client as never);
    render(<Settings />);

    const mode = await screen.findByRole("combobox", { name: /chế độ ai/i });
    expect(mode).toHaveValue("endpoint");
    fireEvent.click(screen.getByRole("button", { name: /lưu cho tài khoản/i }));
    await waitFor(() => expect(client.updateAISettings).toHaveBeenCalledWith(
      expect.objectContaining({ provider: "endpoint" }),
    ));
  });

  it("does not expose an account local model through the hosted web UI", async () => {
    const client = api({
      ...baseSettings,
      provider: "local",
      baseUrl: "http://127.0.0.1:11434/v1",
      source: "account",
      allowedProviders: ["local", "endpoint"],
    });
    vi.mocked(getApiClient).mockReturnValue(client as never);
    render(<Settings />);

    const mode = await screen.findByRole("combobox", { name: /chế độ ai/i });
    expect(mode).toHaveValue("endpoint");
    expect(screen.queryByRole("option", { name: /local/i })).not.toBeInTheDocument();
    expect(screen.getByText("Chưa chọn riêng")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /lưu cho tài khoản/i }));
    await waitFor(() => expect(client.updateAISettings).toHaveBeenCalledWith(
      expect.objectContaining({ provider: "endpoint" }),
    ));
  });

  it("persists and applies appearance and privacy preferences", async () => {
    vi.mocked(getApiClient).mockReturnValue(api() as never);
    render(<Settings />);
    await screen.findByText("Model và chế độ AI");

    fireEvent.click(screen.getByRole("button", { name: "Giao diện" }));
    fireEvent.click(screen.getByRole("button", { name: "Gọn" }));
    fireEvent.click(screen.getByRole("button", { name: "Tối giản" }));
    await waitFor(() => {
      expect(document.documentElement.dataset.density).toBe("compact");
      expect(document.documentElement.dataset.motion).toBe("reduced");
    });

    fireEvent.click(screen.getByRole("button", { name: "Quyền riêng tư" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Lưu lịch sử trên thiết bị" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Che dữ liệu nhạy cảm" }));
    await waitFor(() => expect(JSON.parse(localStorage.getItem("prewise-settings") || "{}")).toMatchObject({
      density: "compact",
      motion: "reduced",
      saveHistory: false,
      maskSensitive: false,
    }));
  });

  it("clears local data and forwards language changes", async () => {
    const { clearResultHistory } = await import("@/lib/result-storage");
    vi.mocked(getApiClient).mockReturnValue(api() as never);
    render(<Settings />);
    await screen.findByText("Model và chế độ AI");

    fireEvent.click(screen.getByRole("button", { name: "Dữ liệu" }));
    fireEvent.click(screen.getByRole("button", { name: "Xóa dữ liệu" }));
    fireEvent.click(screen.getByRole("button", { name: "Xác nhận xóa" }));
    expect(clearResultHistory).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole("button", { name: "Ngôn ngữ" }));
    fireEvent.click(screen.getByRole("button", { name: "English" }));
    expect(languageMocks.setLanguage).toHaveBeenCalledWith("en");
  });
});
