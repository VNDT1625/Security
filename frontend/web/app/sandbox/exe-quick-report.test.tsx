import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ExeSandboxResult } from "@/lib/types";

import {
    ExeQuickReport,
    quickExeEvidence,
    quickExeProviderLabel,
    quickExeVerdictLabel,
    resetQuickExeSelection,
} from "./exe-quick-report";

function result(overrides: Partial<ExeSandboxResult> = {}): ExeSandboxResult {
    return {
        ok: true,
        execution_status: "completed",
        filename: "invoice.exe",
        sha256: "a".repeat(64),
        size_bytes: 4096,
        sandbox: "local_static_analysis",
        network: "disabled",
        verdict: "no_obvious_theft_detected",
        risk_score: 8,
        issues: [],
        processes: [],
        files_created: [],
        network_attempts: [],
        local_analysis: {
            valid: true,
            format: "PE32",
            architecture: "x86",
            subsystem: "windows_gui",
            entry_point_rva: 4096,
            section_count: 3,
            sections: [],
            signature_present: false,
            overlay_bytes: 0,
            compile_time: null,
            characteristics: 0,
            anomalies: [],
            risk_score: 8,
        },
        provider: {
            name: "metadefender",
            configured: false,
            status: "disabled",
            data_id: null,
            progress: 0,
            detected_engines: 0,
            total_engines: 0,
            detections: [],
            risk_score: 0,
            sample_shared: false,
            error: null,
        },
        elapsed_ms: 12,
        ...overrides,
    };
}

describe("Quick EXE output contract", () => {
    it("uses bounded static verdicts and never labels a low score as safe", () => {
        expect(quickExeVerdictLabel("dangerous")).toBe("NGUY HIỂM");
        expect(quickExeVerdictLabel("suspicious")).toBe("ĐÁNG NGỜ");
        expect(quickExeVerdictLabel("no_obvious_theft_detected")).toBe(
            "CHƯA PHÁT HIỆN DẤU HIỆU RÕ",
        );
        expect(quickExeVerdictLabel("unknown")).toBe("CHƯA ĐỦ DỮ LIỆU");
        expect(quickExeVerdictLabel("no_obvious_theft_detected").toLowerCase()).not.toContain(
            "an toàn",
        );
    });

    it("shows score, full SHA, PE, signature, provider, evidence and the no-execution limit", () => {
        render(
            <ExeQuickReport
                result={result({
                    issues: ["Section có entropy cao."],
                    local_analysis: {
                        ...result().local_analysis!,
                        anomalies: ["Không có chữ ký."],
                    },
                })}
                polling={false}
            />,
        );

        expect(screen.getByText("CHƯA PHÁT HIỆN DẤU HIỆU RÕ")).toBeInTheDocument();
        expect(screen.getByLabelText("Điểm rủi ro tĩnh")).toHaveTextContent("8/100");
        expect(screen.getByText(`SHA-256 · ${"a".repeat(64)}`)).toBeInTheDocument();
        expect(screen.getByText("PE32 · x86")).toBeInTheDocument();
        expect(screen.getByText("Không có", { selector: "b" })).toBeInTheDocument();
        expect(screen.getByText("Chưa cấu hình · chỉ có kết quả cục bộ")).toBeInTheDocument();
        expect(screen.getByLabelText("Bằng chứng tĩnh")).toHaveTextContent(
            "Section có entropy cao.",
        );
        expect(screen.getByText(/không thực thi file/i)).toBeInTheDocument();
        expect(screen.getByText(/không xác nhận file vô hại/i)).toBeInTheDocument();
    });

    it("offers both escalation paths without claiming a behavioral result", () => {
        const openAuto = vi.fn();
        const openInteractive = vi.fn();
        render(
            <ExeQuickReport
                result={result()}
                polling={false}
                onOpenAuto={openAuto}
                onOpenInteractive={openInteractive}
            />,
        );

        fireEvent.click(screen.getByRole("button", { name: "Phân tích tự động" }));
        fireEvent.click(screen.getByRole("button", { name: "Điều tra tương tác" }));
        expect(openAuto).toHaveBeenCalledOnce();
        expect(openInteractive).toHaveBeenCalledOnce();
        expect(screen.getByText(/process, file, registry và network/i)).toBeInTheDocument();
    });

    it("deduplicates local and response evidence", () => {
        expect(
            quickExeEvidence(
                result({
                    issues: ["High entropy", "High entropy"],
                    local_analysis: {
                        ...result().local_analysis!,
                        anomalies: ["High entropy", "Unsigned"],
                    },
                }),
            ),
        ).toEqual(["High entropy", "Unsigned"]);
    });

    it("keeps provider states explicit", () => {
        expect(quickExeProviderLabel()).toBe("Chưa cấu hình · chỉ có kết quả cục bộ");
        expect(
            quickExeProviderLabel({
                ...result().provider!,
                configured: true,
                status: "completed",
                detected_engines: 2,
                total_engines: 35,
            }),
        ).toBe("2/35 engine phát hiện");
    });
});

describe("Quick EXE file selection", () => {
    it("clears the previous result, provider polling and consent for every new file", () => {
        const file = new File(["MZ"], "different.exe", {
            type: "application/vnd.microsoft.portable-executable",
        });
        expect(resetQuickExeSelection(file)).toEqual({
            file,
            result: null,
            shareWithProvider: false,
            providerPolling: false,
        });
    });
});
