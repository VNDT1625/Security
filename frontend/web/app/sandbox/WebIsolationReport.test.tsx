import { render, screen } from "@testing-library/react";

import type { BrowserSandboxPayload } from "./web-isolation-report";
import { summarizeWebIsolation } from "./web-isolation-report";
import { WebIsolationReport } from "./WebIsolationReport";

function result(overrides: Partial<BrowserSandboxPayload> = {}): BrowserSandboxPayload {
    return {
        ok: true,
        execution_status: "completed",
        url: "https://login.example.test",
        final_url: "https://collector.example.test/sign-in",
        status_code: 200,
        page_title: "Account Login",
        isolation: {},
        canary: {
            enabled: true,
            mode: "dry_run",
            clone_email: "",
            fields_filled: 2,
            field_types: { password: 1, otp: 1 },
            form_submissions_blocked: 1,
            exfiltration_blocked: true,
            notes: [],
        },
        network_events: [],
        browser_events: [],
        console_errors: [],
        issues: [{
            code: "cross_origin_form_action",
            severity: "critical",
            category: "credential",
            message: "A form would submit data to another origin.",
            detail: "https://collector.example.test/sign-in",
        }],
        scan_steps: [{ key: "probe_forms", label: "Probe forms", status: "failed", detail: "cross_origin_form_action" }],
        elapsed_ms: 1200,
        risk_core: {
            schema_version: "2",
            scoring_version: "test-v2",
            final_score: 84,
            raw_score: 84,
            confidence: 77,
            verdict: "high",
            decision: "hard_block",
            next_action: "report",
            unavailable_checks: ["certificate_reputation"],
        },
        ...overrides,
    };
}

describe("WebIsolationReport", () => {
    it("uses Risk Core and observed backend evidence without inventing TLS facts", () => {
        const summary = summarizeWebIsolation(result());

        expect(summary.conclusion).toBe("NGUY HIỂM");
        expect(summary.riskScore).toBe(84);
        expect(summary.evidence).toEqual(expect.arrayContaining([
            expect.objectContaining({ channel: "Tên miền", title: "Tên miền đích đã thay đổi" }),
            expect.objectContaining({ channel: "Biểu mẫu", title: "Biểu mẫu gửi dữ liệu sang tên miền khác" }),
        ]));
        expect(summary.missingChannels).toContain("Chứng chỉ/TLS chi tiết chưa được backend trả về");
        expect(summary.actions[0]).toMatch(/báo cáo website/i);
    });

    it("never labels a completed legacy payload safe or assigns it a synthetic score", () => {
        const summary = summarizeWebIsolation(result({ risk_core: null, issues: [], canary: { ...result().canary, field_types: {} } }));

        expect(summary.conclusion).toBe("CHƯA ĐỦ DỮ LIỆU");
        expect(summary.riskScore).toBeNull();
    });

    it("recognizes an exact Prewise asset without changing the observed risk result", () => {
        const summary = summarizeWebIsolation(result({
            url: "https://prewise.site/sandbox",
            final_url: "https://prewise.site/sandbox",
            page_title: "Prewise Sandbox",
        }));

        expect(summary.identity.firstParty).toBe(true);
        expect(summary.identity.label).toBe("TÀI SẢN PREWISE ĐÃ NHẬN DIỆN");
        expect(summary.conclusion).toBe("NGUY HIỂM");
        expect(summary.riskScore).toBe(84);
    });

    it("does not mistake a lookalike hostname for a Prewise asset", () => {
        const summary = summarizeWebIsolation(result({
            url: "https://prewise.site.attacker.example",
            final_url: "https://prewise.site.attacker.example",
        }));

        expect(summary.identity.firstParty).toBe(false);
        expect(summary.identity.label).toBe("WEBSITE BÊN NGOÀI");
    });

    it("treats a low score with weak coverage as insufficient evidence", () => {
        const weakCore = {
            ...result().risk_core,
            final_score: 0,
            confidence: 17,
            verdict: "low",
            decision: "allow",
            not_checked_checks: Array.from({ length: 12 }, (_, index) => String(index + 1)),
        };
        const summary = summarizeWebIsolation(result({ risk_core: weakCore }));

        expect(summary.conclusion).toBe("CHƯA ĐỦ DỮ LIỆU");
        expect(summary.riskScore).toBe(0);
        expect(summary.missingChannels).toContain(
            "12 hạng mục Risk Core chưa được kiểm tra trong lượt này",
        );
        expect(summary.missingChannels).not.toContain("Hạng mục 1: chưa kiểm tra");
    });

    it("fails closed when the isolated browser did not complete", () => {
        const summary = summarizeWebIsolation(result({ ok: false, execution_status: "failed", risk_core: null }));

        expect(summary.conclusion).toBe("PHÂN TÍCH THẤT BẠI");
        expect(summary.actions[0]).toMatch(/không coi website là an toàn/i);
    });

    it("renders the compact output sections", () => {
        render(<WebIsolationReport result={result()} />);

        expect(screen.getByText("NGUY HIỂM")).toBeInTheDocument();
        expect(screen.getByText("84/100")).toBeInTheDocument();
        expect(screen.getByText("WEBSITE BÊN NGOÀI")).toBeInTheDocument();
        expect(screen.getByText("1200 ms")).toBeInTheDocument();
        expect(screen.getByText("Browser cô lập + Risk Core")).toBeInTheDocument();
        expect(screen.getByRole("heading", { name: "Bằng chứng chính" })).toBeInTheDocument();
        expect(screen.getByRole("heading", { name: "Kênh còn thiếu" })).toBeInTheDocument();
        expect(screen.getByRole("heading", { name: "Hành động đề xuất" })).toBeInTheDocument();
    });
});
