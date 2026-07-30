import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
    CloudAnalysis,
    CloudAnalysisReport,
    cloudChannelStatus,
    cloudOutcomeLabel,
} from "./cloud-analysis-report";

function analysis(overrides: Partial<CloudAnalysis> = {}): CloudAnalysis {
    return {
        schemaVersion: "1",
        outcome: "inconclusive",
        verdict: "analysis_inconclusive_telemetry_degraded",
        riskScore: 0,
        confidence: 0.5,
        confidenceBasis: "telemetry_coverage",
        isConclusive: false,
        safetyClaim: "not_established",
        evidenceChannels: [
            { id: "process", status: "observed", eventCount: 2 },
            { id: "file", status: "no_activity", eventCount: 0 },
            { id: "registry", status: "unavailable", eventCount: 0 },
            { id: "network", status: "unavailable", eventCount: 0 },
        ],
        missingChannels: ["network", "registry"],
        riskSignals: [],
        recommendedAction: { code: "retry", label: "Phân tích lại trong môi trường tương thích" },
        cleanup: { state: "complete", vmDestroyed: true, remoteAccessRevoked: true },
        ...overrides,
    };
}

describe("CloudAnalysisReport", () => {
    it("renders an inconclusive result as missing evidence, never safe", () => {
        render(<CloudAnalysisReport analysis={analysis()} phase="completed" sampleStatus="completed" />);

        expect(screen.getByText("CHƯA ĐỦ BẰNG CHỨNG")).toBeInTheDocument();
        expect(screen.getByText("0/100")).toBeInTheDocument();
        expect(screen.getByText("50%")).toBeInTheDocument();
        expect(screen.getByText(/chưa thể kết luận file an toàn/i)).toBeInTheDocument();
        expect(screen.getAllByText("Không khả dụng")).toHaveLength(2);
        expect(screen.getByText("VM ĐÃ HỦY")).toBeInTheDocument();
        expect(screen.getByText("Remote access đã thu hồi")).toBeInTheDocument();
    });

    it("does not assign a score or safe claim to failed analysis", () => {
        render(
            <CloudAnalysisReport
                analysis={analysis({
                    outcome: "failed",
                    riskScore: null,
                    confidence: null,
                    evidenceChannels: [],
                    missingChannels: ["process", "file", "registry", "network"],
                })}
                phase="failed"
                sampleStatus="failed"
            />,
        );

        expect(screen.getByText("PHÂN TÍCH THẤT BẠI")).toBeInTheDocument();
        expect(screen.getAllByText("—")).toHaveLength(2);
        expect(screen.getByText(/một lần chạy thất bại/i)).toBeInTheDocument();
    });

    it("limits a low-risk completed result to the observed window", () => {
        render(
            <CloudAnalysisReport
                analysis={analysis({
                    outcome: "no_obvious_behavior",
                    isConclusive: true,
                    safetyClaim: "no_obvious_behavior_only",
                    missingChannels: [],
                })}
                phase="completed"
                sampleStatus="completed"
            />,
        );

        expect(screen.getByText("CHƯA GHI NHẬN HÀNH VI RÕ")).toBeInTheDocument();
        expect(screen.getByText(/không phải chứng nhận file an toàn/i)).toBeInTheDocument();
    });

    it("maps bounded labels and channel states", () => {
        expect(cloudOutcomeLabel("dangerous")).toBe("NGUY HIỂM");
        expect(cloudOutcomeLabel("unexpected")).toBe("CHƯA ĐỦ BẰNG CHỨNG");
        expect(cloudChannelStatus({ id: "file", status: "no_activity", eventCount: 0 })).toMatch(
            /Đã quan sát/,
        );
    });
});
