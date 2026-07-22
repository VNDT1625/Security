import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ExportReportButton } from "./ExportReportButton";

describe("ExportReportButton", () => {
  const originalTitle = document.title;

  afterEach(() => {
    document.title = originalTitle;
    vi.restoreAllMocks();
  });

  it("opens the print dialog with a useful PDF filename and restores the page title", () => {
    document.title = "Prewise";
    const print = vi.spyOn(window, "print").mockImplementation(() => {
      expect(document.title).toBe("prewise-url-scan-123");
    });

    render(<ExportReportButton reportId="scan 123" reportType="url" />);
    fireEvent.click(screen.getByRole("button", { name: /xuất pdf/i }));

    expect(print).toHaveBeenCalledOnce();
    expect(document.title).toBe("Prewise");
  });
});
