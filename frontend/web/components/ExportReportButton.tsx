"use client";

type ExportReportButtonProps = {
  reportId?: string;
  reportType: "url" | "email" | "sms";
};

function safeReportId(value?: string): string {
  const cleaned = (value || "report").replace(/[^a-zA-Z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
  return cleaned || "report";
}

export function ExportReportButton({ reportId, reportType }: ExportReportButtonProps) {
  function exportReport() {
    const previousTitle = document.title;
    document.title = `prewise-${reportType}-${safeReportId(reportId)}`;
    try {
      window.print();
    } finally {
      document.title = previousTitle;
    }
  }

  return <button type="button" onClick={exportReport} title="In hoặc lưu báo cáo dưới dạng PDF">↓ Xuất PDF</button>;
}
