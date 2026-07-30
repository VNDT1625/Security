import { createElement } from "react";
import { render, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { ENGLISH_TRANSLATIONS, LanguageProvider, translateText } from "./LanguageContext";

const CRITICAL_UI_COPY = [
  "Cài đặt",
  "Ngôn ngữ giao diện",
  "English đã sẵn sàng. Phạm vi bản dịch được kiểm tra tự động trong mỗi bản build.",
  "Nhìn kỹ trước khi tin.",
  "Dán tín hiệu đáng ngờ. Prewise sẽ bóc tách điều đang ẩn phía sau.",
  "XEM DEMO TƯƠNG TÁC ↗",
  "Phân tích",
  "Lịch sử",
  "Lịch sử cục bộ",
  "Lịch sử tài khoản",
  "Quyền riêng tư",
  "Khi tắt, lần phân tích mới chỉ được giữ trong tab hiện tại và không xuất hiện trong lịch sử cục bộ.",
  "Che mật khẩu, OTP và số thẻ trong bản xem trước, lịch sử và kết quả được lưu.",
  "Trang Lịch sử trong workspace chỉ đọc dữ liệu trên trình duyệt này. Lịch sử tài khoản được tải riêng sau khi đăng nhập.",
  "Model và chế độ AI",
  "Web hỗ trợ AI bảo mật Prewise hoặc API endpoint HTTPS. Admin chỉ quyết định chế độ và model nào được phép xuất hiện.",
  "Local LLM trên máy cá nhân không thể được web hosted truy cập an toàn. Tùy chọn này chỉ có trên Desktop khi Core API cũng chạy local. Endpoint từ xa bắt buộc HTTPS.",
] as const;

describe("English translation coverage", () => {
  beforeEach(() => {
    localStorage.clear();
    delete document.documentElement.dataset.motion;
    delete document.documentElement.dataset.density;
  });

  it.each(CRITICAL_UI_COPY)("translates critical UI copy: %s", (source) => {
    expect(ENGLISH_TRANSLATIONS[source]).toBeTruthy();
    expect(translateText(source)).not.toBe(source);
  });

  it("does not retain the unfinished-language notice", () => {
    expect(
      ENGLISH_TRANSLATIONS["Bản dịch tiếng Anh đầy đủ sẽ được áp dụng khi gói ngôn ngữ hoàn tất."],
    ).toBeUndefined();
  });

  it("restores appearance preferences on every route load", async () => {
    localStorage.setItem("prewise-settings", JSON.stringify({
      motion: "reduced",
      density: "compact",
    }));
    render(createElement(LanguageProvider, null, createElement("div", null, "Cài đặt")));

    await waitFor(() => {
      expect(document.documentElement.dataset.motion).toBe("reduced");
      expect(document.documentElement.dataset.density).toBe("compact");
    });
  });
});
