# Hướng dẫn lõi đánh giá rủi ro

Phiên bản hiện tại chỉ có một đường chấm điểm. Năm mươi tiêu chí URL là nguồn bằng chứng và bảng kiểm tra, không phải một bộ cộng điểm riêng.

## Quy trình duy nhất

```text
50 tiêu chí và các bộ quan sát
→ chuẩn hóa bằng chứng
→ loại trùng theo sự kiện
→ xác nhận bằng chứng trực tiếp và mức sàn
→ tổng hợp phi tuyến các nhóm độc lập
→ mô hình LightGBM hỗ trợ có giới hạn
→ tính độ tin cậy riêng
→ tầng quyết định
```

Không tồn tại công thức `80 + 20`, không cộng trực tiếp trọng số của 50 tiêu chí và không phối trộn thêm điểm sau tầng quyết định.

## Công thức điểm cuối

```text
điểm cuối = max(
  mức sàn từ bằng chứng trực tiếp đã xác nhận,
  điểm tổng hợp sau loại trùng,
  mức sàn từ quy tắc ghi đè hợp lệ
)
```

Điểm nằm trong khoảng `0–100`. Điểm là mức nguy hiểm vận hành, không phải phần trăm xác suất lừa đảo.

## Năm mươi tiêu chí

Mỗi tiêu chí chỉ ghi:

- trạng thái kiểm tra;
- độ nghiêm trọng;
- chất lượng bằng chứng;
- mã bằng chứng;
- sự kiện liên quan;
- lý do;
- mức mạnh của bằng chứng để hiển thị và kiểm toán.

Không có `max_weight`, `raw_score`, `adjusted_score`, `internal_score` hoặc `external_corroboration_score`.

## Loại trùng

- Cùng sự kiện: hợp nhất, không cộng lặp.
- Bằng chứng hỗ trợ: chỉ tăng thêm trong giới hạn.
- Rủi ro độc lập: giữ lại và tổng hợp phi tuyến.

Không dùng phép lấy lớn nhất cho toàn bộ bằng chứng vì sẽ làm mất các rủi ro độc lập.

## Mức sàn trực tiếp

Mức sàn cao chỉ được áp dụng cho hành vi đã xác nhận với chất lượng và độ nghiêm trọng đủ cao. Một từ khóa như `password`, `OTP` hoặc `malware` không tự tạo mức sàn.

Các mức mặc định:

| Hành vi đã xác nhận | Mức sàn |
|---|---:|
| Lấy cắp thông tin đăng nhập | 95 |
| Lấy cắp mã dùng một lần | 95 |
| Thực thi mã độc | 95 |
| Lệnh phá hủy hệ thống | 92 |
| Nâng quyền trái phép | 94 |
| Mã hóa hoặc xóa hàng loạt | 95 |

Tất cả mức sàn nằm trong `security/risk_core/action_config.py`.

## Vai trò LightGBM

LightGBM chỉ nhận đặc trưng có cấu trúc và hỗ trợ phát hiện tổ hợp tín hiệu yếu. Mức đóng góp mặc định bị giới hạn tối đa `18` điểm.

LightGBM:

- không được hạ mức sàn trực tiếp;
- không được thay đổi quyết định chặn chắc chắn thành cho phép;
- không coi dữ liệu thiếu là an toàn;
- khi không tải được thì trả về đóng góp bằng `0` và lõi vẫn hoạt động;
- khi dữ liệu khác xa dữ liệu huấn luyện thì làm giảm độ tin cậy.

## Độ tin cậy

Độ nguy hiểm và độ tin cậy là hai giá trị riêng, không nhân với nhau. Độ tin cậy xét độ đầy đủ dữ liệu, số nguồn độc lập, chất lượng nguồn, sự đồng thuận và tỷ lệ đặc trưng bị thiếu.

Thiếu dữ liệu quan trọng không được tự động trả về an toàn.

## Tầng quyết định

| Điều kiện | Quyết định mặc định |
|---|---|
| Mức sàn trực tiếp từ 90 | Chặn cứng |
| Điểm từ 85 | Chặn cứng |
| Điểm từ 60 | Chặn mềm và chạy cách ly |
| Điểm từ 40, độ tin cậy cao | Chặn mềm và hỏi xác nhận |
| Điểm từ 40, độ tin cậy thấp | Yêu cầu xem xét và chạy cách ly |
| Điểm từ 20 | Cảnh báo và quét sâu |
| Điểm dưới 20, độ tin cậy dưới 40 | Yêu cầu xem xét và chạy cách ly |
| Điểm dưới 20, đủ dữ liệu | Cho phép |

Tầng quyết định không sửa lại điểm.

## Kết quả kiểm toán

Kết quả phải chứa tối thiểu:

- `risk_score`;
- `confidence_score`;
- `direct_floor`;
- `direct_evidence_ids`;
- `composite_score`;
- `ml_contribution`;
- `missing_fields`;
- `unified_evidence_groups`;
- `deduplicated_evidence_count`;
- `reason_codes`;
- `decision`;
- `next_action`;
- phiên bản quy tắc, lược đồ bằng chứng và mô hình.

Không ghi mật khẩu, mã dùng một lần, khóa truy cập, khóa riêng hoặc nội dung nhạy cảm thô vào nhật ký.

## Tính bất biến bắt buộc

- Cùng đầu vào và cấu hình phải cho cùng kết quả khi không dùng mô hình.
- Một sự kiện không được cộng nhiều lần.
- Bằng chứng độc lập không bị loại bỏ.
- Mức sàn trực tiếp không bị mô hình hạ.
- Dữ liệu thiếu không được coi là an toàn.
- Chỉ có một điểm cuối do `security/risk_core/engine.py` tạo.
- Giao diện web, máy tính, tiện ích mở rộng và MCP chỉ đọc kết quả của lõi này.
