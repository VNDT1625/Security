# Báo cáo nâng cấp lõi rủi ro bảo mật

## 1. Kiến trúc cũ

Yêu cầu hành động đi vào `InferenceService.assess_action`, được chấm bằng các hệ số cố định, sau đó chuyển thẳng sang quyết định công khai. Lõi URL đã có bộ chấm riêng, còn chấm hành động chưa có mô hình bằng chứng, loại trùng theo sự kiện, sàn nguy hiểm, theo dõi chuỗi hành động hoặc độ tin cậy tách biệt.

## 2. Điểm yếu đã phát hiện

- Cộng điểm tuyến tính có thể cộng lặp nhiều tín hiệu cùng mô tả một việc.
- Không bảo đảm bằng chứng nguy hiểm trực tiếp giữ được mức sàn.
- Điểm nguy hiểm và độ tin cậy chưa tách rõ.
- Thiếu dữ liệu có thể không được xử lý đủ thận trọng.
- Mô hình LightGBM đang có chỉ dành cho URL, không phù hợp với dữ liệu hành động.
- Chưa phát hiện rủi ro tích lũy trong một phiên.
- Giải thích và nhật ký hành động chưa đủ chi tiết để đối chiếu.

## 3. Kiến trúc mới

Luồng mới gồm: thu thập bằng chứng → chuẩn hóa → loại trùng theo sự kiện → xác định sàn trực tiếp → chấm tổng hợp phi tuyến → đóng góp giới hạn từ LightGBM → tính độ tin cậy riêng → theo dõi phiên → áp chính sách → tạo giải thích và nhật ký.

Công thức cuối:

```text
điểm nguy hiểm cuối = max(sàn bằng chứng trực tiếp, điểm tổng hợp đã loại trùng)
```

LightGBM chỉ được tăng cảnh giác trong giới hạn cấu hình; không được hạ sàn trực tiếp hoặc tự quyết định cho phép/chặn.

## 4. Tệp chính đã tạo hoặc sửa

- `security/risk_core/action_types.py`: kiểu dữ liệu bằng chứng và kết quả.
- `security/risk_core/action_config.py`: toàn bộ sàn, ngưỡng, giới hạn và suy giảm phiên.
- `security/risk_core/action_evidence.py`: thu thập, chuẩn hóa, loại trùng.
- `security/risk_core/action_scoring.py`: sàn trực tiếp, điểm tổng hợp, độ tin cậy.
- `security/risk_core/action_features.py`: đặc trưng có phiên bản, giữ nguyên giá trị thiếu.
- `security/risk_core/action_lightgbm.py`: bộ nối LightGBM và phương án an toàn khi thiếu mô hình.
- `security/risk_core/action_session.py`: rủi ro tích lũy, suy giảm, gửi nhỏ giọt, chuỗi nhiều bước.
- `security/risk_core/action_policy.py`: quyết định cuối.
- `security/risk_core/action_explanation.py`: giải thích và dữ liệu nhật ký đã che bí mật.
- `security/risk_core/action_engine.py`: điều phối toàn bộ luồng.
- `security/risk_core/action_benchmark.py`, `tools/benchmark_action_risk.py`: đo các chỉ số bảo mật.
- `backend/services/action_audit_service.py`: lưu nhật ký đã băm/che dữ liệu nhạy cảm.
- `backend/services/inference_service.py`, `backend/dependencies.py`, các tuyến `assess` và `agent_security`: nối lõi mới, giữ giao diện cũ.
- `shared/schemas.py`, `mcp_server/tools.py`: thêm dấu vết lõi theo cách tương thích.
- `tests/test_evidence_action_risk_engine.py`, `tests/test_action_risk_benchmark.py`, `tests/fixtures/action_risk/structured_cases.json`: kiểm thử và dữ liệu mẫu.

## 5. Luồng quyết định

1. Phân loại hành động, dữ liệu, đích, quyền và ý định.
2. Tạo bằng chứng có mã sự kiện và quan hệ.
3. Gộp tín hiệu cùng sự kiện; chỉ cộng nhẹ bằng chứng hỗ trợ; giữ rủi ro độc lập.
4. Chỉ đặt sàn 90–95 khi mẫu nguy hiểm đã được xác nhận bằng dữ liệu có cấu trúc.
5. Tính điểm tổng hợp có giới hạn trong 0–100.
6. LightGBM, nếu có, chỉ thêm phần đóng góp bị giới hạn.
7. Tính độ tin cậy riêng; dữ liệu thiếu không được đổi thành số 0 an toàn.
8. Cập nhật rủi ro phiên và áp chính sách cuối.
9. Trả giải thích, đồng thời lưu nhật ký không chứa mật khẩu, mã dùng một lần, khóa hoặc nội dung nhạy cảm thô.

## 6. Chạy kiểm thử

```powershell
python -m pytest -q tests\test_evidence_action_risk_engine.py tests\test_action_risk_benchmark.py
python -m pytest -q tests\test_policy_engine.py tests\test_agent_security.py tests\test_legal_rag.py tests\test_mcp_tools.py tests\integration\test_api_flow.py
python tools\benchmark_action_risk.py
```

## 7. Chuyển chế độ

Biến môi trường `SECURITY_CORE_MODE` nhận:

- `legacy`: chỉ dùng lõi cũ.
- `shadow`: lõi cũ quyết định chính; lõi mới chạy song song và ghi chênh lệch. Đây là mặc định.
- `new_engine`: lõi mới quyết định chính nhưng vẫn ánh xạ về kiểu trả lời công khai cũ.

## 8. Tích hợp LightGBM

Huấn luyện mô hình dành riêng cho bộ đặc trưng hành động phiên bản `action-features-v1`, xuất tệp ONNX, rồi đặt đường dẫn vào `ACTION_LIGHTGBM_MODEL_PATH`. Nếu tệp thiếu, sai hoặc không tải được, lõi quy tắc và chính sách vẫn hoạt động; kết quả ghi rõ mô hình không khả dụng.

Không dùng mô hình URL hiện tại cho hành động vì hai bộ đặc trưng khác nhau.

## 9. Phần chưa thể hoàn thiện

- Chưa có mô hình LightGBM hành động đã huấn luyện.
- Chưa có tập dữ liệu hành động thực tế, độc lập và được gắn nhãn để hiệu chỉnh ngưỡng.
- Chưa thể tuyên bố tỷ lệ phát hiện hoặc báo nhầm trong môi trường thật.

## 10. Rủi ro còn lại

- Quy tắc xác nhận phụ thuộc chất lượng phân loại dữ liệu và thông tin quyền từ nơi gọi.
- Theo dõi phiên hiện ở bộ nhớ tiến trình; triển khai nhiều máy cần kho trạng thái dùng chung.
- Các ngưỡng cần được hiệu chỉnh bằng dữ liệu thật trước khi bật `new_engine` rộng rãi.

## 11. Kết quả kiểm chứng

- 15/15 bài kiểm thử riêng của lõi mới và bộ đo đã qua.
- 61/61 bài kiểm thử tương thích về chính sách, hành động, luật, máy chủ công cụ và luồng giao diện đã qua.
- Kiểm thử riêng tuyến ghi nhật ký đã qua; địa chỉ đích chỉ được lưu dạng băm.
- Lần chạy lại nhóm lõi và tích hợp trọng yếu: 38/38 qua.
- Kiểm tra biên dịch các tệp Python đã thay đổi: qua.
- Toàn bộ bộ kiểm thử dự án chưa hoàn tất vì vượt giới hạn chạy 4 phút; không có kết luận cho các phần ngoài phạm vi đã kiểm tra.

Bộ đo mẫu 3 trường hợp cho kết quả thu hồi nguy hiểm 1, thu hồi nghiêm trọng 1, báo nhầm 0 và bỏ sót 0. Đây chỉ là kiểm tra kỹ thuật trên dữ liệu mẫu, không phải kết quả chất lượng sản phẩm.

## 12. Trạng thái hoàn thành

Các yêu cầu cốt lõi về sàn trực tiếp, loại trùng, giữ bằng chứng độc lập, giới hạn LightGBM, tách nguy hiểm/độ tin cậy, xử lý thiếu dữ liệu, rủi ro phiên, giải thích, nhật ký và chế độ chạy song song đã được triển khai và kiểm tra trong phạm vi nêu trên.
