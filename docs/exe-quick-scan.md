# Test nhanh EXE trong Lab

## Mục tiêu

`Test nhanh EXE` cung cấp bước sàng lọc ban đầu cho tệp Windows `.exe` mà không chạy tệp trên máy chủ. Tính năng luôn thực hiện phân tích PE cục bộ trước, sau đó chỉ dùng MetaDefender Cloud khi API key đã được cấu hình.

Tính năng này không thay thế Sandbox Pro. Lab trả kết quả tĩnh và uy tín hash nhanh; Sandbox Pro dành cho thực thi động, desktop tương tác, process tree, file/registry/network telemetry và điều tra sâu.

## Luồng xử lý

1. Backend đọc tệp trong giới hạn `MAX_UPLOAD_BYTES`.
2. Kiểm tra phần mở rộng `.exe` và cấu trúc DOS/PE.
3. Tính SHA-256, không thực thi tệp.
4. Phân tích PE cục bộ:
   - PE32/PE32+ và kiến trúc;
   - subsystem và entry point;
   - section, quyền R/W/X và entropy;
   - Authenticode directory có tồn tại hay không;
   - overlay, timestamp và cấu trúc bất thường.
5. Khi MetaDefender được cấu hình, backend tra cứu SHA-256 trước.
6. Nếu hash chưa có báo cáo, file chỉ được upload khi request gửi `share_with_provider=true`.
7. Frontend poll báo cáo provider bằng `data_id` cho đến khi hoàn tất hoặc hết thời gian chờ.

## Quyền riêng tư

Mặc định `share_with_provider=false`. Hash có thể được gửi để tra cứu, nhưng bytes của file không rời backend nếu người dùng chưa đồng ý.

Khi người dùng đồng ý upload, backend gửi header `samplesharing: 1`. Không dùng chế độ này với file riêng tư, mã nguồn nội bộ, phần mềm chưa phát hành, dữ liệu cá nhân hoặc tài liệu bí mật. Private scanning của MetaDefender là khả năng theo license riêng và chưa được bật trong luồng Community hiện tại.

## Cấu hình

Thêm vào `.env` của backend:

```env
METADEFENDER_API_KEY=
METADEFENDER_BASE_URL=https://api.metadefender.com/v4
METADEFENDER_TIMEOUT_SECONDS=20
```

Để trống `METADEFENDER_API_KEY` vẫn cho phép phân tích PE cục bộ. API key chỉ được đọc ở backend và không bao giờ gửi xuống trình duyệt.

## API

### MCP cho AI agent

AI agent có thể gọi `quick_scan_exe` với đường dẫn tương đối tới tệp `.exe`
trong `MCP_SANDBOX_DIR`. Tool luôn phân tích tĩnh và không chạy tệp. Tham số
`share_with_provider` mặc định là `false`; chỉ đặt thành `true` sau khi người
dùng đồng ý rõ ràng cho việc tải mẫu lên provider bên ngoài.

Client MCP từ xa không truy cập được filesystem server có thể gọi
`quick_scan_exe_content` với `filename` và `content_base64`. Bytes chỉ tồn tại
trong request/phân tích, không được ghi vào audit log và vẫn chịu giới hạn
`MAX_UPLOAD_BYTES`.

Qua Streamable HTTP, `share_with_provider=true` luôn yêu cầu scope
`mcp:file:share_external` ngoài quyền gọi MCP thông thường. Scope này không
được cấp mặc định. Kết quả MCP chuẩn hóa verdict cho agent thành
`ALLOW|WARN|BLOCK`, đồng thời giữ kết quả gốc trong `scan_verdict`.
`risk_score` MCP luôn nằm trong khoảng `0..1`; điểm Quick Scan gốc `0..100`
được giữ ở `scan_risk_score` hoặc `provider_risk_score`.

Nếu kết quả có `provider.status=queued`, agent dùng
`get_exe_quick_scan_report` với `data_id` được trả về để lấy trạng thái mới.
MCP áp dụng cùng `MAX_UPLOAD_BYTES` như API upload và từ chối path traversal,
tệp ngoài sandbox hoặc tệp không có phần mở rộng `.exe`.
Polling report không trừ thêm quota scan.

### Phân tích nhanh

```http
POST /v1/assess/file/exe-quick-scan
Content-Type: multipart/form-data
```

Form fields:

- `file`: tệp `.exe`.
- `share_with_provider`: `false` mặc định; chỉ đặt `true` sau khi người dùng xác nhận.

Các trường quan trọng trong response:

- `analysis_mode=quick_scan`;
- `dynamic_execution=false`;
- `sha256`, `risk_score`, `verdict`;
- `local_analysis`;
- `provider`;
- `upload_consent_required`;
- `privacy_notice`.

### Lấy báo cáo provider

```http
GET /v1/assess/file/exe-quick-scan/provider/{data_id}
```

`data_id` được kiểm tra theo allowlist ký tự trước khi nối vào URL provider.

## Trạng thái provider

- `disabled`: chưa cấu hình API key, local scan vẫn hoạt động.
- `not_found`: hash chưa có báo cáo; cần xác nhận trước khi upload.
- `known`: đã có báo cáo từ hash lookup.
- `queued`: provider đang xử lý.
- `completed`: provider hoàn tất.
- `failed`: provider lỗi, hết quota hoặc timeout; kết quả local vẫn được giữ.

## Giới hạn an toàn

- Không chạy file trong Quick Scan.
- Không follow redirect từ provider.
- Chỉ chấp nhận SHA-256 hợp lệ và `data_id` theo allowlist.
- Giới hạn số section PE được parse để tránh file cố tình làm tốn CPU.
- Lỗi provider được chuẩn hóa, không trả response body hoặc API key cho client.
- Verdict `no_obvious_theft_detected` chỉ có nghĩa chưa thấy chỉ báo rõ trong phạm vi kiểm tra; không phải chứng nhận an toàn.

## Kiểm thử

```powershell
pytest -q tests/test_exe_quick_scan.py tests/test_exe_quick_scan_api.py
ruff check security/exe_quick_scan.py backend/services/exe_quick_scan_service.py backend/routers/assess.py tests/test_exe_quick_scan.py tests/test_exe_quick_scan_api.py
cd frontend/web
npm run typecheck
```

Khi chưa có MetaDefender API key, test suite dùng provider giả để kiểm tra đầy đủ luồng consent, upload, polling và merge verdict mà không gửi mẫu thật ra Internet.
