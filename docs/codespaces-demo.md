# Chạy Prewise cho buổi demo bằng GitHub Codespaces

Codespace 2 core/8 GB chạy web, API, MCP, PostgreSQL, ClamAV và Cloudflare Tunnel. Đây là cầu nối cho buổi demo, không phải máy chủ 24/7; GitHub tự dừng Codespace khi không hoạt động.

## Thiết lập một lần

1. Trong GitHub, mở **Settings > Codespaces > Secrets > New secret**.
2. Tạo `CLOUDFLARE_TUNNEL_TOKEN`, chọn repository `VNDT1625/Security`.
3. Để bật Gmail OAuth, tạo thêm `GMAIL_OAUTH_CLIENT_ID`,
   `GMAIL_OAUTH_CLIENT_SECRET` và `GMAIL_TOKEN_ENCRYPTION_KEYS`. Redirect URI
   mặc định là `https://api.prewise.site/v1/integrations/gmail/callback`; URI
   này cũng phải được khai báo trong Google Cloud Console. Có thể ghi đè bằng
   secret `GMAIL_OAUTH_REDIRECT_URI` và `GMAIL_WEB_RETURN_URL`.
4. Nếu có AI adapter, tạo thêm `ADAPTER_BASE_URL`, `ADAPTER_API_KEY`, `LLM_BASE_URL`, `LLM_API_KEY` và `LLM_MODEL`.
5. Tạo Codespace từ nhánh phát hành và chọn máy 2 core/8 GB.
6. Trong terminal của Codespace chạy `bash scripts/codespaces-demo-up.sh`.

Script khởi động luôn đồng bộ các Codespaces secret vào `.env.codespaces` (file
bị Git bỏ qua và có mode `0600`), nên secret mới hoặc vừa xoay không còn bị bỏ
qua chỉ vì file runtime đã tồn tại.

Named tunnel hiện có tiếp tục trỏ web tới `127.0.0.1:3000` và toàn bộ API/MCP tới `127.0.0.1:8000`.

API gateway tại cổng 8000 tự chuyển `/mcp`, `/oauth` và `/.well-known` sang MCP; vì vậy không cần public thêm cổng 3001. Nếu cần dữ liệu hiện có, tải file SQLite vào `.aisec-data/armor.db` rồi chạy `bash scripts/codespaces-data-migrate.sh` trước lần khởi động đầy đủ đầu tiên.

## Trước buổi demo

- Đặt idle timeout của Codespaces thành 240 phút.
- Khởi động Codespace trước 15–30 phút và chạy lại script `codespaces-demo-up.sh`.
- Kiểm tra `https://www.prewise.site/` và `https://api.prewise.site/v1/health`.
- Giữ cửa sổ Codespace mở trong suốt buổi demo.

## Dừng

Chạy `bash scripts/codespaces-demo-down.sh`. Không thêm `--volumes` nếu cần giữ PostgreSQL giữa các lần khởi động.
