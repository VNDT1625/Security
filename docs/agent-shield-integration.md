# Prewise Agent Shield — MCP & Harness Integration

Prewise là bước **pre-action security** dành cho AI agent. Agent/harness phải gọi Risk Core trước khi xử lý dữ liệu không tin cậy hoặc thực thi tool.

## MCP

Khởi chạy local bằng Streamable HTTP:

```bash
python -m mcp_server.server --transport streamable-http --host 127.0.0.1 --port 3001
```

MCP URL:

```text
http://127.0.0.1:3001/mcp
```

Streamable HTTP mặc định **bắt buộc** header:

```http
Authorization: Bearer pw_live_...
```

Key phải active, chưa hết hạn, thuộc user active và có scope `mcp:invoke` hoặc
scope đánh giá tương ứng. `mcp:invoke` được giữ làm quyền bao trùm để tương
thích client cũ. Chia sẻ mẫu file ra provider luôn cần thêm
`mcp:file:share_external`; quyền bao trùm không thay thế được quyền nhạy cảm
này. Key bị rotate/revoke bị từ chối ngay. Anonymous bị tắt mặc định và bị cấm
khi `APP_ENV=production`.

Input được validate và kiểm tra scope trước khi trừ quota. Polling báo cáo,
connection test và deterministic summary không tiêu tốn lượt scan. Mỗi tool
call được audit riêng với tên tool, thời gian, kết quả, verdict, trạng thái
provider và cờ chia sẻ mẫu; nội dung/file bytes không được ghi vào audit log.

Các tool:

- `assess_url`: trước `navigate`, `open_url`, `click_link`.
- `assess_text`: trước khi đưa email/SMS/web/tool output vào context của LLM.
- `scan_prompt_injection`: trước khi prompt không tin cậy tới agent.
- `assess_action`: trước mọi tool call có side effect.
- `assess_page`: sau khi browser đọc DOM/HTML.
- `assess_file_static`: trước khi mở/chạy file trong sandbox MCP.
- `quick_scan_exe`: test nhanh EXE đã nằm trong sandbox MCP.
- `quick_scan_exe_content`: test nhanh bytes EXE dạng base64 từ MCP client từ xa.
- `get_exe_quick_scan_report`: poll provider mà không trừ thêm quota scan.

> MCP tool là advisory. Muốn bảo vệ chắc chắn, harness phải đặt Prewise trong hook bắt buộc trước tool executor; không chỉ nhắc LLM tự gọi.

## REST Agent Security API

Base path: `/v1/agent/check`

- `POST /url` — `{ "url": "https://..." }`
- `POST /content` — `{ "content": "...", "content_type": "webpage" }`
- `POST /prompt` — `{ "content": "..." }`
- `POST /file` — `{ "filename": "setup.exe", "content_base64": "...", "source_url": "..." }`
- `POST /action` — action + target + data types + agent context

Có thể gọi anonymous với quota giới hạn, hoặc:

```http
Authorization: Bearer pw_live_...
```

API key được hash với server-side pepper, có scope, trạng thái, last-used và hỗ trợ rotate/revoke. Secret đầy đủ chỉ trả một lần khi rotate; `GET /v1/account/api-key` chỉ trả key đã che.

Scope:

```text
assess:url
assess:content
assess:prompt
assess:file
assess:action
mcp:invoke
mcp:file:share_external
logs:read
```

## Quy tắc enforcement

Response thống nhất có:

```json
{
  "schema_version": "1.0",
  "ok": true,
  "decision": "ALLOW | WARN | ASK_USER_CONFIRMATION | BLOCK",
  "risk_score": 0.91,
  "risk_level": "critical",
  "confidence": 0.94,
  "evidence": [],
  "recommended_agent_behavior": "...",
  "enforcement": {
    "proceed": false,
    "ask_user": false,
    "disable_tools": true,
    "quarantine_content": true
  },
  "request_id": "..."
}
```

Harness bắt buộc:

- `ALLOW`: tiếp tục.
- `WARN`: tiếp tục thận trọng, audit warning.
- `ASK_USER_CONFIRMATION`: dừng và hỏi người dùng.
- `BLOCK`: không thực thi tool, cách ly nội dung.

## TypeScript hook

```ts
async function beforeToolCall(call: ToolCall, apiKey: string) {
  const response = await fetch("https://api.prewise.site/v1/agent/check/action", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      action_type: call.type,
      target: call.target,
      data_types: call.dataTypes ?? [],
      agent_context: {
        agent_type: "browser_agent",
        user_intent: call.userIntent,
        available_assets: call.availableAssets ?? [],
      },
    }),
  });
  const verdict = await response.json();
  if (verdict.decision === "BLOCK") throw new Error(verdict.safe_summary);
  if (verdict.decision === "ASK_USER_CONFIRMATION") return { askUser: true, verdict };
  return { proceed: true, verdict };
}
```

## File safety

`/check/file` chỉ thực hiện static analysis; server chính **không chạy file**. File bị giới hạn bởi `MAX_UPLOAD_BYTES`. Với EXE cần dynamic analysis, chuyển sang sandbox cô lập riêng, không chạy trong process gateway.
