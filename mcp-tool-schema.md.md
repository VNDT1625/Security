# MCP Tool Schema — AI Security Armor

> JSON Schema chi tiết cho input/output của từng MCP tool, dùng cho AI agent
> (ChatGPT/Claude) gọi trước khi thực hiện hành động.

Mọi response hiện dùng envelope tương thích ngược với các trường chung:

```json
{
  "schema_version": "1.0",
  "ok": true,
  "request_id": "uuid",
  "verdict": "ALLOW | WARN | ASK_CONFIRM | BLOCK"
}
```

Các tool EXE bổ sung:

- `quick_scan_exe(path, share_with_provider=false)`: quét file trong `MCP_SANDBOX_DIR`.
- `quick_scan_exe_content(filename, content_base64, share_with_provider=false)`: quét bytes từ client từ xa.
- `get_exe_quick_scan_report(data_id)`: poll reputation provider, không trừ thêm quota scan.

`share_with_provider=true` chỉ hợp lệ sau khi người dùng đồng ý rõ ràng và
credential HTTP có scope `mcp:file:share_external`. Quick Scan không bao giờ
thực thi file.

---

## Tool 1: `check_url_before_click`

**Mục đích:** Agent gọi trước khi click link hoặc điều hướng trình duyệt.

### Input Schema

```json
{
  "name": "check_url_before_click",
  "description": "Assess risk of a URL before the agent navigates to it or clicks it.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "url": {
        "type": "string",
        "description": "The full URL to be assessed, including scheme."
      },
      "context": {
        "type": "string",
        "description": "Optional: surrounding text/context where URL was found.",
        "default": ""
      }
    },
    "required": ["url"]
  }
}
```

### Output Schema

```json
{
  "type": "object",
  "properties": {
    "risk_score": { "type": "number", "minimum": 0, "maximum": 1 },
    "verdict": { "type": "string", "enum": ["ALLOW", "WARN", "BLOCK", "ASK_CONFIRM"] },
    "evidence": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "source": { "type": "string" },
          "message": { "type": "string" },
          "severity": { "type": "string", "enum": ["low", "medium", "high", "critical"] }
        }
      }
    },
    "confidence": { "type": "number", "minimum": 0, "maximum": 1 },
    "explanation": { "type": "string", "description": "Human-readable summary from LLM layer" },
    "request_id": { "type": "string", "format": "uuid" }
  },
  "required": ["risk_score", "verdict", "evidence", "request_id"]
}
```

### Example

```json
// Request
{ "url": "http://paypa1-secure-verify.tk/login", "context": "email body link" }

// Response
{
  "risk_score": 0.94,
  "verdict": "BLOCK",
  "evidence": [
    { "source": "url_adapter", "message": "Domain uses homoglyph: 'paypa1' resembles 'paypal'", "severity": "critical" },
    { "source": "url_adapter", "message": "TLD '.tk' commonly associated with phishing", "severity": "medium" }
  ],
  "confidence": 0.91,
  "explanation": "Đường dẫn này giả mạo PayPal bằng cách thay 'l' thành số '1', kết hợp với TLD miễn phí thường bị lợi dụng cho lừa đảo. Khuyến nghị: KHÔNG truy cập.",
  "request_id": "a1b2c3d4-..."
}
```

---

## Tool 2: `check_content_before_processing`

**Mục đích:** Agent gọi trước khi đọc/xử lý nội dung email, trang web, file text — để phát hiện prompt injection ẩn trong nội dung.

### Input Schema

```json
{
  "name": "check_content_before_processing",
  "description": "Scan text content for prompt injection attempts before the agent processes it as context.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "content": { "type": "string", "description": "Raw text content to scan." },
      "content_type": {
        "type": "string",
        "enum": ["email", "webpage", "file", "chat_message"],
        "default": "webpage"
      }
    },
    "required": ["content"]
  }
}
```

### Output Schema

```json
{
  "type": "object",
  "properties": {
    "risk_score": { "type": "number", "minimum": 0, "maximum": 1 },
    "verdict": { "type": "string", "enum": ["ALLOW", "WARN", "BLOCK"] },
    "injection_detected": { "type": "boolean" },
    "evidence": { "type": "array", "items": { "type": "object" } },
    "safe_summary": {
      "type": "string",
      "description": "Sanitized summary of content safe for agent to use, if injection detected"
    },
    "request_id": { "type": "string", "format": "uuid" }
  },
  "required": ["risk_score", "verdict", "injection_detected", "request_id"]
}
```

---

## Tool 3: `check_action_before_execution`

**Mục đích:** Agent gọi trước khi thực hiện hành động nhạy cảm (submit form, download file, gửi email, gọi API bên ngoài).

### Input Schema

```json
{
  "name": "check_action_before_execution",
  "description": "Assess risk of an action the agent is about to perform on behalf of the user.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "action_type": {
        "type": "string",
        "enum": ["click_link", "submit_form", "download_file", "run_file", "send_email", "call_api"]
      },
      "target": { "type": "string", "description": "URL, file path, or API endpoint the action targets." },
      "protected_assets": {
        "type": "array",
        "items": { "type": "string" },
        "description": "List of user assets potentially exposed (e.g. 'email_credentials', 'payment_info')."
      }
    },
    "required": ["action_type", "target"]
  }
}
```

### Output Schema

```json
{
  "type": "object",
  "properties": {
    "risk_score": { "type": "number", "minimum": 0, "maximum": 1 },
    "verdict": { "type": "string", "enum": ["ALLOW", "WARN", "BLOCK", "ASK_CONFIRM"] },
    "reasoning": { "type": "string" },
    "requires_user_confirmation": { "type": "boolean" },
    "request_id": { "type": "string", "format": "uuid" }
  },
  "required": ["risk_score", "verdict", "requires_user_confirmation", "request_id"]
}
```

### Example — Trường hợp ASK_CONFIRM

```json
// Request
{
  "action_type": "submit_form",
  "target": "https://unknown-survey-site.com/submit",
  "protected_assets": ["email_address", "phone_number"]
}

// Response
{
  "risk_score": 0.55,
  "verdict": "ASK_CONFIRM",
  "reasoning": "Form submits to a domain not previously verified. Contains fields requesting personal contact info. Risk is moderate but not conclusive - recommend user confirmation before proceeding.",
  "requires_user_confirmation": true,
  "request_id": "e5f6g7h8-..."
}
```

---

## Bảng tổng hợp verdict → hành vi agent phải tuân theo

| Verdict | Agent PHẢI làm gì |
|---|---|
| `ALLOW` | Tiếp tục hành động bình thường |
| `WARN` | Tiếp tục NHƯNG log cảnh báo, có thể hiển thị cho user sau |
| `BLOCK` | DỪNG hành động ngay, không thực hiện, thông báo lý do cho user |
| `ASK_CONFIRM` | DỪNG, hỏi xác nhận người dùng trước khi tiếp tục — KHÔNG tự quyết |

---

## Error Response (dùng chung 3 tool)

```json
{
  "type": "object",
  "properties": {
    "error": { "type": "string" },
    "detail": { "type": "string" },
    "request_id": { "type": "string", "format": "uuid" }
  }
}
```

| Error code | Trường hợp |
|---|---|
| `invalid_input` | Thiếu field bắt buộc hoặc sai type |
| `model_unavailable` | ONNX model chưa load / crash |
| `llm_timeout` | Ollama không trả lời trong 5s — vẫn trả risk_score/verdict, chỉ thiếu `explanation` |
| `rate_limited` | Vượt quota MCP API key |
