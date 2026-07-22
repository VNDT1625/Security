# AI Security Armor Docs

- [URL phishing detection](./url-phishing-detection.md)
- [Live URL sandbox](./url-sandbox.md)
- [Advanced browser sandbox](./browser-sandbox.md)
- [Quick EXE Lab](./exe-quick-scan.md)
- [Windows Cloud Lab: Auto Analyze, Interactive Investigate và SePay](./sandbox-cloud-billing.md)
- [Account authentication](./authentication.md)
- [Portable local deployment](./portable-local-deployment.md)
- [PostgreSQL production design](./postgresql-production-design.md)
- [Context adapters and multi-LoRA serving](./context-adapters.md)
- [External integrations and preflight](./external-integrations.md)

Thư mục này gom tài liệu dự án theo hướng dễ đọc hơn các file `.md` rải ở thư mục gốc.
Các tài liệu gốc vẫn được giữ nguyên để không làm gãy tham chiếu cũ.

## Đọc nhanh theo nhu cầu

| Nhu cầu | Tài liệu nên đọc |
|---|---|
| Tổng quan sản phẩm | `../README.md`, `../required.md` |
| Giao diện Home/Web | `../UI_wireframe.md`, `../landingpage.md.md` |
| Kiến trúc hệ thống | `../design.md`, `../c4-model.md`, `../architecture-review.md` |
| Model AI và runtime server | `./server-models.md`, `../model_comparison.md` |
| Cắm LoRA contextual specialist | `./context-adapters.md` |
| Kế hoạch triển khai | `../roadmap.md`, `../engineering-backlog.md` |
| Demo và kiểm thử | `../demo-script.md.md`, `../test-plan.md.md` |

## Quy ước mới

- `docs/`: bản đồ tài liệu, hướng dẫn đọc, quyết định kiến trúc đang dùng.
- `server/models/`: nơi backend runtime tìm các model AI dạng ONNX.
- `ai/`: code adapter, inference engine và training scripts.
- `backend/`: FastAPI Security Gateway.
- `mcp_server/`: MCP tools cho AI agent.

## Ghi chú

Một số tài liệu gốc được tạo trước khi đổi đường dẫn model sang `server/models/`, nên có thể
còn nhắc `ai/models/`. Quy ước runtime hiện tại là `server/models/`.
