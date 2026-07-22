# Local Legal RAG v2 runbook

Legal RAG là evidence engine cục bộ có khả năng từ chối, không phải nguồn quyết định
rằng một hành động chắc chắn hợp pháp. `Risk Core` và `PolicyEngine` vẫn giữ quyền
quyết định kỹ thuật; tầng pháp lý chỉ bổ sung căn cứ hoặc nâng yêu cầu rà soát.

Các invariant vận hành:

- Runtime chỉ đọc SQLite và không truy cập mạng để truy hồi.
- Không tìm thấy căn cứ không đồng nghĩa với được phép.
- Corpus stale, sai checksum, ngoài scope hoặc thiếu manifest production đều fail closed.
- Citation metadata do backend lấy từ database; model không được tự tạo.
- OCR chưa được xác minh có thể giúp tìm candidate nhưng không được làm căn cứ duy nhất
  cho `answered`; kết quả phải chuyển `human_legal_review` và đối chiếu PDF chính thức.

## 1. Cấu hình runtime

Development có thể dùng database legacy để kiểm tra nhanh:

```env
PREWISE_LEGAL_RAG_DB=data/legal_rag/rag.sqlite3
PREWISE_LEGAL_RAG_REQUIRE_MANIFEST=false
PREWISE_LEGAL_RAG_CANDIDATE_K=50
PREWISE_LEGAL_RAG_DENSE_DIR=
PREWISE_LEGAL_RAG_ENABLE_CHAR_NGRAMS=false
PREWISE_LEGAL_RAG_VERIFICATION_OVERLAY=
PREWISE_LEGAL_RAG_VERIFICATION_KEY_FILE=
PREWISE_LEGAL_RAG_VERIFICATION_KEY_ID=
PREWISE_LEGAL_RAG_REQUIRE_VERIFICATION_OVERLAY=false
```

Development không bắt buộc overlay: giữ ba giá trị overlay/key trống và
`PREWISE_LEGAL_RAG_REQUIRE_VERIFICATION_OVERLAY=false` cho đến khi đã có queue được
review và import. Nếu bật overlay, phải cấu hình đồng thời đúng file overlay, secret key
và `key_id`; cấu hình dở dang sẽ làm retrieval suy giảm/fail closed thay vì bỏ qua lỗi.

Production phải trỏ thẳng vào một release bất biến, bắt buộc manifest, và chỉ bật yêu
cầu overlay sau khi artifact đã được con người review/import và kiểm tra với đúng corpus:

```env
PREWISE_LEGAL_RAG_DB=/app/data/legal_rag/releases/vn-legal-2026-07-22.1/rag.sqlite3
PREWISE_LEGAL_RAG_REQUIRE_MANIFEST=true
PREWISE_LEGAL_RAG_CANDIDATE_K=50
PREWISE_LEGAL_RAG_DENSE_DIR=
PREWISE_LEGAL_RAG_ENABLE_CHAR_NGRAMS=false
PREWISE_LEGAL_RAG_VERIFICATION_OVERLAY=/app/data/legal_rag/releases/vn-legal-2026-07-22.1/verification-overlay.json
PREWISE_LEGAL_RAG_VERIFICATION_KEY_FILE=/run/secrets/legal-rag-verification.hmac
PREWISE_LEGAL_RAG_VERIFICATION_KEY_ID=legal-review-2026-01
PREWISE_LEGAL_RAG_REQUIRE_VERIFICATION_OVERLAY=true
```

Không deploy cấu hình production `REQUIRE_VERIFICATION_OVERLAY=true` trước khi cả
overlay và key đã được mount, vì trạng thái thiếu/sai key, HMAC, `key_id`, release ID
hoặc corpus SHA-256 sẽ chủ động làm retrieval fail closed. Sau khi rollout overlay đầu
tiên thành công, giữ cờ này là `true` ở production để tránh vô tình chạy không overlay.

`PREWISE_LEGAL_RAG_DENSE_DIR` là tùy chọn và phải trỏ tới dense artifact được build
từ đúng SHA-256 corpus. `PREWISE_LEGAL_RAG_ENABLE_CHAR_NGRAMS=true` tạo chỉ mục ký tự
trong RAM ở lần truy vấn đầu tiên. Nó có thể giúp câu không dấu hoặc OCR, nhưng làm tăng
cold-start và bộ nhớ. Vì vậy production mặc định là `false`.

Sau khi đổi release path, khởi động lại backend. Không ghi đè database của release đang
chạy và không dùng thư mục `current` có nội dung bị thay in-place.

## 2. Đưa corpus nguồn vào workspace

Tải đúng dataset revision đã duyệt và giữ lại commit SHA để đưa vào manifest:

```powershell
cd C:\NDT\PJ\Ai_Security-main

$sourceRevision = "<PINNED_HUGGING_FACE_COMMIT_SHA>"

hf download `
  thuaannn/prewise-security-adapter-training-v5 `
  --repo-type dataset `
  --revision $sourceRevision `
  --include "legal_rag/**" `
  --local-dir ".\.hf-legal-rag"

$ragSource = Get-ChildItem ".\.hf-legal-rag" -Recurse -Filter "rag.sqlite3" |
  Select-Object -First 1

if (-not $ragSource) {
  throw "Không tìm thấy rag.sqlite3 trong dataset revision đã pin."
}

New-Item -ItemType Directory -Path ".\data\legal_rag" -Force | Out-Null
Copy-Item $ragSource.FullName ".\data\legal_rag\rag.sqlite3" -Force
```

Không đưa Hugging Face token, API key, câu hỏi người dùng hoặc tài liệu nội bộ vào
corpus hay benchmark output.

## 3. Validate read-only

Kiểm tra database nguồn legacy; lệnh này chỉ in JSON và không tạo manifest:

```powershell
python scripts\validate_legal_corpus.py `
  .\data\legal_rag\rag.sqlite3
```

`ready=true` cùng `reason_codes=["manifest_missing"]` là hợp lệ chỉ trong legacy mode.
Production gate phải dùng cả manifest path và `--require-manifest`:

```powershell
$releaseDir = ".\data\legal_rag\releases\vn-legal-2026-07-22.1"

python scripts\validate_legal_corpus.py `
  "$releaseDir\rag.sqlite3" `
  --manifest "$releaseDir\manifest.json" `
  --require-manifest
```

Exit code khác 0 thì không được kích hoạt release.

## 4. Build release side-by-side

Build release mới vào thư mục riêng. Tool từ chối ghi đè release ID đã tồn tại:

```powershell
cd C:\NDT\PJ\Ai_Security-main

$releaseId = "vn-legal-2026-07-22.1"
$sourceRevision = "<PINNED_HUGGING_FACE_COMMIT_SHA>"

python scripts\build_legal_release.py `
  --db ".\data\legal_rag\rag.sqlite3" `
  --releases-dir ".\data\legal_rag\releases" `
  --release-id $releaseId `
  --source-revision $sourceRevision

$releaseDir = ".\data\legal_rag\releases\$releaseId"
python scripts\validate_legal_corpus.py `
  "$releaseDir\rag.sqlite3" `
  --manifest "$releaseDir\manifest.json" `
  --require-manifest
```

Bundle gồm `rag.sqlite3`, `manifest.json` và `validation-report.json`. Chỉ sửa
`PREWISE_LEGAL_RAG_DB` và restart sau khi strict validation pass. Giữ release trước đó
để rollback bằng cách đổi lại path; không xóa last-known-good trong cùng lượt rollout.

### Dense index tùy chọn

Model ONNX phải có sẵn local và revision phải được pin. Build dense index ngoài request
path, sau đó đóng gói nó vào một release ID mới:

```powershell
$denseId = "multilingual-e5-base-deadbeef"
$denseDir = ".\data\legal_rag\dense\$denseId"

python scripts\build_legal_dense_index.py `
  --db ".\data\legal_rag\rag.sqlite3" `
  --model-dir ".\models\multilingual-e5-base-onnx" `
  --model-id "intfloat/multilingual-e5-base" `
  --model-revision "<PINNED_MODEL_COMMIT_SHA>" `
  --output $denseDir

python scripts\build_legal_release.py `
  --db ".\data\legal_rag\rag.sqlite3" `
  --releases-dir ".\data\legal_rag\releases" `
  --release-id "vn-legal-2026-07-22.1-dense" `
  --source-revision "<PINNED_HUGGING_FACE_COMMIT_SHA>" `
  --dense-index $denseDir
```

Không dùng dense artifact nếu `corpus_sha256` không khớp corpus release.

## 5. Benchmark baseline và candidate

Canary công khai chỉ là tập kiểm tra kỹ thuật nhỏ, không phải hidden benchmark đã được
legal reviewer ký duyệt. Khóa dataset, corpus, seed và output riêng cho từng run:

```powershell
cd C:\NDT\PJ\Ai_Security-main

$db = ".\data\legal_rag\rag.sqlite3"
$dataset = ".\benchmarks\legal_rag\v1\canary.jsonl"
$runStamp = Get-Date -Format "yyyyMMdd-HHmmss"

$env:PREWISE_LEGAL_RAG_REQUIRE_MANIFEST = "false"
$env:PREWISE_LEGAL_RAG_ENABLE_CHAR_NGRAMS = "false"
Remove-Item Env:PREWISE_LEGAL_RAG_DENSE_DIR -ErrorAction SilentlyContinue

python scripts\benchmark_legal_rag.py `
  --dataset $dataset `
  --db $db `
  --split canary `
  --mode legacy `
  --top-k 10 `
  --seed 20260722 `
  --output ".\outputs\legal-rag-benchmark\$runStamp-baseline-legacy"

python scripts\benchmark_legal_rag.py `
  --dataset $dataset `
  --db $db `
  --split canary `
  --mode retrieve `
  --top-k 10 `
  --seed 20260722 `
  --output ".\outputs\legal-rag-benchmark\$runStamp-candidate-hybrid"
```

Thử char n-gram như một ablation riêng:

```powershell
$env:PREWISE_LEGAL_RAG_ENABLE_CHAR_NGRAMS = "true"

python scripts\benchmark_legal_rag.py `
  --dataset $dataset `
  --db $db `
  --split canary `
  --mode retrieve `
  --top-k 10 `
  --seed 20260722 `
  --output ".\outputs\legal-rag-benchmark\$runStamp-candidate-char-canary"

$env:PREWISE_LEGAL_RAG_ENABLE_CHAR_NGRAMS = "false"
```

Cải thiện char n-gram quan sát trong smoke ngày 22/07/2026 là Recall@10 từ `0,729` lên
`0,771`, MRR@10 từ `0,781` lên `0,938` và nDCG@10 từ `0,684` lên `0,821`. Đây chỉ là
**canary signal** trên 10 case công khai, không phải bằng chứng chất lượng production.
Không dùng các số này để chốt threshold hoặc thay thế frozen dev/hidden test cùng
legal-reviewer sign-off. Dense model cũng phải qua cùng benchmark và đo cold-start/RAM
trước khi bật.

## 6. POST demo `/v1/legal/answers`

Khởi động backend với release đã validate, rồi dùng API key có scope
`assess:content`. Ví dụ PowerShell dưới đây cố ý dùng `as_of_date` bằng ngày corpus đã
được kiểm chứng; không đổi sang ngày tương lai nếu chưa cập nhật corpus:

```powershell
$apiBase = "http://127.0.0.1:8000"
$apiKey = "dev-key-change-in-production"
$requestId = [guid]::NewGuid().ToString()
$idempotencyKey = "legal-demo-$requestId"

$payload = @{
  schema_version = "legal-answer.v2"
  request_id = $requestId
  idempotency_key = $idempotencyKey
  intent_mode = "legal"
  question = "Doanh nghiệp phải làm gì trước khi chuyển dữ liệu cá nhân cho nhà cung cấp bên thứ ba?"
  legal_context = @{
    jurisdiction = "VN"
    as_of_date = "2026-07-22"
    actor = "doanh nghiệp"
    action = "chuyển dữ liệu cho nhà cung cấp bên thứ ba"
    data_or_asset = "dữ liệu cá nhân của khách hàng"
    recipient = "nhà cung cấp dịch vụ"
    purpose = "vận hành dịch vụ"
    consent_state = "chưa xác định"
  }
} | ConvertTo-Json -Depth 6

$response = Invoke-RestMethod `
  -Method Post `
  -Uri "$apiBase/v1/legal/answers" `
  -Headers @{ Authorization = "Bearer $apiKey" } `
  -ContentType "application/json; charset=utf-8" `
  -Body ([System.Text.Encoding]::UTF8.GetBytes($payload))

$response | ConvertTo-Json -Depth 10
```

Kiểm tra response có `schema_version`, `status`, `reason_code`, `corpus.release_id`,
`corpus.verified_through`, `trace_id`, claims và citations. `answered` chỉ hợp lệ khi
mọi claim và exact quote qua verifier. `need_more_facts`, `insufficient_legal_basis`,
`conflicting_sources` hoặc `human_legal_review` là kết quả fail-closed dự kiến, không
phải lý do để fallback sang câu trả lời tự do. Với corpus hiện tại chủ yếu là OCR, demo
có thể đúng khi trả `human_legal_review`; phải mở URL nguồn và đối chiếu đúng trang PDF.

## 7. Release checklist

- Corpus source revision và model revision đã pin.
- `validate_legal_corpus.py --require-manifest` exit 0.
- SQLite SHA-256, row counts, verified-through và provenance khớp manifest.
- Baseline/candidate outputs giữ nguyên run manifest; không ghi đè run cũ.
- Future-date, out-of-scope, hallucinated citation, citation laundering và OCR paths
  đều fail closed.
- `Risk Core BLOCK` không bao giờ bị Legal RAG hạ mức.
- Giữ last-known-good release và đã thử rollback bằng đổi path + restart.

## 8. Queue xác minh OCR bởi con người

Workflow này tách hoàn toàn khỏi runtime và không sửa SQLite release. Exporter mở
database bằng `mode=ro` + `query_only`, chỉ lấy chunk có `extraction_method` OCR/scan,
rồi sắp xếp ổn định theo `retrieval_default`, trọng lượng pháp lý, mức sử dụng làm gold
trong benchmark và phương pháp OCR. Mỗi dòng JSONL chứa text, trang, URL nguồn, SHA-256
PDF, SHA-256 text và SHA-256 corpus để reviewer đối chiếu đúng artifact.
`queue_record_sha256` bao phủ canonical JSON của mọi trường queue trừ bốn trường review
được phép sửa và chính trường hash; importer từ chối field thừa/thiếu hoặc metadata
queue bị thay đổi.

```powershell
$releaseDir = ".\data\legal_rag\releases\vn-legal-2026-07-22.1"
$reviewDir = ".\outputs\legal-ocr-review\vn-legal-2026-07-22.1"

python scripts\export_legal_ocr_review_queue.py `
  --db "$releaseDir\rag.sqlite3" `
  --manifest "$releaseDir\manifest.json" `
  --require-manifest `
  --benchmark ".\benchmarks\legal_rag\v1\canary.jsonl" `
  --output "$reviewDir\queue.jsonl"
```

Exporter từ chối ghi đè queue đã tồn tại. Cùng corpus và benchmark sẽ cho cùng bytes;
không có timestamp lúc export. Có thể dùng `--limit` để review theo batch hoặc
`--no-benchmark` khi cố ý không dùng gold labels.

Reviewer mở PDF từ `source_page_url`/`source_file_url`, đối chiếu đúng `page_start` và
`page_end`, rồi chỉ sửa bốn trường sau trong bản sao queue:

- `review_status`: `human_verified`, `rejected` hoặc `needs_correction`;
- `reviewer`: định danh reviewer có thể audit;
- `reviewed_at`: RFC3339 UTC, ví dụ `2026-07-22T08:30:00Z`;
- `review_notes`: ghi chú đối chiếu, không chứa secret hay dữ liệu người dùng.

Không sửa text, chunk ID, page, URL hoặc hash. Importer đối chiếu lại mọi trường bất
biến với SQLite và từ chối chunk lạ, trùng, pending, source hash/text hash/corpus hash
sai hoặc record bị chỉnh sửa. Tạo key HMAC tối thiểu 32 byte trong secret storage; ví
dụ local-only sau phải được đặt ngoài Git và giới hạn ACL:

```powershell
New-Item -ItemType Directory ".\.secrets" -Force | Out-Null
python -c "from pathlib import Path; import secrets; Path(r'.secrets/legal-review.hmac').write_bytes(secrets.token_bytes(32))"

python scripts\import_legal_ocr_review.py `
  --db "$releaseDir\rag.sqlite3" `
  --manifest "$releaseDir\manifest.json" `
  --require-manifest `
  --reviews "$reviewDir\queue-reviewed.jsonl" `
  --output "$reviewDir\verification-overlay.json" `
  --signing-key-file ".\.secrets\legal-review.hmac" `
  --key-id "legal-review-2026-01"
```

Overlay có schema chính xác:

```text
schema_version: legal-ocr-verification-overlay.v1
corpus: {release_id, sha256, verified_through}
review_input_sha256
record_count
records: {
  <chunk_id>: {
    text_verification_status, reviewer, reviewed_at, review_notes,
    source_pdf_sha256, text_sha256, page_start, page_end, source_page_url
  }
}
integrity: {
  algorithm: sha256,
  canonicalization: json-sort-keys-compact-utf8-v1,
  payload_sha256
}
authentication: {algorithm: hmac-sha256, key_id, value}
```

`integrity.payload_sha256` là hash của canonical payload gồm mọi trường đứng trước
`integrity` và `authentication`. HMAC xác thực cùng canonical payload cộng với `key_id`
bằng secret key thực sự được cung cấp qua `--signing-key-file`. HMAC là mã xác thực đối
xứng, **không phải chữ ký số public-key và không cung cấp non-repudiation**. Không gọi
overlay là “cryptographically signed”; nếu không bảo vệ/phân phối key đúng cách thì
SHA-256 chỉ phát hiện nội dung thay đổi, không chứng minh danh tính reviewer.

Importer từ chối ghi đè overlay và không bao giờ update SQLite. Sau khi import, kích
hoạt đúng artifact cho runtime rồi restart backend:

```powershell
$env:PREWISE_LEGAL_RAG_VERIFICATION_OVERLAY = `
  (Resolve-Path "$reviewDir\verification-overlay.json").Path
$env:PREWISE_LEGAL_RAG_VERIFICATION_KEY_FILE = `
  (Resolve-Path ".\.secrets\legal-review.hmac").Path
$env:PREWISE_LEGAL_RAG_VERIFICATION_KEY_ID = "legal-review-2026-01"
$env:PREWISE_LEGAL_RAG_REQUIRE_VERIFICATION_OVERLAY = "true"

# Restart backend bằng quy trình chuẩn của môi trường sau khi đặt bốn biến trên.
```

Runtime xác minh SHA-256, HMAC, `key_id`, release ID và corpus SHA trước khi áp dụng.
Record `human_verified` được gắn vào citation; record `rejected` hoặc
`needs_correction` bị loại khỏi cả retrieved references và context references. Chunk
không có record overlay vẫn là OCR chưa xác minh và không được làm căn cứ duy nhất cho
`answered`. Metadata record lệch text hash, PDF hash, trang hoặc URL làm cả lượt truy
xuất fail closed; không được tự sửa overlay để vượt qua kiểm tra.

Key HMAC là secret đối xứng: cả bên tạo và bên xác minh đều có khả năng tạo MAC hợp lệ,
vì vậy nó không phải chữ ký số và không chứng minh non-repudiation. Production phải
mount key read-only từ secret manager, cấp quyền đọc chỉ cho service account (Linux nên
dùng mode `0400` hoặc `0440` phù hợp), không commit, bake vào image, ghi log hoặc đưa
vào artifact công khai. Khi rotate, tạo key và `key_id` mới, import overlay mới bằng key
đó, mount cả hai artifact, đổi đồng thời ba biến overlay/key/key-ID trong một deployment,
restart và kiểm tra; chỉ thu hồi key cũ sau rollback window.

## 9. Health và debug retrieval dành cho admin

Hai endpoint vận hành đều yêu cầu session/token có quyền admin; không expose trực tiếp
ra Internet hoặc dùng token người dùng thường:

- `GET /admin/legal-rag/health`: kiểm tra release, schema, manifest, checksum, row count,
  provenance và các `degraded_reasons` của corpus;
- `POST /admin/legal-rag/debug-retrieval`: chạy một retrieval giới hạn, trả trace an
  toàn, references/context references, conflict và số chunk bị overlay loại. Dùng endpoint
  này sau restart để xác minh overlay/HMAC đã được nạp; không chỉ dựa vào health corpus.

```powershell
$apiBase = "http://127.0.0.1:8000"
$adminToken = "<ADMIN_BEARER_TOKEN>"
$adminHeaders = @{ Authorization = "Bearer $adminToken" }

Invoke-RestMethod `
  -Method Get `
  -Uri "$apiBase/admin/legal-rag/health" `
  -Headers $adminHeaders | ConvertTo-Json -Depth 8

$debugPayload = @{
  question = "Chuyển dữ liệu cá nhân cho bên thứ ba có cần sự đồng ý không?"
  context = @{
    jurisdiction = "VN"
    as_of_date = "2026-07-22"
    actor = "doanh nghiệp"
    action = "chuyển dữ liệu cho bên thứ ba"
    data_or_asset = "dữ liệu cá nhân"
    recipient = "nhà cung cấp dịch vụ"
    purpose = "vận hành dịch vụ"
    consent_state = "chưa xác định"
  }
  top_k = 8
  preview_chars = 240
} | ConvertTo-Json -Depth 6

Invoke-RestMethod `
  -Method Post `
  -Uri "$apiBase/admin/legal-rag/debug-retrieval" `
  -Headers $adminHeaders `
  -ContentType "application/json; charset=utf-8" `
  -Body ([System.Text.Encoding]::UTF8.GetBytes($debugPayload)) |
  ConvertTo-Json -Depth 12
```

Sau rollout, yêu cầu `corpus.ready=true`, không có `insufficient_reason` liên quan
`verification_overlay_*`, và kiểm tra `trace.rejected_reasons` cùng
`text_verification_status` đúng với queue đã review. Nếu overlay/key không hợp lệ, giữ
fail closed, rollback đồng bộ overlay + key + key ID hoặc release; không tắt cờ required
để ép demo trả lời.
