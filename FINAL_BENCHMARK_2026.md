# Prewise — Final Benchmark 2026

**Status:** evidence lock v0.1 — not yet approved as an independent research evaluation  
**Repository revision:** `dc88127e7d5eaa144b8dd53eb261d9508744f44c`  
**Verification date:** 2026-07-18  
**Purpose:** the single source of truth for any metric used in a Prewise report, slide, video, product page or judge presentation.

## Claim policy

Only a result in this document may be cited as a Prewise benchmark result. Every cited result must state its artifact hash, dataset protocol and execution mode. Historical metrics in `README.md`, training summaries and earlier validation reports are context only and must not be presented as the final competition result.

`Model artifact metric` means a score recorded in that artifact's metadata. It is not an independent release claim until the source split and evaluator can be reproduced from a clean checkout.

## Release verification completed

| Check | Result | Command |
|---|---:|---|
| Backend test suite | 361 passed in 101.00 s | `python -m pytest -q` |
| Python static checks | passed | `python -m ruff check .` |
| Product identity | Prewise | web metadata, FastAPI title and public documentation |
| Legacy web route | removed | `frontend/web/app/demo/` has no route entry point |

## Runtime artifacts under review

| Modality | Runtime artifact | SHA-256 | Metadata result | Evidence status |
|---|---|---|---|---|
| URL phishing | `ai/models/url_lgbm.onnx` | `9e954fc286b4d1ee65a8aef9b1b48e4bd0b4077e997f1ff761a06df5e71150da` | accuracy 0.8375, F1 0.8430; 174,884 metadata test rows | artifact metadata only |
| Text phishing | `ai/models/mdeberta_text.onnx` | `1e5dc95763744229d9f3a22103c21bfef034980ec5783feb3529abfba52f2454` | accuracy 0.9413, precision 0.9059, recall 0.9341, F1 0.9198; 10,269 metadata validation rows | artifact metadata only |
| Prompt injection | `ai/models/protectai_prompt.onnx` | `d1533a280f551417d12bd4ba18fe9d66cf59b4643f5c536237b3203c5ea27a9f` | accuracy 0.9951, precision 1.0000, recall 0.9837, F1 0.9918; 1,014 metadata validation rows | artifact metadata only |
| AI-generated image screening | `ai/models/deepfake_image_q4.onnx` | `28c7f06d5aa87bc7e023c023eab1fbf473deef54e9c62f9838a99e50422810ec` | no reproducible holdout metric packaged | do not cite an accuracy/F1 |

### Required wording in the presentation

- The deployed text and prompt artifacts are lightweight TF-IDF logistic-regression models; do not describe them as deployed mDeBERTa or ProtectAI Transformer models unless the corresponding transformer artifact is actually loaded and benchmarked.
- URL result above is a random-row artifact split. It does **not** prove generalization to unseen domains or future phishing campaigns.
- Image screening is not a forensic deepfake conclusion. It screens images and sampled video frames only; it does not analyse audio or temporal consistency.

## System latency: local engineering observation

These values were observed on the verification workstation, not a hardware-independent service-level objective.

| URL analysis mode | Observed wall time | Interpretation |
|---|---:|---|
| compatible cache hit | 36–154 ms | cached response; API reports `analysis_time_ms = 0` |
| quick uncached scan | about 1.865 s | local model, risk core and available enrichment |
| forced fresh scan with external work | about 22.084 s | includes fresh enrichment/network-bound work |

Do not claim end-to-end URL analysis is under 100 ms. That statement is only defensible for an already-warm local decision path or a compatible cache hit, and must be labelled as such.

## Release blockers before any final accuracy claim

1. Commit or archive the exact train/validation/test datasets with source, licence, checksum and row counts. The current workspace does not contain the CSV inputs required to reproduce all historical validation reports.
2. Create an untouched holdout set split by registrable domain and collection time for URL phishing. Do not use a random row split as the only generalization test.
3. Run one evaluator against the deployed artifacts and persist JSON output, confusion matrix and misclassification samples under `artifacts/benchmarks/`.
4. Run an ablation on the same frozen holdout: threat-feed/blacklist only, ML only, rules only, ML + rules, and full Prewise Risk Core + policy. Report precision, recall, F1, false-positive rate, false-negative rate and p95 latency.
5. Re-test the full API path, not only raw model scores. A high raw model score that becomes `SAFE` after risk-core calibration is a release defect until explained and verified.
6. Benchmark AI-generated-image screening on unseen generators, compression levels and real photographs before reporting a deepfake/image-detection score.

## Competition evidence map

The competition allocates 20 points each to innovation, practical value and technical accuracy; 15 to efficiency; 10 to UI/UX; and 5 each to report, presentation and rebuttal. This file supports the technical, efficiency, report and rebuttal criteria only when the blockers above are closed.

| Competition criterion | Required Prewise evidence |
|---|---|
| Innovation (20) | ablation showing Risk Core and policy add measurable value over one detector |
| Practical application (20) | clean-machine startup, stable live workflow and documented fallback mode |
| Technical accuracy (20) | frozen independent holdout, artifact hashes and full API confusion matrices |
| Processing efficiency (15) | p50/p95/p99 for cold start, cache miss and cache hit on declared hardware/concurrency |
| UI/UX (10) | one coherent Prewise workflow at `/analyze`; no dead demo routes or disabled claims |
| Report (5) | this file plus dataset/model licence and provenance appendix |
| Presentation (5) | live run follows `docs/judge-demo.md` exactly |
| Rebuttal (5) | every claim above opens to a reproducible file, command or captured result |

## Re-run checklist

```powershell
python -m pytest -q
python -m ruff check .
# After frozen benchmark datasets and evaluator are committed:
python -m tools.benchmark_release --config artifacts/benchmarks/release-2026.json
```

The last command is intentionally a release gate, not a claim that it already exists. Add the evaluator and dataset manifest before marking this document `approved`.
