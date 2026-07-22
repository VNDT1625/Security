# Legal RAG benchmark v1

`canary.jsonl` is a small, public engineering set backed by chunk IDs in the pinned
local corpus. **It is non-production and cannot approve a release.** It is intended
only for smoke tests and developer comparisons, not as a substitute for the
independently reviewed hidden benchmark described in the v2 design.

Each row contains a scenario-stable `case_id`, Vietnamese query, split/slice, legal
context, and graded chunk relevance (`1` related, `2` supporting, `3` directly
answer-bearing). Paraphrases of one scenario must remain in the same split. Empty
relevance is permitted only for `expected_abstention=true` out-of-scope cases.

Run from the repository root:

```powershell
python scripts/benchmark_legal_rag.py --mode query
python scripts/benchmark_legal_rag.py --mode auto
```

The output directory contains a reproducibility manifest, per-case trace, aggregate
metrics, Markdown report, failures, and `gate-report.json`. Without
`--baseline-metrics`, the gate report is explicitly marked `evaluated=false`.
Gold labels in the canary remain provisional.

## Preparing a reviewed dataset

1. Copy `reviewer-dataset.template.jsonl` to a private/versioned dataset location.
2. Write real scenarios and queries; keep every paraphrase of one `scenario_id` in
   one split.
3. Have two annotators independently assign relevance grades using the corpus
   release being evaluated.
4. Have a legal reviewer adjudicate disagreement and fill `annotation` with
   `status=adjudicated`, two distinct `annotator_ids`, `legal_reviewer_id`, and an ISO
   `reviewed_at` timestamp.
5. Validate each JSONL row against `reviewer-dataset.schema.json` and verify every
   gold chunk ID exists in the pinned corpus.

The template deliberately contains no legal gold and cannot be loaded as a runnable
retrieval case until a reviewer supplies relevance labels.

## Freezing a baseline and running the release gate

Run the legacy baseline and preserve its `metrics.json` together with the dataset,
corpus and run-manifest hashes:

```powershell
python scripts/benchmark_legal_rag.py `
  --dataset .\benchmarks\legal_rag\v1\reviewed-private.jsonl `
  --mode legacy `
  --top-k 10 `
  --output .\outputs\legal-baseline-v1
```

Version-control or otherwise immutably freeze
`outputs/legal-baseline-v1/metrics.json`. Then evaluate the candidate on the same
dataset and cutoff:

```powershell
python scripts/benchmark_legal_rag.py `
  --dataset .\benchmarks\legal_rag\v1\reviewed-private.jsonl `
  --mode auto `
  --top-k 10 `
  --baseline-metrics .\outputs\legal-baseline-v1\metrics.json `
  --min-recall 0.98 `
  --min-mrr 0.80 `
  --min-ndcg 0.85 `
  --min-abstention 0.99 `
  --min-exact-citation 1.0 `
  --max-regression 0.02 `
  --max-p95-latency-ms 2000
```

The command exits with code `2` when any release check fails. A reviewed dataset is
itself a mandatory gate, so supplying the public canary with a baseline always fails
the production release gate even if its engineering metrics look good.
