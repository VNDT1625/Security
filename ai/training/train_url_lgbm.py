"""Train the URL phishing LightGBM classifier and export to ONNX.

Usage:
    python -m ai.training.train_url_lgbm --data data/url_dataset.csv --out server/models

Dataset CSV must have columns ``url,label`` (label: 1=phishing, 0=benign).
It may also contain columns named after ``CONTEXT_FEATURE_NAMES`` so DNS, RDAP,
TLS, redirect, DOM, visual and local-feed observations are learned rather than
silently filled with zeroes.
Sources (see dataset-plan.md): PhishTank, OpenPhish, Tranco (benign).

This is the real training path. It requires the [ml] and [train] extras
(lightgbm, scikit-learn, onnxmltools, numpy). It is intentionally NOT imported by the
runtime; the gateway falls back to heuristics when the ONNX model is absent.
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Mapping
from datetime import UTC, datetime

from ai.adapters.url_adapter import (
    CONTEXT_FEATURE_NAMES,
    STATIC_FEATURE_NAMES,
    parse_url_parts,
)


def _registrable_domain(url: str) -> str:
    """Group key for the split. Unparseable rows form their own group."""
    candidate = url if "://" in url else f"http://{url}"
    try:
        return parse_url_parts(candidate).registrable_domain.lower() or url.lower()
    except Exception:
        return url.lower()


def select_trained_feature_names(
    context_observations: Mapping[str, int],
    *,
    sample_count: int,
    minimum_context_coverage: float,
) -> tuple[str, ...]:
    """Select only context features that were genuinely observed in training.

    Empty CSV fields mean a collector was unavailable.  A zero is instead a
    valid observation, so it counts toward coverage.  This prevents a model
    from claiming it uses live DNS/RDAP/page signals when those columns were
    silently filled with zeros during training.
    """

    if sample_count <= 0:
        return tuple(STATIC_FEATURE_NAMES)
    selected_context = tuple(
        name
        for name in CONTEXT_FEATURE_NAMES
        if context_observations.get(name, 0) / sample_count >= minimum_context_coverage
    )
    return tuple(STATIC_FEATURE_NAMES) + selected_context


def main() -> None:  # pragma: no cover - offline training job
    import collections
    import csv
    import hashlib
    import json

    import lightgbm as lgb
    import numpy as np
    from onnxmltools import convert_lightgbm
    from onnxmltools.convert.common.data_types import FloatTensorType
    from sklearn.metrics import classification_report, f1_score
    from sklearn.model_selection import GroupShuffleSplit, train_test_split

    from ai.adapters.url_adapter import extract_url_features

    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, help="CSV with columns url,label")
    parser.add_argument("--out", default="server/models")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument(
        "--min-context-coverage",
        type=float,
        default=0.05,
        help="Minimum non-empty row share required to train a context feature (default: 0.05)",
    )
    parser.add_argument(
        "--require-context-features",
        action="store_true",
        help="Fail instead of producing a static-only model when no context feature qualifies",
    )
    parser.add_argument(
        "--split",
        choices=("domain", "random"),
        default="domain",
        help=(
            "How to build the held-out split. 'domain' (default) keeps every URL of a "
            "registrable domain on one side, which is the only setting that measures "
            "generalisation to unseen domains. 'random' reproduces the historical "
            "leaky split and is kept only for before/after comparison."
        ),
    )
    args = parser.parse_args()

    if not 0 <= args.min_context_coverage <= 1:
        raise ValueError("--min-context-coverage must be between 0 and 1")

    rows: list[tuple[str, int, dict[str, float]]] = []
    context_observations = {name: 0 for name in CONTEXT_FEATURE_NAMES}
    skipped_rows = 0
    with open(args.data, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            try:
                feature_context = {
                    name: float(row[name])
                    for name in CONTEXT_FEATURE_NAMES
                    if row.get(name) not in {None, ""}
                }
                label = int(row["label"])
                if label not in {0, 1}:
                    raise ValueError("label must be 0 or 1")
                for name in feature_context:
                    context_observations[name] += 1
                rows.append((row["url"], label, feature_context))
            except (TypeError, ValueError, KeyError):
                skipped_rows += 1
                continue

    feature_names = select_trained_feature_names(
        context_observations,
        sample_count=len(rows),
        minimum_context_coverage=args.min_context_coverage,
    )
    selected_context_features = [
        name for name in feature_names if name in CONTEXT_FEATURE_NAMES
    ]
    if args.require_context_features and not selected_context_features:
        raise ValueError(
            "No context features reached minimum coverage; collect labelled DNS/RDAP/TLS/DOM/feed observations first."
        )

    X = [
        extract_url_features(url, feature_names=feature_names, context=feature_context)
        for url, _, feature_context in rows
    ]
    y = [label for _, label, _ in rows]
    X = np.array(X, dtype=np.float32)
    y = np.array(y)

    # A random row split leaks: this corpus holds ~1.8 URLs per registrable
    # domain and 53% of rows sit on a domain that appears more than once, so a
    # random 80/20 puts the *same* domain on both sides for about half the test
    # set. The model then scores well by memorising domains rather than learning
    # phishing structure, which is why the historical 0.8375 accuracy collapsed
    # to 0.4237 on a domain-disjoint holdout. Grouping by registrable domain is
    # the only split that answers the question deployment actually asks: is this
    # brand-new domain, registered an hour ago, a phishing site?
    if args.split == "domain":
        groups = np.array([_registrable_domain(url) for url, _, _ in rows])
        splitter = GroupShuffleSplit(
            n_splits=1, test_size=args.test_size, random_state=42
        )
        train_index, test_index = next(splitter.split(X, y, groups=groups))
        Xtr, Xte = X[train_index], X[test_index]
        ytr, yte = y[train_index], y[test_index]
        overlap = set(groups[train_index]) & set(groups[test_index])
        if overlap:
            raise RuntimeError(
                f"domain split leaked {len(overlap)} registrable domains into both sides"
            )
        print(
            f"[split] domain-grouped: {len(set(groups[train_index]))} train domains, "
            f"{len(set(groups[test_index]))} test domains, 0 shared"
        )
    else:
        Xtr, Xte, ytr, yte = train_test_split(
            X, y, test_size=args.test_size, random_state=42, stratify=y
        )
        print("[split] RANDOM row split - leaky, for comparison only")

    model = lgb.LGBMClassifier(
        n_estimators=300, num_leaves=48, learning_rate=0.05,
        subsample=0.8, colsample_bytree=0.8, random_state=42,
    )
    model.fit(Xtr, ytr)
    pred = model.predict(Xte)
    report = classification_report(yte, pred, output_dict=True)
    f1 = f1_score(yte, pred)
    print(classification_report(yte, pred))
    print("F1:", f1)

    os.makedirs(args.out, exist_ok=True)
    onnx_model = convert_lightgbm(
        model, initial_types=[("input", FloatTensorType([None, len(feature_names)]))]
    )
    out_path = os.path.join(args.out, "url_lgbm.onnx")
    payload = onnx_model.SerializeToString()
    with open(out_path, "wb") as fh:
        fh.write(payload)
    label_counts = collections.Counter(int(value) for value in y.tolist())
    metadata = {
        "artifact": "url_lgbm.onnx",
        "architecture": "LightGBM LGBMClassifier over handcrafted URL features",
        "runtime_input": f"tensor(float) shape [N, {len(feature_names)}]",
        "runtime_outputs": ["label", "probabilities"],
        "purpose": "real-data URL phishing classifier for gateway serving",
        "trained_at_utc": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "label_mapping": {"0": "benign", "1": "phishing"},
        "dataset": {
            "path": args.data,
            "rows": int(len(y)),
            "skipped_rows": int(skipped_rows),
            "class_counts": {str(label): int(label_counts[label]) for label in (0, 1)},
            "test_size": args.test_size,
            "split": args.split,
            "split_note": (
                "domain-grouped: no registrable domain appears on both sides"
                if args.split == "domain"
                else "random row split - leaks domains across sides"
            ),
            "train_rows": int(len(ytr)),
            "test_rows": int(len(yte)),
        },
        "feature_names": list(feature_names),
        "context_feature_coverage": {
            name: context_observations[name] / len(rows) if rows else 0.0
            for name in CONTEXT_FEATURE_NAMES
        },
        "selected_context_features": selected_context_features,
        "minimum_context_coverage": args.min_context_coverage,
        "model_config": {
            "n_estimators": 300,
            "num_leaves": 48,
            "learning_rate": 0.05,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "random_state": 42,
        },
        "metrics": {
            "test": {
                "f1": float(f1),
                "classification_report": report,
            }
        },
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    metadata_path = os.path.join(args.out, "url_lgbm.meta.json")
    with open(metadata_path, "w", encoding="utf-8") as fh:
        json.dump(metadata, fh, indent=2, ensure_ascii=True)
        fh.write("\n")
    print("Saved", out_path)


if __name__ == "__main__":
    main()
