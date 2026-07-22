"""Validate a Legal RAG SQLite corpus without modifying it.

The command prints a machine-readable report to stdout. Writing a report file is
opt-in via ``--output``; validation itself always opens SQLite in read-only mode.
"""

# ruff: noqa: E402 -- direct script execution needs the repository root on sys.path.

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from security.legal.corpus import inspect_corpus

DEFAULT_DB_PATH = REPOSITORY_ROOT / "data" / "legal_rag" / "rag.sqlite3"


def validate(
    db_path: str | Path,
    *,
    manifest_path: str | Path | None = None,
    require_manifest: bool = False,
) -> dict[str, object]:
    """Return the deterministic corpus health report."""

    return inspect_corpus(
        db_path,
        manifest_path=manifest_path,
        require_manifest=require_manifest,
    ).model_dump()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "db_path",
        nargs="?",
        default=DEFAULT_DB_PATH,
        type=Path,
        help=f"SQLite corpus path (default: {DEFAULT_DB_PATH})",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        help="Optional release manifest. Defaults to manifest.json beside the database.",
    )
    parser.add_argument(
        "--require-manifest",
        action="store_true",
        help="Fail validation when no verified manifest is present.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Opt in to writing the JSON report to this new or existing report file.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = validate(
        args.db_path,
        manifest_path=args.manifest,
        require_manifest=args.require_manifest,
    )
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output is not None:
        protected = {
            args.db_path.resolve(),
            (
                args.manifest.resolve()
                if args.manifest is not None
                else args.db_path.resolve().with_name("manifest.json")
            ),
        }
        if args.output.resolve() in protected:
            _parser().error("--output must not overwrite the corpus or its manifest")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return 0 if bool(report["ready"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
