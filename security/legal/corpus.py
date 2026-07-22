"""Read-only corpus inspection, release identity, and supply-chain validation."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_REQUIRED_COLUMNS = {
    "chunk_id",
    "document_id",
    "title",
    "document_number",
    "document_type",
    "jurisdiction",
    "authority",
    "legal_weight",
    "status",
    "effective_date",
    "status_checked_at",
    "retrieval_default",
    "section",
    "page_start",
    "page_end",
    "source_page_url",
    "source_file_url",
    "source_pdf_sha256",
    "extraction_method",
    "text",
}
_OFFICIAL_SOURCE_HOSTS = {
    "vanban.chinhphu.vn",
    "datafiles.chinhphu.vn",
    "nist.gov",
    "www.nist.gov",
    "nvlpubs.nist.gov",
}


@dataclass(frozen=True)
class CorpusSnapshot:
    release_id: str = ""
    schema_version: int = 1
    sha256: str = ""
    verified_through: str = ""
    chunk_count: int = 0
    searchable_chunk_count: int = 0
    document_count: int = 0
    searchable_document_count: int = 0
    coverage_domains: tuple[str, ...] = ()
    manifest_verified: bool = False

    def model_dump(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["coverage_domains"] = list(self.coverage_domains)
        return payload


@dataclass(frozen=True)
class CorpusHealth:
    available: bool
    ready: bool
    quick_check: str = ""
    reason_codes: tuple[str, ...] = ()
    snapshot: CorpusSnapshot = field(default_factory=CorpusSnapshot)
    invalid_source_count: int = 0
    missing_provenance_count: int = 0

    def model_dump(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "ready": self.ready,
            "quick_check": self.quick_check,
            "reason_codes": list(self.reason_codes),
            "snapshot": self.snapshot.model_dump(),
            "invalid_source_count": self.invalid_source_count,
            "missing_provenance_count": self.missing_provenance_count,
        }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=2.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _load_manifest(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _is_official_source(url: str) -> bool:
    host = (urlsplit(url).hostname or "").casefold()
    return host in _OFFICIAL_SOURCE_HOSTS


def inspect_corpus(
    db_path: str | Path,
    *,
    manifest_path: str | Path | None = None,
    require_manifest: bool = False,
) -> CorpusHealth:
    """Validate a local release without mutating it.

    A legacy database can remain ready when ``require_manifest`` is false, but it is
    explicitly marked unverified so production can enforce a manifest independently.
    """

    path = Path(db_path).expanduser()
    if not path.is_file():
        return CorpusHealth(False, False, reason_codes=("corpus_missing",))

    reasons: list[str] = []
    quick_check = ""
    try:
        with _connect(path) as connection:
            quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            if quick_check.casefold() != "ok":
                reasons.append("sqlite_integrity_failed")

            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type IN ('table','view')"
                )
            }
            if not {"chunks", "chunks_fts"}.issubset(tables):
                return CorpusHealth(
                    True,
                    False,
                    quick_check=quick_check,
                    reason_codes=("schema_missing_tables",),
                )
            columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(chunks)")}
            missing_columns = _REQUIRED_COLUMNS.difference(columns)
            if missing_columns:
                reasons.append("schema_missing_columns")

            chunk_count = int(connection.execute("SELECT COUNT(*) FROM chunks").fetchone()[0])
            fts_count = int(connection.execute("SELECT COUNT(*) FROM chunks_fts").fetchone()[0])
            if chunk_count != fts_count:
                reasons.append("fts_row_count_mismatch")
            document_count = int(
                connection.execute("SELECT COUNT(DISTINCT document_id) FROM chunks").fetchone()[0]
            )
            eligibility = """
                retrieval_default = 1
                AND UPPER(jurisdiction) IN ('VN','VIETNAM','VIET NAM','VIỆT NAM')
            """
            searchable_chunk_count = int(
                connection.execute(f"SELECT COUNT(*) FROM chunks WHERE {eligibility}").fetchone()[0]
            )
            searchable_document_count = int(
                connection.execute(
                    f"SELECT COUNT(DISTINCT document_id) FROM chunks WHERE {eligibility}"
                ).fetchone()[0]
            )
            checked_dates = [
                str(row[0])
                for row in connection.execute(
                    f"SELECT DISTINCT status_checked_at FROM chunks WHERE {eligibility} "
                    "AND status_checked_at IS NOT NULL AND status_checked_at <> ''"
                )
                if row[0]
            ]
            verified_through = min(checked_dates) if checked_dates else ""
            if not verified_through:
                reasons.append("status_check_date_missing")

            provenance_rows = connection.execute(
                f"""
                SELECT source_page_url, source_pdf_sha256, page_start
                FROM chunks WHERE {eligibility}
                """
            ).fetchall()
            invalid_source_count = sum(
                1 for row in provenance_rows if not _is_official_source(str(row[0] or ""))
            )
            missing_provenance_count = sum(
                1 for row in provenance_rows if not row[0] or not row[1] or row[2] is None
            )
            if invalid_source_count:
                reasons.append("unapproved_source_host")
            if missing_provenance_count:
                reasons.append("provenance_missing")
    except (OSError, sqlite3.Error):
        return CorpusHealth(True, False, reason_codes=("corpus_unreadable",))

    digest = sha256_file(path)
    sidecar = Path(manifest_path) if manifest_path else path.with_name("manifest.json")
    manifest = _load_manifest(sidecar)
    manifest_verified = False
    coverage_domains: tuple[str, ...] = ()
    schema_version = 1
    release_id = f"legacy-{digest[:12]}"
    if manifest is None:
        reasons.append("manifest_missing")
    else:
        declared_sha = str(manifest.get("sqlite_sha256", "")).casefold()
        declared_chunks = int(manifest.get("chunk_count", -1))
        declared_documents = int(manifest.get("document_count", -1))
        if declared_sha != digest.casefold():
            reasons.append("manifest_sha256_mismatch")
        if declared_chunks != chunk_count or declared_documents != document_count:
            reasons.append("manifest_count_mismatch")
        declared_verified = str(manifest.get("verified_through", ""))
        if declared_verified != verified_through:
            reasons.append("manifest_verified_through_mismatch")
        schema_version = int(manifest.get("schema_version", 1))
        release_id = str(manifest.get("corpus_release_id", release_id))
        raw_coverage = manifest.get("coverage_domains", [])
        if isinstance(raw_coverage, list):
            coverage_domains = tuple(str(item) for item in raw_coverage if str(item))
        manifest_errors = {
            "manifest_sha256_mismatch",
            "manifest_count_mismatch",
            "manifest_verified_through_mismatch",
        }.intersection(reasons)
        manifest_verified = not manifest_errors

    fatal = {
        "sqlite_integrity_failed",
        "schema_missing_columns",
        "fts_row_count_mismatch",
        "status_check_date_missing",
        "unapproved_source_host",
        "provenance_missing",
        "manifest_sha256_mismatch",
        "manifest_count_mismatch",
        "manifest_verified_through_mismatch",
    }
    if require_manifest:
        fatal.add("manifest_missing")
    snapshot = CorpusSnapshot(
        release_id=release_id,
        schema_version=schema_version,
        sha256=digest,
        verified_through=verified_through,
        chunk_count=chunk_count,
        searchable_chunk_count=searchable_chunk_count,
        document_count=document_count,
        searchable_document_count=searchable_document_count,
        coverage_domains=coverage_domains,
        manifest_verified=manifest_verified,
    )
    return CorpusHealth(
        available=True,
        ready=not fatal.intersection(reasons),
        quick_check=quick_check,
        reason_codes=tuple(dict.fromkeys(reasons)),
        snapshot=snapshot,
        invalid_source_count=invalid_source_count,
        missing_provenance_count=missing_provenance_count,
    )


def build_manifest(db_path: str | Path, *, release_id: str) -> dict[str, Any]:
    """Build a deterministic manifest payload for an already validated legacy DB."""

    health = inspect_corpus(db_path, require_manifest=False)
    non_manifest_reasons = [
        reason for reason in health.reason_codes if reason != "manifest_missing"
    ]
    if not health.ready or non_manifest_reasons:
        raise ValueError(f"Corpus validation failed: {', '.join(non_manifest_reasons)}")
    snapshot = health.snapshot
    return {
        "schema_version": 1,
        "corpus_release_id": release_id,
        "jurisdictions": ["VN"],
        "verified_through": snapshot.verified_through,
        "coverage_domains": [
            "personal_data",
            "ai",
            "cybersecurity",
            "children",
            "copyright",
            "electronic_transactions",
            "data_governance",
        ],
        "sqlite_sha256": snapshot.sha256,
        "chunk_count": snapshot.chunk_count,
        "document_count": snapshot.document_count,
    }
