"""Exact + focused lexical + local semantic retrieval with rank fusion."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import sqlite3
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

import numpy as np

from security.legal.corpus import CorpusHealth, CorpusSnapshot, inspect_corpus
from security.legal.dense import DenseIndexError, PrecomputedDenseIndex
from security.legal.query_planner import (
    LegalQueryPlan,
    LegalQueryPlanner,
    fold_accents,
    normalize_text,
)
from security.legal.verification_overlay import (
    VerificationOverlay,
    VerificationOverlayError,
    load_verification_overlay,
)

_CHUNK_SUFFIX = re.compile(r"^(?P<document>.+)::c(?P<ordinal>\d{5})$")
_TOKEN = re.compile(r"[\wÀ-ỹĐđ]{3,}", re.UNICODE)
_BOILERPLATE = (
    "thông tin về tổ chức",
    "thông tin tổ chức đề nghị",
    "mô tả tóm tắt thay đổi",
    "ký ghi rõ họ tên",
    "mẫu số",
    "chưa thực hiện lý do",
)
_PROHIBITION_POLARITY = re.compile(
    r"\b(?:không\s+được|không\s+có\s+quyền|nghiêm\s+cấm|bị\s+cấm|cấm)\b",
    re.IGNORECASE,
)
_PERMISSION_POLARITY = re.compile(
    r"\b(?:được\s+phép|có\s+quyền|cho\s+phép|được)\b",
    re.IGNORECASE,
)
_CONFLICT_STOP_WORDS = {
    "bị",
    "các",
    "cấm",
    "cho",
    "có",
    "của",
    "doanh",
    "được",
    "không",
    "nghiêm",
    "nghiệp",
    "phép",
    "quyền",
    "theo",
    "thì",
    "trong",
    "và",
    "với",
}
_RELATIONSHIP_TABLES = {
    "document_relationships",
    "legal_relationships",
    "provision_relationships",
    "relationships",
}
_CONCEPT_TERMS: dict[str, tuple[str, ...]] = {
    "cross_border_transfer": ("xuyên biên giới", "ngoài lãnh thổ", "nước ngoài"),
    "personal_data_transfer": ("chuyển dữ liệu cá nhân", "chuyển giao dữ liệu", "bên thứ ba"),
    "erasure": ("xóa dữ liệu", "hủy dữ liệu", "quyền của chủ thể dữ liệu"),
    "copyright_training": ("huấn luyện", "quyền tác giả", "dữ liệu huấn luyện"),
    "high_risk_ai": ("trí tuệ nhân tạo có rủi ro cao", "quản lý rủi ro"),
    "child_privacy": ("riêng tư", "bí mật cá nhân", "trẻ em"),
    "ai_labelling": ("gắn nhãn", "nội dung", "trí tuệ nhân tạo"),
    "incident_reporting": ("báo cáo sự cố", "thông báo sự cố"),
    "penalty": ("xử phạt", "mức phạt", "vi phạm hành chính"),
}


@dataclass(frozen=True)
class RetrievedChunk:
    chunk_id: str
    document_id: str
    title: str
    document_number: str
    document_type: str
    jurisdiction: str
    authority: str
    legal_weight: str
    status: str
    effective_date: str
    status_checked_at: str
    topics: str
    section: str
    page_start: int | None
    page_end: int | None
    source_page_url: str
    source_file_url: str
    source_pdf_sha256: str
    extraction_method: str
    text: str
    retrieval_score: float
    relevance_score: float
    channels: tuple[str, ...] = ()
    is_primary: bool = True
    text_verification_status: str = ""

    def model_dump(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["channels"] = list(self.channels)
        return payload


@dataclass(frozen=True)
class RetrievalTrace:
    mode: str
    candidate_counts: dict[str, int] = field(default_factory=dict)
    latency_ms: dict[str, float] = field(default_factory=dict)
    degraded_reasons: tuple[str, ...] = ()
    rejected_reasons: dict[str, int] = field(default_factory=dict)
    plan: dict[str, Any] = field(default_factory=dict)

    def model_dump(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["degraded_reasons"] = list(self.degraded_reasons)
        return payload


@dataclass(frozen=True)
class RetrievalResult:
    references: tuple[RetrievedChunk, ...]
    context_references: tuple[RetrievedChunk, ...]
    snapshot: CorpusSnapshot
    trace: RetrievalTrace
    conflicts: tuple[dict[str, Any], ...] = ()
    insufficient_reason: str = ""


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=2.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _file_identity(path: Path) -> tuple[bool, int, int, int, int]:
    try:
        metadata = path.stat()
    except OSError:
        return False, 0, 0, 0, 0
    return (
        True,
        int(getattr(metadata, "st_dev", 0)),
        int(getattr(metadata, "st_ino", 0)),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


def _legal_polarity(text: str) -> str:
    normalized = normalize_text(text)
    prohibition = bool(_PROHIBITION_POLARITY.search(normalized))
    # Remove prohibition phrases before looking for permission, otherwise the
    # word "được" inside "không được" creates a false permission signal.
    without_prohibition = _PROHIBITION_POLARITY.sub(" ", normalized)
    permission = bool(_PERMISSION_POLARITY.search(without_prohibition))
    if prohibition == permission:
        return ""
    return "prohibition" if prohibition else "permission"


def _proposition_tokens(text: str) -> set[str]:
    normalized = _PERMISSION_POLARITY.sub(" ", _PROHIBITION_POLARITY.sub(" ", normalize_text(text)))
    return {
        token
        for token in _TOKEN.findall(normalized)
        if len(token) >= 2 and token not in _CONFLICT_STOP_WORDS and not token.isdigit()
    }


def _detect_polarity_conflicts(
    references: tuple[RetrievedChunk, ...],
) -> tuple[dict[str, Any], ...]:
    eligible = [
        reference
        for reference in references
        if reference.legal_weight.strip().casefold() == "binding"
        and reference.status.strip().casefold() in {"current", "in_force", "effective"}
        and _legal_polarity(reference.text)
    ]
    conflicts: list[dict[str, Any]] = []
    for left_index, left in enumerate(eligible):
        left_polarity = _legal_polarity(left.text)
        left_tokens = _proposition_tokens(left.text)
        if len(left_tokens) < 4:
            continue
        for right in eligible[left_index + 1 :]:
            if left.document_id == right.document_id:
                continue
            right_polarity = _legal_polarity(right.text)
            if not right_polarity or left_polarity == right_polarity:
                continue
            right_tokens = _proposition_tokens(right.text)
            if len(right_tokens) < 4:
                continue
            intersection = left_tokens & right_tokens
            containment = len(intersection) / min(len(left_tokens), len(right_tokens))
            union = left_tokens | right_tokens
            jaccard = len(intersection) / max(1, len(union))
            if len(intersection) < 4 or containment < 0.82 or jaccard < 0.65:
                continue
            conflicts.append(
                {
                    "type": "opposite_legal_polarity",
                    "left_chunk_id": left.chunk_id,
                    "left_document_id": left.document_id,
                    "left_polarity": left_polarity,
                    "right_chunk_id": right.chunk_id,
                    "right_document_id": right.document_id,
                    "right_polarity": right_polarity,
                    "token_overlap": round(jaccard, 4),
                    "requires_human_review": True,
                }
            )
            if len(conflicts) >= 10:
                return tuple(conflicts)
    return tuple(conflicts)


def _eligibility(as_of_date: str) -> tuple[str, list[Any]]:
    clauses = [
        "c.retrieval_default = 1",
        "UPPER(c.jurisdiction) IN ('VN','VIETNAM','VIET NAM','VIỆT NAM')",
        "LOWER(c.status) = 'current'",
    ]
    params: list[Any] = []
    if as_of_date:
        clauses.extend(
            [
                "c.effective_date IS NOT NULL",
                "c.effective_date <> ''",
                "c.effective_date <= ?",
                "c.status_checked_at IS NOT NULL",
                "c.status_checked_at <> ''",
                "c.status_checked_at >= ?",
            ]
        )
        params.extend([as_of_date, as_of_date])
    return " AND ".join(clauses), params


def _row_chunk(
    row: sqlite3.Row,
    *,
    retrieval_score: float,
    relevance_score: float = 0.0,
    channels: Iterable[str] = (),
    is_primary: bool = True,
) -> RetrievedChunk:
    keys = set(row.keys())
    return RetrievedChunk(
        chunk_id=str(row["chunk_id"]),
        document_id=str(row["document_id"]),
        title=str(row["title"]),
        document_number=str(row["document_number"] or ""),
        document_type=str(row["document_type"] or ""),
        jurisdiction=str(row["jurisdiction"] or ""),
        authority=str(row["authority"] or ""),
        legal_weight=str(row["legal_weight"] or ""),
        status=str(row["status"] or ""),
        effective_date=str(row["effective_date"] or ""),
        status_checked_at=str(row["status_checked_at"] or ""),
        topics=str(row["topics"] or ""),
        section=str(row["section"] or ""),
        page_start=row["page_start"],
        page_end=row["page_end"],
        source_page_url=str(row["source_page_url"] or ""),
        source_file_url=str(row["source_file_url"] or ""),
        source_pdf_sha256=str(row["source_pdf_sha256"] or ""),
        extraction_method=str(row["extraction_method"] or ""),
        text=str(row["text"] or ""),
        retrieval_score=round(float(retrieval_score), 8),
        relevance_score=round(float(relevance_score), 8),
        channels=tuple(channels),
        is_primary=is_primary,
        text_verification_status=(
            str(row["text_verification_status"] or "") if "text_verification_status" in keys else ""
        ),
    )


class _CharNgramIndex:
    """Typo/no-accent candidate channel; not represented as a neural dense model."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        try:
            from sklearn.feature_extraction.text import HashingVectorizer
        except ImportError as exc:  # pragma: no cover - runtime dependency is declared
            raise RuntimeError("scikit-learn is unavailable") from exc
        rows = connection.execute(
            """
            SELECT c.* FROM chunks c
            WHERE c.retrieval_default = 1
              AND UPPER(c.jurisdiction) IN ('VN','VIETNAM','VIET NAM','VIỆT NAM')
              AND LOWER(c.status) = 'current'
            ORDER BY c.chunk_id
            """
        ).fetchall()
        self.rows = tuple(rows)
        self.vectorizer = HashingVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 4),
            n_features=2**14,
            alternate_sign=False,
            norm="l2",
            lowercase=True,
            preprocessor=fold_accents,
        )
        texts = [f"{row['title']} {row['section']} {row['text']}" for row in rows]
        self.matrix = self.vectorizer.transform(texts)

    def search(self, query: str, *, top_k: int) -> list[tuple[sqlite3.Row, float]]:
        if not self.rows:
            return []
        vector = self.vectorizer.transform([query])
        scores = np.asarray((self.matrix @ vector.T).toarray()).reshape(-1)
        count = max(1, min(int(top_k), len(self.rows)))
        pool = np.argpartition(-scores, count - 1)[:count]
        indices = pool[np.argsort(-scores[pool])]
        return [
            (self.rows[int(index)], float(scores[int(index)]))
            for index in indices
            if scores[int(index)] > 0
        ]


class HybridLegalRetriever:
    def __init__(
        self,
        db_path: str | Path,
        *,
        candidate_k: int = 50,
        enable_char_ngrams: bool | None = None,
        dense_dir: str | Path | None = None,
        require_manifest: bool = False,
        verification_overlay_path: str | Path | None = None,
        verification_signing_key_file: str | Path | None = None,
        verification_key_id: str | None = None,
        require_verification_overlay: bool = False,
    ) -> None:
        self.db_path = Path(db_path).expanduser()
        self.candidate_k = max(20, min(200, int(candidate_k)))
        self.enable_char_ngrams = (
            os.getenv("PREWISE_LEGAL_RAG_ENABLE_CHAR_NGRAMS", "").strip().casefold()
            in {"1", "true", "yes", "on"}
            if enable_char_ngrams is None
            else enable_char_ngrams
        )
        self.planner = LegalQueryPlanner()
        self._health: CorpusHealth | None = None
        self._health_identity: (
            tuple[
                tuple[bool, int, int, int, int],
                tuple[bool, int, int, int, int],
            ]
            | None
        ) = None
        self._char_index: _CharNgramIndex | None = None
        self._char_failed = False
        self._dense: PrecomputedDenseIndex | None = None
        self._dense_failed_reason = ""
        self.require_manifest = require_manifest
        self.verification_overlay_path = (
            Path(verification_overlay_path).expanduser() if verification_overlay_path else None
        )
        self.verification_signing_key_file = (
            Path(verification_signing_key_file).expanduser()
            if verification_signing_key_file
            else None
        )
        self.verification_key_id = verification_key_id or None
        self.require_verification_overlay = require_verification_overlay
        self._verification_overlay: VerificationOverlay | None = None
        self._verification_overlay_identity: tuple[object, ...] | None = None
        self._verification_overlay_failure = ""
        configured_dense = dense_dir or os.getenv("PREWISE_LEGAL_RAG_DENSE_DIR", "")
        if configured_dense:
            try:
                self._dense = PrecomputedDenseIndex.load(configured_dense)
            except (OSError, ValueError, DenseIndexError) as exc:
                self._dense_failed_reason = f"dense_unavailable:{type(exc).__name__}"

    @property
    def health(self) -> CorpusHealth:
        if self._health is None or self._health_identity != self._corpus_identity():
            return self._validate_health()
        return self._health

    def refresh_health(self) -> CorpusHealth:
        return self._validate_health(force=True)

    def _corpus_identity(
        self,
    ) -> tuple[
        tuple[bool, int, int, int, int],
        tuple[bool, int, int, int, int],
    ]:
        return (
            _file_identity(self.db_path),
            _file_identity(self.db_path.with_name("manifest.json")),
        )

    def _validate_health(self, *, force: bool = False) -> CorpusHealth:
        previous_identity = self._health_identity
        health: CorpusHealth | None = None
        stable_identity = self._corpus_identity()
        for _ in range(2):
            before = self._corpus_identity()
            try:
                health = inspect_corpus(self.db_path, require_manifest=self.require_manifest)
            except (OSError, TypeError, ValueError, sqlite3.Error):
                health = CorpusHealth(
                    available=self.db_path.is_file(),
                    ready=False,
                    reason_codes=("corpus_validation_failed",),
                )
            after = self._corpus_identity()
            stable_identity = after
            if before == after:
                break
        else:
            health = replace(
                health or CorpusHealth(False, False),
                ready=False,
                reason_codes=tuple(
                    dict.fromkeys(
                        [
                            *(health.reason_codes if health else ()),
                            "corpus_changed_during_validation",
                        ]
                    )
                ),
            )

        manifest_exists = stable_identity[1][0]
        if health is not None and manifest_exists and "manifest_missing" in health.reason_codes:
            health = replace(
                health,
                ready=False,
                reason_codes=tuple(dict.fromkeys([*health.reason_codes, "manifest_invalid"])),
            )
        database_changed = (
            previous_identity is not None and previous_identity[0] != stable_identity[0]
        )
        manifest_removed = (
            previous_identity is not None and previous_identity[1][0] and not stable_identity[1][0]
        )
        if health is not None and database_changed and not health.snapshot.manifest_verified:
            health = replace(
                health,
                ready=False,
                reason_codes=tuple(
                    dict.fromkeys(
                        [
                            *health.reason_codes,
                            "corpus_changed_without_verified_manifest",
                        ]
                    )
                ),
            )
        if health is not None and manifest_removed:
            health = replace(
                health,
                ready=False,
                reason_codes=tuple(dict.fromkeys([*health.reason_codes, "manifest_removed"])),
            )
        if force or previous_identity != stable_identity:
            # A character index is an in-memory copy of corpus text and must never
            # survive an atomic DB/release replacement.
            self._char_index = None
            self._char_failed = False
            self._verification_overlay = None
            self._verification_overlay_identity = None
            self._verification_overlay_failure = ""
        self._health_identity = stable_identity
        self._health = health or CorpusHealth(False, False, reason_codes=("corpus_missing",))
        return self._health

    def _overlay_identity(self, snapshot: CorpusSnapshot) -> tuple[object, ...]:
        return (
            snapshot.release_id,
            snapshot.sha256,
            _file_identity(self.verification_overlay_path)
            if self.verification_overlay_path is not None
            else None,
            _file_identity(self.verification_signing_key_file)
            if self.verification_signing_key_file is not None
            else None,
            self.verification_key_id,
            self.require_verification_overlay,
        )

    @staticmethod
    def _overlay_error_reason(exc: VerificationOverlayError) -> str:
        normalized = str(exc).casefold()
        if "corpus sha-256 mismatch" in normalized or "release identity mismatch" in normalized:
            return "verification_overlay_corpus_mismatch"
        if "checksum mismatch" in normalized or "signature mismatch" in normalized:
            return "verification_overlay_integrity_invalid"
        if "required" in normalized or "missing" in normalized:
            return "verification_overlay_missing"
        return "verification_overlay_invalid"

    def _load_verification_overlay(
        self, snapshot: CorpusSnapshot
    ) -> tuple[VerificationOverlay | None, str]:
        identity = self._overlay_identity(snapshot)
        if self._verification_overlay_identity == identity:
            return self._verification_overlay, self._verification_overlay_failure

        overlay: VerificationOverlay | None = None
        failure = ""
        if self.verification_overlay_path is None:
            if self.require_verification_overlay:
                failure = "verification_overlay_missing"
        elif not self.verification_overlay_path.is_file() and not self.require_verification_overlay:
            overlay = None
        elif self.verification_signing_key_file is None:
            failure = "verification_overlay_key_missing"
        else:
            try:
                signing_key = self.verification_signing_key_file.read_bytes()
                overlay = load_verification_overlay(
                    self.verification_overlay_path,
                    signing_key=signing_key,
                    expected_corpus_sha256=snapshot.sha256,
                    expected_release_id=snapshot.release_id,
                    expected_signing_key_id=self.verification_key_id,
                    required=self.require_verification_overlay,
                )
            except OSError:
                failure = "verification_overlay_key_unreadable"
            except VerificationOverlayError as exc:
                failure = self._overlay_error_reason(exc)

        self._verification_overlay_identity = identity
        self._verification_overlay = overlay
        self._verification_overlay_failure = failure
        return overlay, failure

    @staticmethod
    def _apply_verification_overlay(
        chunks: Iterable[RetrievedChunk], overlay: VerificationOverlay | None
    ) -> tuple[tuple[RetrievedChunk, ...], int, bool]:
        if overlay is None:
            return tuple(chunks), 0, False
        output: list[RetrievedChunk] = []
        rejected = 0
        for chunk in chunks:
            record = overlay.get(chunk.chunk_id)
            if record is None:
                output.append(replace(chunk, text_verification_status=""))
                continue
            runtime_text_hash = hashlib.sha256(chunk.text.encode("utf-8")).hexdigest()
            record_matches = (
                hmac.compare_digest(record.text_sha256, runtime_text_hash)
                and hmac.compare_digest(
                    record.source_pdf_sha256, chunk.source_pdf_sha256.casefold()
                )
                and record.page_start == chunk.page_start
                and record.page_end == chunk.page_end
                and record.source_page_url == chunk.source_page_url
            )
            if not record_matches:
                return (), rejected, True
            if record.text_verification_status in {"rejected", "needs_correction"}:
                rejected += 1
                continue
            output.append(
                replace(
                    chunk,
                    text_verification_status=record.text_verification_status,
                )
            )
        return tuple(output), rejected, False

    def _exact_candidates(
        self,
        connection: sqlite3.Connection,
        plan: LegalQueryPlan,
        *,
        as_of_date: str,
    ) -> list[tuple[sqlite3.Row, float]]:
        if not plan.document_numbers and not plan.article_numbers:
            return []
        eligible, params = _eligibility(as_of_date)
        clauses = [eligible]
        values = list(params)
        if plan.document_numbers:
            placeholders = ",".join("?" for _ in plan.document_numbers)
            clauses.append("REPLACE(UPPER(c.document_number), ' ', '') IN (" + placeholders + ")")
            values.extend(plan.document_numbers)
        if plan.article_numbers:
            article_parts: list[str] = []
            for article in plan.article_numbers:
                article_parts.append("(c.section LIKE ? OR c.text LIKE ?)")
                values.extend([f"%Điều {article}%", f"%Điều {article}%"])
            clauses.append("(" + " OR ".join(article_parts) + ")")
        sql = f"""
            SELECT c.* FROM chunks c
            WHERE {" AND ".join(clauses)}
            ORDER BY
              CASE WHEN LOWER(c.section) LIKE 'điều %' THEN 0 ELSE 1 END,
              CASE WHEN LENGTH(TRIM(c.text)) >= 60 THEN 0 ELSE 1 END,
              c.page_start, c.chunk_id
            LIMIT ?
        """
        values.append(min(20, self.candidate_k))
        return [
            (row, 1.0 - rank * 0.001)
            for rank, row in enumerate(connection.execute(sql, values).fetchall(), start=1)
        ]

    def _lexical_candidates(
        self,
        connection: sqlite3.Connection,
        plan: LegalQueryPlan,
        *,
        as_of_date: str,
    ) -> list[list[tuple[sqlite3.Row, float]]]:
        eligible, params = _eligibility(as_of_date)
        outputs: list[list[tuple[sqlite3.Row, float]]] = []
        sql = f"""
            SELECT c.*, bm25(chunks_fts, 0.0, 2.5, 4.0, 1.0, 2.2, 1.0) AS bm25_score
            FROM chunks_fts
            JOIN chunks c ON c.chunk_id = chunks_fts.chunk_id
            WHERE chunks_fts MATCH ? AND {eligible}
            ORDER BY bm25_score
            LIMIT ?
        """
        for query in plan.lexical_queries:
            try:
                rows = connection.execute(sql, [query, *params, self.candidate_k]).fetchall()
            except sqlite3.OperationalError:
                continue
            if rows:
                outputs.append([(row, -float(row["bm25_score"])) for row in rows])
        return outputs

    def _char_candidates(
        self,
        connection: sqlite3.Connection,
        plan: LegalQueryPlan,
        *,
        as_of_date: str,
    ) -> list[tuple[sqlite3.Row, float]]:
        if not self.enable_char_ngrams or self._char_failed:
            return []
        try:
            if self._char_index is None:
                self._char_index = _CharNgramIndex(connection)
            raw = self._char_index.search(
                plan.dense_query, top_k=min(len(self._char_index.rows), self.candidate_k * 3)
            )
        except Exception:
            self._char_failed = True
            return []
        if not as_of_date:
            return raw[: self.candidate_k]
        return [
            (row, score)
            for row, score in raw
            if str(row["effective_date"] or "") <= as_of_date
            and str(row["status_checked_at"] or "") >= as_of_date
        ][: self.candidate_k]

    def _dense_candidates(
        self,
        connection: sqlite3.Connection,
        plan: LegalQueryPlan,
        *,
        as_of_date: str,
    ) -> list[tuple[sqlite3.Row, float]]:
        if self._dense is None:
            return []
        try:
            raw = self._dense.search(plan.dense_query, top_k=self.candidate_k * 3)
        except (OSError, ValueError, DenseIndexError) as exc:
            self._dense_failed_reason = f"dense_runtime_failed:{type(exc).__name__}"
            return []
        ids = [chunk_id for chunk_id, _ in raw]
        if not ids:
            return []
        eligible, params = _eligibility(as_of_date)
        placeholders = ",".join("?" for _ in ids)
        rows = connection.execute(
            f"SELECT c.* FROM chunks c WHERE c.chunk_id IN ({placeholders}) AND {eligible}",
            [*ids, *params],
        ).fetchall()
        by_id = {str(row["chunk_id"]): row for row in rows}
        return [(by_id[chunk_id], score) for chunk_id, score in raw if chunk_id in by_id][
            : self.candidate_k
        ]

    @staticmethod
    def _concept_score(plan: LegalQueryPlan, haystack: str) -> float:
        if not plan.concepts:
            return 0.0
        hits = 0.0
        for concept in plan.concepts:
            phrases = _CONCEPT_TERMS.get(concept, ())
            phrase_score = 0.0
            for phrase in phrases:
                terms = set(_TOKEN.findall(normalize_text(phrase)))
                if not terms:
                    continue
                overlap = sum(1 for term in terms if term in haystack) / len(terms)
                phrase_score = max(phrase_score, overlap)
            hits += phrase_score
        return hits / len(plan.concepts)

    @staticmethod
    def _boilerplate_penalty(text: str, section: str) -> float:
        haystack = normalize_text(f"{section} {text}")
        penalty = 0.0
        if len(text.strip()) < 50:
            penalty += 0.18
        if any(phrase in haystack for phrase in _BOILERPLATE):
            penalty += 0.45
        if len(text.strip()) < 12:
            penalty += 0.35
        return penalty

    def _rank(
        self,
        plan: LegalQueryPlan,
        rows: dict[str, sqlite3.Row],
        channel_ranks: dict[str, dict[str, int]],
    ) -> list[RetrievedChunk]:
        weights = {"exact": 3.0, "lexical": 1.2, "char_ngram": 0.75, "dense": 1.5}
        ranked: list[RetrievedChunk] = []
        focus = set(plan.focus_tokens)
        normalized_docs = {item.replace(" ", "").upper() for item in plan.document_numbers}
        for chunk_id, row in rows.items():
            channels = channel_ranks.get(chunk_id, {})
            fused = sum(
                weights.get(channel, 1.0) / (60.0 + rank) for channel, rank in channels.items()
            )
            haystack = normalize_text(f"{row['title']} {row['section']} {row['text']}")
            overlap = sum(1 for token in focus if token in haystack) / max(1, len(focus))
            concept = self._concept_score(plan, haystack)
            exact = 0.0
            document_number = str(row["document_number"] or "").replace(" ", "").upper()
            if normalized_docs and document_number in normalized_docs:
                exact += 0.55
            if plan.article_numbers and any(
                f"điều {article}" in normalize_text(str(row["section"] or ""))
                for article in plan.article_numbers
            ):
                exact += 0.45
            agreement = min(1.0, len(channels) / 3.0)
            penalty = self._boilerplate_penalty(str(row["text"] or ""), str(row["section"] or ""))
            relevance = max(
                0.0,
                min(1.0, 0.48 * overlap + 0.37 * concept + 0.15 * agreement + exact - penalty),
            )
            authority_bonus = (
                0.03 if str(row["legal_weight"] or "").casefold() == "binding" else 0.0
            )
            final_score = 8.0 * fused + relevance + authority_bonus
            ranked.append(
                _row_chunk(
                    row,
                    retrieval_score=final_score,
                    relevance_score=relevance,
                    channels=sorted(channels),
                )
            )
        return sorted(
            ranked,
            key=lambda item: (item.retrieval_score, item.relevance_score, len(item.text)),
            reverse=True,
        )

    def _expand_context(
        self,
        connection: sqlite3.Connection,
        references: tuple[RetrievedChunk, ...],
        *,
        as_of_date: str,
        limit: int = 18,
    ) -> tuple[RetrievedChunk, ...]:
        output: list[RetrievedChunk] = list(references)
        seen = {item.chunk_id for item in output}
        neighbor_ids: list[str] = []
        for item in references:
            match = _CHUNK_SUFFIX.match(item.chunk_id)
            if not match:
                continue
            ordinal = int(match.group("ordinal"))
            document = match.group("document")
            deltas = (-1, 1, 2) if normalize_text(item.section).startswith("điều ") else (-1, 1)
            for delta in deltas:
                candidate = f"{document}::c{ordinal + delta:05d}"
                if candidate not in seen:
                    neighbor_ids.append(candidate)
                    seen.add(candidate)
        if neighbor_ids:
            eligible, params = _eligibility(as_of_date)
            placeholders = ",".join("?" for _ in neighbor_ids)
            rows = connection.execute(
                f"SELECT c.* FROM chunks c WHERE c.chunk_id IN ({placeholders}) AND {eligible}",
                [*neighbor_ids, *params],
            ).fetchall()
            by_id = {str(row["chunk_id"]): row for row in rows}
            for chunk_id in neighbor_ids:
                if chunk_id in by_id and len(output) < limit:
                    output.append(
                        _row_chunk(
                            by_id[chunk_id],
                            retrieval_score=0.0,
                            channels=("neighbor",),
                            is_primary=False,
                        )
                    )
        return tuple(output[:limit])

    def retrieve(
        self,
        question: str,
        *,
        context: dict[str, str] | None = None,
        top_k: int = 8,
    ) -> RetrievalResult:
        started = time.perf_counter()
        health = self.health
        if not health.available or not health.ready:
            return RetrievalResult(
                references=(),
                context_references=(),
                snapshot=health.snapshot,
                trace=RetrievalTrace(
                    mode="unavailable",
                    degraded_reasons=health.reason_codes,
                ),
                insufficient_reason="corpus_unavailable",
            )
        verification_overlay, overlay_failure = self._load_verification_overlay(health.snapshot)
        if overlay_failure:
            return RetrievalResult(
                references=(),
                context_references=(),
                snapshot=health.snapshot,
                trace=RetrievalTrace(
                    mode="unavailable",
                    degraded_reasons=(overlay_failure,),
                ),
                insufficient_reason=overlay_failure,
            )
        context = context or {}
        as_of_date = str(context.get("as_of_date", ""))
        if as_of_date and health.snapshot.verified_through < as_of_date:
            return RetrievalResult(
                references=(),
                context_references=(),
                snapshot=health.snapshot,
                trace=RetrievalTrace(mode="stale"),
                insufficient_reason="corpus_stale",
            )
        plan = self.planner.plan(question, context=context)
        if plan.out_of_scope_hint and not plan.document_numbers:
            return RetrievalResult(
                references=(),
                context_references=(),
                snapshot=health.snapshot,
                trace=RetrievalTrace(mode="out_of_scope", plan=plan.model_dump()),
                insufficient_reason="corpus_out_of_scope",
            )

        timings: dict[str, float] = {}
        degraded: list[str] = []
        rows: dict[str, sqlite3.Row] = {}
        channel_ranks: dict[str, dict[str, int]] = {}
        counts: dict[str, int] = {}
        relationship_metadata_available = False

        def add(channel: str, candidates: list[tuple[sqlite3.Row, float]]) -> None:
            counts[channel] = counts.get(channel, 0) + len(candidates)
            for rank, (row, _score) in enumerate(candidates, start=1):
                chunk_id = str(row["chunk_id"])
                rows[chunk_id] = row
                existing = channel_ranks.setdefault(chunk_id, {})
                existing[channel] = min(rank, existing.get(channel, rank))

        try:
            with _connect(self.db_path) as connection:
                table_names = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                relationship_metadata_available = bool(
                    table_names.intersection(_RELATIONSHIP_TABLES)
                )
                stage = time.perf_counter()
                add("exact", self._exact_candidates(connection, plan, as_of_date=as_of_date))
                timings["exact"] = (time.perf_counter() - stage) * 1000

                stage = time.perf_counter()
                lexical_groups = self._lexical_candidates(connection, plan, as_of_date=as_of_date)
                for group in lexical_groups:
                    add("lexical", group)
                timings["lexical"] = (time.perf_counter() - stage) * 1000

                stage = time.perf_counter()
                char_candidates = self._char_candidates(connection, plan, as_of_date=as_of_date)
                add("char_ngram", char_candidates)
                timings["char_ngram"] = (time.perf_counter() - stage) * 1000
                if self._char_failed:
                    degraded.append("char_ngram_unavailable")

                stage = time.perf_counter()
                dense_candidates = self._dense_candidates(connection, plan, as_of_date=as_of_date)
                add("dense", dense_candidates)
                timings["dense"] = (time.perf_counter() - stage) * 1000
                if self._dense_failed_reason:
                    degraded.append(self._dense_failed_reason)

                stage = time.perf_counter()
                ranked = self._rank(plan, rows, channel_ranks)
                ranked, overlay_rejected, overlay_record_mismatch = (
                    self._apply_verification_overlay(ranked, verification_overlay)
                )
                if overlay_record_mismatch:
                    return RetrievalResult(
                        references=(),
                        context_references=(),
                        snapshot=health.snapshot,
                        trace=RetrievalTrace(
                            mode="unavailable",
                            candidate_counts=counts,
                            latency_ms=timings,
                            degraded_reasons=("verification_overlay_record_mismatch",),
                            plan=plan.model_dump(),
                        ),
                        insufficient_reason="verification_overlay_record_mismatch",
                    )
                minimum_relevance = 0.12 if plan.concepts else 0.2
                selected = tuple(
                    item
                    for item in ranked
                    if item.relevance_score >= minimum_relevance or "exact" in item.channels
                )[: max(1, min(20, int(top_k)))]
                timings["fusion_rerank"] = (time.perf_counter() - stage) * 1000
                context_references = self._expand_context(
                    connection, selected, as_of_date=as_of_date
                )
                context_references, context_overlay_rejected, overlay_record_mismatch = (
                    self._apply_verification_overlay(context_references, verification_overlay)
                )
                if overlay_record_mismatch:
                    return RetrievalResult(
                        references=(),
                        context_references=(),
                        snapshot=health.snapshot,
                        trace=RetrievalTrace(
                            mode="unavailable",
                            candidate_counts=counts,
                            latency_ms=timings,
                            degraded_reasons=("verification_overlay_record_mismatch",),
                            plan=plan.model_dump(),
                        ),
                        insufficient_reason="verification_overlay_record_mismatch",
                    )
        except (OSError, sqlite3.Error) as exc:
            degraded.append(f"retrieval_error:{type(exc).__name__}")
            return RetrievalResult(
                references=(),
                context_references=(),
                snapshot=health.snapshot,
                trace=RetrievalTrace(
                    mode="unavailable",
                    candidate_counts=counts,
                    latency_ms=timings,
                    degraded_reasons=tuple(degraded),
                    plan=plan.model_dump(),
                ),
                insufficient_reason="corpus_unreadable",
            )

        timings["total"] = (time.perf_counter() - started) * 1000
        mode_parts = ["exact", "lexical"]
        if char_candidates:
            mode_parts.append("char_ngram")
        if dense_candidates:
            mode_parts.append("dense")
        if self._dense is None:
            degraded.append("neural_dense_not_configured")
        if not relationship_metadata_available:
            degraded.append("relationship_metadata_unavailable")
        conflicts = _detect_polarity_conflicts(selected)
        trace = RetrievalTrace(
            mode="+".join(mode_parts),
            candidate_counts=counts,
            latency_ms={key: round(value, 3) for key, value in timings.items()},
            degraded_reasons=tuple(dict.fromkeys(degraded)),
            rejected_reasons={
                "below_relevance_threshold": max(0, len(ranked) - len(selected)),
                "verification_overlay_rejected": overlay_rejected + context_overlay_rejected,
            },
            plan=plan.model_dump(),
        )
        return RetrievalResult(
            references=selected,
            context_references=context_references,
            snapshot=health.snapshot,
            trace=trace,
            conflicts=conflicts,
            insufficient_reason="" if selected else "low_relevance",
        )

    def legacy_search(self, question: str, *, top_k: int = 8) -> tuple[RetrievedChunk, ...]:
        """Frozen current OR-FTS baseline for benchmark comparison."""

        health = self.health
        if not health.available or not health.ready:
            return ()
        verification_overlay, overlay_failure = self._load_verification_overlay(health.snapshot)
        if overlay_failure:
            return ()
        terms: list[str] = []
        seen: set[str] = set()
        for term in re.findall(r"[\wÀ-ỹĐđ]{2,}", question, flags=re.UNICODE):
            folded = term.casefold()
            if folded not in seen:
                seen.add(folded)
                terms.append(term.replace('"', ""))
            if len(terms) >= 24:
                break
        fts_query = " OR ".join(f'"{term}"' for term in terms) or '""'
        sql = """
            SELECT c.*, bm25(chunks_fts, 0.0, 1.5, 2.0, 0.8, 1.0, 1.0) AS score
            FROM chunks_fts JOIN chunks c ON c.chunk_id = chunks_fts.chunk_id
            WHERE chunks_fts MATCH ?
              AND c.retrieval_default = 1
              AND UPPER(c.jurisdiction) IN ('VN','VIETNAM','VIET NAM','VIỆT NAM')
            ORDER BY score LIMIT ?
        """
        with _connect(self.db_path) as connection:
            rows = connection.execute(sql, (fts_query, max(1, min(8, top_k)))).fetchall()
        chunks = tuple(
            _row_chunk(row, retrieval_score=-float(row["score"]), channels=("legacy",))
            for row in rows
        )
        filtered, _, mismatch = self._apply_verification_overlay(chunks, verification_overlay)
        return () if mismatch else filtered
