"""Bounded Vietnamese legal intent detection and deterministic query planning."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

_WORD = re.compile(r"[\wÀ-ỹĐđ]{2,}", re.UNICODE)
_DOCUMENT_NUMBER = re.compile(r"\b\d{1,4}\s*/\s*\d{4}\s*/\s*[A-ZĐa-zđ0-9-]{2,20}\b", re.UNICODE)
_ARTICLE = re.compile(r"\b(?:điều|dieu)\s+(\d+[a-z]?)\b", re.IGNORECASE)
_CLAUSE = re.compile(r"\b(?:khoản|khoan)\s+(\d+)\b", re.IGNORECASE)

_LEGAL_PATTERN_TEXTS = (
    r"\b(?:luật|pháp luật|nghị định|thông tư|điều khoản|xử phạt|trách nhiệm pháp lý)\b",
    r"\b(?:có được phép|có vi phạm|có bị phạt|có phải xin|có bắt buộc|có thể)\b",
    r"\b(?:được phép|bị cấm|trái pháp luật|mức phạt|nghĩa vụ|chịu trách nhiệm)\b",
    r"\b(?:có quyền|quyền yêu cầu|được chia sẻ|được thu thập|được xử lý)\b",
    r"\b(?:dữ liệu cá nhân|quyền tác giả|an ninh mạng|trẻ em|bí mật nhà nước)\b",
)

_STOP_WORDS = {
    "ai",
    "anh",
    "chị",
    "cho",
    "có",
    "của",
    "doanh",
    "nghiệp",
    "được",
    "hay",
    "không",
    "khi",
    "là",
    "một",
    "này",
    "năm",
    "ngày",
    "nhà",
    "phải",
    "tại",
    "theo",
    "thì",
    "tôi",
    "trong",
    "trước",
    "việt",
    "nam",
    "và",
    "với",
}

_COVERED_DOMAIN_TERMS = {
    "dữ liệu",
    "cá nhân",
    "quyền tác giả",
    "bản quyền",
    "trí tuệ nhân tạo",
    "an ninh mạng",
    "trẻ em",
    "bí mật nhà nước",
    "giao dịch điện tử",
    "chữ ký điện tử",
}
_OUT_OF_SCOPE_TERMS = {
    "thuế",
    "lao động",
    "đất đai",
    "thừa kế",
    "hôn nhân",
    "bảo hiểm xã hội",
    "hình sự",
    "giờ làm thêm",
}

_CONCEPT_PHRASES: dict[str, tuple[str, ...]] = {
    "cross_border_transfer": (
        "chuyển dữ liệu cá nhân xuyên biên giới",
        "dữ liệu đặt ngoài lãnh thổ",
        "tổ chức cá nhân ở nước ngoài",
    ),
    "personal_data_transfer": (
        "chuyển giao dữ liệu cá nhân",
        "chuyển dữ liệu cá nhân",
        "bên thứ ba",
    ),
    "erasure": (
        "quyền yêu cầu xóa dữ liệu cá nhân",
        "xóa dữ liệu cá nhân",
        "hủy dữ liệu cá nhân",
    ),
    "copyright_training": (
        "huấn luyện hệ thống trí tuệ nhân tạo",
        "quyền tác giả dữ liệu huấn luyện",
        "sử dụng tác phẩm huấn luyện",
    ),
    "high_risk_ai": (
        "hệ thống trí tuệ nhân tạo có rủi ro cao",
        "quản lý rủi ro trí tuệ nhân tạo",
    ),
    "child_privacy": (
        "đời sống riêng tư bí mật cá nhân trẻ em",
        "công bố thông tin trẻ em",
    ),
    "ai_labelling": (
        "nội dung do trí tuệ nhân tạo tạo ra gắn nhãn",
        "minh bạch nội dung trí tuệ nhân tạo",
    ),
    "incident_reporting": (
        "báo cáo sự cố an ninh mạng",
        "thông báo sự cố dữ liệu",
    ),
    "penalty": (
        "xử phạt vi phạm hành chính",
        "mức phạt",
    ),
}


def normalize_text(value: str) -> str:
    return " ".join(unicodedata.normalize("NFC", value or "").casefold().split())


def fold_accents(value: str) -> str:
    normalized = unicodedata.normalize("NFD", normalize_text(value))
    folded = "".join(char for char in normalized if unicodedata.category(char) != "Mn")
    return folded.replace("đ", "d")


_LEGAL_PATTERNS = tuple(re.compile(pattern, re.IGNORECASE) for pattern in _LEGAL_PATTERN_TEXTS)
_LEGAL_PATTERNS_FOLDED = tuple(
    re.compile(fold_accents(pattern), re.IGNORECASE) for pattern in _LEGAL_PATTERN_TEXTS
)
_STOP_WORDS_FOLDED = {fold_accents(term) for term in _STOP_WORDS}
_COVERED_DOMAIN_TERMS_FOLDED = {fold_accents(term) for term in _COVERED_DOMAIN_TERMS}
_OUT_OF_SCOPE_TERMS_FOLDED = {fold_accents(term) for term in _OUT_OF_SCOPE_TERMS}


def _quote_fts(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


@dataclass(frozen=True)
class LegalQueryPlan:
    original_question: str
    normalized_question: str
    accent_folded_question: str
    document_numbers: tuple[str, ...]
    article_numbers: tuple[str, ...]
    clause_numbers: tuple[str, ...]
    concepts: tuple[str, ...]
    lexical_queries: tuple[str, ...]
    dense_query: str
    focus_tokens: tuple[str, ...]
    required_facets: tuple[str, ...]
    out_of_scope_hint: bool = False

    def model_dump(self) -> dict[str, Any]:
        return {
            "original_question": self.original_question,
            "normalized_question": self.normalized_question,
            "accent_folded_question": self.accent_folded_question,
            "document_numbers": list(self.document_numbers),
            "article_numbers": list(self.article_numbers),
            "clause_numbers": list(self.clause_numbers),
            "concepts": list(self.concepts),
            "lexical_queries": list(self.lexical_queries),
            "dense_query": self.dense_query,
            "focus_tokens": list(self.focus_tokens),
            "required_facets": list(self.required_facets),
            "out_of_scope_hint": self.out_of_scope_hint,
        }


class LegalQueryPlanner:
    """Create small, auditable retrieval views instead of one broad OR query."""

    @staticmethod
    def is_legal_question(question: str) -> bool:
        normalized = normalize_text(question)
        folded = fold_accents(normalized)
        return any(pattern.search(normalized) for pattern in _LEGAL_PATTERNS) or any(
            pattern.search(folded) for pattern in _LEGAL_PATTERNS_FOLDED
        )

    @staticmethod
    def _concepts(text: str, folded: str) -> tuple[str, ...]:
        values: list[str] = []

        def contains(*terms: str) -> bool:
            for term in terms:
                needle = fold_accents(term)
                if needle and re.search(rf"(?<!\w){re.escape(needle)}(?!\w)", folded):
                    return True
            return False

        def add(name: str, condition: bool) -> None:
            if condition and name not in values:
                values.append(name)

        data = contains("dữ liệu", "thông tin", "cccd", "sinh trắc")
        foreign = contains(
            "xuyên biên giới",
            "nước ngoài",
            "ngoài lãnh thổ",
            "singapore",
            "server nước ngoài",
            "máy chủ nước ngoài",
            "cloud nước ngoài",
        )
        transfer = contains("chuyển", "chia sẻ", "gửi", "đưa", "upload", "cung cấp")
        add("cross_border_transfer", data and foreign)
        add("personal_data_transfer", data and transfer)
        add("erasure", data and contains("xóa", "huỷ", "hủy"))
        add(
            "copyright_training",
            contains("tác phẩm", "bản quyền", "quyền tác giả")
            and contains("huấn luyện", "mô hình", "trí tuệ nhân tạo", " ai "),
        )
        add(
            "high_risk_ai",
            contains("rủi ro cao") and contains("trí tuệ nhân tạo", "hệ thống ai", "mô hình ai"),
        )
        add(
            "child_privacy",
            contains("trẻ em", "trẻ nhỏ")
            and contains("riêng tư", "bí mật", "hình ảnh", "thông tin"),
        )
        add(
            "ai_labelling",
            contains("gắn nhãn", "đánh dấu", "minh bạch")
            and contains(" ai ", "trí tuệ nhân tạo", "deepfake"),
        )
        add(
            "incident_reporting",
            contains("sự cố", "làm lộ", "rò rỉ") and contains("báo cáo", "thông báo", "khi nào"),
        )
        add("penalty", contains("mức phạt", "xử phạt", "bị phạt"))
        return tuple(values)

    def plan(
        self,
        question: str,
        *,
        context: Mapping[str, Any] | None = None,
    ) -> LegalQueryPlan:
        normalized = normalize_text(question)
        folded = fold_accents(question)
        document_numbers = tuple(
            "".join(match.group(0).upper().split())
            for match in _DOCUMENT_NUMBER.finditer(question or "")
        )
        article_numbers = tuple(
            match.group(1).lower() for match in _ARTICLE.finditer(question or "")
        )
        clause_numbers = tuple(match.group(1) for match in _CLAUSE.finditer(question or ""))
        concepts = self._concepts(f" {normalized} ", f" {folded} ")

        focus: list[str] = []
        seen: set[str] = set()
        for token in _WORD.findall(normalized):
            if fold_accents(token) in _STOP_WORDS_FOLDED or token.isdigit() or len(token) < 3:
                continue
            if token not in seen:
                focus.append(token)
                seen.add(token)
        for concept in concepts:
            for phrase in _CONCEPT_PHRASES[concept]:
                for token in _WORD.findall(phrase):
                    if token not in _STOP_WORDS and token not in seen:
                        focus.append(token)
                        seen.add(token)

        lexical: list[str] = []
        for concept in concepts:
            for phrase in _CONCEPT_PHRASES[concept]:
                phrase_tokens = _WORD.findall(phrase)
                if len(phrase_tokens) >= 2:
                    lexical.append(
                        f"section:{_quote_fts(' '.join(phrase_tokens))} OR "
                        f"text:{_quote_fts(' '.join(phrase_tokens))}"
                    )
                compact = phrase_tokens[:6]
                if compact:
                    lexical.append(" AND ".join(_quote_fts(token) for token in compact))

        compact_focus = focus[:8]
        if compact_focus:
            lexical.append(" AND ".join(_quote_fts(token) for token in compact_focus[:5]))
            lexical.append(" OR ".join(_quote_fts(token) for token in compact_focus))
        lexical = list(dict.fromkeys(lexical))[:12]

        context = context or {}
        dense_parts = [question]
        for key in ("action", "data_or_asset", "purpose", "recipient"):
            value = str(context.get(key, "")).strip()
            if value and value.casefold() not in normalized:
                dense_parts.append(value)
        for concept in concepts:
            dense_parts.append(_CONCEPT_PHRASES[concept][0])

        required_facets: list[str] = list(concepts)
        if document_numbers:
            required_facets.append("exact_document")
        if article_numbers:
            required_facets.append("exact_article")

        has_covered = any(term in folded for term in _COVERED_DOMAIN_TERMS_FOLDED)
        out_of_scope = (
            any(term in folded for term in _OUT_OF_SCOPE_TERMS_FOLDED) and not has_covered
        )
        return LegalQueryPlan(
            original_question=question,
            normalized_question=normalized,
            accent_folded_question=folded,
            document_numbers=document_numbers,
            article_numbers=article_numbers,
            clause_numbers=clause_numbers,
            concepts=concepts,
            lexical_queries=tuple(lexical),
            dense_query=" ".join(dense_parts),
            focus_tokens=tuple(focus[:24]),
            required_facets=tuple(required_facets),
            out_of_scope_hint=out_of_scope,
        )


def context_mapping(value: object) -> dict[str, str]:
    """Convert dataclass/Pydantic/mapping legal context without importing backend code."""

    if isinstance(value, Mapping):
        return {str(key): str(item) for key, item in value.items()}
    output: dict[str, str] = {}
    for key in (
        "jurisdiction",
        "as_of_date",
        "actor",
        "action",
        "data_or_asset",
        "purpose",
        "recipient",
    ):
        item = getattr(value, key, "")
        if item is not None:
            output[key] = str(item)
    return output
