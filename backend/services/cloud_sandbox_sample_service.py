"""Private, short-lived sample storage for disposable cloud sandbox sessions."""

from __future__ import annotations

import hashlib
import hmac
import re
import shutil
from pathlib import Path

from backend.config import settings


def agent_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_agent_token(expected_hash: str | None, supplied: str | None) -> bool:
    if not expected_hash or not supplied:
        return False
    return hmac.compare_digest(expected_hash, agent_token_hash(supplied))


# Control characters (notably CR/LF) must never reach a response header.
_UNSAFE_NAME_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def safe_sample_name(filename: str) -> str:
    name = Path(filename).name.strip()
    if not name or name in {".", ".."}:
        raise ValueError("Tên file không hợp lệ")
    # ``.strip()`` only removes surrounding whitespace, so an interior CR/LF
    # survived into the raw X-Sandbox-Sample-Filename response header and split
    # it. Control characters have no legitimate place in a sample name.
    name = _UNSAFE_NAME_CHARS.sub("_", name)
    if not name.strip("._"):
        raise ValueError("Tên file không hợp lệ")
    return name[:240]


def sample_path(session_id: str, filename: str) -> Path:
    base = Path(settings.sandbox_sample_storage_path).resolve()
    target = (base / session_id / safe_sample_name(filename)).resolve()
    if not target.is_relative_to(base):
        raise ValueError("Đường dẫn file không hợp lệ")
    return target


def store_sample(session_id: str, filename: str, content: bytes) -> tuple[str, str]:
    target = sample_path(session_id, filename)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    return str(target), hashlib.sha256(content).hexdigest()


def remove_session_samples(session_id: str) -> None:
    base = Path(settings.sandbox_sample_storage_path).resolve()
    # ``is_relative_to`` is true for the base itself, so an empty or traversing
    # session id would have deleted every stored sample rather than one session.
    cleaned = Path(str(session_id)).name.strip()
    if not cleaned or cleaned in {".", ".."}:
        return
    directory = (base / cleaned).resolve()
    if directory != base and directory.is_relative_to(base):
        shutil.rmtree(directory, ignore_errors=True)
