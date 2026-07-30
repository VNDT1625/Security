"""Bounded collectors and local lookup for public URL threat feeds."""
from __future__ import annotations

import bz2
import csv
import io
import logging
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from sqlalchemy import delete, func, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.config import settings
from backend.db import SessionLocal
from backend.models import ThreatFeedIndicator, ThreatFeedSyncState
from backend.security_utils import utcnow
from security.risk_core.normalization import make_finding_key, make_incident_key, normalize_url
from security.risk_core.types import (
    CriterionStatus,
    EvidenceV2,
    MatchedSubject,
    ProviderVerdict,
)
from shared.net_guard import SSRFBlocked, assert_global_target

logger = logging.getLogger(__name__)

PHISHING_DATABASE_SOURCE = "phishing_database"

OFFICIAL_FEED_HOSTS = {
    "data.phishtank.com",
    "raw.githubusercontent.com",
    "urlhaus-api.abuse.ch",
}
REMOTE_FEED_SOURCES = frozenset({"phishtank", "openphish", "urlhaus"})
_MAX_FEED_REDIRECTS = 3


@dataclass(frozen=True)
class FeedSpec:
    source: str
    url: str
    parser: str
    enabled: bool
    min_interval: timedelta


@dataclass(frozen=True)
class FeedRecord:
    url: str
    source_ref: str = ""
    first_seen_at: datetime | None = None
    tags: tuple[str, ...] = ()
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class FeedSyncResult:
    source: str
    status: str
    records_seen: int = 0
    records_upserted: int = 0
    error: str = ""


def _naive_utc(value: datetime | None) -> datetime:
    if value is None:
        return utcnow()
    if value.tzinfo is not None:
        value = value.astimezone(UTC).replace(tzinfo=None)
    return value


def _parse_datetime(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return _naive_utc(datetime.fromisoformat(text.replace("Z", "+00:00")))
    except ValueError:
        return None


def _bounded_decompress(payload: bytes, decompressor: object, limit: int) -> bytes:
    """Decompress incrementally and abort once the output exceeds ``limit``.

    ``gzip.decompress`` and ``bz2.decompress`` have no output bound, so a 64 MiB
    archive of zero bytes expands to tens of gigabytes and kills the process that
    the scheduler shares with the API.
    """
    out = bytearray()
    chunk_size = 1 << 20
    for offset in range(0, len(payload), chunk_size):
        out.extend(
            decompressor.decompress(  # type: ignore[attr-defined]
                payload[offset : offset + chunk_size], limit - len(out) + 1
            )
        )
        if len(out) > limit:
            raise ValueError(
                f"Threat feed expanded beyond the {limit} byte decompression limit"
            )
    return bytes(out)


def _decode_payload(payload: bytes) -> str:
    limit = max(1, int(settings.threat_feed_max_decompressed_bytes))
    if payload.startswith(b"\x1f\x8b"):
        payload = _bounded_decompress(
            payload, zlib.decompressobj(16 + zlib.MAX_WBITS), limit
        )
    elif payload.startswith(b"BZh"):
        payload = _bounded_decompress(payload, bz2.BZ2Decompressor(), limit)
    return payload.decode("utf-8-sig", errors="replace")


def parse_phishtank(payload: bytes, limit: int) -> list[FeedRecord]:
    reader = csv.DictReader(io.StringIO(_decode_payload(payload)))
    records: list[FeedRecord] = []
    for row in reader:
        url = str(row.get("url") or "").strip()
        if not url:
            continue
        records.append(
            FeedRecord(
                url=url,
                source_ref=str(row.get("phish_id") or "")[:160],
                first_seen_at=_parse_datetime(row.get("submission_time")),
                tags=("phishing", str(row.get("target") or "unknown")[:80]),
                metadata={
                    "verified": str(row.get("verified") or "").lower() == "yes",
                    "online": str(row.get("online") or "").lower() == "yes",
                    "target": str(row.get("target") or "")[:160],
                },
            )
        )
        if len(records) >= limit:
            break
    return records


def parse_openphish(payload: bytes, limit: int) -> list[FeedRecord]:
    records: list[FeedRecord] = []
    for token in _decode_payload(payload).split():
        url = token.strip()
        if not url.startswith(("http://", "https://")):
            continue
        records.append(FeedRecord(url=url, tags=("phishing", "openphish-community")))
        if len(records) >= limit:
            break
    return records


def parse_urlhaus(payload: bytes, limit: int) -> list[FeedRecord]:
    lines = _decode_payload(payload).splitlines()
    header_index = next(
        (
            index
            for index, line in enumerate(lines)
            if "," in line and "url" in line.lower() and "dateadded" in line.lower()
        ),
        -1,
    )
    if header_index < 0:
        return []
    normalized = [lines[header_index].lstrip("# "), *lines[header_index + 1 :]]
    reader = csv.DictReader(io.StringIO("\n".join(normalized)))
    records: list[FeedRecord] = []
    for row in reader:
        url = str(row.get("url") or "").strip()
        if not url:
            continue
        tags = tuple(
            tag.strip()[:80]
            for tag in str(row.get("tags") or "malware").split(",")
            if tag.strip()
        )
        records.append(
            FeedRecord(
                url=url,
                source_ref=str(row.get("id") or row.get("urlhaus_link") or "")[:160],
                first_seen_at=_parse_datetime(row.get("dateadded")),
                tags=("malware", *tags),
                metadata={
                    "url_status": str(row.get("url_status") or "")[:32],
                    "threat": str(row.get("threat") or "malware_download")[:80],
                },
            )
        )
        if len(records) >= limit:
            break
    return records


def parse_phishing_database_repository(
    repository: str | Path,
    limit: int,
) -> list[FeedRecord]:
    """Read the repository's current-active URL shards without loading history.

    The upstream root ``phishing-links-ACTIVE.txt`` contains a much larger
    historical aggregate.  Its manifest-backed ``phishing-links-ACTIVE``
    directory is the current actively revalidated feed advertised by upstream.
    """

    root = Path(repository).expanduser().resolve()
    active_dir = (root / "phishing-links-ACTIVE").resolve()
    manifest = active_dir / "phishing-links-ACTIVE.manifest.txt"
    if not root.is_dir():
        raise ValueError(f"Phishing.Database repository not found: {root}")

    paths: list[Path] = []
    if manifest.is_file():
        for raw_name in manifest.read_text(encoding="utf-8-sig", errors="replace").splitlines():
            name = raw_name.strip()
            if not name or name.startswith("#"):
                continue
            candidate = (active_dir / name).resolve()
            if candidate.is_relative_to(active_dir) and candidate.is_file() and candidate not in paths:
                paths.append(candidate)
    else:
        fallback = root / "phishing-links-ACTIVE.txt"
        if fallback.is_file():
            paths.append(fallback.resolve())
    if not paths:
        raise ValueError("No active Phishing.Database URL feed was found")

    records: list[FeedRecord] = []
    seen: set[str] = set()
    for path in paths:
        with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            for raw_line in handle:
                url = raw_line.strip()
                if (
                    not url
                    or url.startswith(("#", "!"))
                    or not url.startswith(("http://", "https://"))
                    or url in seen
                ):
                    continue
                seen.add(url)
                records.append(
                    FeedRecord(
                        url=url,
                        tags=("phishing", "phishing-database", "active"),
                        metadata={
                            "repository": "Phishing-Database/Phishing.Database",
                            "feed": "phishing-links-ACTIVE",
                        },
                    )
                )
                if len(records) >= limit:
                    return records
    return records


PARSERS = {
    "phishtank": parse_phishtank,
    "openphish": parse_openphish,
    "urlhaus": parse_urlhaus,
}


def configured_feed_specs(
    *, openphish_enabled: bool | None = None
) -> tuple[FeedSpec, ...]:
    phishtank_url = settings.threat_feed_phishtank_url
    if settings.threat_feed_phishtank_app_key and "{app_key}" in phishtank_url:
        phishtank_url = phishtank_url.format(app_key=settings.threat_feed_phishtank_app_key)
    elif settings.threat_feed_phishtank_app_key and phishtank_url.endswith(
        "/online-valid.csv.gz"
    ):
        phishtank_url = (
            "https://data.phishtank.com/data/"
            f"{settings.threat_feed_phishtank_app_key}/online-valid.csv.gz"
        )
    urlhaus_url = settings.threat_feed_urlhaus_url.replace(
        "{auth_key}", settings.threat_feed_urlhaus_auth_key
    )
    return (
        FeedSpec(
            "phishtank",
            phishtank_url,
            "phishtank",
            settings.threat_feed_phishtank_enabled,
            timedelta(hours=1),
        ),
        FeedSpec(
            "openphish",
            settings.threat_feed_openphish_url,
            "openphish",
            settings.threat_feed_openphish_enabled
            if openphish_enabled is None
            else openphish_enabled,
            timedelta(hours=max(1, settings.threat_feed_openphish_interval_hours)),
        ),
        FeedSpec(
            "urlhaus",
            urlhaus_url,
            "urlhaus",
            settings.threat_feed_urlhaus_enabled
            and bool(settings.threat_feed_urlhaus_auth_key),
            timedelta(hours=1),
        ),
    )


def _configured_feed_specs_for_runtime(
    openphish_enabled: bool | None,
) -> tuple[FeedSpec, ...]:
    """Keep callers and integrations using the legacy no-argument factory working."""

    if openphish_enabled is None:
        return configured_feed_specs()
    return configured_feed_specs(openphish_enabled=openphish_enabled)


def _validate_feed_url(url: str, source: str) -> None:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not host:
        raise ValueError(f"Invalid {source} feed URL")
    if parsed.scheme != "https":
        raise ValueError("Threat-feed endpoints must use HTTPS")
    if not settings.threat_feed_allow_custom_endpoints and host not in OFFICIAL_FEED_HOSTS:
        raise ValueError(f"Unapproved threat-feed host: {host}")
    # Even an approved host must not resolve into private space; a hijacked or
    # rebinding DNS answer would otherwise turn the collector into an SSRF probe.
    try:
        assert_global_target(url)
    except SSRFBlocked as exc:
        raise ValueError(f"{source} feed host resolves to a non-public address") from exc


def _validate_endpoint(spec: FeedSpec) -> None:
    _validate_feed_url(spec.url, spec.source)


def _safe_endpoint(url: str) -> str:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.hostname or ''}"


def _download(spec: FeedSpec, state: ThreatFeedSyncState | None) -> tuple[bytes | None, dict]:
    _validate_endpoint(spec)
    headers = {"User-Agent": settings.threat_feed_user_agent}
    if state is not None and state.etag:
        headers["If-None-Match"] = state.etag
    if state is not None and state.last_modified:
        headers["If-Modified-Since"] = state.last_modified
    # Redirects are followed manually so every hop is re-validated. With
    # follow_redirects=True httpx silently leaves the approved host list, and a
    # 302 from an allowlisted host (raw.githubusercontent.com is one) to
    # http://169.254.169.254/... would be fetched and parsed as a feed.
    target = spec.url
    with httpx.Client(
        follow_redirects=False,
        timeout=settings.threat_feed_request_timeout_seconds,
        headers=headers,
    ) as client:
        for _hop in range(_MAX_FEED_REDIRECTS + 1):
            with client.stream("GET", target) as response:
                if response.status_code == 304:
                    return None, dict(response.headers)
                if response.is_redirect:
                    location = response.headers.get("location", "")
                    if not location:
                        raise ValueError(f"{spec.source} feed redirect had no Location")
                    target = str(httpx.URL(target).join(location))
                    _validate_feed_url(target, spec.source)
                    continue
                response.raise_for_status()
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > settings.threat_feed_max_download_bytes:
                        raise ValueError(f"{spec.source} feed exceeded download limit")
                    chunks.append(chunk)
                return b"".join(chunks), dict(response.headers)
    raise ValueError(f"{spec.source} feed exceeded {_MAX_FEED_REDIRECTS} redirects")


def _upsert_records(
    db: Session,
    source: str,
    records: list[FeedRecord],
    *,
    observed_at: datetime | None = None,
) -> int:
    now = _naive_utc(observed_at)
    expires_at = now + timedelta(days=settings.threat_feed_retention_days)
    normalized: dict[str, tuple[FeedRecord, object]] = {}
    for record in records:
        try:
            keys = normalize_url(record.url)
        except (TypeError, ValueError):
            continue
        if not keys.normalized_url.startswith(("http://", "https://")):
            continue
        normalized[keys.exact_subject_key] = (record, keys)

    changed = 0
    items = list(normalized.items())
    for offset in range(0, len(items), 400):
        chunk = items[offset : offset + 400]
        hashes = [item[0] for item in chunk]
        existing = {
            row.exact_url_key: row
            for row in db.execute(
                select(ThreatFeedIndicator).where(
                    ThreatFeedIndicator.source == source,
                    ThreatFeedIndicator.exact_url_key.in_(hashes),
                )
            ).scalars()
        }
        for exact_key, (record, keys) in chunk:
            row = existing.get(exact_key)
            if row is None:
                row = ThreatFeedIndicator(
                    source=source,
                    source_ref=record.source_ref or None,
                    normalized_value=keys.normalized_url,
                    exact_url_key=keys.exact_subject_key,
                    campaign_key=keys.campaign_subject_key,
                    registrable_domain=keys.registrable_domain_key,
                    first_seen_at=_naive_utc(record.first_seen_at),
                    last_seen_at=now,
                    expires_at=expires_at,
                )
                db.add(row)
            row.source_ref = record.source_ref or row.source_ref
            row.tags = list(dict.fromkeys(record.tags))[:20]
            row.extra_metadata = dict(record.metadata)
            row.last_seen_at = now
            row.expires_at = expires_at
            changed += 1
        db.commit()
    return changed


def import_phishing_database(
    repository: str | Path | None = None,
    *,
    limit: int | None = None,
) -> FeedSyncResult:
    """Import the cloned current-active Phishing.Database snapshot idempotently."""

    source = PHISHING_DATABASE_SOURCE
    repository = repository or settings.threat_feed_phishing_database_path
    maximum = limit if limit is not None else settings.threat_feed_max_records_per_source
    if maximum <= 0:
        raise ValueError("Phishing.Database import limit must be positive")
    observed_at = utcnow()
    records = parse_phishing_database_repository(repository, maximum)
    if not records:
        raise ValueError("Phishing.Database active feed contains no supported HTTP(S) URLs")

    with SessionLocal() as db:
        upserted = _upsert_records(
            db,
            source,
            records,
            observed_at=observed_at,
        )
        state = db.get(ThreatFeedSyncState, source)
        if state is None:
            state = ThreatFeedSyncState(
                source=source,
                endpoint="local://Phishing.Database/phishing-links-ACTIVE",
            )
            db.add(state)
        state.status = "completed"
        state.last_attempt_at = observed_at
        state.last_success_at = observed_at
        state.records_seen = len(records)
        state.records_upserted = upserted
        state.error = None
        db.commit()
    return FeedSyncResult(source, "completed", len(records), upserted)


def sync_feed(spec: FeedSpec, *, force: bool = False) -> FeedSyncResult:
    if not spec.enabled:
        return FeedSyncResult(spec.source, "disabled")
    now = utcnow()
    with SessionLocal() as db:
        state = db.get(ThreatFeedSyncState, spec.source)
        if state is not None and state.next_allowed_at and state.next_allowed_at > now and not force:
            return FeedSyncResult(spec.source, "not_due", state.records_seen, 0)
        etag = state.etag if state is not None else None
        last_modified = state.last_modified if state is not None else None
        state_snapshot = None
        if state is not None:
            state_snapshot = ThreatFeedSyncState(
                source=state.source,
                endpoint=state.endpoint,
                etag=etag,
                last_modified=last_modified,
            )

    try:
        payload, headers = _download(spec, state_snapshot)
        records = [] if payload is None else PARSERS[spec.parser](
            payload, settings.threat_feed_max_records_per_source
        )
        with SessionLocal() as db:
            state = db.get(ThreatFeedSyncState, spec.source)
            if state is None:
                state = ThreatFeedSyncState(source=spec.source, endpoint=_safe_endpoint(spec.url))
                db.add(state)
            state.last_attempt_at = now
            state.next_allowed_at = now + spec.min_interval
            state.etag = headers.get("etag") or state.etag
            state.last_modified = headers.get("last-modified") or state.last_modified
            if payload is None:
                state.status = "not_modified"
                state.last_success_at = now
                state.error = None
                db.commit()
                return FeedSyncResult(spec.source, "not_modified", state.records_seen, 0)
            upserted = _upsert_records(db, spec.source, records)
            state = db.get(ThreatFeedSyncState, spec.source)
            state.status = "completed"
            state.last_success_at = now
            state.records_seen = len(records)
            state.records_upserted = upserted
            state.error = None
            db.commit()
        return FeedSyncResult(spec.source, "completed", len(records), upserted)
    except Exception as exc:
        logger.warning("Threat feed %s sync failed: %s", spec.source, exc)
        with SessionLocal() as db:
            state = db.get(ThreatFeedSyncState, spec.source)
            if state is None:
                state = ThreatFeedSyncState(source=spec.source, endpoint=_safe_endpoint(spec.url))
                db.add(state)
            state.status = "failed"
            state.last_attempt_at = now
            state.next_allowed_at = now + spec.min_interval
            state.error = f"{type(exc).__name__}: {exc}"[:1000]
            db.commit()
        return FeedSyncResult(spec.source, "failed", error=f"{type(exc).__name__}: {exc}")


def sync_all_feeds(
    *, force: bool = False, openphish_enabled: bool | None = None
) -> list[FeedSyncResult]:
    results = [
        sync_feed(spec, force=force)
        for spec in _configured_feed_specs_for_runtime(openphish_enabled)
    ]
    with SessionLocal() as db:
        db.execute(delete(ThreatFeedIndicator).where(ThreatFeedIndicator.expires_at <= utcnow()))
        db.commit()
    return results


def sync_configured_feeds(
    sources: tuple[str, ...] | None = None,
    *,
    openphish_enabled: bool | None = None,
) -> list[FeedSyncResult]:
    """Refresh only configured remote feeds without bypassing source rate limits.

    This is the safe entry point for an administrator-triggered refresh.  It
    intentionally does not expose a ``force`` parameter: repeated requests
    still honour each provider's configured minimum interval and source URLs
    always come from server-side settings.
    """

    configured = {
        spec.source: spec
        for spec in _configured_feed_specs_for_runtime(openphish_enabled)
    }
    selected = tuple(sources) if sources is not None else tuple(configured)
    unknown = set(selected) - REMOTE_FEED_SOURCES
    if unknown:
        raise ValueError(f"Unsupported threat-feed source: {sorted(unknown)[0]}")
    if len(set(selected)) != len(selected):
        raise ValueError("Duplicate threat-feed sources are not allowed")

    results = [sync_feed(configured[source], force=False) for source in selected]
    with SessionLocal() as db:
        db.execute(delete(ThreatFeedIndicator).where(ThreatFeedIndicator.expires_at <= utcnow()))
        db.commit()
    return results


def feed_status(
    db: Session, *, openphish_enabled: bool | None = None
) -> list[dict[str, object]]:
    configured = {
        spec.source: spec
        for spec in _configured_feed_specs_for_runtime(openphish_enabled)
    }
    states = {row.source: row for row in db.execute(select(ThreatFeedSyncState)).scalars()}
    output = []
    for source, spec in configured.items():
        state = states.get(source)
        count = db.execute(
            select(func.count(ThreatFeedIndicator.id)).where(
                ThreatFeedIndicator.source == source,
                ThreatFeedIndicator.expires_at > utcnow(),
            )
        ).scalar_one()
        last_success = state.last_success_at if state else None
        stale_after = spec.min_interval * 2
        if not spec.enabled:
            health = "disabled"
        elif state is None or last_success is None:
            health = "pending"
        elif state.status == "failed":
            health = "failed"
        elif last_success < utcnow() - stale_after:
            health = "stale"
        else:
            health = "healthy"
        output.append(
            {
                "source": source,
                "enabled": spec.enabled,
                "status": state.status if state else "never",
                "health": health,
                "active_indicators": int(count),
                "last_success_at": state.last_success_at.isoformat() if state and state.last_success_at else None,
                "next_allowed_at": state.next_allowed_at.isoformat() if state and state.next_allowed_at else None,
                "records_seen": state.records_seen if state else 0,
                "records_upserted": state.records_upserted if state else 0,
                "error": state.error if state else None,
            }
        )
    for source, state in sorted(states.items()):
        if source in configured:
            continue
        count = db.execute(
            select(func.count(ThreatFeedIndicator.id)).where(
                ThreatFeedIndicator.source == source,
                ThreatFeedIndicator.expires_at > utcnow(),
            )
        ).scalar_one()
        output.append(
            {
                "source": source,
                "enabled": True,
                "status": state.status,
                "health": "failed" if state.status == "failed" else "retired",
                "active_indicators": int(count),
                "last_success_at": (
                    state.last_success_at.isoformat() if state.last_success_at else None
                ),
                "next_allowed_at": None,
                "records_seen": state.records_seen,
                "records_upserted": state.records_upserted,
                "error": state.error,
            }
        )
    return output


def collect_local_threat_feed_evidence(url: str) -> list[EvidenceV2]:
    try:
        keys = normalize_url(url)
        now = utcnow()
        with SessionLocal() as db:
            rows = list(
                db.execute(
                    select(ThreatFeedIndicator)
                    .where(
                        ThreatFeedIndicator.expires_at > now,
                        or_(
                            ThreatFeedIndicator.exact_url_key == keys.exact_subject_key,
                            ThreatFeedIndicator.campaign_key == keys.campaign_subject_key,
                        ),
                    )
                    .limit(20)
                ).scalars()
            )
    except (SQLAlchemyError, TypeError, ValueError) as exc:
        logger.warning("Local threat-feed lookup unavailable: %s", exc)
        return []
    evidence: list[EvidenceV2] = []
    for row in rows:
        exact = row.exact_url_key == keys.exact_subject_key
        campaign = row.campaign_key == keys.campaign_subject_key
        if not (exact or campaign):
            continue
        finding_type = "local_feed_exact_url"
        evidence.append(
            EvidenceV2(
                evidence_id=f"local-feed-{row.source}-{row.id}",
                exact_subject_key=keys.exact_subject_key,
                campaign_subject_key=keys.campaign_subject_key,
                finding_key=make_finding_key(keys.exact_subject_key, finding_type, row.source),
                incident_key=make_incident_key(keys.campaign_subject_key, "threat_feed", "active"),
                criterion_id=11,
                source_id=f"local_{row.source}",
                organization_id=row.source,
                source_family="local_threat_feed",
                feed_lineage=(row.source,),
                matched_subject=MatchedSubject.EXACT_URL,
                finding_type=finding_type,
                status=CriterionStatus.MALICIOUS,
                provider_verdict=ProviderVerdict.MALICIOUS,
                severity=0.99,
                evidence_quality=0.98,
                match_strength=1.0,
                authority_tier=3,
                observed_at=row.last_seen_at.replace(tzinfo=UTC).isoformat(),
                metadata={
                    "summary": f"Exact URL matched the active local {row.source} feed.",
                    "source_ref": row.source_ref,
                    "tags": row.tags,
                    "local_lookup": True,
                },
            )
        )
    return evidence
