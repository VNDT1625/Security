"""Observed redirect-chain checks for criteria 16 and 17."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlsplit

from ai.adapters.url_adapter import SHORTLINK_DOMAINS, parse_url_parts

RedirectStatus = Literal["clean", "suspicious", "not_checked"]


@dataclass(frozen=True)
class RedirectAssessment:
    status: RedirectStatus
    summary: str
    finding_type: str | None = None
    severity: float = 0.0
    quality: float = 0.0
    shortlink_expanded: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def assess_redirect_chain(
    initial_url: str,
    *,
    redirects: Iterable[object],
    final_url: str = "",
) -> RedirectAssessment:
    chain: list[dict[str, Any]] = []
    for item in redirects:
        if isinstance(item, Mapping):
            chain.append(dict(item))
        elif hasattr(item, "model_dump"):
            dumped = item.model_dump()
            if isinstance(dumped, dict):
                chain.append(dumped)
        elif hasattr(item, "to_url"):
            chain.append(
                {
                    "from_url": str(getattr(item, "from_url", "") or ""),
                    "to_url": str(getattr(item, "to_url", "") or ""),
                    "status_code": getattr(item, "status_code", None),
                }
            )
    initial = urlsplit(initial_url)
    initial_host = (initial.hostname or "").casefold()
    shortlink = initial_host in SHORTLINK_DOMAINS
    if not initial_host:
        return RedirectAssessment(
            status="not_checked",
            summary="The initial URL had no hostname for redirect comparison.",
        )
    if not chain:
        return RedirectAssessment(
            status="clean",
            summary="No HTTP redirect was observed.",
            shortlink_expanded=False,
            metadata={"redirect_count": 0},
        )

    targets = [str(item.get("to_url") or "") for item in chain]
    parsed_targets = [urlsplit(value) for value in targets]
    domains = []
    issues: list[str] = []
    previous_scheme = initial.scheme.casefold()
    for target in parsed_targets:
        scheme = target.scheme.casefold()
        host = (target.hostname or "").casefold()
        if scheme not in {"http", "https"} or not host:
            issues.append("unsupported_redirect_target")
            continue
        if previous_scheme == "https" and scheme == "http":
            issues.append("https_downgrade")
        if target.username or target.password:
            issues.append("credentials_in_redirect_target")
        if _is_ip(host) and not _is_ip(initial_host):
            issues.append("redirect_to_ip_literal")
        previous_scheme = scheme
        domains.append(parse_url_parts(target.geturl()).registrable_domain)
    distinct_domains = tuple(dict.fromkeys(domain for domain in domains if domain))
    if len(chain) > 5:
        issues.append("excessive_redirect_hops")
    if len(distinct_domains) >= 3:
        issues.append("multiple_cross_domain_hops")

    metadata = {
        "redirect_count": len(chain),
        "distinct_target_domains": list(distinct_domains),
        "final_url": final_url or targets[-1],
        "shortlink_expanded": shortlink,
        "issues": list(dict.fromkeys(issues)),
    }
    if issues:
        return RedirectAssessment(
            status="suspicious",
            summary="Observed redirect chain contains unsafe routing behavior.",
            finding_type="observed_redirect_anomaly",
            severity=0.7,
            quality=1.0,
            shortlink_expanded=shortlink,
            metadata=metadata,
        )
    return RedirectAssessment(
        status="clean",
        summary="Observed redirects completed without an unsafe routing pattern.",
        shortlink_expanded=shortlink,
        quality=1.0,
        metadata=metadata,
    )
