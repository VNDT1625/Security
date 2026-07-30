"""Bounded, decaying session-risk tracker with no raw sensitive payload storage."""

from __future__ import annotations

import hashlib
import math
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from .action_config import ActionRiskConfig
from .action_types import EvidenceCategory, SessionRiskResult


@dataclass
class _SessionEvent:
    observed_at: float
    categories: frozenset[EvidenceCategory]
    external_sensitive_transfer: bool
    workflow_approved: bool


@dataclass
class _SessionState:
    updated_at: float
    cumulative_risk: float = 0.0
    events: list[_SessionEvent] = field(default_factory=list)


class SessionRiskTracker:
    def __init__(
        self,
        config: ActionRiskConfig,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config
        self._clock = clock
        self._states: dict[str, _SessionState] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(session_id: str) -> str:
        return hashlib.sha256(session_id.encode("utf-8", errors="ignore")).hexdigest()

    def assess_and_record(
        self,
        session_id: str | None,
        categories: set[EvidenceCategory],
        current_rule_score: float,
        *,
        external_sensitive_transfer: bool,
        workflow_approved: bool,
    ) -> SessionRiskResult:
        if not session_id:
            return SessionRiskResult(None, 0.0, 0.0, 0, False, False, 0)
        now = self._clock()
        key = self._key(session_id)
        with self._lock:
            state = self._states.get(key)
            if state is None:
                state = _SessionState(updated_at=now)
                self._states[key] = state
            elapsed = max(0.0, now - state.updated_at)
            decay = math.pow(0.5, elapsed / self.config.session_half_life_seconds)
            state.cumulative_risk *= decay
            state.updated_at = now

            cutoff = now - self.config.session_half_life_seconds * 4
            state.events = [
                event for event in state.events if event.observed_at >= cutoff
            ][-self.config.session_history_limit :]
            prior_categories = {
                category for event in state.events for category in event.categories
            }
            repeated_access_count = sum(
                bool(
                    event.categories
                    & {
                        EvidenceCategory.CREDENTIAL_ACCESS,
                        EvidenceCategory.SENSITIVE_DATA_ACCESS,
                    }
                )
                for event in state.events
            )
            transfer_count = sum(
                event.external_sensitive_transfer
                for event in state.events
            )
            if categories & {
                EvidenceCategory.CREDENTIAL_ACCESS,
                EvidenceCategory.SENSITIVE_DATA_ACCESS,
            }:
                repeated_access_count += 1
            if external_sensitive_transfer:
                transfer_count += 1

            slow_exfiltration = (
                transfer_count >= self.config.slow_exfiltration_count
            )
            multi_step_attack = (
                external_sensitive_transfer
                and bool(
                    prior_categories
                    & {
                        EvidenceCategory.CREDENTIAL_ACCESS,
                        EvidenceCategory.SENSITIVE_DATA_ACCESS,
                    }
                )
            )
            increment = min(15.0, max(0.0, current_rule_score) * 0.15)
            if workflow_approved:
                increment *= self.config.workflow_approval_discount
            if slow_exfiltration:
                increment += 22.0
            if multi_step_attack:
                increment += 18.0
            state.cumulative_risk = min(
                self.config.session_max_risk,
                state.cumulative_risk + increment,
            )
            contribution = min(
                self.config.session_max_contribution,
                state.cumulative_risk * 0.30,
            )
            state.events.append(
                _SessionEvent(
                    observed_at=now,
                    categories=frozenset(categories),
                    external_sensitive_transfer=external_sensitive_transfer,
                    workflow_approved=workflow_approved,
                )
            )
            state.events = state.events[-self.config.session_history_limit :]
            return SessionRiskResult(
                session_id_hash=key[:16],
                cumulative_risk=round(state.cumulative_risk, 4),
                contribution=round(contribution, 4),
                repeated_access_count=repeated_access_count,
                slow_exfiltration=slow_exfiltration,
                multi_step_attack=multi_step_attack,
                action_count=len(state.events),
            )

    def clear(self) -> None:
        with self._lock:
            self._states.clear()
