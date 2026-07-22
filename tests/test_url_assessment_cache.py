from datetime import timedelta
from types import SimpleNamespace

from backend.db import SessionLocal
from backend.demo import routes as demo_routes
from backend.demo.models import (
    AIDetection,
    TraditionalDetection,
    URLAnalysisRequest,
    URLAnalysisResponse,
)
from backend.models import AssessmentCache
from backend.routers import assess as assess_router
from backend.routers.assess import (
    _cached_url_result,
    _store_url_result,
    _url_cache_key,
)
from backend.security_utils import utcnow
from shared.schemas import AssessResponse, Decision, Modality, RiskLevel


def _result(score: float) -> AssessResponse:
    return AssessResponse(
        risk_score=score,
        risk_level=RiskLevel.LOW,
        decision=Decision.ALLOW,
        confidence=0.5,
        modality=Modality.URL,
    )


def test_url_cache_toggle_controls_read_and_write() -> None:
    url = "https://cache-toggle.example.test/path"
    namespace = "test-cache-toggle"
    with SessionLocal() as db:
        _store_url_result(
            db, url, _result(0.2), cache_namespace=namespace, enabled=False
        )
        db.commit()
        assert _cached_url_result(db, url, cache_namespace=namespace, enabled=False) is None

        _store_url_result(
            db, url, _result(0.2), cache_namespace=namespace, enabled=True
        )
        db.commit()
        cached = _cached_url_result(db, url, cache_namespace=namespace, enabled=True)
        assert cached is not None
        assert cached.risk_score == 0.2
        assert cached.cache_hit is True
        assert cached.cache_status == "hit"
        assert _cached_url_result(db, url, cache_namespace=namespace, enabled=False) is None

        key = _url_cache_key(url, cache_namespace=namespace)
        entry = db.get(AssessmentCache, key)
        entry.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
        assert _cached_url_result(db, url, cache_namespace=namespace, enabled=True) is None
        db.delete(entry)
        db.commit()


def test_standard_url_cache_hit_skips_scan_quota(monkeypatch) -> None:
    cached = _result(0.2)
    cached.cache_status = "miss"
    service = SimpleNamespace(adapter_cache_token="test-adapter")

    monkeypatch.setattr(
        assess_router,
        "resolve_actor",
        lambda *_: SimpleNamespace(user=None),
    )
    monkeypatch.setattr(
        assess_router,
        "get_user_inference_service",
        lambda *_: service,
    )
    monkeypatch.setattr(assess_router, "require_api_key_scope", lambda *_: None)
    monkeypatch.setattr(
        assess_router,
        "build_actor_plan_info",
        lambda *_: SimpleNamespace(autoWebContext=False, tier="free"),
    )
    monkeypatch.setattr(
        assess_router, "get_effective_ai_context_weight_percent", lambda *_, **__: 0
    )
    monkeypatch.setattr(assess_router, "get_url_assessment_cache_enabled", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(assess_router, "_cached_url_result", lambda *_args, **_kwargs: cached)
    monkeypatch.setattr(assess_router, "log_assessment", lambda *_args, **_kwargs: None)

    def quota_must_not_run(*_args, **_kwargs):
        raise AssertionError("a URL cache hit must not reserve scan quota")

    monkeypatch.setattr(assess_router, "reserve_scan_quota", quota_must_not_run)
    result = assess_router.assess_url(
        assess_router.AssessURLRequest(url="https://cache-hit.example.test"),
        request=object(),
        credentials=object(),
        db=object(),
        svc=service,
    )
    assert result is cached


def test_demo_url_cache_hit_skips_scan_quota(monkeypatch) -> None:
    service = SimpleNamespace(adapter_cache_token="test-adapter")
    cached = URLAnalysisResponse(
        url="https://cache-hit.example.test",
        risk_score=2,
        threat_level="safe",
        analysis_time_ms=0,
        traditional_detection=TraditionalDetection(detected=False),
        ai_detection=AIDetection(detected=False, confidence=0.5),
        cache_hit=True,
        cache_status="hit",
    )
    monkeypatch.setattr(
        demo_routes,
        "resolve_actor",
        lambda *_: SimpleNamespace(user=None),
    )
    monkeypatch.setattr(
        demo_routes,
        "get_user_inference_service",
        lambda *_: service,
    )
    monkeypatch.setattr(
        demo_routes,
        "build_actor_plan_info",
        lambda *_: SimpleNamespace(autoWebContext=False, tier="free"),
    )
    monkeypatch.setattr(demo_routes, "_validate_url", lambda *_: None)
    monkeypatch.setattr(
        demo_routes, "get_effective_ai_context_weight_percent", lambda *_, **__: 0
    )
    monkeypatch.setattr(demo_routes, "get_url_assessment_cache_enabled", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(demo_routes, "_load_demo_url_cache", lambda *_: cached)

    def quota_must_not_run(*_args, **_kwargs):
        raise AssertionError("a demo URL cache hit must not reserve scan quota")

    monkeypatch.setattr(demo_routes, "reserve_scan_quota", quota_must_not_run)
    response = __import__("asyncio").run(
        demo_routes.analyze_url(
            URLAnalysisRequest(url="https://cache-hit.example.test"),
            request=object(),
            credentials=object(),
            db=object(),
        )
    )
    assert response is cached
