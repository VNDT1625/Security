from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend.db import SessionLocal
from backend.main import app
from backend.models import ScanEvent, SystemSetting, User
from backend.routers import admin

client = TestClient(app)


def test_cors_preflight_allows_admin_setting_updates() -> None:
    response = client.options(
        "/admin/settings/ai-context-weight",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )

    assert response.status_code == 200
    assert "PUT" in response.headers["access-control-allow-methods"]


def test_spec_id_rejects_path_traversal() -> None:
    with pytest.raises(ValueError):
        admin.SpecExecutionRequest(specId="../../outside")


def test_training_data_must_be_inside_allowlisted_directory(tmp_path: Path) -> None:
    outside = tmp_path / "outside.csv"
    outside.write_text("text,label\nexample,0\n", encoding="utf-8")

    with pytest.raises(HTTPException) as exc:
        admin._training_data_file(str(outside))

    assert exc.value.status_code == 400


def test_admin_dependency_rejects_non_admin() -> None:
    class User:
        role = "user"

    class Auth:
        user = User()

    with pytest.raises(HTTPException) as exc:
        admin.require_admin(Auth())  # type: ignore[arg-type]

    assert exc.value.status_code == 403


def test_admin_overview_counts_current_high_risk_levels_and_scales_scores() -> None:
    event_ids = ["admin-overview-low", "admin-overview-high", "admin-overview-critical"]
    with SessionLocal() as db:
        db.query(ScanEvent).filter(ScanEvent.id.in_(event_ids)).delete(synchronize_session=False)
        before = admin.get_overview(db)
        for event_id, risk_level, score in (
            (event_ids[0], "low", 0.12),
            (event_ids[1], "high", 0.73),
            (event_ids[2], "critical", 0.99),
        ):
            db.add(ScanEvent(
                id=event_id,
                request_id=f"request-{event_id}",
                channel="test",
                modality="url",
                normalized_url=f"https://{event_id}.test",
                risk_score=score,
                risk_level=risk_level,
                decision="BLOCK" if risk_level != "low" else "ALLOW",
                confidence=0.9,
                model_version="test",
                latency_ms=10,
            ))
        db.commit()

        try:
            overview = admin.get_overview(db)
            assert overview["metrics"]["dangerousScans"] == before["metrics"]["dangerousScans"] + 2
            scores = {item["id"]: item["score"] for item in overview["recentScans"]}
            assert scores[event_ids[1]] == 73
            assert scores[event_ids[2]] == 99
        finally:
            db.query(ScanEvent).filter(ScanEvent.id.in_(event_ids)).delete(synchronize_session=False)
            db.commit()


def test_admin_api_requires_admin_session() -> None:
    assert client.get("/admin/specs").status_code == 401
    assert client.get("/admin/users").status_code == 401
    assert client.get("/admin/finance").status_code == 401

    # The public demo account intentionally remains a normal user.  Promote
    # it only inside this isolated authorization test.
    with SessionLocal() as db:
        demo = db.query(User).filter(User.email == "demo@aisec.local").one()
        demo.role = "admin"
        current_weight = db.get(SystemSetting, "ai_context_weight_percent")
        previous_weight = current_weight.value if current_weight is not None else None
        current_cache = db.get(SystemSetting, "url_assessment_cache_enabled")
        previous_cache = current_cache.value if current_cache is not None else None
        operational_keys = (
            "threat_feed_scheduler_enabled",
            "threat_feed_openphish_enabled",
            "operational_maintenance_scheduler_enabled",
        )
        previous_operations = {
            key: (db.get(SystemSetting, key).value if db.get(SystemSetting, key) else None)
            for key in operational_keys
        }
        if current_weight is not None:
            db.delete(current_weight)
        if current_cache is not None:
            db.delete(current_cache)
        db.commit()

    try:
        login = client.post(
            "/v1/auth/login",
            json={"email": "demo@aisec.local", "password": "Demo@123456"},
        )
        assert login.status_code == 200
        token = login.json()["token"]

        response = client.get("/admin/specs", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 200

        users = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
        assert users.status_code == 200
        assert any(item["email"] == "demo@aisec.local" for item in users.json()["users"])

        finance = client.get("/admin/finance", headers={"Authorization": f"Bearer {token}"})
        assert finance.status_code == 200
        assert "totalRevenueVnd" in finance.json()["summary"]

        current = client.get(
            "/admin/settings/ai-context-weight",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert current.status_code == 200
        assert current.json()["percent"] == 0

        updated = client.put(
            "/admin/settings/ai-context-weight",
            headers={"Authorization": f"Bearer {token}"},
            json={"percent": 40},
        )
        assert updated.status_code == 200
        assert updated.json()["percent"] == 40

        with SessionLocal() as db:
            assert db.get(SystemSetting, "ai_context_weight_percent").value == 40

        cache_current = client.get(
            "/admin/settings/url-assessment-cache",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert cache_current.status_code == 200
        cache_updated = client.put(
            "/admin/settings/url-assessment-cache",
            headers={"Authorization": f"Bearer {token}"},
            json={"enabled": False},
        )
        assert cache_updated.status_code == 200
        assert cache_updated.json()["enabled"] is False

        operations_current = client.get(
            "/admin/settings/operations",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert operations_current.status_code == 200
        operations_updated = client.put(
            "/admin/settings/operations",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "threatFeedSchedulerEnabled": True,
                "openphishEnabled": True,
                "operationalMaintenanceSchedulerEnabled": True,
            },
        )
        assert operations_updated.status_code == 200
        assert operations_updated.json()["openphishEnabled"] is True
    finally:
        with SessionLocal() as db:
            setting = db.get(SystemSetting, "ai_context_weight_percent")
            if previous_weight is None:
                if setting is not None:
                    db.delete(setting)
            elif setting is None:
                db.add(SystemSetting(key="ai_context_weight_percent", value=previous_weight))
            else:
                setting.value = previous_weight
            cache_setting = db.get(SystemSetting, "url_assessment_cache_enabled")
            if previous_cache is None:
                if cache_setting is not None:
                    db.delete(cache_setting)
            elif cache_setting is None:
                db.add(SystemSetting(key="url_assessment_cache_enabled", value=previous_cache))
            else:
                cache_setting.value = previous_cache
            for key, previous in previous_operations.items():
                operational_setting = db.get(SystemSetting, key)
                if previous is None:
                    if operational_setting is not None:
                        db.delete(operational_setting)
                elif operational_setting is None:
                    db.add(SystemSetting(key=key, value=previous))
                else:
                    operational_setting.value = previous
            db.commit()


def test_ai_context_weight_is_bounded_and_not_public() -> None:
    assert client.get("/admin/settings/ai-context-weight").status_code == 401
    assert client.get("/admin/settings/llm-provider").status_code == 401
    with pytest.raises(ValueError):
        admin.AIContextWeightRequest(percent=101)


def test_purge_url_cache_only_targets_url_entries() -> None:
    class Result:
        rowcount = 3

    class FakeDb:
        statement = None
        committed = False

        def execute(self, statement):
            self.statement = statement
            return Result()

        def commit(self):
            self.committed = True

    db = FakeDb()
    assert admin.purge_url_assessment_cache(db) == {"purged": 3}
    assert db.committed is True
    assert "assessment_cache.modality" in str(db.statement)


def test_training_request_accepts_only_one_model_per_dataset() -> None:
    with pytest.raises(ValueError):
        admin.ModelTrainingRequest(
            dataPath="data/demo_text_training.csv",
            models=["text", "url"],
        )
