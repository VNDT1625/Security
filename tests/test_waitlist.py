from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.db import Base, get_db
from backend.models import ProductWaitlistEntry
from backend.routers.waitlist import router


def make_client() -> tuple[TestClient, sessionmaker]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    app = FastAPI()
    app.include_router(router)

    def override_db():
        with sessions() as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    return TestClient(app), sessions


def test_waitlist_persists_normalized_subscription_and_is_idempotent():
    client, sessions = make_client()
    payload = {"email": "  User@Example.COM ", "product": "windows"}

    first = client.post("/v1/waitlist", json=payload)
    duplicate = client.post("/v1/waitlist", json=payload)

    assert first.status_code == 200
    assert first.json() == {
        "email": "user@example.com",
        "product": "windows",
        "registered": True,
    }
    assert duplicate.status_code == 200
    assert duplicate.json()["registered"] is False
    with Session(sessions.kw["bind"]) as db:
        entries = db.execute(select(ProductWaitlistEntry)).scalars().all()
        assert len(entries) == 1


def test_waitlist_allows_one_email_to_follow_each_product():
    client, _ = make_client()
    for product in ("windows", "browser_extension"):
        response = client.post(
            "/v1/waitlist",
            json={"email": "person@example.com", "product": product},
        )
        assert response.status_code == 200
        assert response.json()["registered"] is True


def test_waitlist_rejects_invalid_email_and_product():
    client, _ = make_client()
    assert client.post(
        "/v1/waitlist", json={"email": "not-an-email", "product": "windows"}
    ).status_code == 422
    assert client.post(
        "/v1/waitlist", json={"email": "ok@example.com", "product": "mac"}
    ).status_code == 422
