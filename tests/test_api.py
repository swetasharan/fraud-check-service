from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.store import store

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_store():
    store.clear()
    yield
    store.clear()


def make_tx(**overrides) -> dict:
    tx = {
        "transaction_id": "tx-1",
        "account_id": "acct-1",
        "card_id": "card-1",
        "amount": 50.0,
        "currency": "USD",
        "merchant": "Corner Cafe",
        "merchant_category": "groceries",
        "country": "US",
        "card_present": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    tx.update(overrides)
    return tx


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_low_risk_transaction_not_flagged():
    resp = client.post("/transactions/check", json=make_tx())
    assert resp.status_code == 200
    body = resp.json()
    assert body["is_fraud"] is False
    assert body["risk_level"] == "low"


def test_high_amount_flagged():
    resp = client.post("/transactions/check", json=make_tx(transaction_id="tx-2", amount=15000))
    body = resp.json()
    assert body["risk_score"] >= 40
    assert any("exceeds" in r for r in body["reasons"])


def test_velocity_triggers_after_several_rapid_transactions():
    now = datetime.now(timezone.utc)
    for i in range(3):
        client.post(
            "/transactions/check",
            json=make_tx(transaction_id=f"tx-{i}", timestamp=(now + timedelta(minutes=i)).isoformat()),
        )
    resp = client.post(
        "/transactions/check",
        json=make_tx(transaction_id="tx-final", timestamp=(now + timedelta(minutes=4)).isoformat()),
    )
    body = resp.json()
    assert any("transactions within" in r for r in body["reasons"])


def test_impossible_travel_flagged():
    now = datetime.now(timezone.utc)
    client.post(
        "/transactions/check",
        json=make_tx(transaction_id="tx-a", country="US", timestamp=now.isoformat()),
    )
    resp = client.post(
        "/transactions/check",
        json=make_tx(
            transaction_id="tx-b",
            country="FR",
            timestamp=(now + timedelta(minutes=30)).isoformat(),
        ),
    )
    body = resp.json()
    assert body["is_fraud"] is True
    assert any("impossible travel" in r for r in body["reasons"])


def test_combined_signals_flag_as_fraud():
    resp = client.post(
        "/transactions/check",
        json=make_tx(
            transaction_id="tx-big",
            amount=20000,
            merchant_category="gambling",
            card_present=False,
        ),
    )
    body = resp.json()
    assert body["is_fraud"] is True
    assert body["risk_level"] == "high"


def test_history_endpoints():
    client.post("/transactions/check", json=make_tx())
    resp = client.get("/accounts/acct-1/history")
    assert resp.status_code == 200
    assert len(resp.json()) == 1

    resp = client.delete("/accounts/acct-1/history")
    assert resp.status_code == 200

    resp = client.delete("/accounts/acct-1/history")
    assert resp.status_code == 404
