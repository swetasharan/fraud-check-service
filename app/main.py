"""Fraud-check API for banking transactions.

Run locally with:
    uvicorn app.main:app --reload

Then POST a transaction to /transactions/check.
"""

from fastapi import FastAPI, HTTPException

from app.models import FraudCheckResult, Transaction
from app.rules import score_transaction
from app.store import store

app = FastAPI(
    title="Fraud Check Service",
    description="Rule-based fraud detection for banking transactions.",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/transactions/check", response_model=FraudCheckResult)
def check_transaction(transaction: Transaction) -> FraudCheckResult:
    """Score a transaction for fraud risk and record it in account history.

    Subsequent calls for the same account_id take prior transactions into
    account (velocity, new country/merchant, impossible travel, etc.).
    """
    history = store.get_history(transaction.account_id)
    result = score_transaction(transaction, history)
    store.add(transaction)
    return result


@app.get("/accounts/{account_id}/history", response_model=list[Transaction])
def get_history(account_id: str) -> list[Transaction]:
    return store.get_history(account_id)


@app.delete("/accounts/{account_id}/history")
def clear_history(account_id: str) -> dict[str, str]:
    if not store.clear_account(account_id):
        raise HTTPException(status_code=404, detail="No history for this account")
    return {"status": "cleared"}
