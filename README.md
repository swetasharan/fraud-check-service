# fraud-check-service

A fraud detection API for banking transactions. Submit a transaction and get
back a fraud verdict, a 0–100 risk score, and the specific reasons behind it.

Detection is a transparent, tunable **rules engine** (no training data
required) — see `app/rules.py` for every signal and its weight. It's
structured so a trained model can replace `score_transaction()` later without
changing the API surface.

## Signals it checks

- Large / elevated transaction amount
- Velocity (too many transactions in a short window)
- Impossible travel (different countries in a short time span)
- First transaction from a new country for the account
- Unusual hour (1am–5am UTC)
- High-risk merchant category (gambling, crypto, cash advance)
- Card-not-present with an elevated amount
- First transaction with a new merchant at an elevated amount

Each account's recent transaction history is kept in memory (see
`app/store.py`) so later transactions are judged against the account's
pattern, not in isolation.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
uvicorn app.main:app --reload
```

Interactive docs: http://127.0.0.1:8000/docs

## API

### `POST /transactions/check`

```bash
curl -X POST http://127.0.0.1:8000/transactions/check \
  -H "Content-Type: application/json" \
  -d '{
    "transaction_id": "tx-100",
    "account_id": "acct-42",
    "card_id": "card-42",
    "amount": 25000,
    "merchant": "Random Casino",
    "merchant_category": "gambling",
    "country": "US",
    "card_present": false
  }'
```

```json
{
  "transaction_id": "tx-100",
  "account_id": "acct-42",
  "is_fraud": true,
  "risk_score": 70,
  "risk_level": "high",
  "reasons": [
    "Amount 25000.00 USD exceeds $10,000",
    "High-risk merchant category: gambling",
    "Card-not-present transaction with elevated amount"
  ]
}
```

### `GET /accounts/{account_id}/history`

Returns the stored transaction history for an account.

### `DELETE /accounts/{account_id}/history`

Clears an account's stored history (404 if none exists).

### `GET /health`

Liveness check.

## Tests

```bash
pytest tests/ -v
```

## Notes / next steps

- History is in-memory and resets on restart — swap `app/store.py` for a real
  database before running this anywhere persistent.
- Thresholds/weights live at the top of `app/rules.py`; tune them to your
  data instead of taking the defaults as ground truth.
- No auth is implemented; add it before exposing this beyond localhost.
