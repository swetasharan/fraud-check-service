"""Adversarial test harness for app/rules.py.

Crafts transaction sequences designed to evade the rule-based fraud engine
and reports how much of each evasion technique gets through. The point is
to find gaps in the rules *before* a real attacker does, so treat a
"successful" scenario here as a bug report against rules.py, not a win.

Each scenario exploits a specific gap in the current rule set:

  - stay_under_elevated   single tx priced just below ELEVATED_AMOUNT
  - structuring           large total split into chunks that each dodge
                           the amount/velocity/new-merchant rules
  - impossible_travel_gap cross-border tx spaced just past
                           IMPOSSIBLE_TRAVEL_WINDOW, so the 60-point rule
                           never fires even though the travel is still
                           physically impossible
  - category_laundering   high-risk category tx kept under MEDIUM_THRESHOLD
                           by avoiding every other rule

Run offline (default) to score against app/rules.py directly with a
simulated in-memory history. Pass --live to replay the same transactions
against a running `uvicorn app.main:app` instance instead, to check the
API's real behavior matches the offline simulation.

Usage:
    python attack.py                       # run all scenarios offline
    python attack.py --scenario structuring
    python attack.py --live --base-url http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import itertools
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.models import Transaction
from app.rules import (
    ELEVATED_AMOUNT,
    FRAUD_THRESHOLD,
    HIGH_RISK_CATEGORIES,
    IMPOSSIBLE_TRAVEL_WINDOW,
    MEDIUM_THRESHOLD,
    NEW_MERCHANT_AMOUNT,
    VELOCITY_WINDOW,
    score_transaction,
)

SAFE_HOUR = 14  # clear of ODD_HOUR_START..ODD_HOUR_END


def make_tx(
    *,
    account_id: str,
    amount: float,
    card_id: str | None = None,
    merchant: str = "Everyday Groceries",
    merchant_category: str | None = "groceries",
    country: str = "US",
    card_present: bool = True,
    timestamp: datetime,
) -> Transaction:
    return Transaction(
        transaction_id=str(uuid.uuid4()),
        account_id=account_id,
        card_id=card_id or f"card-{account_id}",
        amount=amount,
        merchant=merchant,
        merchant_category=merchant_category,
        country=country,
        card_present=card_present,
        timestamp=timestamp,
    )


@dataclass
class StepResult:
    tx: Transaction
    score: int
    level: str
    reasons: list[str]

    @property
    def evaded(self) -> bool:
        return self.score < FRAUD_THRESHOLD


def run_sequence(txs: list[Transaction]) -> list[StepResult]:
    """Score each tx against the ones before it, mirroring store.py's
    append-after-score semantics."""
    history: list[Transaction] = []
    results = []
    for tx in txs:
        result = score_transaction(tx, history)
        results.append(
            StepResult(tx=tx, score=result.risk_score, level=result.risk_level.value, reasons=result.reasons)
        )
        history.append(tx)
    return results


# --- Scenarios ---------------------------------------------------------


def scenario_stay_under_elevated() -> list[Transaction]:
    account_id = f"attack-elevated-{uuid.uuid4().hex[:8]}"
    base = datetime.now(timezone.utc).replace(hour=SAFE_HOUR, minute=0, second=0, microsecond=0)
    seed = make_tx(account_id=account_id, amount=50, timestamp=base)
    big = make_tx(
        account_id=account_id,
        amount=ELEVATED_AMOUNT - 0.01,
        timestamp=base + timedelta(days=1),
    )
    return [seed, big]


def scenario_structuring(total: float = 50_000, chunk: float | None = None) -> list[Transaction]:
    account_id = f"attack-structuring-{uuid.uuid4().hex[:8]}"
    chunk = chunk or (ELEVATED_AMOUNT - 1)
    base = datetime.now(timezone.utc).replace(hour=SAFE_HOUR, minute=0, second=0, microsecond=0)
    gap = VELOCITY_WINDOW + timedelta(minutes=1)

    txs = []
    remaining = total
    i = 0
    while remaining > 0:
        amount = min(chunk, remaining)
        txs.append(
            make_tx(
                account_id=account_id,
                amount=amount,
                merchant="Trusted Retailer",
                timestamp=base + gap * i,
            )
        )
        remaining -= amount
        i += 1
    return txs


def scenario_impossible_travel_gap() -> list[Transaction]:
    account_id = f"attack-travel-{uuid.uuid4().hex[:8]}"
    base = datetime.now(timezone.utc).replace(hour=SAFE_HOUR, minute=0, second=0, microsecond=0)
    home = make_tx(account_id=account_id, amount=40, country="US", timestamp=base)
    gap = IMPOSSIBLE_TRAVEL_WINDOW + timedelta(minutes=1)
    abroad = make_tx(
        account_id=account_id,
        amount=ELEVATED_AMOUNT - 1,
        country="RO",
        merchant="Overseas Electronics",
        timestamp=base + gap,
    )
    return [home, abroad]


def scenario_category_laundering() -> list[Transaction]:
    account_id = f"attack-category-{uuid.uuid4().hex[:8]}"
    base = datetime.now(timezone.utc).replace(hour=SAFE_HOUR, minute=0, second=0, microsecond=0)
    category = next(iter(HIGH_RISK_CATEGORIES))
    seed = make_tx(
        account_id=account_id,
        amount=50,
        merchant="Lucky Draw Co",
        merchant_category=category,
        timestamp=base,
    )
    followup = make_tx(
        account_id=account_id,
        amount=min(NEW_MERCHANT_AMOUNT, ELEVATED_AMOUNT) - 1,
        merchant="Lucky Draw Co",
        merchant_category=category,
        timestamp=base + timedelta(days=1),
    )
    return [seed, followup]


SCENARIOS = {
    "stay_under_elevated": scenario_stay_under_elevated,
    "structuring": scenario_structuring,
    "impossible_travel_gap": scenario_impossible_travel_gap,
    "category_laundering": scenario_category_laundering,
}


# --- Reporting -----------------------------------------------------------


def print_offline_report(name: str, results: list[StepResult]) -> None:
    print(f"\n=== {name} ===")
    total_moved = 0.0
    max_score = 0
    for i, r in enumerate(results):
        total_moved += r.tx.amount
        max_score = max(max_score, r.score)
        flag = "EVADED" if r.evaded else "CAUGHT"
        print(
            f"  [{i:02d}] {flag:7s} score={r.score:3d} level={r.level:6s} "
            f"amount={r.tx.amount:>10.2f} country={r.tx.country} "
            f"reasons={r.reasons}"
        )
    all_evaded = all(r.evaded for r in results)
    print(
        f"  -> total_moved={total_moved:,.2f}  max_score={max_score}  "
        f"fully_evaded={all_evaded}  (FRAUD_THRESHOLD={FRAUD_THRESHOLD}, "
        f"MEDIUM_THRESHOLD={MEDIUM_THRESHOLD})"
    )


def run_live(base_url: str, txs: list[Transaction], cleanup: bool) -> list[dict]:
    import httpx

    out = []
    with httpx.Client(base_url=base_url, timeout=10) as client:
        for tx in txs:
            resp = client.post("/transactions/check", json=tx.model_dump(mode="json"))
            resp.raise_for_status()
            out.append(resp.json())
        if cleanup:
            account_id = txs[0].account_id
            client.delete(f"/accounts/{account_id}/history")
    return out


def print_live_report(name: str, live_results: list[dict]) -> None:
    print(f"\n=== {name} (LIVE) ===")
    for i, r in enumerate(live_results):
        flag = "EVADED" if r["risk_score"] < FRAUD_THRESHOLD else "CAUGHT"
        print(f"  [{i:02d}] {flag:7s} score={r['risk_score']:3d} level={r['risk_level']:6s} reasons={r['reasons']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIOS) + ["all"],
        default="all",
        help="Which evasion scenario to run (default: all)",
    )
    parser.add_argument("--live", action="store_true", help="Replay against a running API instead of scoring offline")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="Base URL for --live mode")
    parser.add_argument(
        "--no-cleanup", action="store_true", help="Don't delete the attack account's history after a --live run"
    )
    args = parser.parse_args()

    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]

    for name in names:
        txs = SCENARIOS[name]()
        if args.live:
            live_results = run_live(args.base_url, txs, cleanup=not args.no_cleanup)
            print_live_report(name, live_results)
        else:
            results = run_sequence(txs)
            print_offline_report(name, results)


if __name__ == "__main__":
    main()
