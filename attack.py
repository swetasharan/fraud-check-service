#!/usr/bin/env python3
"""
attack.py - adversarial probe for fraud-check-service.

Usage:
    python attack.py                      # run every scenario
    python attack.py --scenario velocity  # run one
    python attack.py --url http://127.0.0.1:8000

Scenarios:
    control    one ordinary purchase (sanity check)
    whale      a single $1,000,000 transaction
    velocity   5 small purchases in 92 seconds (card being drained)
    travel     Atlanta -> London in 30 minutes
    duplicate  the exact same transaction sent twice
    oddhour    9pm in Atlanta (= 02:00 UTC)
    garbage    missing field, negative amount
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

G, R, Y, B, DIM, OFF = (
    "\033[92m", "\033[91m", "\033[93m", "\033[1m", "\033[2m", "\033[0m",
)

BASE = "http://127.0.0.1:8000"


# --------------------------------------------------------------------------- http

def post_check(base, payload):
    req = urllib.request.Request(
        f"{base}/transactions/check",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")
    except Exception as e:  # noqa: BLE001
        return 0, {"error": str(e)}


def reset(base, account_id):
    """Clear prior history so each scenario starts clean."""
    req = urllib.request.Request(
        f"{base}/accounts/{account_id}/history", method="DELETE"
    )
    try:
        urllib.request.urlopen(req, timeout=10).read()
    except Exception:  # noqa: BLE001
        pass


# --------------------------------------------------------------------------- output

def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def txn(account, amount, merchant, tid, when, *, country="US",
        category="retail", card_present=True, currency="USD"):
    return {
        "transaction_id": tid,
        "account_id": account,
        "amount": amount,
        "currency": currency,
        "merchant": merchant,
        "merchant_category": category,
        "country": country,
        "card_present": card_present,
        "timestamp": iso(when),
    }


def show(payload, status, body, *, expect=None):
    if status == 0:
        print(f"  {R}CONNECTION FAILED{OFF}  {body.get('error')}")
        return
    if status >= 400:
        print(f"  {Y}HTTP {status}{OFF}  rejected by validation")
        detail = body.get("detail")
        if isinstance(detail, list) and detail:
            msg = detail[0].get("msg", "")
            loc = ".".join(str(p) for p in detail[0].get("loc", []))
            print(f"  {DIM}{loc}: {msg}{OFF}")
        return

    fraud = body.get("is_fraud")
    score = body.get("risk_score")
    level = (body.get("risk_level") or "").upper()
    verdict = f"{R}{B}BLOCKED{OFF}" if fraud else f"{G}APPROVED{OFF}"
    amount = payload["amount"]
    print(
        f"  {payload['account_id']:<10} ${amount:>12,.2f}  "
        f"{payload['merchant']:<12} score {str(score):>3}  "
        f"{level:<6}  {verdict}"
    )
    for reason in body.get("reasons", []):
        print(f"       {DIM}- {reason}{OFF}")
    if expect:
        print(f"       {Y}^ {expect}{OFF}")


def header(name, blurb):
    print(f"\n{B}=== {name.upper()} ==={OFF}  {DIM}{blurb}{OFF}")


# --------------------------------------------------------------------------- scenarios

def s_control(base):
    header("control", "one ordinary grocery run - should be clean")
    acct = "acct_control"
    reset(base, acct)
    now = datetime.now(timezone.utc).replace(hour=18, minute=0, second=0)
    p = txn(acct, 45.00, "Kroger", "ctl-1", now, category="grocery")
    show(p, *post_check(base, p))


def s_whale(base):
    header("whale", "a single one-million-dollar charge")
    acct = "acct_whale"
    reset(base, acct)
    now = datetime.now(timezone.utc).replace(hour=18, minute=0, second=0)
    p = txn(acct, 1_000_000.00, "Unknown", "whale-1", now)
    show(p, *post_check(base, p),
         expect="40 points max. Threshold is 70. No amount can block alone.")


def s_velocity(base):
    header("velocity", "5 purchases, 92 seconds, one card being drained")
    acct = "acct_velocity"
    reset(base, acct)
    start = datetime.now(timezone.utc).replace(hour=18, minute=0, second=0)
    items = [
        (170.00, "TechMart"), (185.00, "GameStop"), (150.00, "BestBuy"),
        (180.00, "Walmart"), (155.00, "Target"),
    ]
    for i, (amount, merchant) in enumerate(items):
        p = txn(acct, amount, merchant, f"vel-{i+1}", start + timedelta(seconds=23 * i))
        show(p, *post_check(base, p))
    print(f"       {Y}^ velocity caps at 35 points. It can never reach 70.{OFF}")


def s_travel(base):
    header("travel", "Atlanta then London, 30 minutes apart")
    acct = "acct_travel"
    reset(base, acct)
    start = datetime.now(timezone.utc).replace(hour=18, minute=0, second=0)
    p1 = txn(acct, 60.00, "Publix", "trv-1", start, country="US", category="grocery")
    show(p1, *post_check(base, p1))
    p2 = txn(acct, 90.00, "Harrods", "trv-2", start + timedelta(minutes=30), country="GB")
    show(p2, *post_check(base, p2),
         expect="60 for travel + 15 for new country = 75. Blocks only because of the second rule.")


def s_duplicate(base):
    header("duplicate", "the exact same transaction, sent twice")
    acct = "acct_dup"
    reset(base, acct)
    now = datetime.now(timezone.utc).replace(hour=18, minute=0, second=0)
    p = txn(acct, 320.00, "AppleStore", "dup-1", now, category="electronics")
    show(p, *post_check(base, p))
    show(p, *post_check(base, p),
         expect="same transaction_id accepted twice - no replay protection.")


def s_oddhour(base):
    header("oddhour", "9pm in Atlanta = 02:00 UTC")
    acct = "acct_hour"
    reset(base, acct)
    evening_et = datetime.now(timezone.utc).replace(hour=2, minute=0, second=0)
    p = txn(acct, 60.00, "Kroger", "hr-1", evening_et, category="grocery")
    show(p, *post_check(base, p),
         expect="normal evening shopping, penalised. Real 3am ET (08:00 UTC) is not.")


def s_garbage(base):
    header("garbage", "malformed input")
    acct = "acct_garbage"
    reset(base, acct)
    now = datetime.now(timezone.utc).replace(hour=18, minute=0, second=0)

    bad = txn(acct, 50.00, "Kroger", "bad-1", now)
    del bad["amount"]
    print(f"  {DIM}missing amount:{OFF}")
    bad["amount"] = 0  # for display only
    status, body = post_check(base, {k: v for k, v in bad.items() if k != "amount"})
    show(bad, status, body)

    print(f"  {DIM}negative amount:{OFF}")
    neg = txn(acct, -5000.00, "Kroger", "bad-2", now)
    show(neg, *post_check(base, neg),
         expect="does a negative amount validate? does any rule catch it?")


SCENARIOS = {
    "control": s_control,
    "whale": s_whale,
    "velocity": s_velocity,
    "travel": s_travel,
    "duplicate": s_duplicate,
    "oddhour": s_oddhour,
    "garbage": s_garbage,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", choices=list(SCENARIOS) + ["all"], default="all")
    ap.add_argument("--url", default=BASE)
    args = ap.parse_args()

    base = args.url.rstrip("/")
    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    for n in names:
        SCENARIOS[n](base)
    print()


if __name__ == "__main__":
    sys.exit(main())