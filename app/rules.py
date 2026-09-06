"""Rule-based fraud scoring engine.

Each rule inspects the incoming transaction (and the account's recent
history) and contributes points + a human-readable reason when it fires.
Points are summed and capped at 100 to produce a risk_score, which is then
bucketed into a risk_level and a final is_fraud decision.

This is deliberately transparent and tunable rather than a black-box model —
swap in a trained classifier later by replacing `score_transaction` while
keeping the same return shape.
"""

from datetime import timedelta

from app.models import FraudCheckResult, RiskLevel, Transaction

# --- Tunable thresholds -----------------------------------------------------

HIGH_AMOUNT = 10_000
ELEVATED_AMOUNT = 5_000
VELOCITY_WINDOW = timedelta(minutes=10)
VELOCITY_HIGH_COUNT = 4
VELOCITY_MEDIUM_COUNT = 3
IMPOSSIBLE_TRAVEL_WINDOW = timedelta(hours=2)
ODD_HOUR_START = 1
ODD_HOUR_END = 5
HIGH_RISK_CATEGORIES = {"gambling", "crypto", "cash_advance"}
NEW_MERCHANT_AMOUNT = 2_000

FRAUD_THRESHOLD = 70
MEDIUM_THRESHOLD = 40

# Each rule returns (points, reason) or None if it doesn't fire.
RuleResult = tuple[int, str] | None


def _rule_high_amount(tx: Transaction, history: list[Transaction]) -> RuleResult:
    if tx.amount > HIGH_AMOUNT:
        return 40, f"Amount {tx.amount:.2f} {tx.currency} exceeds ${HIGH_AMOUNT:,}"
    if tx.amount > ELEVATED_AMOUNT:
        return 20, f"Amount {tx.amount:.2f} {tx.currency} exceeds ${ELEVATED_AMOUNT:,}"
    return None


def _rule_velocity(tx: Transaction, history: list[Transaction]) -> RuleResult:
    recent = [t for t in history if tx.timestamp - t.timestamp <= VELOCITY_WINDOW]
    count = len(recent) + 1  # include the current transaction
    if count >= VELOCITY_HIGH_COUNT:
        return 35, f"{count} transactions within {int(VELOCITY_WINDOW.total_seconds() // 60)} minutes"
    if count >= VELOCITY_MEDIUM_COUNT:
        return 20, f"{count} transactions within {int(VELOCITY_WINDOW.total_seconds() // 60)} minutes"
    return None


def _rule_impossible_travel(tx: Transaction, history: list[Transaction]) -> RuleResult:
    if not history:
        return None
    last = history[-1]
    if last.country != tx.country and tx.timestamp - last.timestamp <= IMPOSSIBLE_TRAVEL_WINDOW:
        hours = (tx.timestamp - last.timestamp).total_seconds() / 3600
        return 60, (
            f"Transaction in {tx.country} occurred {hours:.1f}h after a transaction in "
            f"{last.country} (impossible travel)"
        )
    return None


def _rule_new_country(tx: Transaction, history: list[Transaction]) -> RuleResult:
    if not history:
        return None
    known_countries = {t.country for t in history}
    if tx.country not in known_countries:
        return 15, f"First transaction from {tx.country} for this account"
    return None


def _rule_odd_hour(tx: Transaction, history: list[Transaction]) -> RuleResult:
    hour = tx.timestamp.hour
    if ODD_HOUR_START <= hour <= ODD_HOUR_END:
        return 10, f"Transaction occurred at {hour:02d}:00 UTC (unusual hours)"
    return None


def _rule_high_risk_category(tx: Transaction, history: list[Transaction]) -> RuleResult:
    if tx.merchant_category and tx.merchant_category.lower() in HIGH_RISK_CATEGORIES:
        return 20, f"High-risk merchant category: {tx.merchant_category}"
    return None


def _rule_card_not_present(tx: Transaction, history: list[Transaction]) -> RuleResult:
    if not tx.card_present and tx.amount > 1_000:
        return 10, "Card-not-present transaction with elevated amount"
    return None


def _rule_new_merchant_large_amount(tx: Transaction, history: list[Transaction]) -> RuleResult:
    if not history:
        return None
    known_merchants = {t.merchant for t in history}
    if tx.merchant not in known_merchants and tx.amount > NEW_MERCHANT_AMOUNT:
        return 15, f"First transaction with merchant '{tx.merchant}' at an elevated amount"
    return None


RULES = [
    _rule_high_amount,
    _rule_velocity,
    _rule_impossible_travel,
    _rule_new_country,
    _rule_odd_hour,
    _rule_high_risk_category,
    _rule_card_not_present,
    _rule_new_merchant_large_amount,
]


def score_transaction(tx: Transaction, history: list[Transaction]) -> FraudCheckResult:
    """Run all rules against a transaction and return a FraudCheckResult.

    `history` should be prior transactions for the same account, sorted
    oldest-to-newest, and must NOT include `tx` itself.
    """
    score = 0
    reasons: list[str] = []

    for rule in RULES:
        result = rule(tx, history)
        if result is not None:
            points, reason = result
            score += points
            reasons.append(reason)

    score = min(score, 100)

    if score >= FRAUD_THRESHOLD:
        level = RiskLevel.HIGH
    elif score >= MEDIUM_THRESHOLD:
        level = RiskLevel.MEDIUM
    else:
        level = RiskLevel.LOW

    if not reasons:
        reasons.append("No fraud indicators triggered")

    return FraudCheckResult(
        transaction_id=tx.transaction_id,
        account_id=tx.account_id,
        is_fraud=score >= FRAUD_THRESHOLD,
        risk_score=score,
        risk_level=level,
        reasons=reasons,
    )
