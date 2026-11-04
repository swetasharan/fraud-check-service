"""Rule-based fraud scoring engine.

Implements specs/fraud-rules.md v2. Each rule inspects the incoming
transaction (and the account's recent history) and contributes points +
a human-readable reason when it fires. Points are summed and capped at
100 to produce a risk_score, which is then bucketed into a risk_level
and a final is_fraud decision — same contract as the original engine.

R3 ("cumulative amount guard") is implemented as two independent
functions, _rule_short_window_amount and _rule_long_window_amount, since
the spec has them fire independently over two different windows rather
than as a single tiered ladder.
"""

from datetime import timedelta

from app.models import FraudCheckResult, RiskLevel, Transaction

# --- Tunable thresholds (see specs/fraud-rules.md §6) -----------------------

HIGH_AMOUNT = 10_000
ELEVATED_AMOUNT = 5_000

VELOCITY_WINDOW = timedelta(minutes=10)
VELOCITY_HIGH_COUNT = 4
VELOCITY_MEDIUM_COUNT = 3

SHORT_WINDOW = VELOCITY_WINDOW  # same 10-minute window as velocity, but summing value
SHORT_WINDOW_HIGH = 9_000
SHORT_WINDOW_MEDIUM = 4_500

LONG_WINDOW = timedelta(hours=24)
LONG_WINDOW_VERY_HIGH = 30_000
LONG_WINDOW_HIGH = 15_000
LONG_WINDOW_MEDIUM = 7_500

TRAVEL_DECAY_HOURS = 12.0
TRAVEL_BASE_POINTS = 70

ODD_HOUR_START = 1
ODD_HOUR_END = 5

HIGH_RISK_CATEGORIES = {"gambling", "crypto", "cash_advance"}
HIGH_RISK_WINDOW = timedelta(hours=24)
HIGH_RISK_BASE = 20
HIGH_RISK_REPEAT_INCREMENT = 15
HIGH_RISK_AMOUNT_THRESHOLD = 1_000
HIGH_RISK_AMOUNT_BONUS = 10
HIGH_RISK_MAX = 80

NEW_MERCHANT_AMOUNT = 2_000

FRAUD_THRESHOLD = 70
MEDIUM_THRESHOLD = 40

# Each rule returns (points, reason) or None if it doesn't fire.
RuleResult = tuple[int, str] | None


def _within(tx: Transaction, history: list[Transaction], window: timedelta) -> list[Transaction]:
    return [t for t in history if tx.timestamp - t.timestamp <= window]


def _rule_high_amount(tx: Transaction, history: list[Transaction]) -> RuleResult:
    if tx.amount > HIGH_AMOUNT:
        return 40, f"Amount {tx.amount:.2f} {tx.currency} exceeds ${HIGH_AMOUNT:,}"
    if tx.amount > ELEVATED_AMOUNT:
        return 20, f"Amount {tx.amount:.2f} {tx.currency} exceeds ${ELEVATED_AMOUNT:,}"
    return None


def _rule_velocity(tx: Transaction, history: list[Transaction]) -> RuleResult:
    recent = _within(tx, history, VELOCITY_WINDOW)
    count = len(recent) + 1  # include the current transaction
    if count >= VELOCITY_HIGH_COUNT:
        return 35, f"{count} transactions within {int(VELOCITY_WINDOW.total_seconds() // 60)} minutes"
    if count >= VELOCITY_MEDIUM_COUNT:
        return 20, f"{count} transactions within {int(VELOCITY_WINDOW.total_seconds() // 60)} minutes"
    return None


def _rule_short_window_amount(tx: Transaction, history: list[Transaction]) -> RuleResult:
    recent = _within(tx, history, SHORT_WINDOW)
    count = len(recent) + 1
    if count < 2:
        return None
    total = sum(t.amount for t in recent) + tx.amount
    minutes = int(SHORT_WINDOW.total_seconds() // 60)
    if total > SHORT_WINDOW_HIGH:
        return 30, f"${total:,.2f} moved across {count} transactions within {minutes} minutes"
    if total > SHORT_WINDOW_MEDIUM:
        return 15, f"${total:,.2f} moved across {count} transactions within {minutes} minutes"
    return None


def _rule_long_window_amount(tx: Transaction, history: list[Transaction]) -> RuleResult:
    recent = _within(tx, history, LONG_WINDOW)
    count = len(recent) + 1
    if count < 2:
        return None
    total = sum(t.amount for t in recent) + tx.amount
    hours = int(LONG_WINDOW.total_seconds() // 3600)
    if total > LONG_WINDOW_VERY_HIGH:
        return 70, f"${total:,.2f} moved across {count} transactions within {hours}h"
    if total > LONG_WINDOW_HIGH:
        return 45, f"${total:,.2f} moved across {count} transactions within {hours}h"
    if total > LONG_WINDOW_MEDIUM:
        return 25, f"${total:,.2f} moved across {count} transactions within {hours}h"
    return None


def _rule_impossible_travel(tx: Transaction, history: list[Transaction]) -> RuleResult:
    if not history:
        return None
    last = history[-1]
    if last.country == tx.country:
        return None
    elapsed_hours = (tx.timestamp - last.timestamp).total_seconds() / 3600
    fraction = max(0.0, 1 - elapsed_hours / TRAVEL_DECAY_HOURS)
    points = round(TRAVEL_BASE_POINTS * fraction)
    if points <= 0:
        return None
    return points, (
        f"Transaction in {tx.country} occurred {elapsed_hours:.1f}h after a transaction in "
        f"{last.country} (cross-border risk decays over {TRAVEL_DECAY_HOURS:.0f}h)"
    )


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
    if not tx.merchant_category or tx.merchant_category.lower() not in HIGH_RISK_CATEGORIES:
        return None
    window_history = _within(tx, history, HIGH_RISK_WINDOW)
    prior_count = sum(
        1 for t in window_history if t.merchant_category and t.merchant_category.lower() in HIGH_RISK_CATEGORIES
    )
    amount_bonus = HIGH_RISK_AMOUNT_BONUS if tx.amount >= HIGH_RISK_AMOUNT_THRESHOLD else 0
    points = min(HIGH_RISK_MAX, HIGH_RISK_BASE + HIGH_RISK_REPEAT_INCREMENT * prior_count + amount_bonus)
    window_hours = int(HIGH_RISK_WINDOW.total_seconds() // 3600)
    return points, (
        f"High-risk merchant category: {tx.merchant_category} "
        f"({prior_count} similar transaction(s) in the last {window_hours}h)"
    )


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
    _rule_short_window_amount,
    _rule_long_window_amount,
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
