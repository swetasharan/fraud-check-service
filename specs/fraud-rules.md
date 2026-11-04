# Fraud Rules Specification v2

Status: Draft, `specs` branch. Supersedes `app/rules.py` as implemented on
`vibes`. This document is written before any code on this branch — the
implementation should be built to match it, not the other way around.

## 1. Purpose

`vibes/app/rules.py` was adversarially tested with `attack.py`, a harness
that crafts transaction sequences designed to evade the scoring engine.
All four of its scenarios evaded detection completely (`risk_score` well
under `FRAUD_THRESHOLD`, most under `MEDIUM_THRESHOLD` too):

| Scenario | What it exploited | Result on `vibes` |
|---|---|---|
| `stay_under_elevated` | single tx priced just under `ELEVATED_AMOUNT` | $5,050 moved, score 0 |
| `structuring` | $4,999 chunks spaced past `VELOCITY_WINDOW`, same merchant/country | $50,000 moved, score 0 |
| `impossible_travel_gap` | cross-border tx timed just past `IMPOSSIBLE_TRAVEL_WINDOW` | score 30 (travel-specific rule never fired) |
| `category_laundering` | repeated high-risk-category tx, each kept under the amount thresholds | score 20, flat, no matter how many repeats |

This spec defines a replacement rule set with the same contract
(`score_transaction(tx, history) -> FraudCheckResult`) that closes each of
these gaps by construction, with worked numeric examples so the gaps can
be verified against this document before any code is written.

## 2. Non-goals

- **No geo-distance travel-speed modeling.** `Transaction` has no
  coordinates, only an ISO alpha-2 country code — there's no distance to
  compute. The impossible-travel fix (§4.4) addresses the *timing cliff*
  that `attack.py` exploited, not full travel physics. Real distance-aware
  scoring is future work (§7).
- **No cross-account correlation** (shared devices, merchant collusion
  rings). Single-account scope only, matching the existing engine.
- **No blocking/holding logic.** `score_transaction` stays a pure,
  stateless scoring function per call — deciding what to *do* with a HIGH
  score (block, hold, step-up auth) is a product decision for the caller,
  not this engine.
- **Thresholds stay at `FRAUD_THRESHOLD=70` / `MEDIUM_THRESHOLD=40`.**
  Keeping the buckets identical to `vibes` isolates the comparison to rule
  quality, not goalpost-moving.

## 3. Inputs / outputs (unchanged)

Same as `vibes`: `Transaction` in, `history: list[Transaction]` (prior
transactions for the account, oldest→newest, excluding `tx`), returns
`FraudCheckResult` with `risk_score` (0–100, summed rule points capped),
`risk_level` (LOW/MEDIUM/HIGH via the thresholds above), `is_fraud`
(`risk_score >= FRAUD_THRESHOLD`), and `reasons` (one human-readable
string per rule that fired).

## 4. Rule catalogue

Each rule is independent and additive, same as `vibes` — a rule returns
`(points, reason)` or nothing, points sum and cap at 100. Rules carried
over unchanged are noted as such; everything else is new or redesigned
specifically to close a gap from §1.

### 4.1 R1 — Single-transaction amount (unchanged)

| Condition | Points |
|---|---|
| `amount > HIGH_AMOUNT` ($10,000) | 40 |
| `amount > ELEVATED_AMOUNT` ($5,000) | 20 |

Carried over as-is. A single transaction under $5,000 with no history is
*not* required to score anything by itself — `stay_under_elevated` in
isolation is legitimate behavior. The actual gap was that **many** such
transactions moved real money undetected; that's closed by R3.

### 4.2 R2 — Velocity by count (unchanged)

| Condition (within `VELOCITY_WINDOW` = 10 min, count includes current tx) | Points |
|---|---|
| count ≥ `VELOCITY_HIGH_COUNT` (4) | 35 |
| count ≥ `VELOCITY_MEDIUM_COUNT` (3) | 20 |

Carried over as-is. Still useful for rapid-fire small transactions; it
just can't see *value*, which is why R3 exists.

### 4.3 R3 — Cumulative amount guard (NEW — closes `structuring`)

The root gap: nothing tracked money moved *over time*, only per-transaction
size (R1) and transaction *count* (R2). An attacker who keeps each
transaction under R1's threshold and spaces them past R2's window moves
unlimited money at score 0, as `attack.py` demonstrated.

Fix: sum transaction amounts (history + current tx) over two windows. To
avoid double-penalizing a single legitimate large purchase (already
covered by R1), **this rule only fires when the window contains 2 or more
transactions** — it targets accumulation across multiple transactions, not
transaction size.

**Short window** — `SHORT_WINDOW` = 10 min (same window as R2, but summing
value instead of counting):

| Condition (count ≥ 2 in window) | Points |
|---|---|
| sum > `SHORT_WINDOW_HIGH` ($9,000) | 30 |
| sum > `SHORT_WINDOW_MEDIUM` ($4,500) | 15 |

**Long window** — `LONG_WINDOW` = 24 h:

| Condition (count ≥ 2 in window) | Points |
|---|---|
| sum > `LONG_WINDOW_VERY_HIGH` ($30,000) | 70 |
| sum > `LONG_WINDOW_HIGH` ($15,000) | 45 |
| sum > `LONG_WINDOW_MEDIUM` ($7,500) | 25 |

Both windows are evaluated independently and both can fire on the same
transaction (they measure different things: a current burst vs.
cumulative drift) — see the worked example below for how they interact.

**Worked example — `attack.py`'s `structuring` scenario**, 11 transactions
of ~$4,999 each, spaced 11 minutes apart (past the 10-minute short
window), same merchant and country throughout:

| tx | elapsed since tx1 | long-window sum | long-window points | short-window points | total score | bucket |
|---|---|---|---|---|---|---|
| 1 | 0 min | 4,999 (count=1) | 0 (count<2) | 0 | 0 | LOW |
| 2 | 11 min | 9,998 | 25 | 0 (tx1 outside 10-min window) | 25 | LOW |
| 3 | 22 min | 14,997 | 25 | 0 | 25 | LOW |
| 4 | 33 min | 19,996 | 45 | 0 | 45 | **MEDIUM** |
| 5 | 44 min | 24,995 | 45 | 0 | 45 | MEDIUM |
| 6 | 55 min | 29,994 | 45 | 0 | 45 | MEDIUM |
| 7 | 66 min | 34,993 | 70 | 0 | 70 | **HIGH / is_fraud** |

By transaction 7 (~$35,000 moved, not even the full $50,000 `attack.py`
pushed through), the engine flags HIGH risk — versus `vibes`, which let
all 11 transactions ($50,000 total) through at score 0.

### 4.4 R4 — Impossible travel (REDESIGNED — closes `impossible_travel_gap`)

`vibes` used a hard cutoff: inside `IMPOSSIBLE_TRAVEL_WINDOW` (2h), +60
points; one minute past it, +0. `attack.py` just waited past the cutoff.

Fix: replace the cliff with a **linear decay** over `TRAVEL_DECAY_HOURS`
(12h). The rule still compares `tx` against the most recent prior
transaction (`history[-1]`), same as `vibes` — only the scoring curve
changes:

```
if tx.country != last.country:
    elapsed_hours = (tx.timestamp - last.timestamp) / 1h
    fraction = max(0, 1 - elapsed_hours / TRAVEL_DECAY_HOURS)
    points = round(TRAVEL_BASE_POINTS * fraction)   # TRAVEL_BASE_POINTS = 70
```

At `elapsed_hours = 0` this is 70 points (same ballpark as `vibes`' 60);
it decays smoothly to 0 at 12 hours. There is no instant where switching
countries quickly looks risk-free, which is what `attack.py` relied on.

**Worked example** — `attack.py`'s `impossible_travel_gap` scenario: home
country tx, then a cross-border tx at `IMPOSSIBLE_TRAVEL_WINDOW + 1min`
(2h01m) old-cutoff-evading gap:

```
elapsed_hours = 2.0167
fraction = 1 - 2.0167/12 = 0.8319
points   = round(70 * 0.8319) = 58
```

Combined with R5 (new country, +15, unchanged) and R8 (new merchant at
elevated amount, +15, unchanged): **58 + 15 + 15 = 88 → HIGH / is_fraud**,
versus `vibes`' score of 30 (LOW) for the identical input.

### 4.5 R5 — New country (unchanged)

First transaction from a country not seen anywhere in history: +15.
Carried over as-is; fires alongside R4 when relevant, same as `vibes`.

### 4.6 R6 — Odd hour (unchanged)

Transaction hour within `[ODD_HOUR_START, ODD_HOUR_END]` (01:00–05:00
UTC): +10. Carried over as-is.

### 4.7 R7 — High-risk category (REDESIGNED — closes `category_laundering`)

`vibes` gave a flat +20 for any transaction in `HIGH_RISK_CATEGORIES`
(`gambling`, `crypto`, `cash_advance`), regardless of how many times the
account had already done it or how large the amount was. `attack.py`
repeated the same low-amount high-risk transaction indefinitely at a
constant score of 20.

Fix: escalate with repetition (any high-risk category counts toward the
count — rotating between `gambling`/`crypto`/`cash_advance` doesn't reset
it) and add an amount-aware bonus, capped so one rule can't dominate the
whole score unboundedly:

```
prior_count = count of history entries in the last HIGH_RISK_WINDOW (24h)
              whose merchant_category is in HIGH_RISK_CATEGORIES
amount_bonus = HIGH_RISK_AMOUNT_BONUS (10) if tx.amount >= HIGH_RISK_AMOUNT_THRESHOLD ($1,000) else 0
points = min(HIGH_RISK_MAX (80),
             HIGH_RISK_BASE (20) + HIGH_RISK_REPEAT_INCREMENT (15) * prior_count + amount_bonus)
```

**Worked example.** `attack.py`'s current `category_laundering` scenario
only has 2 steps (seed + one followup), which already shows the fix
working — score moves from a flat 20 to 45 (LOW → **MEDIUM**) on the
second occurrence, instead of staying at 20 forever like `vibes`.
Extending the same pattern to more repeats — clustered within the same
rolling 24h window as each other (e.g. several occurrences within one
day; spacing them exactly 24h apart would let the window evict all but
the immediately-preceding one, capping `prior_count` at 1) — shows where
the escalation leads:

| occurrence | amount | prior_count | points | cumulative risk_score | bucket |
|---|---|---|---|---|---|
| 1 (in `attack.py`) | $50 | 0 | 20 | 20 | LOW |
| 2 (in `attack.py`) | $1,999 | 1 | 20 + 15·1 + 10 = 45 | 45 | **MEDIUM** |
| 3 (hypothetical) | $1,999 | 2 | 20 + 15·2 + 10 = 60 | 60 | MEDIUM |
| 4 (hypothetical) | $1,999 | 3 | 20 + 15·3 + 10 = 75 | 75 | **HIGH / is_fraud** |

Two repeats a day apart is a reasonable thing to flag as MEDIUM rather than
wave through at a flat LOW score; a system that also saw a 3rd and 4th
repeat escalates all the way to HIGH. Closing the gap fully (reaching
HIGH within `attack.py`'s existing 2-step scenario) would require either
a much steeper curve — which would make a single repeat alone enough to
block a legitimate once-a-day gambler — or extending the scenario itself
to more repeats. §7 reflects the 2-step scenario's actual ceiling; adding
more repeat steps to `attack.py` is listed as follow-up work.

### 4.8 R8 — New merchant + elevated amount (unchanged)

First transaction with a merchant not seen in history, amount >
`NEW_MERCHANT_AMOUNT` ($2,000): +15. Carried over as-is.

### 4.9 R9 — Card-not-present + elevated amount (unchanged)

`card_present = false` and amount > $1,000: +10. Carried over as-is.

## 5. Scoring aggregation (unchanged)

```
score = min(100, sum of all fired rule points)
risk_level = HIGH if score >= 70 else MEDIUM if score >= 40 else LOW
is_fraud = score >= 70
reasons = [reason for each fired rule] or ["No fraud indicators triggered"]
```

## 6. Configuration reference

| Constant | Default | Status |
|---|---|---|
| `HIGH_AMOUNT` | $10,000 | unchanged |
| `ELEVATED_AMOUNT` | $5,000 | unchanged |
| `VELOCITY_WINDOW` | 10 min | unchanged |
| `VELOCITY_HIGH_COUNT` / `VELOCITY_MEDIUM_COUNT` | 4 / 3 | unchanged |
| `SHORT_WINDOW` | 10 min | new (= `VELOCITY_WINDOW`) |
| `SHORT_WINDOW_HIGH` / `SHORT_WINDOW_MEDIUM` | $9,000 / $4,500 | new |
| `LONG_WINDOW` | 24 h | new |
| `LONG_WINDOW_VERY_HIGH` / `_HIGH` / `_MEDIUM` | $30,000 / $15,000 / $7,500 | new |
| `TRAVEL_DECAY_HOURS` | 12 h | new (replaces `IMPOSSIBLE_TRAVEL_WINDOW` cutoff) |
| `TRAVEL_BASE_POINTS` | 70 | redesigned (was flat 60) |
| `ODD_HOUR_START` / `ODD_HOUR_END` | 1 / 5 | unchanged |
| `HIGH_RISK_CATEGORIES` | `{gambling, crypto, cash_advance}` | unchanged |
| `HIGH_RISK_WINDOW` | 24 h | new |
| `HIGH_RISK_BASE` | 20 | unchanged value, new role (base of a formula, not flat) |
| `HIGH_RISK_REPEAT_INCREMENT` | 15 | new |
| `HIGH_RISK_AMOUNT_THRESHOLD` / `_BONUS` | $1,000 / 10 | new |
| `HIGH_RISK_MAX` | 80 | new (cap) |
| `NEW_MERCHANT_AMOUNT` | $2,000 | unchanged |
| `FRAUD_THRESHOLD` / `MEDIUM_THRESHOLD` | 70 / 40 | unchanged (§2) |

## 7. Acceptance criteria

Implementation is done when `attack.py`, run unmodified against this
engine (offline or `--live` against this service), reports for every
scenario:

- `stay_under_elevated`: still evades (score 0) — this is correct
  behavior, not a regression; see §4.1.
- `structuring`: `fully_evaded=False`; some transaction before the full
  $50,000 moves scores `>= FRAUD_THRESHOLD` (§4.3 table predicts tx 7).
- `impossible_travel_gap`: `max_score >= FRAUD_THRESHOLD` (§4.4 predicts
  88).
- `category_laundering`: `max_score` rises from 20 (flat, both steps on
  `vibes`) to 45 on the second occurrence (§4.7) — crossing into MEDIUM.
  It does **not** need to cross `FRAUD_THRESHOLD` within this scenario's
  current 2 steps; §4.7 shows the same escalation reaches HIGH by a 4th
  repeat, which `attack.py` doesn't yet exercise (see §8 follow-up).

## 8. Future work (explicitly out of scope for this spec)

- Geo-coordinate/distance-aware travel-speed scoring (needs a location
  field beyond ISO country code).
- Cross-account / device-fingerprint correlation.
- Durable history storage (currently in-memory via `store.py`, resets on
  restart — unchanged by this spec).
- Automatic blocking/step-up-auth workflow triggered by HIGH risk (a
  caller-side decision, not this engine's).
- Extending `attack.py`'s `category_laundering` scenario to 4 repeats, to
  exercise the full escalation curve in §4.7 against a running
  implementation instead of only the hand-computed table here.
