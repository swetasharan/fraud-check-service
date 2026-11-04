"""In-memory transaction history, keyed by account.

Swap this for a real database (Postgres, Redis, etc.) in production —
the interface is intentionally small so that's a drop-in change.
"""

from collections import defaultdict
from threading import Lock

from app.models import Transaction

# How much history to keep per account before trimming (keeps memory bounded).
MAX_HISTORY_PER_ACCOUNT = 200


class TransactionStore:
    def __init__(self) -> None:
        self._history: dict[str, list[Transaction]] = defaultdict(list)
        self._lock = Lock()

    def get_history(self, account_id: str) -> list[Transaction]:
        with self._lock:
            return list(self._history[account_id])

    def add(self, transaction: Transaction) -> None:
        with self._lock:
            bucket = self._history[transaction.account_id]
            bucket.append(transaction)
            bucket.sort(key=lambda t: t.timestamp)
            if len(bucket) > MAX_HISTORY_PER_ACCOUNT:
                del bucket[: len(bucket) - MAX_HISTORY_PER_ACCOUNT]

    def clear(self) -> None:
        with self._lock:
            self._history.clear()

    def clear_account(self, account_id: str) -> bool:
        """Remove history for one account. Returns True if it existed."""
        with self._lock:
            return self._history.pop(account_id, None) is not None


# Single shared instance used by the API. Not persisted across restarts.
store = TransactionStore()
