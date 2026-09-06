"""Pydantic schemas for the fraud-check API."""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Transaction(BaseModel):
    transaction_id: str = Field(..., description="Unique ID for this transaction")
    account_id: str = Field(..., description="ID of the account making the transaction")
    amount: float = Field(..., gt=0, description="Transaction amount")
    currency: str = Field("USD", min_length=3, max_length=3)
    merchant: str = Field(..., description="Merchant name")
    merchant_category: Optional[str] = Field(
        None, description="e.g. groceries, electronics, travel, gambling"
    )
    country: str = Field(..., min_length=2, max_length=2, description="ISO 3166-1 alpha-2 country code")
    card_present: bool = Field(True, description="Was the physical card used")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the transaction occurred (defaults to now)",
    )


class FraudCheckResult(BaseModel):
    transaction_id: str
    account_id: str
    is_fraud: bool
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    reasons: list[str]
