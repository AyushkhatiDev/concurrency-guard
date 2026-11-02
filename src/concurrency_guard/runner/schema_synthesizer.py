"""Deterministic Pydantic payload synthesis via model field introspection."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel

# Field name patterns that indicate an identifier (set to 1)
_ID_PATTERNS = ("id", "user_id", "item_id", "account_id", "product_id")

# Field name patterns that indicate a delta/amount (set to initial_quota)
_AMOUNT_PATTERNS = (
    "amount",
    "quantity",
    "qty",
    "units",
    "credits",
    "deduct",
    "withdraw",
    "count",
)

# Field name patterns that indicate a string label
_STRING_LABEL_PATTERNS = ("sku", "code", "email", "name")


def synthesize_request_payload(
    pydantic_model: Optional[type[BaseModel]],
    initial_quota: int = 50,
) -> dict[str, Any]:
    """Synthesize a deterministic request payload from Pydantic model field introspection.

    For integer/float ID-like fields, sets value to 1.
    For integer/float amount-like fields, sets value to initial_quota.
    For string fields matching label patterns, sets value to "test_item_1".
    For any other required fields, synthesizes a type-appropriate fallback.
    """
    if pydantic_model is None:
        return {}

    payload: dict[str, Any] = {}

    for field_name, field_info in pydantic_model.model_fields.items():
        annotation = field_info.annotation
        lower_name = field_name.lower()

        # Determine if this is an ID field
        if (lower_name in _ID_PATTERNS or lower_name.endswith("_id")) and annotation in (
            int,
            float,
        ):
            payload[field_name] = 1
            continue

        # Determine if this is an amount/delta field
        if any(pat in lower_name for pat in _AMOUNT_PATTERNS) and annotation in (int, float):
            payload[field_name] = initial_quota
            continue

        # Determine if this is a string label field
        if any(pat in lower_name for pat in _STRING_LABEL_PATTERNS) and annotation is str:
            payload[field_name] = "test_item_1"
            continue

        # Fallback: synthesize based on type
        if annotation is int:
            payload[field_name] = 1
        elif annotation is float:
            payload[field_name] = 1.0
        elif annotation is str:
            payload[field_name] = "test"
        elif annotation is bool:
            payload[field_name] = True
        else:
            # Last resort for unknown types
            payload[field_name] = None

    return payload
