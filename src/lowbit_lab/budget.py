from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path

from lowbit_lab.constants import (
    FROZEN_AUTOMATED_CEILING,
    FROZEN_H100_PRICE_PER_SECOND,
    FROZEN_PHASE_CAPS,
    FROZEN_RESERVE,
    FROZEN_SINGLE_JOB_CAP,
    FROZEN_TOTAL_CREDITS,
)


class BudgetError(ValueError):
    pass


@dataclass(frozen=True)
class BudgetAuthorization:
    phase: int
    requested: Decimal
    phase_spent: Decimal
    total_spent: Decimal
    phase_remaining_after: Decimal
    total_remaining_after: Decimal


def _money(value: object, label: str) -> Decimal:
    if not isinstance(value, str):
        raise BudgetError(f"{label} must be a decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise BudgetError(f"{label} is not a decimal") from exc
    if not parsed.is_finite() or parsed < 0 or parsed.as_tuple().exponent < -6:
        raise BudgetError(f"{label} must be finite, non-negative, and at most 6 decimals")
    return parsed


class BudgetGuard:
    def __init__(self, policy_path: Path) -> None:
        raw = json.loads(policy_path.read_text(encoding="utf-8"))
        if raw.get("schema_version") != 1:
            raise BudgetError("unsupported budget policy")
        required = {
            "schema_version",
            "currency",
            "total_credits",
            "automated_spend_ceiling",
            "reserve",
            "single_job_cap",
            "h100_price_per_second",
            "phase_caps",
        }
        if set(raw) != required or raw["currency"] != "USD":
            raise BudgetError("budget policy schema is closed and must use USD")
        self.total_credits = _money(raw["total_credits"], "total_credits")
        self.ceiling = _money(raw["automated_spend_ceiling"], "automated_spend_ceiling")
        self.reserve = _money(raw["reserve"], "reserve")
        self.single_job_cap = _money(raw["single_job_cap"], "single_job_cap")
        self.h100_price_per_second = _money(raw["h100_price_per_second"], "h100_price_per_second")
        self.phase_caps = {
            int(key): _money(value, f"phase_caps.{key}") for key, value in raw["phase_caps"].items()
        }
        if self.ceiling + self.reserve != self.total_credits:
            raise BudgetError("ceiling plus reserve must equal total credits")
        frozen_values = (
            ("total_credits", self.total_credits, FROZEN_TOTAL_CREDITS),
            ("automated_spend_ceiling", self.ceiling, FROZEN_AUTOMATED_CEILING),
            ("reserve", self.reserve, FROZEN_RESERVE),
            ("single_job_cap", self.single_job_cap, FROZEN_SINGLE_JOB_CAP),
            (
                "h100_price_per_second",
                self.h100_price_per_second,
                FROZEN_H100_PRICE_PER_SECOND,
            ),
        )
        for label, actual, expected in frozen_values:
            if actual != expected:
                raise BudgetError(f"{label} does not match the frozen zero-spend policy")
        if self.phase_caps != FROZEN_PHASE_CAPS:
            raise BudgetError("phase caps do not match the frozen zero-spend policy")

    def authorize(
        self,
        *,
        phase: int,
        requested_cost_usd: str,
        phase_spent_usd: str = "0",
        total_spent_usd: str = "0",
    ) -> BudgetAuthorization:
        requested = _money(requested_cost_usd, "requested_cost_usd")
        phase_spent = _money(phase_spent_usd, "phase_spent_usd")
        total_spent = _money(total_spent_usd, "total_spent_usd")
        if phase not in self.phase_caps:
            raise BudgetError(f"phase {phase} has no authorized budget")
        if requested > self.single_job_cap:
            raise BudgetError("requested cost exceeds the single-job cap")
        phase_after = phase_spent + requested
        total_after = total_spent + requested
        if phase_after > self.phase_caps[phase]:
            raise BudgetError("requested cost exceeds the phase cap")
        if total_after > self.ceiling:
            raise BudgetError("requested cost exceeds the automated spend ceiling")
        return BudgetAuthorization(
            phase=phase,
            requested=requested,
            phase_spent=phase_spent,
            total_spent=total_spent,
            phase_remaining_after=self.phase_caps[phase] - phase_after,
            total_remaining_after=self.ceiling - total_after,
        )

    def estimate_h100_cost(self, gpu_count: int, wall_clock_seconds: int) -> Decimal:
        if not 0 <= gpu_count <= 8 or not 1 <= wall_clock_seconds <= 86_400:
            raise BudgetError("invalid resources for H100 cost estimation")
        return self.h100_price_per_second * gpu_count * wall_clock_seconds
