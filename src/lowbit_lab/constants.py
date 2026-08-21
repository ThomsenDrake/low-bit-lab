from decimal import Decimal

EVALUATION_FAMILIES = (
    "coding",
    "tool_call_validity",
    "long_context_retrieval",
    "throughput",
    "memory",
    "soak",
)

FROZEN_TOTAL_CREDITS = Decimal("0")
FROZEN_AUTOMATED_CEILING = Decimal("0")
FROZEN_RESERVE = Decimal("0")
FROZEN_SINGLE_JOB_CAP = Decimal("0")
FROZEN_H100_PRICE_PER_SECOND = Decimal("0")
FROZEN_PHASE_CAPS = {phase: Decimal("0") for phase in range(8)}
