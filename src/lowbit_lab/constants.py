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

# Independently frozen human grant and its closed, target-neutral capability.
REFERENCE_AUTHORITY_STATEMENT_SHA256 = (
    "856755b202130d56bd5446d2bd7cef354159ab891f8d1629a64715bd641bb2e4"
)
REFERENCE_AUTHORITY_SHA256 = "8be94c8db6adae0de538ca41f43e7d250b9d4b5af4ffa6cd14ee445ca45d0d61"
REFERENCE_INCREMENTAL_CAP_USD = Decimal("4.00")
REFERENCE_SETTLED_SMOKE_USD = Decimal("0.00270969")
REFERENCE_CUMULATIVE_CAP_USD = Decimal("4.00270969")
