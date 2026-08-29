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

# Independently frozen bootstrap-evidence amendment. It narrows only when four
# provider-derived facts may be observed; it does not add an action or budget.
REFERENCE_BOOTSTRAP_STATEMENT_SHA256 = (
    "4bba426073b4372079a800b9dcee7db38f509664be9d4fa97c904047e394ad90"
)
REFERENCE_BOOTSTRAP_AUTHORITY_SHA256 = (
    "942c6d41c1c38452b5f2fb60250e50b92430bd552b39a33ab1749b1b8fcb8f23"
)
REFERENCE_BOOTSTRAP_MERGE_COMMIT = "af05202502a8982a340c238447874e999cdff2e4"

# Independently frozen signed-CDN transport amendment. It changes only the
# redirect transport boundary and adds no action, retry, or budget authority.
REFERENCE_SIGNED_CDN_STATEMENT_SHA256 = (
    "3843da6c982c09c0975d95060b685c6a0506ca6c4be9c4d05c2e18fd77da1223"
)
REFERENCE_SIGNED_CDN_AUTHORITY_SHA256 = (
    "71aad476f7ad75df23f4b34ae9d3a7fbec121883b7e2e56b492ada124f82c890"
)
REFERENCE_SIGNED_CDN_MERGE_COMMIT = "a96d5949f2826438b0f219b1dd8633c8bd42f8c1"
REFERENCE_SIGNED_REDIRECT_POLICY = (
    ("huggingface.co", "/api/resolve-cache/models/"),
    ("us.aws.cdn.hf.co", "/xet-bridge-us/"),
)
REFERENCE_IMMUTABLE_ORIGIN_HOSTS = ("huggingface.co",)

# Independently frozen recovery authority. The statement remains ignored and
# local; tracked code records only its digest and a closed target-neutral shape.
REFERENCE_RECOVERY_STATEMENT_SHA256 = (
    "f905a9ba67df04a20ea60d8f56821d2512ea48f6dcc4717ced3d0aecf2e7246e"
)
REFERENCE_RECOVERY_AUTHORITY_SHA256 = (
    "3a4a1c03a682e7726199f6e701396f1b7b00c7237328d281bb611716979c9e68"
)

# One immutable mapping between historical logical scope and authenticated
# provider identity. Exact values remain in ignored local authority bytes.
REFERENCE_WORKSPACE_RECONCILIATION_STATEMENT_SHA256 = (
    "d8897340cb2c5b2b78de905cd3dda608cf963bcbe403c86e57e15504737ff603"
)
REFERENCE_WORKSPACE_RECONCILIATION_AUTHORITY_SHA256 = (
    "69ee88285e103eb5508675b21c95f7d33618c8a0230bf00bc1c20eb1dad00dc6"
)
REFERENCE_WORKSPACE_RECONCILIATION_BASE_COMMIT = "fe73bdee00c3cbe59587f4f677168865908bdafd"

# Independently frozen final append-only U8 authority. Historical reference
# and replacement grants remain consumed; this generation adds exactly one
# separately identified action under the newly stated lifetime ceiling.
REFERENCE_ADDITIONAL_STATEMENT_SHA256 = (
    "4b1947c5929d7baf926efbd5edabe85c7f9a6b0705a7c8cf01d791b1651cefb4"
)
REFERENCE_ADDITIONAL_STATEMENT_ARTIFACT_SHA256 = (
    "a976bf1513b7534bbfb1b6741675dc085976d264b4cd0a4d03ab584a7128b042"
)
REFERENCE_ADDITIONAL_AUTHORITY_SHA256 = (
    "67e933af4afc8a66384c816cf311a3cf1bbc386911254cdf1a5c6a8fc9700f0b"
)
REFERENCE_ADDITIONAL_BASE_COMMIT = "c90368d205f083f58a647f3134f70c033ce8703c"
REFERENCE_ADDITIONAL_SETTLEMENT_RECEIPT_SHA256 = (
    "f3bd5f4c64b9c725be3c0682d908f7064438d65341fa97b4072ad516b7031555"
)
REFERENCE_ADDITIONAL_PRIOR_EXECUTION_SCOPE_SHA256 = (
    "eaa894a7be7f2d0b4e3adbd3ddb36777addb5d9ecfc410bd15ba83eada4a5186"
)
REFERENCE_ADDITIONAL_PRIOR_SPEND_USD = Decimal("0.00564445")
REFERENCE_ADDITIONAL_INCREMENTAL_CAP_USD = Decimal("4.00")
REFERENCE_ADDITIONAL_CUMULATIVE_CAP_USD = Decimal("4.00564445")
