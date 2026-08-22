import pytest

from lowbit_lab.evaluation import (
    EVALUATION_FAMILIES,
    CandidateExecutionBlocked,
    EvaluationResult,
    assert_candidate_execution_allowed,
    placeholder_result,
    validate_context_state,
)


def test_all_placeholder_families_disclaim_proof() -> None:
    assert len(EVALUATION_FAMILIES) == 6
    for family in EVALUATION_FAMILIES:
        result = placeholder_result(family)
        assert result.status == "placeholder_not_executed"
        assert result.useful_context_proven is False


def test_context_states_remain_separate_until_retrieval_evidence_exists() -> None:
    state = validate_context_state(
        configured_tokens=8192,
        runtime_initialized=True,
        usefulness_proven=False,
        retrieval_evidence_sha256=None,
    )
    assert state.runtime_initialized is True
    assert state.usefulness_proven is False

    with pytest.raises(ValueError, match="retrieval evidence"):
        validate_context_state(
            configured_tokens=8192,
            runtime_initialized=True,
            usefulness_proven=True,
            retrieval_evidence_sha256=None,
        )


def test_result_cannot_claim_useful_context_without_retrieval_evidence() -> None:
    with pytest.raises(ValueError, match="retrieval evidence"):
        EvaluationResult(
            family="long_context_retrieval",
            status="completed",
            metrics={"retrieval_accuracy": 1.0},
            useful_context_proven=True,
        )


def test_candidate_execution_requires_full_authorized_lock() -> None:
    with pytest.raises(CandidateExecutionBlocked, match="blocked"):
        assert_candidate_execution_allowed(
            {"status": "pending_threshold_authority", "promotion_authorized": False}
        )

    with pytest.raises(CandidateExecutionBlocked, match="blocked"):
        assert_candidate_execution_allowed(
            {"status": "locked", "promotion_authorized": True, "candidate_execution": "allowed"}
        )
