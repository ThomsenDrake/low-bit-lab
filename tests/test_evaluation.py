from lowbit_lab.evaluation import EVALUATION_FAMILIES, placeholder_result


def test_all_placeholder_families_disclaim_proof() -> None:
    assert len(EVALUATION_FAMILIES) == 6
    for family in EVALUATION_FAMILIES:
        result = placeholder_result(family)
        assert result.status == "placeholder_not_executed"
        assert result.useful_context_proven is False
