import pytest
from gridshield.routing import route_attack_probability


@pytest.mark.parametrize(
    ("probability", "expected"),
    [
        (1.0, "high_confidence_attack"),
        (0.90, "high_confidence_attack"),
        (0.899, "potential_new_attack"),
        (0.70, "potential_new_attack"),
        (0.699, "human_review"),
        (0.30, "human_review"),
        (0.299, "below_attack_collection_threshold"),
        (0.0, "below_attack_collection_threshold"),
    ],
)
def test_route_boundaries(probability, expected):
    assert route_attack_probability(probability) == expected


@pytest.mark.parametrize("probability", [-0.01, 1.01])
def test_invalid_probability(probability):
    with pytest.raises(ValueError):
        route_attack_probability(probability)
