
import pytest

from gridshield.agents import candidate_collection_node


def test_candidate_starts_pending_and_ineligible():
    state = {
        "event_id": "candidate-001",
        "measurements": {"voltageMU1": 0.75},
        "attack_probability": 0.78,
        "confidence_route": "potential_new_attack",
        "audit_events": [],
    }

    result = candidate_collection_node(state)

    assert result["candidate_sample"]["status"] == "awaiting_human_review"
    assert result["candidate_sample"]["eligible_for_training"] is False
    assert result["human_review_status"] == "pending"
    assert result["data_admission_status"] == "pending"
    assert result["sample_eligible"] is False


def test_candidate_rejects_wrong_confidence_route():
    state = {
        "event_id": "candidate-002",
        "measurements": {"voltageMU1": 0.75},
        "attack_probability": 0.78,
        "confidence_route": "high_confidence_attack",
        "audit_events": [],
    }

    with pytest.raises(ValueError):
        candidate_collection_node(state)

def test_human_review_route_can_create_candidate():
    state = {
        "event_id": "candidate-human-review-001",
        "measurements": {"voltageMU1": 0.75},
        "attack_probability": 0.50,
        "confidence_route": "human_review",
        "audit_events": [],
    }

    result = candidate_collection_node(state)

    assert result["candidate_sample"]["event_id"] == (
        "candidate-human-review-001"
    )
    assert result["candidate_sample"]["confidence_route"] == "human_review"
    assert result["candidate_sample"]["status"] == "awaiting_human_review"
    assert result["candidate_sample"]["eligible_for_training"] is False
    assert result["human_review_status"] == "pending"
    assert result["data_admission_status"] == "pending"
    assert result["sample_eligible"] is False

