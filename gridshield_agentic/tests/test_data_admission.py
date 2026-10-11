
import pytest

from gridshield.agents import data_admission_node


def confirmed_candidate_state():
    return {
        "event_id": "admission-001",
        "attack_probability": 0.78,
        "human_review_status": "confirmed_attack",
        "human_verified_attack": True,
        "candidate_sample": {
            "event_id": "admission-001",
            "status": "awaiting_human_review",
        },
        "sample_eligible": False,
        "audit_events": [],
    }


def test_admission_requires_human_confirmation():
    state = confirmed_candidate_state()
    state["human_review_status"] = "pending"

    with pytest.raises(ValueError):
        data_admission_node(state)


def test_admission_rejects_mismatched_candidate():
    state = confirmed_candidate_state()
    state["candidate_sample"]["event_id"] = "different-event"

    with pytest.raises(ValueError):
        data_admission_node(state)


def test_admission_requires_verification_flag():
    state = confirmed_candidate_state()
    state["human_verified_attack"] = False

    with pytest.raises(ValueError):
        data_admission_node(state)
