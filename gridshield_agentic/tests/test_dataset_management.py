
import pytest

from gridshield.agents import dataset_management_node


def valid_state():
    return {
        "event_id": "dataset-001",
        "human_review_status": "confirmed_attack",
        "human_verified_attack": True,
        "data_admission_status": "approved",
        "candidate_sample": {
            "event_id": "dataset-001",
            "measurements": {
                "voltageMU1": 0.75,
                "frequencyMU1": 50.0,
            },
        },
        "sample_eligible": False,
        "audit_events": [],
    }


def test_valid_candidate_passes_validation():
    result = dataset_management_node(valid_state())

    assert result["sample_eligible"] is False
    assert result["candidate_sample"]["status"] == (
        "stored_pending_eligibility"

    )
    assert result["candidate_sample"]["eligible_for_training"] is False


def test_unapproved_candidate_is_rejected():
    state = valid_state()
    state["data_admission_status"] = "pending"

    with pytest.raises(ValueError):
        dataset_management_node(state)


def test_non_finite_measurement_is_rejected():
    state = valid_state()
    state["candidate_sample"]["measurements"]["voltageMU1"] = float("nan")

    with pytest.raises(ValueError):
        dataset_management_node(state)


def test_candidate_event_id_must_match():
    state = valid_state()
    state["candidate_sample"]["event_id"] = "different-event"

    with pytest.raises(ValueError):
        dataset_management_node(state)
