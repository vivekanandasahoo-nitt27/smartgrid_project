
import pytest

from gridshield import agents
from gridshield.repository import JsonSampleRepository


def test_eligibility_node_promotes_persisted_sample(
    tmp_path, monkeypatch
):
    repository = JsonSampleRepository(tmp_path / "samples.json")
    repository.admit({
        "event_id": "event-001",
        "measurements": {"voltage": 0.85},
        "status": "validated_pending_persistence",
        "eligible_for_training": False,
    })

    monkeypatch.setattr(
        agents,
        "get_sample_repository",
        lambda: repository,
    )

    state = {
        "event_id": "event-001",
        "candidate_sample": {
            "event_id": "event-001",
            "measurements": {"voltage": 0.85},
        },
        "human_review_status": "confirmed_attack",
        "human_verified_attack": True,
        "data_admission_status": "approved",
        "audit_events": [],
    }

    result = agents.eligibility_management_node(state)

    assert result["sample_eligible"] is True
    assert result["candidate_sample"]["eligible_for_training"] is True
    assert repository.count_eligible() == 1



def test_eligibility_node_rejects_unapproved_admission(
    tmp_path, monkeypatch
):
    repository = JsonSampleRepository(tmp_path / "samples.json")
    repository.admit({
        "event_id": "event-002",
        "measurements": {"voltage": 0.85},
        "status": "validated_pending_persistence",
        "eligible_for_training": False,
    })

    monkeypatch.setattr(
        agents,
        "get_sample_repository",
        lambda: repository,
    )

    state = {
        "event_id": "event-002",
        "candidate_sample": {
            "event_id": "event-002",
            "measurements": {"voltage": 0.85},
        },
        "human_review_status": "confirmed_attack",
        "human_verified_attack": True,
        "data_admission_status": "rejected",
        "audit_events": [],
    }

    with pytest.raises(ValueError, match="approved data admission"):
        agents.eligibility_management_node(state)

    assert repository.count_eligible() == 0




def test_eligibility_node_is_idempotent(
    tmp_path, monkeypatch
):
    repository = JsonSampleRepository(tmp_path / "samples.json")
    repository.admit({
        "event_id": "event-003",
        "measurements": {"voltage": 0.85},
        "status": "validated_pending_persistence",
        "eligible_for_training": False,
    })

    monkeypatch.setattr(
        agents,
        "get_sample_repository",
        lambda: repository,
    )

    state = {
        "event_id": "event-003",
        "candidate_sample": {
            "event_id": "event-003",
            "measurements": {"voltage": 0.85},
        },
        "human_review_status": "confirmed_attack",
        "human_verified_attack": True,
        "data_admission_status": "approved",
        "audit_events": [],
    }

    first = agents.eligibility_management_node(state)

    second = agents.eligibility_management_node({
        **state,
        "candidate_sample": first["candidate_sample"],
    })

    assert first["sample_eligible"] is True
    assert second["sample_eligible"] is True
    assert repository.count_eligible() == 1
