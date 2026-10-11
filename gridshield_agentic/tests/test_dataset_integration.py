
from gridshield import agents
from gridshield.repository import JsonSampleRepository


def approved_state(event_id="integration-001"):
    return {
        "event_id": event_id,
        "human_review_status": "confirmed_attack",
        "human_verified_attack": True,
        "data_admission_status": "approved",
        "candidate_sample": {
            "event_id": event_id,
            "measurements": {
                "voltageMU1": 0.75,
                "frequencyMU1": 50.0,
            },
            "status": "awaiting_human_review",
        },
        "sample_eligible": False,
        "audit_events": [],
    }


def test_dataset_agent_persists_validated_candidate(tmp_path, monkeypatch):
    monkeypatch.setattr(
        agents,
        "SAMPLE_REPOSITORY_PATH",
        tmp_path / "samples.json",
    )
    monkeypatch.setattr(agents, "_sample_repository", None)

    result = agents.dataset_management_node(approved_state())

    assert result["repository_inserted"] is True
    assert result["candidate_sample"]["status"] == "stored_pending_eligibility"
    assert result["sample_eligible"] is False

    repo = JsonSampleRepository(tmp_path / "samples.json")
    stored = repo.get("integration-001")

    assert stored is not None
    assert stored["eligible_for_training"] is False


def test_duplicate_candidate_is_not_inserted_twice(tmp_path, monkeypatch):
    monkeypatch.setattr(
        agents,
        "SAMPLE_REPOSITORY_PATH",
        tmp_path / "samples.json",
    )
    monkeypatch.setattr(agents, "_sample_repository", None)

    first = agents.dataset_management_node(approved_state())
    second = agents.dataset_management_node(approved_state())

    assert first["repository_inserted"] is True
    assert second["repository_inserted"] is False
    assert second["repository_status"] == "duplicate_event_id"
    assert second["sample_eligible"] is False
