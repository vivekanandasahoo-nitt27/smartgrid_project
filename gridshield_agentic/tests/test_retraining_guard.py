
from gridshield import agents
from gridshield.repository import JsonSampleRepository


def test_retraining_guard_blocks_below_100(
    tmp_path, monkeypatch
):
    repository = JsonSampleRepository(tmp_path / "samples.json")
    monkeypatch.setattr(
        agents,
        "get_sample_repository",
        lambda: repository,
    )

    result = agents.retraining_node({})

    assert result["retraining_status"] == (
        "blocked_insufficient_eligible_samples"
    )
    assert result["eligible_attack_sample_count"] == 0
    assert result["training_run_id"] is None


def test_retraining_guard_allows_gate_at_100(
    tmp_path, monkeypatch
):
    repository = JsonSampleRepository(tmp_path / "samples.json")

    for index in range(100):
        event_id = f"guard-event-{index:03d}"
        repository.admit({
            "event_id": event_id,
            "measurements": {"voltage": 0.85},
            "status": "validated_pending_persistence",
            "eligible_for_training": False,
        })
        repository.promote_to_eligible(
            event_id,
            human_review_status="confirmed_attack",
            human_verified_attack=True,
            data_admission_status="approved",
            validation_passed=True,
        )

    monkeypatch.setattr(
        agents,
        "get_sample_repository",
        lambda: repository,
    )

    result = agents.retraining_node({})

    assert result["retraining_status"] == "ready_for_training"
    assert result["eligible_attack_sample_count"] == 100
    assert result["training_run_id"] is None

def test_retraining_guard_blocks_at_99_eligible_samples(
    tmp_path, monkeypatch
):
    repository = JsonSampleRepository(tmp_path / "samples.json")

    for index in range(99):
        event_id = f"guard-99-event-{index:03d}"
        repository.admit({
            "event_id": event_id,
            "measurements": {"voltage": 0.85},
            "status": "validated_pending_persistence",
            "eligible_for_training": False,
        })
        repository.promote_to_eligible(
            event_id,
            human_review_status="confirmed_attack",
            human_verified_attack=True,
            data_admission_status="approved",
            validation_passed=True,
        )

    monkeypatch.setattr(
        agents, "get_sample_repository", lambda: repository
    )

    result = agents.retraining_node({})

    assert repository.count_eligible() == 99
    assert result["retraining_status"] == (
        "blocked_insufficient_eligible_samples"
    )
    assert result["eligible_attack_sample_count"] == 99
    assert result["training_run_id"] is None