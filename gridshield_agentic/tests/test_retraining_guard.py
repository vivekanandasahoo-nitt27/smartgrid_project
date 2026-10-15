
from gridshield import agents
from gridshield.repository import JsonSampleRepository


def _add_eligible_samples(repository, count, prefix):
    """Create human-confirmed, approved eligible attack samples."""
    for index in range(count):
        event_id = f"{prefix}-{index:03d}"

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


def _use_repository(repository, monkeypatch):
    """Use an isolated JSON repository for each test."""
    monkeypatch.setattr(
        agents,
        "get_sample_repository",
        lambda: repository,
    )


def test_retraining_guard_blocks_below_100(
    tmp_path, monkeypatch
):
    repository = JsonSampleRepository(
        tmp_path / "samples.json"
    )
    _use_repository(repository, monkeypatch)

    result = agents.retraining_node({})

    assert result["retraining_status"] == (
        "blocked_insufficient_eligible_samples"
    )
    assert result["eligible_attack_sample_count"] == 0
    assert result["training_run_id"] is None


def test_retraining_guard_requires_training_paths_at_100(
    tmp_path, monkeypatch
):
    repository = JsonSampleRepository(
        tmp_path / "samples.json"
    )
    _add_eligible_samples(
        repository,
        count=100,
        prefix="guard-event",
    )
    _use_repository(repository, monkeypatch)

    result = agents.retraining_node({})

    assert repository.count_eligible() == 100
    assert result["eligible_attack_sample_count"] == 100

    # The threshold is reached, but training must not proceed
    # without the required trusted training dataset paths.
    assert result["retraining_status"] == (
        "blocked_missing_training_paths"
    )
    assert result["training_run_id"] is None


def test_retraining_guard_blocks_at_99_eligible_samples(
    tmp_path, monkeypatch
):
    repository = JsonSampleRepository(
        tmp_path / "samples.json"
    )
    _add_eligible_samples(
        repository,
        count=99,
        prefix="guard-99-event",
    )
    _use_repository(repository, monkeypatch)

    result = agents.retraining_node({})

    assert repository.count_eligible() == 99
    assert result["retraining_status"] == (
        "blocked_insufficient_eligible_samples"
    )
    assert result["eligible_attack_sample_count"] == 99
    assert result["training_run_id"] is None
