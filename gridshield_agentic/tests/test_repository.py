
import pytest

from gridshield.repository import JsonSampleRepository
def make_stored_repository(tmp_path):
    repo = JsonSampleRepository(tmp_path / "samples.json")

    repo.admit({
        "event_id": "event-001",
        "measurements": {"voltage": 0.85},
        "status": "validated_pending_persistence",
        "eligible_for_training": False,
    })

    return repo


def test_promote_confirmed_approved_sample(tmp_path):
    repo = make_stored_repository(tmp_path)

    result = repo.promote_to_eligible(
        "event-001",
        human_review_status="confirmed_attack",
        human_verified_attack=True,
        data_admission_status="approved",
        validation_passed=True,
    )

    assert result["promoted"] is True
    assert result["sample"]["eligible_for_training"] is True
    assert result["sample"]["verified_label"] == 1
    assert repo.count_eligible() == 1


def test_rejected_admission_cannot_promote(tmp_path):
    repo = make_stored_repository(tmp_path)

    with pytest.raises(ValueError, match="Data admission"):
        repo.promote_to_eligible(
            "event-001",
            human_review_status="confirmed_attack",
            human_verified_attack=True,
            data_admission_status="rejected",
            validation_passed=True,
        )

    assert repo.count_eligible() == 0


def test_failed_validation_cannot_promote(tmp_path):
    repo = make_stored_repository(tmp_path)

    with pytest.raises(ValueError, match="validation"):
        repo.promote_to_eligible(
            "event-001",
            human_review_status="confirmed_attack",
            human_verified_attack=True,
            data_admission_status="approved",
            validation_passed=False,
        )

    assert repo.count_eligible() == 0


def test_promoting_twice_does_not_double_count(tmp_path):
    repo = make_stored_repository(tmp_path)

    approval = {
        "human_review_status": "confirmed_attack",
        "human_verified_attack": True,
        "data_admission_status": "approved",
        "validation_passed": True,
    }

    first = repo.promote_to_eligible("event-001", **approval)
    second = repo.promote_to_eligible("event-001", **approval)

    assert first["promoted"] is True
    assert second["promoted"] is False
    assert second["reason"] == "already_eligible"
    assert repo.count_eligible() == 1
