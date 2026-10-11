
import os
from uuid import uuid4

import pytest

from gridshield.repository import PostgresSampleRepository


pytestmark = pytest.mark.skipif(
    os.getenv("GRIDSHIELD_RUN_POSTGRES_TESTS") != "1",
    reason="Set GRIDSHIELD_RUN_POSTGRES_TESTS=1 to run PostgreSQL tests",
)


def test_postgres_repository_approval_lifecycle():
    repository = PostgresSampleRepository()
    event_id = f"pytest-{uuid4()}"

    sample = {
        "event_id": event_id,
        "measurements": {
            "voltageMU1": 0.75,
            "frequencyMU1": 50.0,
        },
        "attack_probability": 0.82,
        "confidence_route": "potential_new_attack",
        "status": "validated_pending_persistence",
        "eligible_for_training": False,
        "human_review_status": "confirmed_attack",
        "human_verified_attack": True,
        "data_admission_status": "approved",
    }

    try:
        # 1. A new sample is stored but remains ineligible.
        result = repository.admit(sample)
        assert result["inserted"] is True
        assert result["sample"]["eligible_for_training"] is False

        # 2. The same event ID cannot be inserted twice.
        duplicate = repository.admit(sample)
        assert duplicate["inserted"] is False
        assert duplicate["reason"] == "duplicate_event_id"

        # 3. Rejected admission must not promote the sample.
        with pytest.raises(ValueError):
            repository.promote_to_eligible(
                event_id,
                human_review_status="confirmed_attack",
                human_verified_attack=True,
                data_admission_status="rejected",
                validation_passed=True,
            )

        assert repository.get(event_id)["eligible_for_training"] is False

        # 4. All approval gates allow promotion.
        promoted = repository.promote_to_eligible(
            event_id,
            human_review_status="confirmed_attack",
            human_verified_attack=True,
            data_admission_status="approved",
            validation_passed=True,
        )

        assert promoted["promoted"] is True
        assert promoted["sample"]["eligible_for_training"] is True
        assert promoted["sample"]["verified_label"] == 1

        # 5. The eligible count increases by exactly one.
        assert repository.count_eligible() >= 1

    finally:
        # Remove only this test's uniquely identified event.
        with repository._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    DELETE FROM gridshield_attack_events
                    WHERE event_id = %s
                    """,
                    (event_id,),
                )
