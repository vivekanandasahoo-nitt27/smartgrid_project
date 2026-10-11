
import json
from pathlib import Path
from threading import RLock
from typing import Any


class JsonSampleRepository:
    """Local development repository with event-ID deduplication."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._initialize()

    def _initialize(self) -> None:
        with self._lock:
            if not self.path.exists():
                self.path.write_text("{}", encoding="utf-8")

            data = self._read()
            if not isinstance(data, dict):
                raise ValueError("Repository must contain a JSON object")

    def _read(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("Repository JSON is corrupted") from exc

        if not isinstance(data, dict):
            raise ValueError("Repository must contain a JSON object")

        return data

    def _write(self, data: dict[str, Any]) -> None:
        temp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        temp_path.write_text(
            json.dumps(data, indent=2, allow_nan=False),
            encoding="utf-8",
        )
        temp_path.replace(self.path)

    def admit(self, sample: dict[str, Any]) -> dict[str, Any]:
        """Persist one validated sample; never count an event ID twice."""

        event_id = sample.get("event_id")
        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError("Sample requires a valid event_id")

        if sample.get("status") != "validated_pending_persistence":
            raise ValueError("Sample has not passed dataset validation")

        if sample.get("eligible_for_training") is not False:
            raise ValueError("Sample must not already be marked eligible")

        with self._lock:
            data = self._read()

            if event_id in data:
                return {
                    "inserted": False,
                    "reason": "duplicate_event_id",
                    "sample": data[event_id],
                }

            stored_sample = {
                **sample,
                "status": "stored_pending_eligibility",
                "eligible_for_training": False,
            }
            data[event_id] = stored_sample
            self._write(data)

            return {
                "inserted": True,
                "reason": "stored_pending_eligibility",
                "sample": stored_sample,
            }
    
    
    def get(self, event_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._read().get(event_id)

    def count_eligible(self) -> int:
        with self._lock:
            data = self._read()
            return sum(
                sample.get("eligible_for_training") is True
                for sample in data.values()
            )
    
    def promote_to_eligible(
        self,
        event_id: str,
        *,
        human_review_status: str,
        human_verified_attack: bool,
        data_admission_status: str,
        validation_passed: bool,
    ) -> dict[str, Any]:
        """Promote a stored sample only after all required gates pass."""

        # Check every approval gate before changing the repository.
        if human_review_status != "confirmed_attack":
            raise ValueError("Human review has not confirmed an attack")

        if human_verified_attack is not True:
            raise ValueError("Attack verification is required")

        if data_admission_status != "approved":
            raise ValueError("Data admission has not been approved")

        if validation_passed is not True:
            raise ValueError("Dataset validation has not passed")

        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError("A valid event_id is required")

        with self._lock:
            data = self._read()
            sample = data.get(event_id)

            if sample is None:
                raise ValueError("Sample does not exist in the repository")

            if sample.get("status") == "eligible_for_training":
                if sample.get("eligible_for_training") is True:
                    return {
                        "promoted": False,
                        "reason": "already_eligible",
                        "sample": sample,
                    }

            if sample.get("status") != "stored_pending_eligibility":
                raise ValueError(
                    "Sample is not awaiting eligibility"
                )

            if sample.get("eligible_for_training") is not False:
                raise ValueError(
                    "Sample must be stored as ineligible before promotion"
                )

            from datetime import datetime, timezone

            updated_sample = {
                **sample,
                "status": "eligible_for_training",
                "eligible_for_training": True,
                "verified_label": 1,
                "eligibility_approved_at": (
                    datetime.now(timezone.utc).isoformat()
                ),
            }

            data[event_id] = updated_sample
            self._write(data)

            return {
                "promoted": True,
                "reason": "eligibility_approved",
                "sample": updated_sample,
            }




class PostgresSampleRepository:
    """PostgreSQL repository for human-reviewed attack events."""

    def __init__(self, env_path=None):
        import os
        from dotenv import load_dotenv

        project_root = Path(__file__).resolve().parents[1]
        load_dotenv(env_path or project_root / ".env")

        self.db_config = {
            "host": os.getenv("PGHOST", "localhost"),
            "port": os.getenv("PGPORT", "5432"),
            "dbname": os.getenv("PGDATABASE", "gridshield_db"),
            "user": os.getenv("PGUSER", "postgres"),
            "password": os.getenv("PGPASSWORD"),
        }

        if not self.db_config["password"]:
            raise RuntimeError("PGPASSWORD is missing from .env")

        # Fail early if PostgreSQL is unreachable.
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")

    def _connect(self):
        import psycopg
        return psycopg.connect(**self.db_config)

    @staticmethod
    def _row_to_sample(row):
        if row is None:
            return None

        sample = {
            "event_id": row["event_id"],
            "measurements": row["measurements"],
            "attack_probability": row["attack_probability"],
            "confidence_route": row["confidence_route"],
            "status": row["status"],
            "eligible_for_training": row["eligible_for_training"],
            "human_review_status": row["human_review_status"],
            "human_verified_attack": row["human_verified_attack"],
            "data_admission_status": row["data_admission_status"],
            "verified_label": row["verified_label"],
        }

        if row["eligibility_approved_at"] is not None:
            sample["eligibility_approved_at"] = (
                row["eligibility_approved_at"].isoformat()
            )

        return sample

    def admit(self, sample):
        """Persist a validated sample as ineligible; deduplicate by event ID."""

        event_id = sample.get("event_id")
        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError("Sample requires a valid event_id")

        if sample.get("status") != "validated_pending_persistence":
            raise ValueError("Sample has not passed dataset validation")

        if sample.get("eligible_for_training") is not False:
            raise ValueError("Sample must not already be marked eligible")

        measurements = sample.get("measurements")
        if not isinstance(measurements, dict) or not measurements:
            raise ValueError("Sample requires measurements")

        probability = sample.get("attack_probability")
        if (
            not isinstance(probability, (int, float))
            or isinstance(probability, bool)
            or not 0.0 <= probability <= 1.0
        ):
            raise ValueError("Sample requires a valid attack probability")

        from psycopg.types.json import Jsonb
        from psycopg.rows import dict_row

        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    INSERT INTO gridshield_attack_events (
                        event_id,
                        measurements,
                        attack_probability,
                        confidence_route,
                        status,
                        eligible_for_training,
                        human_review_status,
                        human_verified_attack,
                        data_admission_status
                    )
                    VALUES (%s, %s, %s, %s, %s, FALSE,
                            %s, %s, %s)
                    ON CONFLICT (event_id) DO NOTHING
                    RETURNING *
                    """,
                    (
                        event_id,
                        Jsonb(measurements),
                        float(probability),
                        sample.get("confidence_route", "unknown"),
                        "stored_pending_eligibility",
                        sample.get("human_review_status", "confirmed_attack"),
                        sample.get("human_verified_attack", False),
                        sample.get("data_admission_status", "approved"),
                    ),
                )
                row = cur.fetchone()

                if row is not None:
                    return {
                        "inserted": True,
                        "reason": "stored_pending_eligibility",
                        "sample": self._row_to_sample(row),
                    }

                # Return the existing record without overwriting it.
                cur.execute(
                    """
                    SELECT * FROM gridshield_attack_events
                    WHERE event_id = %s
                    """,
                    (event_id,),
                )
                existing = cur.fetchone()

                return {
                    "inserted": False,
                    "reason": "duplicate_event_id",
                    "sample": self._row_to_sample(existing),
                }
    def register_pending_review(self, sample):
        """Persist a reviewable incident without admitting it to training."""
        event_id = sample.get("event_id")
        measurements = sample.get("measurements")
        probability = sample.get("attack_probability")

        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError("A valid event_id is required")
        if not isinstance(measurements, dict) or not measurements:
            raise ValueError("Measurements are required")
        if (
            not isinstance(probability, (int, float))
            or isinstance(probability, bool)
            or not 0.0 <= probability <= 1.0
        ):
            raise ValueError("A valid attack probability is required")

        from psycopg.rows import dict_row
        from psycopg.types.json import Jsonb

        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    INSERT INTO gridshield_attack_events (
                        event_id, measurements, attack_probability,
                        confidence_route, status, eligible_for_training,
                        human_review_status, human_verified_attack,
                        data_admission_status
                    )
                    VALUES (%s, %s, %s, %s, FALSE,
                            'pending', FALSE, FALSE, 'pending')
                    ON CONFLICT (event_id) DO NOTHING
                    RETURNING *
                    """,
                    (
                        event_id,
                        Jsonb(measurements),
                        float(probability),
                        sample.get("confidence_route", "unknown"),
                    ),
                )
                row = cur.fetchone()

                if row is None:
                    cur.execute(
                        """
                        SELECT * FROM gridshield_attack_events
                        WHERE event_id = %s
                        """,
                        (event_id,),
                    )
                    row = cur.fetchone()

                if row is None:
                    raise RuntimeError("Could not persist pending incident")

                return self._row_to_sample(row)

    def list_pending_reviews(self):
        """Return incidents awaiting the first officer decision."""
        from psycopg.rows import dict_row

        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT *
                    FROM gridshield_attack_events
                    WHERE human_review_status = 'pending'
                        AND status = 'pending'
                        AND human_verified_attack = FALSE
                    ORDER BY created_at ASC
                    """
                )
                return [
                    self._row_to_sample(row)
                    for row in cur.fetchall()
                ]



    def get(self, event_id):
        from psycopg.rows import dict_row

        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT * FROM gridshield_attack_events
                    WHERE event_id = %s
                    """,
                    (event_id,),
                )
                return self._row_to_sample(cur.fetchone())

    def count_eligible(self):
        """Count only approved, eligible attack events."""

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM gridshield_attack_events
                    WHERE eligible_for_training = TRUE
                      AND status = 'eligible_for_training'
                      AND human_review_status = 'confirmed_attack'
                      AND human_verified_attack = TRUE
                      AND data_admission_status = 'approved'
                      AND verified_label = 1
                    """
                )
                return cur.fetchone()[0]

    def promote_to_eligible(
        self,
        event_id,
        *,
        human_review_status,
        human_verified_attack,
        data_admission_status,
        validation_passed,
    ):
        """Promote only after every approval and validation gate passes."""

        if human_review_status != "confirmed_attack":
            raise ValueError("Human review has not confirmed an attack")

        if human_verified_attack is not True:
            raise ValueError("Attack verification is required")

        if data_admission_status != "approved":
            raise ValueError("Data admission has not been approved")

        if validation_passed is not True:
            raise ValueError("Dataset validation has not passed")

        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError("A valid event_id is required")

        from psycopg.rows import dict_row

        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT * FROM gridshield_attack_events
                    WHERE event_id = %s
                    FOR UPDATE
                    """,
                    (event_id,),
                )
                row = cur.fetchone()

                if row is None:
                    raise ValueError(
                        "Sample does not exist in the repository"
                    )

                sample = self._row_to_sample(row)

                if (
                    sample["status"] == "eligible_for_training"
                    and sample["eligible_for_training"] is True
                ):
                    return {
                        "promoted": False,
                        "reason": "already_eligible",
                        "sample": sample,
                    }

                if sample["status"] != "stored_pending_eligibility":
                    raise ValueError("Sample is not awaiting eligibility")

                if sample["eligible_for_training"] is not False:
                    raise ValueError(
                        "Sample must be ineligible before promotion"
                    )

                cur.execute(
                    """
                    UPDATE gridshield_attack_events
                    SET status = 'eligible_for_training',
                        eligible_for_training = TRUE,
                        human_review_status = %s,
                        human_verified_attack = TRUE,
                        data_admission_status = %s,
                        verified_label = 1,
                        eligibility_approved_at = NOW()
                    WHERE event_id = %s
                    RETURNING *
                    """,
                    (
                        human_review_status,
                        data_admission_status,
                        event_id,
                    ),
                )
                updated = self._row_to_sample(cur.fetchone())

                return {
                    "promoted": True,
                    "reason": "eligibility_approved",
                    "sample": updated,
                }

