
import os
from uuid import uuid4

import pytest
from langgraph.checkpoint.postgres import PostgresSaver
from psycopg_pool import ConnectionPool

from langgraph.checkpoint.base import empty_checkpoint
@pytest.mark.skipif(
    os.getenv("GRIDSHIELD_RUN_POSTGRES_TESTS") != "1",
    reason="Set GRIDSHIELD_RUN_POSTGRES_TESTS=1 to test PostgreSQL",
)
def test_postgres_checkpointer_can_save_and_read_checkpoint():
    from gridshield.postgres_checkpointer import postgres_checkpointer

    with postgres_checkpointer() as checkpointer:
        assert isinstance(checkpointer, PostgresSaver)

        thread_id = f"gridshield-checkpoint-test-{uuid4()}"
        config = {
        "configurable": {
            "thread_id": thread_id,
            "checkpoint_ns": "",
        }
    }

        # Confirm this unique thread has no previous checkpoint.
        assert checkpointer.get_tuple(config) is None

        # Create and save a real checkpoint.
        checkpoint = empty_checkpoint()
        checkpoint["channel_values"] = {
            "smoke_test_value": "gridshield-persistence-works"
        }

        metadata = {
            "source": "input",
            "step": 0,
            "writes": {"smoke_test": "saved"},
            "parents": {},
        }

        saved_config = checkpointer.put(
            config,
            checkpoint,
            metadata,
            {},
        )

        # Read the checkpoint back from PostgreSQL.
        saved = checkpointer.get_tuple(saved_config)

        assert saved is not None
        assert (
            saved.checkpoint["channel_values"]["smoke_test_value"]
            == "gridshield-persistence-works"
        )
        assert saved.metadata["source"] == "input"
