
import os
from contextlib import contextmanager
from pathlib import Path

from dotenv import load_dotenv
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from langgraph.checkpoint.postgres import PostgresSaver


@contextmanager
def postgres_checkpointer():
    """Yield a PostgreSQL-backed LangGraph checkpointer."""

    project_root = Path(__file__).resolve().parents[1]
    load_dotenv(project_root / ".env", override=False)

    required = ("PGHOST", "PGDATABASE", "PGUSER", "PGPASSWORD")
    missing = [key for key in required if not os.getenv(key)]

    if missing:
        raise RuntimeError(
            f"Missing PostgreSQL settings: {', '.join(missing)}"
        )

    conninfo = (
        f"host={os.environ['PGHOST']} "
        f"port={os.getenv('PGPORT', '5432')} "
        f"dbname={os.environ['PGDATABASE']} "
        f"user={os.environ['PGUSER']} "
        f"password={os.environ['PGPASSWORD']}"
    )

    with ConnectionPool(
        conninfo=conninfo,
        min_size=1,
        max_size=5,
        kwargs={
            "row_factory": dict_row,
            "autocommit": True,
        },
        open=True,
    ) as pool:
        checkpointer = PostgresSaver(pool)
        checkpointer.setup()
        yield checkpointer
