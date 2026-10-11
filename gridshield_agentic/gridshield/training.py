
from __future__ import annotations

import pandas as pd

from gridshield.repository import PostgresSampleRepository


def load_baseline_training_data() -> tuple[pd.DataFrame, pd.Series]:
    """Load only curated baseline rows assigned to the training split."""

    repository = PostgresSampleRepository()

    with repository._connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT measurements, label
                FROM gridshield_samples
                WHERE dataset_role = 'training'
                ORDER BY id
                """
            )
            rows = cur.fetchall()

    if not rows:
        raise ValueError("No baseline training records found in PostgreSQL.")

    X = pd.DataFrame([row[0] for row in rows])
        # Enforce the active model's exact feature order.
    from gridshield.model import load_model

    _, expected_features = load_model()

    if set(X.columns) != set(expected_features):
        missing = sorted(set(expected_features) - set(X.columns))
        unexpected = sorted(set(X.columns) - set(expected_features))
        raise ValueError(
            f"Feature mismatch. Missing: {missing}; "
            f"unexpected: {unexpected}"
        )

    X = X[expected_features]
    y = pd.Series([row[1] for row in rows], name="label", dtype="int64")

    if X.empty:
        raise ValueError("Baseline training features are empty.")

    if X.isna().any().any() or y.isna().any():
        raise ValueError("Training data contains missing values.")

    if not set(y.unique()).issubset({0, 1, 2}):
        raise ValueError("Training data contains unsupported labels.")

    if X.columns.duplicated().any():
        raise ValueError("Training data contains duplicate feature names.")

    return X, y
