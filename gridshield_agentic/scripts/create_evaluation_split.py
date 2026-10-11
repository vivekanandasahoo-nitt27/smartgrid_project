from pathlib import Path
import json
import pandas as pd
from sklearn.model_selection import train_test_split

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = PROJECT_ROOT / "data" / "raw"
EVAL_DIR = PROJECT_ROOT / "data" / "evaluation"
TRAIN_DIR = PROJECT_ROOT / "data" / "baseline_split"

def main():
    healthy = pd.read_csv(RAW_DIR / "complete_healthy_clean.csv")
    fault = pd.read_csv(RAW_DIR / "combined_fault_dataset.csv")
    attack = pd.read_csv(RAW_DIR / "final_new_attack1.csv")

    # Match the notebook: fault dataset establishes feature-column order.
    expected_columns = list(fault.columns)
    healthy = healthy[expected_columns]
    attack = attack[expected_columns]

    # The supplied fault CSV contains 510 duplicate rows; the notebook's stated
    # combined dataset size of 30,330 matches deduplicating these rows.
    fault = fault.drop_duplicates().reset_index(drop=True)

    combined = pd.concat([healthy, fault, attack], ignore_index=True)
    combined = combined.reset_index(drop=True)

    if "class" not in combined.columns:
        raise ValueError("Expected target column 'class' is missing.")
    if combined["class"].isna().any():
        raise ValueError("Target column contains missing values.")
    labels = set(combined["class"].astype(int).unique())
    if labels != {0, 1, 2}:
        raise ValueError(f"Expected class labels {{0, 1, 2}}, got {labels}")

    X = combined.drop(columns=["class"])
    y = combined["class"].astype(int)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, shuffle=True, stratify=y
    )

    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    TRAIN_DIR.mkdir(parents=True, exist_ok=True)
    X_test.to_csv(EVAL_DIR / "X_test.csv", index=False)
    y_test.rename("class").to_frame().to_csv(EVAL_DIR / "y_test.csv", index=False)
    X_train.to_csv(TRAIN_DIR / "X_train.csv", index=False)
    y_train.rename("class").to_frame().to_csv(TRAIN_DIR / "y_train.csv", index=False)

    manifest = {
        "combined_rows": len(combined),
        "feature_count": X.shape[1],
        "class_mapping": {"0": "healthy", "1": "attack", "2": "fault"},
        "split": {"test_size": 0.2, "random_state": 42, "shuffle": True, "stratify": "class"},
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "train_class_counts": {str(int(k)): int(v) for k, v in y_train.value_counts().sort_index().items()},
        "test_class_counts": {str(int(k)): int(v) for k, v in y_test.value_counts().sort_index().items()},
    }
    (EVAL_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))

if __name__ == "__main__":
    main()
