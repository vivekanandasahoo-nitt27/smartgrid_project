import hashlib
import json
import numpy as np
import pandas as pd
from src.common import TRAIN_X, TRAIN_Y, TEST_X, TEST_Y, VALIDATION_REPORT_PATH, ensure_output_dirs, write_json

def row_hashes(frame):
    return {hashlib.sha256(row.tobytes()).hexdigest() for row in frame.to_numpy(dtype=np.float64)}

def main():
    ensure_output_dirs()
    paths = [TRAIN_X, TRAIN_Y, TEST_X, TEST_Y]
    missing = [str(p) for p in paths if not p.is_file()]
    if missing:
        raise FileNotFoundError("Copy the four fixed CSV files first. Missing: " + ", ".join(missing))

    Xtr, ytr = pd.read_csv(TRAIN_X), pd.read_csv(TRAIN_Y)
    Xte, yte = pd.read_csv(TEST_X), pd.read_csv(TEST_Y)
    errors = []
    if ytr.shape[1] != 1 or yte.shape[1] != 1:
        errors.append("Each label CSV must have exactly one column.")
    if Xtr.empty or Xte.empty:
        errors.append("Feature datasets must not be empty.")
    if list(Xtr.columns) != list(Xte.columns):
        errors.append("Train/test feature columns or order differ.")
    if Xtr.columns.duplicated().any() or Xte.columns.duplicated().any():
        errors.append("Duplicate feature names detected.")
    if len(Xtr) != len(ytr) or len(Xte) != len(yte):
        errors.append("Feature/label row counts differ.")
    for name, df in [("X_train", Xtr), ("X_test", Xte)]:
        if len(df.select_dtypes(exclude=[np.number]).columns):
            errors.append(f"{name} contains non-numeric columns.")
        if df.isna().any().any():
            errors.append(f"{name} contains missing values.")
        if not len(df.select_dtypes(exclude=[np.number]).columns) and not np.isfinite(df.to_numpy(dtype=float)).all():
            errors.append(f"{name} contains non-finite values.")
    for name, df in [("y_train", ytr), ("y_test", yte)]:
        if df.shape[1] == 1:
            values = pd.to_numeric(df.iloc[:, 0], errors="coerce")
            if values.isna().any() or not np.equal(values, np.floor(values)).all() or set(values.astype(int)) != {0, 1, 2}:
                errors.append(f"{name} must contain integer labels 0, 1, 2.")
    overlap = None
    if list(Xtr.columns) == list(Xte.columns) and not Xtr.empty and not Xte.empty:
        overlap = len(row_hashes(Xtr) & row_hashes(Xte))
        if overlap:
            errors.append(f"Exact feature-row overlap: {overlap}")
    report = {
        "validation_status": "passed" if not errors else "failed",
        "errors": errors, "train_rows": len(Xtr), "test_rows": len(Xte),
        "feature_count": Xtr.shape[1], "feature_columns": list(Xtr.columns),
        "train_label_distribution": {str(k): int(v) for k, v in (ytr.iloc[:, 0].value_counts().sort_index().to_dict().items() if ytr.shape[1] == 1 else [])},
        "test_label_distribution": {str(k): int(v) for k, v in (yte.iloc[:, 0].value_counts().sort_index().to_dict().items() if yte.shape[1] == 1 else [])},
        "exact_feature_row_overlap_count": overlap, "evaluation_split_read_only": True
    }
    write_json(VALIDATION_REPORT_PATH, report)
    print(json.dumps(report, indent=2))
    if errors:
        raise SystemExit("Validation failed; do not train until corrected.")

if __name__ == "__main__":
    main()
