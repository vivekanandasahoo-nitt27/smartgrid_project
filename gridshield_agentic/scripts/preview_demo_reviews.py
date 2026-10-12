
from pathlib import Path

import joblib
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]

MODEL_PATH = ROOT / "artifacts" / "smartgrid_rf_model3.pkl"
FEATURES_PATH = ROOT / "artifacts" / "feature_columns3.pkl"

X_PATH = ROOT / "data" / "evaluation" / "X_test.csv"
Y_PATH = ROOT / "data" / "evaluation" / "y_test.csv"

OUTPUT_PATH = (
    ROOT / "data" / "evaluation" / "demo_review_preview.csv"
)


def main():
    # 1. Verify all required files exist.
    for path in [MODEL_PATH, FEATURES_PATH, X_PATH, Y_PATH]:
        if not path.exists():
            raise FileNotFoundError(f"Required file not found: {path}")

    print("Loading the original trained model...")
    model = joblib.load(MODEL_PATH)
    feature_columns = list(joblib.load(FEATURES_PATH))

    print("Model:", MODEL_PATH.name)
    print("Feature schema:", FEATURES_PATH.name)
    print("Model expected features:", model.n_features_in_)
    print("Feature-column file count:", len(feature_columns))

    if len(feature_columns) != model.n_features_in_:
        raise ValueError(
            "The feature-column file does not match the model's "
            "expected input feature count."
        )

    # 2. Load the held-out evaluation data.
    X = pd.read_csv(X_PATH)
    y_df = pd.read_csv(Y_PATH)

    if "class" not in y_df.columns:
        raise ValueError("Expected the target column 'class' in y_test.csv.")

    y = y_df["class"]

    if len(X) != len(y):
        raise ValueError("X_test and y_test row counts do not match.")

    missing = [c for c in feature_columns if c not in X.columns]
    extra = [c for c in X.columns if c not in feature_columns]

    if missing or extra:
        raise ValueError(
            f"Feature schema mismatch. Missing: {missing}; extra: {extra}"
        )

    # Use exactly the feature order saved with the original model.
    X_model = X[feature_columns]

    print("Evaluation rows:", len(X_model))
    print("Input shape:", X_model.shape)
    print("Ground-truth class counts:")
    print(y.value_counts().sort_index().to_string())

    # 3. Run the actual model. No fabricated probabilities.
    probabilities = model.predict_proba(X_model)
    predicted_classes = model.predict(X_model)

    class_labels = [int(label) for label in model.classes_]

    if 1 not in class_labels:
        raise ValueError(
            f"Attack class 1 not found in model classes: {class_labels}"
        )

    attack_index = class_labels.index(1)
    attack_probabilities = probabilities[:, attack_index]

    # 4. Build a review preview from real held-out rows.
    preview = X_model.copy()
    preview["ground_truth_class"] = y.to_numpy()
    preview["predicted_class"] = predicted_classes
    preview["attack_probability"] = attack_probabilities

    # Strictly between 30% and 70%, as requested.
    review = preview[
        (preview["attack_probability"] > 0.30)
        & (preview["attack_probability"] < 0.70)
    ].copy()

    print("\nReview-band samples:", len(review))
    print("\nFirst 20 review candidates:")

    if review.empty:
        print("No samples fall strictly inside the 30%-70% band.")
    else:
        print(
            review[
                [
                    "ground_truth_class",
                    "predicted_class",
                    "attack_probability",
                ]
            ].head(20).to_string()
        )

    # This file is only a preview; it does not write to PostgreSQL.
    review.to_csv(OUTPUT_PATH, index=False)
    print("\nPreview CSV saved to:")
    print(OUTPUT_PATH)
    print("\nNo database records were changed.")


if __name__ == "__main__":
    main()
