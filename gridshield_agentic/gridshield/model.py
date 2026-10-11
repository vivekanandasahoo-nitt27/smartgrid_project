from pathlib import Path
import joblib
import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[1]
ARTIFACT_DIR = BASE_DIR / "artifacts"
MODEL_PATH = ARTIFACT_DIR / "smartgrid_rf_model3.pkl"
FEATURES_PATH = ARTIFACT_DIR / "feature_columns3.pkl"

_model = None
_feature_columns = None


def load_model():
    """Load model lazily, after the artifact files have been copied into artifacts/."""
    global _model, _feature_columns
    if _model is None:
        if not MODEL_PATH.exists() or not FEATURES_PATH.exists():
            raise FileNotFoundError(
                "Copy smartgrid_rf_model3(3).pkl and feature_columns3(5).pkl "
                "into the project's artifacts/ folder first."
            )
        _model = joblib.load(MODEL_PATH)
        _feature_columns = list(joblib.load(FEATURES_PATH))
        if len(_feature_columns) != _model.n_features_in_:
            raise ValueError(
                f"Model expects {_model.n_features_in_} features, "
                f"but feature file contains {len(_feature_columns)}."
            )
    return _model, _feature_columns


def classify_measurements(measurements: dict) -> dict:
    model, feature_columns = load_model()
    missing = [name for name in feature_columns if name not in measurements]
    if missing:
        raise ValueError(f"Missing required features: {missing}")

    row = pd.DataFrame(
        [[measurements[name] for name in feature_columns]],
        columns=feature_columns,
    )
    probabilities = model.predict_proba(row)[0]
    predicted_class = int(model.predict(row)[0])

    attack_indices = [
        i for i, label in enumerate(model.classes_) if int(label) == 1
    ]
    if len(attack_indices) != 1:
        raise ValueError(
            f"Expected exactly one attack class with label 1; got {model.classes_!r}"
        )

    return {
        "predicted_class": predicted_class,
        "attack_probability": float(probabilities[attack_indices[0]]),
        "class_probabilities": {
            str(label): float(prob)
            for label, prob in zip(model.classes_, probabilities)
        },
    }
