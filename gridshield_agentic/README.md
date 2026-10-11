# GridShield Agentic Framework

This is the initial LangGraph scaffold for the agreed GridShield architecture.
It is designed to live as a separate folder inside your existing smart-grid project.

## Setup
1. Copy your existing model and feature-column pickle files into `artifacts/`.
   - `smartgrid_rf_model3(3).pkl`
   - `feature_columns3(5).pkl`
2. Use the Python environment compatible with the scikit-learn version used to save the model (currently expected to be scikit-learn 1.4.2).
3. Install dependencies: `python -m pip install -r requirements.txt`
4. Run tests: `pytest -q`

The workflow is deliberately in simulation/local-development mode. The event reporter,
human review, data admission, database persistence, retraining, and deployment nodes are
explicit placeholders until each is implemented and tested. Do not connect to real relay
controls until the protection path has been separately validated.

## Confidence policy
The router uses `P(Attack | x)`, specifically the probability for class label `1`.
- >= 0.90: high-confidence attack workflow
- >= 0.70 and < 0.90: potential new attack workflow
- >= 0.30 and < 0.70: human review
- < 0.30: no automatic attack-dataset admission

Only confirmed, approved, eligible attack samples count toward the 100-sample
retraining trigger. The high-confidence branch also creates an event report.
