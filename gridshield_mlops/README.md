# GridShield MLOps starter

This is a separate project. It does not modify `gridshield_agentic`, PostgreSQL, or the active model.

## Folder layout
Recommended: `D:\PROJECTS\smartgrid_project\gridshield_mlops` beside `gridshield_agentic`.

## Copy the four fixed datasets
Copy from `gridshield_agentic`:
- `data/baseline_split/X_train.csv`
- `data/baseline_split/y_train.csv`
- `data/evaluation/X_test.csv`
- `data/evaluation/y_test.csv`

Put them at the same relative paths in this project. Do not regenerate or rebalance the fixed evaluation split.

## Setup
```powershell
conda activate smartgrid_gpu
python -m pip install -r requirements.txt
python -m src.validate_data
python -m src.train
python -m src.evaluate
```

## DVC
From this folder, after reviewing the files:
```powershell
git init
dvc init
dvc repro
```

## DagsHub / MLflow
Create a DagsHub repository for this project. Use the tracking URI and credentials shown by DagsHub; never commit tokens.
```powershell
$env:MLFLOW_TRACKING_URI = "<DagsHub MLflow tracking URI>"
$env:MLFLOW_TRACKING_USERNAME = "<DagsHub username>"
$env:MLFLOW_TRACKING_PASSWORD = "<DagsHub access token>"
$env:MLFLOW_EXPERIMENT_NAME = "gridshield-candidate-training"
python -m src.train
python -m src.evaluate
```
Without a remote URI, MLflow tracks locally in `mlruns/`.

## Safety boundaries
- First version uses trusted baseline split only. PostgreSQL-approved attack data is a later stage.
- Evaluation data remains fixed and untouched.
- Candidate is written under `artifacts/candidates/`; no deployment or active-model replacement occurs.
- DVC tracks validation -> training -> evaluation.
- A failed evaluation exits non-zero and must not proceed to approval.
