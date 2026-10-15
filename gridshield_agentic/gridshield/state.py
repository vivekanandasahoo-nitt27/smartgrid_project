from typing import Any, TypedDict


class GridShieldState(TypedDict, total=False):
    event_id: str
    event_timestamp: str
    measurements: dict[str, Any]

    predicted_class: int
    class_probabilities: dict[str, float]
    attack_probability: float
    confidence_route: str

    root_cause_report: str
    incident_report_status: str

    candidate_sample: dict[str, Any]
    human_review_status: str
    human_verified_attack: bool
    data_admission_status: str
    sample_eligible: bool
    eligible_attack_sample_count: int

    
    candidate_model_version: str
    candidate_model_path: str
    candidate_feature_columns_path: str
    training_run_id: str

    # Evaluation Agent outputs
    evaluation_status: str
    evaluation_dataset_path: str
    evaluation_label_path: str
    evaluation_metrics: dict[str, Any]
    confusion_matrix: list[list[int]]
    evaluation_class_labels: list[int]
    accuracy: float
    precision: dict[str, Any]
    recall: dict[str, Any]
    f1_score: dict[str, Any]
    evaluation_report: dict[str, Any]

    # Deployment remains a separate approval gate
    deployment_approval_status: str
    deployed_model_version: str
    eligibility_status: str


    audit_events: list[dict[str, Any]]
    errors: list[str]
    
    dataset_validation_status: str
    repository_inserted: bool
    repository_status: str
    notification_status: str
    notification_event_type: str
    notification_status_code: int
    notification_error: str
