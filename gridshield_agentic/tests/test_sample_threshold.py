
from gridshield.workflow import choose_sample_count


def test_99_eligible_samples_do_not_trigger_retraining():
    assert choose_sample_count({
        "eligible_attack_sample_count": 99,
    }) == "collect"


def test_100_eligible_samples_trigger_retraining():
    assert choose_sample_count({
        "eligible_attack_sample_count": 100,
    }) == "retrain"
