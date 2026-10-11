def route_attack_probability(p_attack: float) -> str:
    """Route on P(Attack | x), where the attack class label is 1."""
    if not 0.0 <= p_attack <= 1.0:
        raise ValueError("Attack probability must be between 0 and 1.")

    if p_attack >= 0.90:
        return "high_confidence_attack"
    if p_attack >= 0.70:
        return "potential_new_attack"
    if p_attack >= 0.30:
        return "human_review"
    return "below_attack_collection_threshold"
