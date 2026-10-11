
from gridshield import communication_agent as communication_module


def test_communication_agent_builds_notification(monkeypatch):
    captured = {}

    def fake_send_email(subject, body):
        captured["subject"] = subject
        captured["body"] = body
        return 202

    monkeypatch.setattr(
        communication_module,
        "send_gridshield_email",
        fake_send_email,
    )

    result = communication_module.communication_agent(
        event_type="attack_review_required",
        subject="GridShield: Attack review required",
        details={
            "event_id": "test-event-001",
            "confidence": 0.78,
            "status": "awaiting_human_review",
        },
    )

    assert result["notification_status"] == "sent"
    assert result["notification_status_code"] == 202
    assert captured["subject"] == "GridShield: Attack review required"
    assert "test-event-001" in captured["body"]
    assert "awaiting_human_review" in captured["body"]
