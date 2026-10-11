
from gridshield import email_service


def test_gridshield_email_uses_fixed_sender_and_officer(monkeypatch):
    monkeypatch.setenv("SENDGRID_API_KEY", "test-api-key")
    monkeypatch.setenv(
        "GRIDSHIELD_OFFICER_EMAIL",
        "officer@example.com",
    )

    captured = {}

    class FakeSendGridClient:
        def __init__(self, api_key):
            assert api_key == "test-api-key"

        def send(self, message):
            captured["message"] = message
            return type("Response", (), {"status_code": 202})()

    monkeypatch.setattr(
        email_service,
        "SendGridAPIClient",
        FakeSendGridClient,
    )

    status = email_service.send_gridshield_email(
        subject="GridShield test alert",
        body="A candidate attack requires human review.",
    )

    message = captured["message"]

    assert status == 202
    assert message.from_email.email == email_service.SENDER_EMAIL
    assert message.personalizations[0].tos[0]["email"] == (
    "officer@example.com"
    )
    assert message.subject.get() == "GridShield test alert"
    assert message.contents[0].get()["value"] == (
    "A candidate attack requires human review."
)
