
import os
from dotenv import load_dotenv
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

load_dotenv()


# Reuse the fixed, verified sender from Doctor AI.
SENDER_EMAIL = "sahoovivekananda8@gmail.com"


def send_gridshield_email(subject: str, body: str) -> int:
    """Send a GridShield notification to the configured officer."""

    api_key = os.getenv("SENDGRID_API_KEY")
    officer_email = os.getenv("GRIDSHIELD_OFFICER_EMAIL")

    if not api_key:
        raise RuntimeError("SENDGRID_API_KEY is missing from .env")

    if not officer_email:
        raise RuntimeError(
            "GRIDSHIELD_OFFICER_EMAIL is missing from .env"
        )

    message = Mail(
        from_email=SENDER_EMAIL,
        to_emails=officer_email,
        subject=subject,
        plain_text_content=body,
    )

    client = SendGridAPIClient(api_key)
    response = client.send(message)

    return response.status_code
