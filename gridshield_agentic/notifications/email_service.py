import os
import base64
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Attachment, FileContent, FileName, FileType, Disposition
from dotenv import load_dotenv

load_dotenv()

SENDER_EMAIL = "sahoovivekananda8@gmail.com"

def send_appointment_email(patient_email, doctor_email, report_path, slot):

    subject = "AI Healthcare Appointment Confirmation"

    html_content = f"""
    <strong>Appointment Confirmed</strong><br><br>

    Slot: {slot}<br><br>

    The patient medical report is attached.<br><br>

    Regards,<br>
    AI Clinical Prioritization System
    """

    message = Mail(
        from_email=SENDER_EMAIL,
        to_emails=[patient_email, doctor_email],
        subject=subject,
        html_content=html_content
    )

    if report_path and os.path.exists(report_path):

        with open(report_path, "rb") as f:
            data = f.read()

        encoded_file = base64.b64encode(data).decode()
        filename = os.path.basename(report_path)

        attachment = Attachment(
            FileContent(encoded_file),
            FileName(filename),
            FileType("application/pdf"),
            Disposition("attachment")
        )

        message.attachment = attachment

    sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
    response = sg.send(message)
    print("DEBUG REPORT PATH:", report_path)

    return response.status_code