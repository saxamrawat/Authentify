import os
import resend
from dotenv import load_dotenv

load_dotenv()

resend.api_key = os.getenv("RESEND_API_KEY")

EMAIL_FROM = os.getenv("EMAIL_FROM")


def send_verification_email(to_email: str, verification_link: str):

    response = resend.Emails.send({
        "from": EMAIL_FROM,
        "to": [to_email],
        "subject": "Verify your email",
        "html": f"""
        <h2>Verify Your Email</h2>

        <p>Thank you for registering.</p>

        <p>
            Click the link below to verify your email:
        </p>

        <a href="{verification_link}">
            Verify Email
        </a>

        <p>
            This link expires in 15 minutes.
        </p>
        """
    })

    print(response)


def send_password_reset_email(to_email: str, reset_link: str):

    response = resend.Emails.send({
        "from": EMAIL_FROM,
        "to": [to_email],
        "subject": "Reset your password",
        "html": f"""
        <h2>Password Reset</h2>

        <p>
            Click below to reset your password:
        </p>

        <a href="{reset_link}">
            Reset Password
        </a>

        <p>
            This link expires in 15 minutes.
        </p>
        """
    })

    print(response)