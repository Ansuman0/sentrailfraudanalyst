"""Invitation emails over SMTP (any open-source MTA such as Postfix, or a relay).
In development (no SMTP_HOST) the link is printed to the server log instead."""
import os
import smtplib
from email.message import EmailMessage

def send_invitation(to: str, org_name: str, role: str, link: str):
    msg = EmailMessage()
    msg["Subject"] = f"You're invited to {org_name} on Sentrail"
    msg["From"] = os.environ.get("MAIL_FROM", "no-reply@sentrail.local")
    msg["To"] = to
    msg.set_content(f"You've been invited to join {org_name} as {role}.\n\n"
                    f"Set up your account here (expires in 72 hours, works once):\n{link}\n\n"
                    "If you weren't expecting this, ignore this email.")
    host = os.environ.get("SMTP_HOST")
    if not host:
        print(f"[dev] invitation for {to}: {link}")
        return
    with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", 587))) as s:
        s.starttls()
        if os.environ.get("SMTP_USER"):
            s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
        s.send_message(msg)
