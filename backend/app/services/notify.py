"""Security notifications to the person concerned: sign-in from a new device, two-factor changes, password and role changes.

Sent by email over SMTP when SMTP_HOST is set (same settings as invitations); otherwise only logged, with a masked address.
A notification never contains a secret and a failure to send never fails the request that caused it.
"""
import logging
import os
import smtplib
from email.message import EmailMessage

from app.security import crypto

log = logging.getLogger("sentrail.notify")

MESSAGES = {
    "new_device": ("New sign-in to Sentrail",
                   "Your account was just used to sign in from a device we haven't seen before{where}.\n\n"
                   "If this was you, no action is needed. If not, sign in, end your other sessions under My account and ask your "
                   "administrator to reset your two-factor authentication."),
    "mfa_enabled": ("Two-factor authentication turned on",
                    "Two-factor authentication was turned on for your Sentrail account.\n\n"
                    "If this wasn't you, contact your administrator immediately."),
    "mfa_reset": ("Two-factor authentication was reset",
                  "An administrator reset two-factor authentication on your Sentrail account. You will be asked to set it up again at "
                  "your next sign-in.\n\nIf you didn't expect this, contact your administrator."),
    "password_changed": ("Your Sentrail password was changed",
                         "The password for your Sentrail account was changed.\n\nIf this wasn't you, contact your administrator immediately."),
    "role_changed": ("Your Sentrail role was changed",
                     "Your role in Sentrail was changed{where}. Your access updates the next time you sign in.\n\n"
                     "If you didn't expect this, contact your administrator."),
}


def security_event(to: str | None, kind: str, detail: dict | None = None) -> None:
    """Notify `to` (a plain email address) about `kind`. Best effort; never raises."""
    if not to or kind not in MESSAGES:
        return
    try:
        subject, body = MESSAGES[kind]
        where = (detail or {}).get("where")
        body = body.format(where=f" ({where})" if where else "")
        log.info("security notification", extra={"event": "security_notification", "kind": kind, "to": crypto.mask_email(to)})
        host = os.environ.get("SMTP_HOST")
        if not host:
            return                                      # development / no mail server: the log line above is the record
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = os.environ.get("MAIL_FROM", "no-reply@sentrail.local")
        msg["To"] = to
        msg.set_content(body)
        with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", 587)), timeout=10) as s:
            s.starttls()
            if os.environ.get("SMTP_USER"):
                s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"])
            s.send_message(msg)
    except Exception:                                   # noqa: BLE001 - a mail problem must not break sign-in or an admin action
        log.warning("security notification failed", extra={"event": "security_notification_failed", "kind": kind}, exc_info=True)
