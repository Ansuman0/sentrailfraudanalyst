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
    "owner_access_requested": ("A Sentrail platform owner asks to enter your organization",
                               "A platform owner asked for temporary access to your organization{where}. Sign in as an administrator "
                               "to approve or deny it. Nothing happens until you decide."),
    "owner_access_started": ("A Sentrail platform owner has entered your organization",
                             "A platform owner started a time-limited access session in your organization{where}. Everything they do is "
                             "recorded in your audit log. You can see and review it under Security."),
    "owner_access_ended": ("A Sentrail platform owner's access to your organization has ended",
                           "A platform owner's access session in your organization has ended{where}."),
    "break_glass_used": ("The break-glass owner account was just used",
                         "The sealed break-glass account of the Sentrail platform was used to sign in{where}. If this was planned, "
                         "no action is needed. If not, treat it as a security incident. The account's password must now be rotated."),
    "passkey_registered": ("A passkey was added to your Sentrail account",
                           "A passkey ({where}) was added to your Sentrail account as a second factor.\n\n"
                           "If this wasn't you, contact your administrator immediately."),
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
