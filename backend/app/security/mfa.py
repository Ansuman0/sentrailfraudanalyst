"""TOTP (RFC 6238) with replay protection, plus single-use recovery codes."""
import secrets
import time
import pyotp
from app.security.passwords import hash_password, verify_password

ISSUER = "Sentrail"


def new_secret() -> str:
    return pyotp.random_base32(32)


def provisioning_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER)


def verify(secret: str, code: str, last_step: int) -> int | None:
    """Return the accepted time step, or None. Rejects any step already used."""
    if not code.isdigit() or len(code) != 6:
        return None
    totp = pyotp.TOTP(secret)
    now_step = int(time.time()) // 30
    for step in (now_step - 1, now_step, now_step + 1):        # allow ±30s clock drift
        if step > last_step and secrets.compare_digest(totp.at(step * 30), code):
            return step
    return None


def new_recovery_codes(n: int = 8) -> tuple[list[str], list[str]]:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    codes = ["".join(secrets.choice(alphabet) for _ in range(4)) + "-" +
             "".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(n)]
    return codes, [hash_password(c) for c in codes]


def check_recovery(code: str, hashes: list[str]) -> int | None:
    for i, h in enumerate(hashes):
        if verify_password(h, code.strip().upper()):
            return i
    return None
