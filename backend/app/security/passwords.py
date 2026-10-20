"""Password hashing (argon2id) and policy, following NIST SP 800-63B:
length over complexity rules, no forced periodic rotation, block known-breached passwords."""
import hashlib
import httpx
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

# OWASP-recommended argon2id parameters (19 MiB, t=2, p=1) or stronger
_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
DUMMY_HASH = _ph.hash("timing-equalizer")  # verify against this when the user doesn't exist


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(stored: str | None, pw: str) -> bool:
    try:
        return _ph.verify(stored or DUMMY_HASH, pw) and stored is not None
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(stored: str) -> bool:
    return _ph.check_needs_rehash(stored)


def breached(pw: str) -> bool:
    """Have I Been Pwned range API (k-anonymity): only the first 5 hash chars leave the server."""
    h = hashlib.sha1(pw.encode()).hexdigest().upper()
    try:
        r = httpx.get(f"https://api.pwnedpasswords.com/range/{h[:5]}", timeout=5,
                      headers={"Add-Padding": "true"})
        return any(line.split(":")[0] == h[5:] for line in r.text.splitlines())
    except httpx.HTTPError:
        return False  # fail open on this check only; length rule still applies


def check_policy(pw: str, min_len: int, context: list[str]) -> list[str]:
    problems = []
    if len(pw) < min_len:
        problems.append(f"Use at least {min_len} characters")
    if len(pw) > 256:
        problems.append("Use 256 characters or fewer")
    low = pw.lower()
    if any(c and len(c) >= 4 and c.lower() in low for c in context):
        problems.append("Don't include your name, email or company name")
    if not problems and breached(pw):
        problems.append("This password has appeared in a data breach. Choose another")
    return problems
