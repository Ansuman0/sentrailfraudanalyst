"""Fill the empty values in .env with random local-development secrets. Never overwrites a value that is set.

  python -m scripts.dev_env              # creates .env from .env.example first if it doesn't exist

Development only: production secrets come from your secret manager / OpenBao, never from this script.
Nothing is printed except the names of the variables that were filled in.
"""
import re
import secrets
import shutil
import sys
from pathlib import Path
from urllib.parse import quote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.security.crypto import generate_key_b64

ROOT = Path(__file__).resolve().parents[2]          # .env lives at the repository root, shared with docker-compose.yml
ENV_FILE, EXAMPLE = ROOT / ".env", ROOT / ".env.example"
PASSWORDS = ["POSTGRES_SUPERUSER_PASSWORD", "SENTRAIL_OWNER_PASSWORD", "APP_DB_PASSWORD", "KEYCLOAK_DB_PASSWORD",
             "KEYCLOAK_CLIENT_SECRET", "KEYCLOAK_ADMIN_CLIENT_SECRET", "KEYCLOAK_ADMIN_PASSWORD",
             "SEED_ADMIN_PASSWORD", "SEED_DEMO_PASSWORD", "GRAFANA_ADMIN_PASSWORD"]
FIXED = {"KEYCLOAK_ADMIN_USER": "kcadmin", "SEED_ADMIN_EMAIL": "owner@sentrail.qatech.world"}
LINE = re.compile(r"^(?P<key>[A-Z][A-Z0-9_]*)=(?P<value>[^#\n]*?)(?P<rest>\s+#.*)?$")


def generated() -> dict:
    pem = Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()).decode()
    out = {k: secrets.token_urlsafe(24) for k in PASSWORDS}
    out.update(FIXED)
    out["SENTRAIL_DATA_KEYS"] = f"v1:{generate_key_b64()}"
    out["SENTRAIL_INDEX_KEY"] = generate_key_b64()
    out["SENTRAIL_JWT_PRIVATE_KEY"] = '"' + pem.strip().replace("\n", "\\n") + '"'
    return out


def main():
    if not ENV_FILE.exists():
        shutil.copy(EXAMPLE, ENV_FILE)
    lines = ENV_FILE.read_text().splitlines()
    values = {m["key"]: m["value"].strip() for m in map(LINE.match, lines) if m}
    if values.get("ENV", "production") == "production":
        sys.exit("ENV is production (or unset) in .env. This script is for local development only")
    new, filled = generated(), []
    for k, v in new.items():
        if not values.get(k):
            values[k] = v
            filled.append(k)
    # DATABASE_URL / OWNER_DATABASE_URL in .env.example carry <PLACEHOLDER> passwords: fill them from the real ones.
    for url_key, pw_key in (("DATABASE_URL", "APP_DB_PASSWORD"), ("OWNER_DATABASE_URL", "SENTRAIL_OWNER_PASSWORD")):
        if f"<{pw_key}>" in values.get(url_key, ""):
            values[url_key] = values[url_key].replace(f"<{pw_key}>", quote(values[pw_key], safe=""))
            filled.append(url_key)
    present = {m["key"] for m in map(LINE.match, lines) if m}
    out = []
    for line in lines:
        m = LINE.match(line)
        if m and m["key"] in filled:
            line = f"{m['key']}={values[m['key']]}{m['rest'] or ''}"
        out.append(line)
    out += [f"{k}={values[k]}" for k in filled if k not in present]     # keys an older .env doesn't have yet
    ENV_FILE.write_text("\n".join(out) + "\n")
    print("Filled in .env:", ", ".join(filled) if filled else "nothing (every value was already set)")


if __name__ == "__main__":
    main()
