"""Print fresh secrets for .env (development) or for wrapping into OpenBao (production)."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from app.security.crypto import generate_key_b64

pem = Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()).decode()
print(f"SENTRAIL_DATA_KEYS=v1:{generate_key_b64()}")
print(f"SENTRAIL_INDEX_KEY={generate_key_b64()}")
print('SENTRAIL_JWT_PRIVATE_KEY="' + pem.strip().replace("\n", "\\n") + '"')
