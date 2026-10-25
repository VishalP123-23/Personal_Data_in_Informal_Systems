import hashlib
import hmac
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from .config import settings

password_hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)

def hash_password(password: str) -> str:
    return password_hasher.hash(password)

def verify_password(password: str, encoded: str) -> bool:
    try:
        return password_hasher.verify(encoded, password)
    except (VerifyMismatchError, VerificationError, TypeError):
        return False

def new_token() -> str:
    return secrets.token_urlsafe(32)

def token_hash(token: str) -> str:
    return hmac.new(settings.secret_key.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()
