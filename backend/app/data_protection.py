"""Authenticated field encryption and keyed lookup digests for personal data."""
import base64
import hashlib
import hmac
import os
import unicodedata
from datetime import datetime
from functools import lru_cache

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.types import Text, TypeDecorator


@lru_cache(maxsize=1)
def _keys():
    encoded = os.getenv("PERSONAL_DATA_KEY", "").strip()
    if not encoded:
        raise RuntimeError("PERSONAL_DATA_KEY is required before personal data can be stored")
    try:
        master = base64.urlsafe_b64decode(encoded.encode("ascii"))
    except Exception as exc:
        raise RuntimeError("PERSONAL_DATA_KEY must be a URL-safe base64 encoded 32-byte key") from exc
    if len(master) != 32:
        raise RuntimeError("PERSONAL_DATA_KEY must decode to exactly 32 bytes")
    encryption_key = hmac.new(master, b"clinic-personal-data-encryption-v1", hashlib.sha256).digest()
    digest_key = hmac.new(master, b"clinic-personal-data-digest-v1", hashlib.sha256).digest()
    return encryption_key, digest_key


def personal_data_hash(value: str | None, context: str) -> str | None:
    if value is None:
        return None
    _, digest_key = _keys()
    normalized = unicodedata.normalize("NFKC", value).strip().casefold()
    message = context.encode("utf-8") + b"\0" + normalized.encode("utf-8")
    return "hmac:v1:" + hmac.new(digest_key, message, hashlib.sha256).hexdigest()


def mask_contact_value(value: str | None) -> str | None:
    """Return a display-only mask; never use this value for storage or lookup."""
    if value is None or not value.strip():
        return None
    value = value.strip()
    if "@" in value:
        local, domain = value.rsplit("@", 1)
        domain_parts = domain.split(".")
        masked_local = (local[:1] or "•") + "•••"
        if len(domain_parts) > 1:
            suffix = domain_parts[-1]
            masked_domain = (domain_parts[0][:1] or "•") + "•••." + suffix
        else:
            masked_domain = (domain[:1] or "•") + "•••"
        return f"{masked_local}@{masked_domain}"
    digits = "".join(character for character in value if character.isdigit())
    if len(digits) <= 4:
        return "••••"
    return "••••••" + digits[-4:]


def encrypt_personal_data(value: str | None, context: str) -> str | None:
    if value is None:
        return None
    encryption_key, _ = _keys()
    nonce = os.urandom(12)
    ciphertext = AESGCM(encryption_key).encrypt(nonce, value.encode("utf-8"), context.encode("utf-8"))
    token = base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")
    return "enc:v1:" + token


def decrypt_personal_data(value: str | None, context: str) -> str | None:
    if value is None:
        return None
    if not value.startswith("enc:v1:"):
        raise RuntimeError(f"Unencrypted value found in protected field {context}; run the data-protection migration")
    encryption_key, _ = _keys()
    try:
        payload = base64.urlsafe_b64decode(value[7:].encode("ascii"))
        nonce, ciphertext = payload[:12], payload[12:]
        return AESGCM(encryption_key).decrypt(nonce, ciphertext, context.encode("utf-8")).decode("utf-8")
    except Exception as exc:
        raise RuntimeError(f"Could not decrypt protected field {context}; verify the personal-data key") from exc


class EncryptedText(TypeDecorator):
    impl = Text
    cache_ok = True

    def __init__(self, context: str):
        super().__init__()
        self.context = context

    def process_bind_param(self, value, dialect):
        return encrypt_personal_data(value, self.context)

    def process_result_value(self, value, dialect):
        return decrypt_personal_data(value, self.context)


class EncryptedDateTime(TypeDecorator):
    """Store operational datetimes as authenticated ciphertext at rest."""
    impl = Text
    cache_ok = True

    def __init__(self, context: str):
        super().__init__()
        self.context = context

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if not isinstance(value, datetime):
            raise TypeError("EncryptedDateTime values must be datetime objects")
        return encrypt_personal_data(value.isoformat(), self.context)

    def process_result_value(self, value, dialect):
        clear = decrypt_personal_data(value, self.context)
        return datetime.fromisoformat(clear) if clear is not None else None
