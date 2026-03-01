# encryption.py
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Tuple

from cryptography.fernet import Fernet, InvalidToken


def derive_fernet_key(personal_seed: str) -> bytes:
    """
    Генерація ключа Fernet із персональних даних.
    1) SHA-256(personal_seed) => 32 байти
    2) URL-safe Base64 => 44 символи (ключ Fernet)
    """
    seed_bytes = personal_seed.encode("utf-8")
    digest = hashlib.sha256(seed_bytes).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_bytes(plain: bytes, personal_seed: str) -> Tuple[bytes, str]:
    key = derive_fernet_key(personal_seed)
    token = Fernet(key).encrypt(plain)
    return token, base64.urlsafe_b64encode(key).decode("ascii", errors="ignore")  # для довідки


def decrypt_bytes(token: bytes, personal_seed: str) -> bytes:
    key = derive_fernet_key(personal_seed)
    return Fernet(key).decrypt(token)


@dataclass
class DecryptResult:
    ok: bool
    data: bytes
    error: str = ""


def safe_decrypt_bytes(token: bytes, personal_seed: str) -> DecryptResult:
    try:
        data = decrypt_bytes(token, personal_seed)
        return DecryptResult(ok=True, data=data)
    except InvalidToken:
        return DecryptResult(ok=False, data=b"", error="InvalidToken: неправильний ключ або пошкоджені дані.")
    except Exception as e:
        return DecryptResult(ok=False, data=b"", error=f"Помилка дешифрування: {e}")