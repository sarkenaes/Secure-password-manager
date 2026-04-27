"""Encryption helper functions for the password vault."""

from pathlib import Path
from cryptography.fernet import Fernet

KEY_FILE = Path(__file__).resolve().parent / "secret.key"


def generate_key() -> bytes:
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    return key


def load_key() -> bytes:
    if not KEY_FILE.exists():
        return generate_key()
    return KEY_FILE.read_bytes()


def encrypt_text(text: str) -> str:
    cipher = Fernet(load_key())
    return cipher.encrypt(text.encode("utf-8")).decode("utf-8")


def decrypt_text(encrypted_text: str) -> str:
    cipher = Fernet(load_key())
    return cipher.decrypt(encrypted_text.encode("utf-8")).decode("utf-8")
