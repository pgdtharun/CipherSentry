"""Examples that should NOT trigger any findings -- used to check for false positives."""

import os
import secrets
import hashlib

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import RSA



def load_key():
    return os.environ["ENCRYPTION_KEY"].encode()


def encrypt(data: bytes, key: bytes):
    nonce = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce, ciphertext, tag


def hash_file_for_integrity(path):
    # sha256 used for file integrity, not password hashing -- fine
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def derive_key_from_password(password: str, salt: bytes):
    return scrypt(password.encode(), salt, key_len=32, N=2 ** 14, r=8, p=1)


def generate_token():
    return secrets.token_urlsafe(32)


def generate_strong_rsa_key():
    return RSA.generate(2048)