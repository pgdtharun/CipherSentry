"""
Deliberately vulnerable examples for the misuse scanner to catch.
Do NOT use any pattern from this file in real code -- it exists purely
to demonstrate what the scanner flags.
"""

import hashlib
import random
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA

# CM001 -- hardcoded secret
SECRET_KEY = "s3cr3t-signing-key-2024"
api_key = "sk_live_51Hxxxxxxxxxxxxxxxxxx"


def encrypt_config(data):
    # CM002 -- ECB mode leaks plaintext patterns
    cipher = AES.new(SECRET_KEY.encode().ljust(32, b"0"), AES.MODE_ECB)
    return cipher.encrypt(data)


def hash_password(password):
    # CM003 -- MD5 is not a password hash
    return hashlib.md5(password.encode()).hexdigest()


def generate_session_token():
    # CM004 -- the random module is not cryptographically secure
    session_token = random.randint(100000, 999999)
    return session_token


def legacy_encrypt(data):
    # CM005 -- DES is a deprecated cipher (also flagged at the import above)
    cipher = DES.new(b"8bytekey", DES.MODE_ECB)
    return cipher.encrypt(data)

def generate_weak_rsa_key():
    # CM006 -- 1024-bit RSA is well below the 2048-bit minimum
    return RSA.generate(1024)
