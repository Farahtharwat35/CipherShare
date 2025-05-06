import os
import base64
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

def hash_password(password):
    """
    Hash the password using Argon2.
    Returns (base64-hash, base64-salt)
    """
    salt = os.urandom(16)
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=1,
        lanes=4,
        memory_cost=64 * 1024,
        ad=None,
        secret=None,
    )
    hashed_password = kdf.derive(password.encode())

    hashed_b64 = base64.b64encode(hashed_password).decode('utf-8')
    salt_b64 = base64.b64encode(salt).decode('utf-8')

    return hashed_b64, salt_b64

def verify_password(password, stored_hash_b64, salt_b64):
    salt = base64.b64decode(salt_b64)
    expected_hash = base64.b64decode(stored_hash_b64)

    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=1,
        lanes=4,
        memory_cost=64 * 1024,
        ad=None,
        secret=None,
    )

    derived = kdf.derive(password.encode())

    return derived == expected_hash
