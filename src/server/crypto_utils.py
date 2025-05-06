import secrets
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def hash_password(password, salt=None):
    """
    Hash the password using Argon2
    
    Args:
        password (str): The password to hash
        salt (bytes, optional): The salt to use for the hash. If None, a random salt will be generated.
    
    Returns:
        tuple: A tuple containing the hashed password and the salt used for the hash
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    kdf = Argon2id(
        salt=salt,
        time_cost=2,
        memory_cost=102400,
        parallelism=8,
        length=32,
        backend=default_backend()
    )
    hashed_password = kdf.derive(password.encode('utf-8'))
    return hashed_password, salt

def verify_password(password, hashed_password, salt):
    """
    Verify the password using Argon2
    
    Args:
        password (str): The password to verify
        hashed_password (bytes): The hashed password to compare against
        salt (bytes): The salt used for the hash
    
    Returns:
        bool: True if the password matches the hash, False otherwise
    """
    kdf = Argon2id(
        salt=salt,
        time_cost=2,
        memory_cost=102400,
        parallelism=8,
        length=32,
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode('utf-8'), hashed_password)
        return True
    except Exception:
        return False
