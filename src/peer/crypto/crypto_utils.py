import os , sys
import hashlib
import logging
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)
from src.config.config import P , G


class CryptoUtils:
    """Utility class for cryptographic operations in CipherShare."""
    
    def __init__(self):
        logging.info("Initializing CryptoUtils with standardized Diffie-Hellman parameters")
        
        # Creating DH parameters using the standardized values
        dh_parameter_numbers = dh.DHParameterNumbers(
            p=P,
            g=G,
            q=None  # q is optional
        )
        self.parameters = dh_parameter_numbers.parameters(default_backend())
        
        # Generating our private key based on the standard parameters
        self.private_key = None
        # Deriving our public key
        self.public_key = None
        
        # Storing shared keys for each peer
        self.shared_keys = {}
        logging.info("CryptoUtils initialized successfully with standardized parameters")
        
    def get_public_key_bytes(self):
        """
        Get the public key in serialized form
        """
        logging.debug("Serializing public key to bytes")
        key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        logging.debug(f"Public key serialized, length: {len(key_bytes)} bytes")
        return key_bytes
        
    def has_shared_key(self, peer_username):
        """
        Check if we have a shared key with a specific peer
        """
        has_key = peer_username in self.shared_keys
        logging.debug(f"Shared key check for peer {peer_username}: {'Found' if has_key else 'Not found'}")
        return has_key
    
    def remove_shared_key(self, peer_username):
        """
        Remove a shared key for a peer
        """
        if peer_username in self.shared_keys:
            del self.shared_keys[peer_username]
            logging.info(f"Removed shared key for peer: {peer_username}")
            return True
        logging.warning(f"Attempted to remove nonexistent shared key for peer: {peer_username}")
        return False
        
    def generate_shared_key(self, peer_username, peer_public_key_bytes):
        """
        Generate a shared key with a peer using their public key
        
        Args:
            peer_username: The username of the peer
            peer_public_key_bytes: The serialized public key of the peer
            
        Returns:
            bool: True if key generation succeeded, False otherwise
        """
        try:
            logging.info(f"Generating shared key with peer: {peer_username}")
            # Load peer's public key
            logging.debug(f"Loading peer public key, size: {len(peer_public_key_bytes)} bytes")
            peer_public_key = serialization.load_pem_public_key(
                peer_public_key_bytes,
                backend=default_backend()
            )
            logging.debug("Successfully loaded peer's public key")
            
            # Check if the peer's public key is compatible with our parameters
            if not isinstance(peer_public_key, dh.DHPublicKey):
                logging.error(f"Incompatible key type from peer {peer_username}")
                return False
                
            # Generate shared key
            logging.debug("Performing key exchange with peer's public key")
            shared_key = self.private_key.exchange(peer_public_key)
            logging.debug(f"Raw shared secret generated, length: {len(shared_key)} bytes")
            
            # Derive a cryptographic key from the shared secret
            logging.debug("Deriving cryptographic key using HKDF")
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256 bits for AES-256
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_key)
            
            # Store the derived key for this peer
            self.shared_keys[peer_username] = derived_key
            logging.info(f"Successfully generated and stored shared key for peer {peer_username}")
            return True
            
        except ValueError as e:
            logging.error(f"Error generating shared key with {peer_username}: {str(e)}")
            logging.error("This error typically occurs when peers use different DH parameters.")
            logging.error("Make sure all peers are using the same standardized parameters.")
            return False
            
        except Exception as e:
            logging.error(f"Error generating shared key with {peer_username}: {e}", exc_info=True)
            return False
            
    def encrypt_file(self, peer_username, input_file_path, output_file_path):
        """
        Encrypt a file for a specific peer
        
        Args:
            peer_username: The username of the peer
            input_file_path: Path to the input file
            output_file_path: Path where the encrypted file will be saved
            
        Returns:
            str: The file integrity hash
        """
        if peer_username not in self.shared_keys:
            logging.error(f"Cannot encrypt file: No shared key found for peer {peer_username}")
            raise ValueError(f"No shared key found for peer {peer_username}")
            
        try:
            logging.info(f"Encrypting file {input_file_path} for peer {peer_username}")
            # Read the input file
            with open(input_file_path, 'rb') as f:
                plaintext = f.read()
            logging.debug(f"Read file for encryption, size: {len(plaintext)} bytes")
                
            # Generate a random initialization vector (IV)
            iv = os.urandom(16)  # 16 bytes for AES
            logging.debug(f"Generated random IV for encryption: {iv.hex()[:10]}...")
            
            # Create an encryptor
            logging.debug("Creating AES-CFB encryptor")
            encryptor = Cipher(
                algorithms.AES(self.shared_keys[peer_username]),
                modes.CFB(iv),
                backend=default_backend()
            ).encryptor()
            
            # Encrypt the plaintext
            logging.debug("Encrypting file content")
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            logging.debug(f"File encrypted, ciphertext size: {len(ciphertext)} bytes")
            
            # Calculate integrity hash
            integrity_hash = hashlib.sha256(ciphertext).hexdigest()
            logging.debug(f"Generated integrity hash for encrypted data: {integrity_hash[:10]}...")
            
            # Write the IV and ciphertext to the output file
            with open(output_file_path, 'wb') as f:
                f.write(iv + ciphertext)
            logging.info(f"Encrypted file written to {output_file_path}, size: {len(iv) + len(ciphertext)} bytes")
                
            return integrity_hash
            
        except Exception as e:
            logging.error(f"Error encrypting file for {peer_username}: {e}", exc_info=True)
            raise
            
    def decrypt_file(self, peer_username, input_file_path, output_file_path, integrity_hash):
        """
        Decrypt a file from a specific peer
        
        Args:
            peer_username: The username of the peer
            input_file_path: Path to the encrypted file
            output_file_path: Path where the decrypted file will be saved
            integrity_hash: The expected hash of the ciphertext for integrity check
            
        Returns:
            bool: True if decryption succeeded and integrity check passed, False otherwise
        """
        if peer_username not in self.shared_keys:
            logging.error(f"Cannot decrypt file: No shared key found for peer {peer_username}")
            return False
            
        try:
            logging.info(f"Decrypting file from peer {peer_username}: {input_file_path}")
            # Read the encrypted file
            with open(input_file_path, 'rb') as f:
                data = f.read()
            logging.debug(f"Read encrypted file, size: {len(data)} bytes")
                
            # First 16 bytes are the IV
            iv = data[:16]
            ciphertext = data[16:]
            logging.debug(f"Extracted IV: {iv.hex()[:10]}... and ciphertext (size: {len(ciphertext)} bytes)")
            
            # Verify integrity
            calculated_hash = hashlib.sha256(ciphertext).hexdigest()
            logging.debug(f"Calculated hash: {calculated_hash[:10]}..., expected hash: {integrity_hash[:10]}...")
            
            if calculated_hash != integrity_hash:
                logging.error(f"File integrity check failed. Hash mismatch: {calculated_hash[:10]}... vs {integrity_hash[:10]}...")
                return False
            
            logging.debug("File integrity check passed")
                
            # Create a decryptor
            logging.debug("Creating AES-CFB decryptor")
            decryptor = Cipher(
                algorithms.AES(self.shared_keys[peer_username]),
                modes.CFB(iv),
                backend=default_backend()
            ).decryptor()
            
            # Decrypt the ciphertext
            logging.debug("Decrypting file content")
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            logging.debug(f"File decrypted, plaintext size: {len(plaintext)} bytes")
            
            # Write the plaintext to the output file
            with open(output_file_path, 'wb') as f:
                f.write(plaintext)
            logging.info(f"Decrypted file written to {output_file_path}")
                
            return True
            
        except Exception as e:
            logging.error(f"Error decrypting file from {peer_username}: {e}", exc_info=True)
            return False

    def get_file_hash(self, file_path: str) -> str:
        """Calculate and return the SHA-256 hash of a file."""
        logging.debug(f"Calculating hash for file: {file_path}")
        hash_value = self._calculate_file_hash(file_path)
        logging.debug(f"File hash calculated: {hash_value[:10]}...")
        return hash_value
        
    def verify_file_integrity(self, file_path: str, expected_hash: str) -> bool:
        """Verify the integrity of a file using its SHA-256 hash."""
        logging.debug(f"Verifying integrity of file: {file_path}")
        actual_hash = self._calculate_file_hash(file_path)
        result = actual_hash == expected_hash
        logging.debug(f"Integrity check result: {'Passed' if result else 'Failed'}")
        return result

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            bytes_read = 0
            while True:
                data = f.read(65536)  # Read 64KB chunks
                if not data:
                    break
                sha256.update(data)
                bytes_read += len(data)
                
        hash_value = sha256.hexdigest()
        logging.debug(f"Calculated hash for {bytes_read} bytes: {hash_value[:10]}...")
        return hash_value

    def derive_user_key(self, password: str, salt: bytes = None) -> bytes:
        """
        Derive a cryptographic key from a password using PBKDF2.

        Args:
            password: The user's password.
            salt: A unique salt (must be securely stored alongside the encrypted data).

        Returns:
            A 32-byte key suitable for AES-256.
        """
        if salt is None:
            import secrets
            salt = secrets.token_bytes(16)

        logging.info("Deriving encryption key from password using PBKDF2HMAC")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        logging.info("User encryption key derived successfully")
        return key

    def save_private_key_encrypted(self, filepath: str, password: str):
        if self.private_key is None:
            logging.info("No existing private key found, generating new DH private key")
            self.private_key = self.parameters.generate_private_key()
            self.public_key = self.private_key.public_key()

        # Derive a key from the password
        salt = os.urandom(16)
        key = self.derive_user_key(password, salt)

        # Serialize the private key
        private_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Encrypt the private key using AES
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_private = encryptor.update(private_bytes) + encryptor.finalize()

        with open(filepath, 'wb') as f:
            f.write(salt + iv + encrypted_private)

    def load_private_key_encrypted(self, filepath: str, password: str):
        with open(filepath, 'rb') as f:
            data = f.read()
        salt = data[:16]
        iv = data[16:32]
        encrypted_private = data[32:]
        key = self.derive_user_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        private_bytes = decryptor.update(encrypted_private) + decryptor.finalize()

        self.private_key = serialization.load_pem_private_key(
            private_bytes,
            password=None,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
