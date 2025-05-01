import os
import hashlib
import base64
import logging
from typing import Tuple, Dict, Optional
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


class CryptoUtils:
    """Utility class for cryptographic operations in CipherShare."""
    
    def __init__(self):
        # Our main Diffie-Hellman parameters and keys
        self.dh_parameters = None
        self.private_key = None
        self.public_key = None
        
        # For storing shared keys with other peers
        self.shared_keys: Dict[str, bytes] = {}
        
        # Generate our main DH parameters only once on initialization
        self.generate_dh_parameters()
        logging.info("Initialized crypto utilities with DH parameters")
        
    def generate_dh_parameters(self) -> None:
        """Generate new Diffie-Hellman parameters."""
        self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
        self.private_key = self.dh_parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
        logging.info("Generated new DH key pair")
    
    def get_public_key_bytes(self) -> bytes:
        """Get the public key in bytes format for transmission."""
        if not self.public_key:
            self.generate_dh_parameters()
            
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def get_dh_parameters_bytes(self) -> bytes:
        """Get the DH parameters in bytes format for transmission."""
        if not self.dh_parameters:
            self.generate_dh_parameters()
            
        return self.dh_parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
    
    def load_peer_public_key(self, peer_public_key_bytes: bytes) -> object:
        """Load a peer's public key from bytes."""
        return serialization.load_pem_public_key(peer_public_key_bytes)
    
    def generate_shared_key(self, peer_username: str, peer_public_key_bytes: bytes) -> bytes:
        """
        Generate a shared key with a peer using their public key.
        
        Args:
            peer_username: Username of the peer for key storage
            peer_public_key_bytes: The peer's public key in bytes
            
        Returns:
            bytes: The derived shared key
        """
        if not self.private_key:
            self.generate_dh_parameters()
            
        peer_public_key = self.load_peer_public_key(peer_public_key_bytes)
        
        shared_key = self.private_key.exchange(peer_public_key)
        
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=None,
            info=b'ciphershare-encryption'
        ).derive(shared_key)
        
        self.shared_keys[peer_username] = derived_key
        logging.info(f"Generated shared key with peer: {peer_username}")
        
        return derived_key
    
    def get_shared_key(self, peer_username: str) -> bytes:
        """Get the shared key for a specific peer."""
        if peer_username not in self.shared_keys:
            raise KeyError(f"No shared key found for peer: {peer_username}")
        return self.shared_keys[peer_username]
    
    def has_shared_key(self, peer_username: str) -> bool:
        """Check if we have a shared key with a specific peer."""
        return peer_username in self.shared_keys
    
    def remove_shared_key(self, peer_username: str) -> bool:
        """Remove a shared key for a specific peer."""
        if peer_username in self.shared_keys:
            del self.shared_keys[peer_username]
            logging.info(f"Removed shared key for peer: {peer_username}")
            return True
        return False
    
    def encrypt_file(self, peer_username: str, file_path: str, output_path: str) -> str:
        """
        Encrypt a file using AES with the shared key of a peer.
        
        Args:
            peer_username: Username of the peer whose shared key to use
            file_path: Path to the file to encrypt
            output_path: Path to save the encrypted file
            
        Returns:
            str: The SHA-256 hash of the original file for integrity verification
        """
        key = self.get_shared_key(peer_username)
        
        # Generate a random IV
        iv = os.urandom(16)
        
        file_hash = self._calculate_file_hash(file_path)
        
        encryptor = Cipher(
            algorithms.AES(key),
            modes.CBC(iv)
        ).encryptor()
        
        padder = PKCS7(algorithms.AES.block_size).padder()
        
        with open(file_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # Write the IV at the beginning of the file
            f_out.write(iv)
            
            # Encrypt and write the file content
            while True:
                chunk = f_in.read(8192)  # Read 8KB chunks
                if not chunk:
                    break
                    
                # Pad the last chunk if needed
                if len(chunk) % 16 != 0:
                    chunk = padder.update(chunk)
                    if not chunk:
                        chunk = padder.finalize()
                        
                encrypted_chunk = encryptor.update(chunk)
                f_out.write(encrypted_chunk)
            
            # Finalize the encryption
            if hasattr(padder, '_buffer') and padder._buffer:
                chunk = padder.finalize()
                encrypted_chunk = encryptor.update(chunk)
                f_out.write(encrypted_chunk)
                
            final_block = encryptor.finalize()
            if final_block:
                f_out.write(final_block)
                
        logging.info(f"Encrypted file {file_path} for peer {peer_username}")
        return file_hash
    
    def decrypt_file(self, peer_username: str, encrypted_file_path: str, output_path: str, original_hash: str) -> bool:
        """
        Decrypt a file using AES with the shared key of a peer and verify its integrity.
        
        Args:
            peer_username: Username of the peer whose shared key to use
            encrypted_file_path: Path to the encrypted file
            output_path: Path to save the decrypted file
            original_hash: The SHA-256 hash of the original file for verification
            
        Returns:
            bool: True if the file was successfully decrypted and integrity verified
        """
        key = self.get_shared_key(peer_username)
        
        with open(encrypted_file_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # Read the IV from the beginning of the file
            iv = f_in.read(16)
            
            decryptor = Cipher(
                algorithms.AES(key),
                modes.CBC(iv)
            ).decryptor()
            
            unpadder = PKCS7(algorithms.AES.block_size).unpadder()
            
            while True:
                chunk = f_in.read(8192)  # Read 8KB chunks
                if not chunk:
                    break
                    
                decrypted_chunk = decryptor.update(chunk)
                
                # Only unpad the last chunk
                if len(chunk) < 8192:
                    try:
                        decrypted_chunk = unpadder.update(decrypted_chunk) + unpadder.finalize()
                    except ValueError:
                        # If unpadding fails, it might not be the last block
                        pass
                        
                f_out.write(decrypted_chunk)
            
            final_block = decryptor.finalize()
            if final_block:
                f_out.write(final_block)
        
        decrypted_file_hash = self._calculate_file_hash(output_path)
        is_valid = decrypted_file_hash == original_hash
        
        if is_valid:
            logging.info(f"Successfully decrypted file {encrypted_file_path} from peer {peer_username}")
        else:
            logging.error(f"Integrity check failed for file {encrypted_file_path} from peer {peer_username}")
            
        return is_valid
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(65536)  # Read 64KB chunks
                if not data:
                    break
                sha256.update(data)
                
        return sha256.hexdigest()

    def get_file_hash(self, file_path: str) -> str:
        """Calculate and return the SHA-256 hash of a file."""
        return self._calculate_file_hash(file_path)
        
    def verify_file_integrity(self, file_path: str, expected_hash: str) -> bool:
        """Verify the integrity of a file using its SHA-256 hash."""
        actual_hash = self._calculate_file_hash(file_path)
        return actual_hash == expected_hash