import logging
from typing import Tuple
from dataclasses import dataclass
import os
from re import L
import uuid
import mimetypes
from typing import List, Optional
import socket
import tempfile
from .crypto.crypto_utils import CryptoUtils

SHARED_DIR = "shared"
RECEIVED_DIR = "received"

@dataclass
class FileInfo:
    id: str
    name: str
    size: int
    owner_id: str
    mime_type: Optional[str] = None
    keywords: Optional[List[str]] = None
    description: Optional[str] = None
    is_public: bool = False

class FileService:
    def __init__(self, peer):
        self.peer = peer
        self.shared_files : dict[str, List[str]] = {}   #peer_username -> file_id
        self.shared_files_info : dict[str, FileInfo] = {}    #file_id -> FileInfo
        self.received_files : dict[str, FileInfo] = {}
        logging.info("Initializing CryptoUtils instance for FileService")
        self.crypto = CryptoUtils()  # Initialize the crypto utils
        logging.info("FileService initialized with CryptoUtils")

    def start(self):
        logging.info(f"Starting FileService, creating directories: {SHARED_DIR}, {RECEIVED_DIR}")
        os.makedirs(SHARED_DIR, exist_ok=True)
        os.makedirs(RECEIVED_DIR, exist_ok=True)
        logging.info("FileService directories created/verified")

    def share_file(self, file_path: str, keywords: Optional[List[str]] = None, description: Optional[str]=None, peer_list: Optional[List[str]] = None, is_public: bool = True)-> FileInfo:
        if not os.path.isfile(file_path):
            logging.error(f"File not found for sharing: {file_path}")
            raise FileNotFoundError(f"File not found: {file_path}")
            
        logging.info(f"Sharing file: {file_path}")
        file_id = str(uuid.uuid4())
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        mime_type, _ = mimetypes.guess_type(file_path)
        
        logging.debug(f"Generated file ID: {file_id}")
        logging.debug(f"File details: name={file_name}, size={file_size}, mime_type={mime_type}")
        
        file_info = FileInfo(
            id=file_id,
            name=file_name,
            size=file_size,
            owner_id=self.peer.username,
            mime_type=mime_type,
            keywords=keywords,
            description=description,
            is_public=is_public
        )
        
        logging.debug(f"Copying file to shared directory: {file_path} -> {os.path.join(SHARED_DIR, file_id)}")
        with open(file_path, 'rb') as src, open(os.path.join(SHARED_DIR, file_id), 'wb') as dst:
            content = src.read()
            dst.write(content)
            logging.debug(f"File copied, size: {len(content)} bytes")
        
        peers_to_share = peer_list if peer_list is not None else self.peer.available_peers.keys()
        logging.info(f"Sharing file {file_id} with {len(peers_to_share)} peers: {', '.join(peers_to_share) if len(peers_to_share) <= 5 else ', '.join(list(peers_to_share)[:5]) + '...'}")
    
        for peer in peers_to_share:
            self.shared_files.setdefault(peer, []).append(file_id)
            logging.debug(f"File {file_id} added to share list for peer {peer}")
            
        self.shared_files_info[file_id] = file_info
        logging.info(f"File {file_id} ({file_name}) shared successfully")
        return file_info
    
    def unshare_file(self, file_id: str):
        if file_id not in self.shared_files_info:
            raise ValueError(f"File ID {file_id} not found in shared files.")
        
        peers_to_unshare = self.peer.available_peers.keys()
        for peer in peers_to_unshare:
            if peer in self.shared_files and file_id in self.shared_files[peer]:
                self.shared_files[peer].remove(file_id)
                if not self.shared_files[peer]:
                    del self.shared_files[peer]

        del self.shared_files_info[file_id]
        os.remove(os.path.join(SHARED_DIR, file_id))
        print(f"File {file_id} unshared and removed from shared files.")
    
    def get_shared_files(self) -> List[FileInfo]:
        return list(self.shared_files_info.values())
   
    def get_shared_files_by_peer(self, peer: str) -> List[FileInfo]:
        peer_file_ids = self.shared_files.get(peer, [])
        return [self.shared_files_info[file_id] for file_id in peer_file_ids]
    
    def get_shared_files_by_peer_and_keywords(self, peer: str, keywords: List[str]) -> List[FileInfo]:
        peer_file_ids = self.shared_files.get(peer, [])
        return [
            self.shared_files_info[file_id]
            for file_id in peer_file_ids
            if self.shared_files_info[file_id].keywords and
               all(keyword in (self.shared_files_info[file_id].keywords or []) for keyword in keywords)
        ]
    
    def get_shared_files_by_peer_and_file_name(self, peer: str, file_name: str) -> List[FileInfo]:
        all_files = []
        file_ids = self.shared_files.get(peer, [])
        logging.info(f"Searching for files with name '{file_name}' for peer '{peer}'.")
        logging.info(f"File IDs: {file_ids}")
        for file_id in file_ids:
            file_info = self.shared_files_info[file_id]
            if file_info.name.lower() == file_name.lower():
                logging.info(f"Found matching file: {file_info.name}")
                all_files.append(file_info)
        logging.info(f"Found {len(all_files)} files matching '{file_name}' for peer '{peer}'.")
        return all_files
    
    def parse_file_info(self, metadata: str) -> FileInfo:
        if not metadata.startswith("info|"):
            raise ValueError(f"Expected 'info|' prefix in metadata, but received: {metadata}")
        
        metadata_parts = metadata[5:].split("|")
        metadata_dict = {part.split(":")[0]: part.split(":")[1] for part in metadata_parts if ":" in part}

        return FileInfo(
            id=metadata_dict["id"],
            name=metadata_dict["name"],
            size=int(metadata_dict["size"]),
            owner_id=metadata_dict["owner_id"],
            mime_type=metadata_dict.get("mime_type"),
            keywords=metadata_dict["keywords"].split(",") if "keywords" in metadata_dict and metadata_dict["keywords"] else None,
            description=metadata_dict.get("description"),
            is_public=metadata_dict.get("is_public", "").lower() == "true"
        )
    
    def format_file_info(self, file_info: FileInfo) -> str:
        return (
        f"info|id:{file_info.id}|name:{file_info.name}|size:{file_info.size}|"
        f"mime_type:{file_info.mime_type}|owner_id:{file_info.owner_id}|"
        f"keywords:{','.join(file_info.keywords) if file_info.keywords else ''}|"
        f"description:{file_info.description}|is_public:{file_info.is_public}"
        )
    
    def download_file(self, file_id: str, socket: socket.socket):
        temp_file_path = None
        try:
            logging.info(f"Starting file download process for file ID: {file_id}")
            socket.settimeout(60)
            logging.debug("Socket timeout set to 60 seconds")
            
            metadata = socket.recv(1024).decode().strip()
            logging.debug(f"Received file metadata: {metadata}")
            file_info = self.parse_file_info(metadata)
            peer_username = file_info.owner_id
            logging.info(f"File info: id={file_info.id}, name={file_info.name}, size={file_info.size}, from peer={peer_username}")

            socket.sendall(f"metadata_received\n".encode())
            logging.debug("Sent metadata_received acknowledgment")
            
            start_signal = socket.recv(1024).decode().strip()
            logging.debug(f"Received signal from peer: {start_signal}")
            if start_signal != "start":
                logging.error(f"Expected 'start' signal, but received: {start_signal}")
                raise ValueError(f"Expected 'start' signal, but received: {start_signal}")
            
            logging.info(f"Received start signal from peer")
            logging.info(f"Starting file download...")
            
            # Ensure temp directory exists
            temp_dir = tempfile.gettempdir()
            if not os.path.exists(temp_dir):
                os.makedirs(temp_dir, exist_ok=True)
                logging.debug(f"Created temp directory: {temp_dir}")
            
            # Create a temporary file for the encrypted data with a unique name
            temp_file_path = os.path.join(temp_dir, f"ciphershare_temp_{file_id}")
            logging.debug(f"Created temporary file path for encrypted content: {temp_file_path}")
            
            # Ensure the RECEIVED_DIR exists
            if not os.path.exists(RECEIVED_DIR):
                os.makedirs(RECEIVED_DIR, exist_ok=True)
                logging.debug(f"Created received directory: {RECEIVED_DIR}")
            
            bytes_received = 0
            buffer = b""
            logging.debug("Beginning file content reception")

            # First, receive the encrypted file and integrity hash
            with open(temp_file_path, 'wb') as f:
                integrity_hash = None
                while True:
                    try:
                        data = socket.recv(4096)
                        if not data:
                            logging.debug("No more data received, connection closed")
                            break
                        
                        buffer += data
                        logging.debug(f"Received {len(data)} bytes, buffer size: {len(buffer)} bytes")
                        
                        if b"EOF\n" in buffer:
                            eof_pos = buffer.find(b"EOF\n")
                            f.write(buffer[:eof_pos])
                            bytes_received += eof_pos
                            
                            # Extracting the hash from the remaining buffer
                            hash_marker = buffer[eof_pos+4:].strip()
                            if hash_marker.startswith(b"HASH:"):
                                integrity_hash = hash_marker[5:].decode()
                                logging.info(f"Received file integrity hash: {integrity_hash[:10]}...")
                            
                            logging.info(f"Received EOF marker after {bytes_received} bytes")
                            break
                        else:
                            to_write = buffer[:-5] if len(buffer) > 5 else b""
                            buffer = buffer[-5:] if len(buffer) > 5 else buffer
                            if to_write:
                                f.write(to_write)
                                bytes_received += len(to_write)
                                logging.debug(f"Wrote {len(to_write)} bytes to file, total received: {bytes_received} bytes")
                    except socket.timeout:
                        logging.error("Socket timeout during file download")
                        break
                    except Exception as e:
                        logging.error(f"Error during file download: {e}", exc_info=True)
                        break
            
            if not os.path.exists(temp_file_path) or os.path.getsize(temp_file_path) == 0:
                logging.error("Temporary file was not created or is empty")
                print("Error: Failed to receive file data")
                return
                
            logging.info(f"Download complete, received {bytes_received} bytes of encrypted data")
            
            # Here we decrypt the file 
            if not integrity_hash:
                logging.error("No integrity hash received with the file")
                print("Error: No integrity hash received with the file")
                return
                
            if not self.crypto.has_shared_key(peer_username):
                logging.error(f"No shared key found for peer {peer_username}")
                print(f"Error: No shared key found for peer {peer_username}")
                return
            
            logging.info(f"Preparing to decrypt file from peer {peer_username}")
            final_path = os.path.join(RECEIVED_DIR, file_id)
            logging.debug(f"Decryption output path: {final_path}")
            
            
            logging.info(f"Decrypting file with shared key for peer {peer_username}")
            if self.crypto.decrypt_file(peer_username, temp_file_path, final_path, integrity_hash):
                logging.info(f"File {file_id} downloaded and decrypted successfully")
                self.received_files[file_id] = file_info
                logging.debug(f"Added file info to received_files dictionary")
                new_final_path = os.path.join(RECEIVED_DIR, file_info.name)
                os.rename(final_path, new_final_path)
                logging.debug(f"Renamed file from {final_path} to {new_final_path}")
                print(f"File {file_id} downloaded and decrypted successfully to {new_final_path}")
            else:
                logging.error("File integrity check failed. The file may have been tampered with.")
                print("Error: File integrity check failed. The file may have been tampered with.")
                return
                
        except Exception as e:
            logging.error(f"Error downloading file: {e}", exc_info=True)
            print(f"Error downloading file: {e}")
            
        finally:
            # Clean up: Remove the temporary file if it exists
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                    logging.debug(f"Removed temporary encrypted file {temp_file_path}")
                except Exception as e:
                    logging.warning(f"Failed to remove temporary file: {e}")
        

    def upload_file(self, peer_username: str, file_id: str, socket: socket.socket):
        temp_file_path = None
        try:
            requester_username = peer_username
            logging.info(f"Starting file upload process for file ID: {file_id} to peer: {peer_username}")
            socket.settimeout(60)
            logging.debug("Socket timeout set to 60 seconds")

            if requester_username not in self.shared_files or file_id not in self.shared_files[requester_username]:
                logging.error(f"File {file_id} is not shared with {requester_username}.")
                socket.sendall(f"not-allowed\n".encode())
                logging.debug("Sent not-allowed message")
                return
            
            logging.info(f"Uploading file {file_id} to {peer_username}.")
            
            if not self.crypto.has_shared_key(peer_username):
                logging.error(f"No shared key found for peer {peer_username}")
                socket.sendall(f"encryption-error\n".encode())
                logging.debug("Sent encryption-error message")
                return
            
            socket.sendall(f"upload\n".encode())
            logging.debug("Sent upload signal")
            
            # Waiting for the client to be ready to receive metadata
            ready_signal = None
            try:
                ready_signal = socket.recv(1024).decode().strip()
                logging.debug(f"Received readiness signal: {ready_signal}")
            except Exception as e:
                logging.error(f"Error receiving readiness signal: {e}")
                return
                
            if ready_signal != "ready_for_metadata":
                logging.warning(f"Client not ready for metadata, received: '{ready_signal}'. Continuing anyway...")
            
           
            file_info = self.shared_files_info[file_id]
            metadata = self.format_file_info(file_info)
            socket.sendall(f"{metadata}\n".encode())
            logging.info(f"Sent file metadata: {metadata[:50]}...")

 
            try:
                ack = socket.recv(1024).decode().strip()
                logging.debug(f"Received acknowledgment: {ack}")
                if ack != "metadata_received":
                    logging.error(f"Expected 'metadata_received' signal, but received: {ack}")
                    return
            except Exception as e:
                logging.error(f"Error receiving metadata acknowledgment: {e}")
                return
            

            socket.sendall("start\n".encode())
            logging.debug("Sent start signal")
            
            file_path = os.path.join(SHARED_DIR, file_id)
            logging.debug(f"Original file path: {file_path}")
            
            # Creating a temporary file for the encrypted data
            temp_dir = tempfile.gettempdir()
            temp_file_path = os.path.join(temp_dir, f"ciphershare_temp_upload_{file_id}")
            logging.debug(f"Temporary encryption output path: {temp_file_path}")
            
            
            logging.info(f"Encrypting file {file_path} for peer {peer_username}")
            try:
                file_hash = self.crypto.encrypt_file(peer_username, file_path, temp_file_path)
                logging.info(f"File encrypted successfully, hash: {file_hash[:10]}...")
            except Exception as e:
                logging.error(f"Encryption failed: {e}", exc_info=True)
                socket.sendall("encryption-error\n".encode())
                return
            
            logging.info("Beginning to send encrypted file")
            bytes_sent = 0
            
            if os.path.exists(temp_file_path):
                with open(temp_file_path, 'rb') as f:
                    while True:
                        data = f.read(4096)
                        if not data:
                            logging.debug("End of file reached")
                            break
                        socket.sendall(data)
                        bytes_sent += len(data)
                        logging.debug(f"Sent {bytes_sent} bytes so far")
                
                socket.sendall(f"EOF\nHASH:{file_hash}\n".encode())
                logging.info(f"Sent EOF marker and integrity hash: {file_hash[:10]}...")
                logging.info(f"File {file_id} encrypted and uploaded to {peer_username}, total bytes sent: {bytes_sent}")
            else:
                logging.error(f"Encrypted file {temp_file_path} not found")
                socket.sendall("error-during-transfer\n".encode())
                
        except Exception as e:
            logging.error(f"Error uploading file: {e}", exc_info=True)
            try:
                socket.sendall("error-during-transfer\n".encode())
                logging.debug("Sent error-during-transfer message")
            except Exception:
                logging.error("Failed to send error message after exception")
        finally:
            # Remove the temporary encrypted file if it exists
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                    logging.debug(f"Removed temporary encrypted file {temp_file_path}")
                except Exception as e:
                    logging.warning(f"Failed to remove temporary file: {e}")



