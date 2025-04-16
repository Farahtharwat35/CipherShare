from typing import Tuple
from dataclasses import dataclass
import os
from re import L
import uuid
import mimetypes
from typing import List, Optional
import socket


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
        self.shared_files : dict[Tuple[str,int], List[str]] = {}   #peer -> file_id
        self.shared_files_info : dict[str, FileInfo] = {}    #file_id -> FileInfo
        self.received_files : dict[str, FileInfo] = {}

    def start(self):
        os.makedirs(SHARED_DIR, exist_ok=True)
        os.makedirs(RECEIVED_DIR, exist_ok=True)

    def share_file(self, file_path: str, keywords: Optional[List[str]] = None, description: Optional[str]=None, peer_list: Optional[List[Tuple[str, int]]] = None, is_public: bool = True)-> FileInfo:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        file_id = str(uuid.uuid4())
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        mime_type, _ = mimetypes.guess_type(file_path)
        file_info = FileInfo(
            id=file_id,
            name=file_name,
            size=file_size,
            owner_id=self.peer.id,
            mime_type=mime_type,
            keywords=keywords,
            description=description,
            is_public=is_public
        )
        
        with open(file_path, 'rb') as src, open(os.path.join(SHARED_DIR, file_id), 'wb') as dst:
            dst.write(src.read())
        
        peers_to_share = peer_list if peer_list is not None else self.peer.peers
    
        for peer in peers_to_share:
            if isinstance(peer, str):  
                peer = (peer, 0)  
            self.shared_files.setdefault(peer, []).append(file_id)
        self.shared_files_info[file_id] = file_info
        return file_info
    
   
    def get_shared_files_by_peer(self, peer: Tuple[str, int]) -> List[FileInfo]:
        peer_file_ids = self.shared_files.get(peer, [])
        return [self.shared_files_info[file_id] for file_id in peer_file_ids]
    
    def get_shared_files_by_peer_and_keywords(self, peer: Tuple[str, int], keywords: List[str]) -> List[FileInfo]:
        peer_file_ids = self.shared_files.get(peer, [])
        return [
            self.shared_files_info[file_id]
            for file_id in peer_file_ids
            if self.shared_files_info[file_id].keywords and
               all(keyword in (self.shared_files_info[file_id].keywords or []) for keyword in keywords)
        ]
    
    def get_shared_files_by_peer_and_file_name(self, peer: Tuple[str, int], file_name: str) -> List[FileInfo]:
        all_files = []
        for peer, file_ids in self.shared_files.items():
            for file_id in file_ids:
                file_info = self.shared_files_info.get(file_id)
                if file_info and file_name.lower() in file_info.name.lower():
                    print(f"Found matching file: {file_info.name}")
                    all_files.append(file_info)
        print(f"Found {str(all_files)} matching files for {file_name}")
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
        try:
            socket.sendall(f"download {file_id}\n".encode())

            upload_signal = socket.recv(1024).decode().strip()
            if upload_signal != "upload":
                raise ValueError(f"Expected 'upload' signal, but received: {upload_signal}")
            
            metadata = socket.recv(1024).decode().strip()
            file_info = self.parse_file_info(metadata)
            self.received_files[file_id] = file_info
            start_signal = socket.recv(1024).decode().strip()
            if start_signal != "start":
                raise ValueError(f"Expected 'start' signal, but received: {start_signal}")
            
            file_path = os.path.join(RECEIVED_DIR, file_id)
            with open(file_path, 'wb') as f:
                while True:
                    data = socket.recv(4096)
                    if not data:
                        break
                    f.write(data)
        except Exception as e:
            print(f"Error downloading file: {e}")
        


    def upload_file(self, file_id: str, socket: socket.socket):
        print(f"Uploading file {file_id}")
        socket.sendall(f"upload\n".encode())
        file_info = self.shared_files_info[file_id]
        metadata = self.format_file_info(file_info)
        socket.sendall(f"{metadata}\n".encode())
        socket.sendall("start\n".encode())
        file_path = os.path.join(SHARED_DIR, file_id)
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(4096)
                if not data:
                    break
                socket.sendall(data)
        
