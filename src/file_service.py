from dataclasses import dataclass
import os
from re import L
import uuid
import mimetypes
from typing import List, Optional


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

class FileService:
    def __init__(self, peer):
        self.peer = peer
        self.shared_files : dict[str, List[str]] = {}   #peer -> file_id
        self.shared_files_info : dict[str, FileInfo] = {}    #file_id -> FileInfo
        self.received_files : dict[str, FileInfo] = {}

    def start(self):
        os.makedirs(SHARED_DIR, exist_ok=True)
        os.makedirs(RECEIVED_DIR, exist_ok=True)

    def share_file(self, file_path: str, keywords: Optional[List[str]] = None, description: Optional[str]=None, peer_list: Optional[List[str]] = None)-> FileInfo:
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
            owner_id=self.peer.local_peer_port,
            mime_type=mime_type,
            keywords=keywords,
            description=description
        )
        
        with open(file_path, 'rb') as src, open(os.path.join(SHARED_DIR, file_id), 'wb') as dst:
            dst.write(src.read())
        
        for peer in (peer_list or self.peer.peers.keys()):
            self.shared_files.setdefault(peer, []).append(file_id)
        self.shared_files_info[file_id] = file_info
        return file_info
    
   
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
    
    def download_file(self, file_id: str, peer: str, destination_path: str):
        pass

    def upload_file(self, file_path: str, peer: str):
        pass
