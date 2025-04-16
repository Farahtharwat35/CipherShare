from concurrent.futures import thread
from os import name
import socket
import threading
import time
from typing import Tuple

from src.file_service import FileInfo, FileService
import logging


logging.basicConfig(
    filename="peer_connections.log",  
    level=logging.INFO,              
    format="%(asctime)s - %(levelname)s - %(message)s"  
)

UDP_PORT = 5001
TCP_PORT = 5000
HEARTBEAT_INTERVAL = 3


class Peer:
    def __init__(self, server_address, id):
        self.server_address = server_address
        self.id=id
        self.file_service = FileService(self)
        self.running = False
        self.peers = []
        self.tcp_port = TCP_PORT
        self.udp_port = UDP_PORT

    def start(self):
        self.running = True
        #self.register_with_server()
        #self.start_heartbeat_thread()
        #self.peers = self.request_peer_list()
        self.file_service.start()
        threading.Thread(target=self.listen_for_other_peers, daemon=True).start()

    def register_with_server(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.server_address, TCP_PORT))
            s.sendall(f"register {self.id}\n".encode())
            response = s.recv(1024).decode()
            if response == "registered\n":
                print("Registered with server")
            else:
                print("Failed to register with server")
            s.close()
        except Exception as e:
            print(f"Error registering with server: {e}")

    def start_heartbeat_thread(self):
        def send_heartbeat():
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            while self.running:
                try:
                    udp_sock.sendto(f"heartbeat {self.id}\n".encode(), (self.server_address, UDP_PORT))
                except Exception as e:
                    print(f"Error sending heartbeat: {e}")
                time.sleep(HEARTBEAT_INTERVAL)
            udp_sock.close()
        threading.Thread(target=send_heartbeat, daemon=True).start()

    def request_peer_list(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.server_address, TCP_PORT))
            s.sendall("list-peers\n".encode())
            response = s.recv(4096).decode()
            if not response:
                return []
            peer_list = response.strip().split('\n')
            peers = []
            for peer in peer_list:
                ip, port = peer.split(':')
                peers.append((ip, int(port)))
            self.peers = peers
            return peers
        except Exception as e:
            print(f"Error requesting peer list: {e}")
            return []

    def _handle_search_request(self, client_socket, name):
        try:
            peer = client_socket.getpeername()
            matching_files = self.file_service.get_shared_files_by_peer_and_file_name(peer,name)
            logging.info(f"Found {len(matching_files)} matching files for {name} for {peer}")
            files_info= []
            for file_info in matching_files:
                metadata = self.file_service.format_file_info(file_info)
                files_info.append(metadata)

            response = "\n".join(files_info)
            client_socket.sendall(response.encode())
        except Exception as e:
            print(f"Error handling search request: {e}")
        finally:
            client_socket.close()

    def _handle_download_request(self, client_socket, file_id):
        self.file_service.upload_file(file_id, client_socket)
        client_socket.close()

    def _handle_upload_request(self, client_socket, file_id):
        self.file_service.download_file(file_id, client_socket)
        client_socket.close()


    def listen_for_other_peers(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('', self.tcp_port))
        server_socket.listen(5)
        print(f"Listening for other peers on port {self.tcp_port}")

        server_socket.settimeout(4)
        
        while self.running:
            try:
                client_socket, address = server_socket.accept()
                thread = threading.Thread(target=self._handle_peer_connection, args=(client_socket, address), daemon=True)
                thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error accepting connection: {e}")
                time.sleep(1)  

    
    def _handle_peer_connection(self, client_socket: socket.socket, address: Tuple[str, int]):
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    logging.info(f"Connection closed by {address}")
                    break
                command = data.decode()
                logging.info(f"Received command from {address}: {command}")
                if command.startswith("search"):
                    self._handle_search_request(client_socket, command.split()[1])
                    logging.info(f"Search request handled for {address}")
                elif command.startswith("download"):
                    self._handle_download_request(client_socket, command.split()[1])
                    logging.info(f"Download request handled for {address}")
                elif command.startswith("upload"):
                    self._handle_upload_request(client_socket, command.split()[1])
                    logging.info(f"Upload request handled for {address}")
                break
        except Exception as e:
            print(f"Error handling peer connection: {e}")
            logging.error(f"Error handling peer connection: {e}")
        


    def send_search_request_with_file_name(self, name)->list[FileInfo]:
        try:
            files = []
            for peer in self.peers:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect(peer)
                s.sendall(f"search {name}".encode())
                response = s.recv(4096).decode()
                if not response:
                    continue
                files_info = response.strip().split('\n')
                for file_info in files_info:
                    metadata = self.file_service.parse_file_info(file_info)
                    files.append(metadata)
            return files
        except Exception as e:
            print(f"Error sending search request: {e}")
        return []