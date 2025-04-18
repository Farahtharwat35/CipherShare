from concurrent.futures import thread
from os import name
import socket
import threading
import time
from typing import Tuple

from file_service import FileInfo, FileService
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
    def __init__(self, username, server_ip,server_port):
        self.server_address = (server_ip, server_port)
        self.username=username
        self.file_service = FileService(self)
        self.running = False
        self.avilable_peers = {} #username-> (ip, port)
        self.active_connections = {} #username-> socket
        self.connection_lock = threading.Lock()
        self.tcp_port = TCP_PORT
        self.udp_port = UDP_PORT
        
        self.rendezvous_server_socket = None

    def start(self):
        self.running = True
        self.initialize_peer_server_socket()
        threading.Thread(target=self.listen_for_other_peers, daemon=True).start()
        self.register_with_server()
        self.start_heartbeat_thread()
        self.request_peer_list()
        self.file_service.start()

    def register_with_server(self):
        try:
            self.rendezvous_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.rendezvous_server_socket.connect(self.server_address)
            self.rendezvous_server_socket.sendall(f"#JOIN {self.username} {socket.gethostbyname(socket.gethostname())} {self.tcp_port}#\n".encode())
            response = self.rendezvous_server_socket.recv(1024).decode()
            if response.startswith("join-success"):
                print("Registered with server")
            else:
                print("Failed to register with server")
        except Exception as e:
            print(f"Error registering with server: {e}")

    def start_heartbeat_thread(self):
        def send_heartbeat():
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            while self.running:
                try:
                    udp_sock.sendto(f"heartbeat {self.username}\n".encode(), (self.server_address[0], UDP_PORT))
                except Exception as e:
                    print(f"Error sending heartbeat: {e}")
                time.sleep(HEARTBEAT_INTERVAL)
            udp_sock.close()
        threading.Thread(target=send_heartbeat, daemon=True).start()

    def request_peer_list(self):
        try:
            if self.rendezvous_server_socket is None:
                print("Not connected to rendezvous server")
                return []
            self.rendezvous_server_socket.sendall("LIST".encode())
            response = self.rendezvous_server_socket.recv(4096).decode()
            print(f"Received peer list: {response}")
            if not response:
                return []
            peer_list = response.strip().split('\n')

            for peer in peer_list:
                username, address = peer.split('#')
                ip, port = address.split(':')
                port = int(port)
                if username != self.username:
                    self.avilable_peers[username] = (ip, port)

            return self.avilable_peers

        except Exception as e:
            print(f"Error requesting peer list: {e}")
            return []

    def _handle_search_request(self, peer_username, client_socket, name):
        try:
            matching_files = self.file_service.get_shared_files_by_peer_and_file_name(peer_username,name)
            logging.info(f"Found {len(matching_files)} matching files for {name} for {peer_username}")
            files_info = []
            for file_info in matching_files:
                metadata = self.file_service.format_file_info(file_info)
                files_info.append(metadata)

            response = "\n".join(files_info)
            client_socket.sendall(response.encode())
        except Exception as e:
            print(f"Error handling search request: {e}")
        finally:
            client_socket.close()

    def _handle_search_request_keyword(self, peer_username, client_socket, keyword):
        print("Not implemented yet")

    def _handle_download_request(self, client_socket, file_id):
        self.file_service.upload_file(file_id, client_socket)
        client_socket.close()

    def _handle_upload_request(self, peer_username, client_socket, file_id):
        self.file_service.download_file(file_id, client_socket)
        client_socket.close()

    def initialize_peer_server_socket(self):
        self.peer_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.peer_server_socket.bind(('', self.tcp_port))
        self.peer_server_socket.listen(5)
        print(f"Listening for other peers on port {self.tcp_port}")
        self.peer_server_socket.settimeout(4)

    def listen_for_other_peers(self):
        while self.running:
            try:
                client_socket, address = self.peer_server_socket.accept()
                thread = threading.Thread(target=self._handle_peer_connection, args=(client_socket, address), daemon=True)
                thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error accepting connection: {e}")
                time.sleep(1)  

    def _handle_peer_connection(self, client_socket: socket.socket, address: Tuple[str, int]):
        try:
            data = client_socket.recv(1024)
            if not data:
                logging.info(f"Connection closed by {address}")
                return
            peer_username = data.decode().strip()
            logging.info(f"Peer {peer_username} connected from {address}")
            with self.connection_lock:
                self.active_connections[peer_username] = client_socket

            while True:
                data = client_socket.recv(1024)
                if not data:
                    logging.info(f"Connection closed by {address}")
                    break
                command = data.decode()
                logging.info(f"Received command from {address}: {command}")
                if command.startswith("search by keyword"):
                    self._handle_search_request_keyword(peer_username , client_socket, command.split()[1])
                    logging.info(f"Search request by keyword handled for {address}")
                elif command.startswith("search"):
                    self._handle_search_request(peer_username, client_socket, command.split()[1])
                    logging.info(f"Search request handled for {address}")
                elif command.startswith("download"):
                    self._handle_download_request(peer_username, client_socket, command.split()[1])
                    logging.info(f"Download request handled for {address}")
                elif command.startswith("upload"):
                    self._handle_upload_request(peer_username, client_socket, command.split()[1])
                    logging.info(f"Upload request handled for {address}")
                break
        except Exception as e:
            if peer_username is not None and peer_username in self.active_connections:
                del self.active_connections[peer_username]
            logging.error(f"Error handling peer connection: {e}")

    def send_search_request_with_file_name(self, name)->list[FileInfo]:
        try:
            files_info=[]
            for connection in self.active_connections.values():
                connection.sendall(f"search {name}".encode())
                data = connection.recv(1024).decode()
                if data:
                    files_info_str = data.strip().split('\n')
                    for file_info_str in files_info_str:
                        file_info = self.file_service.parse_file_info(file_info_str)
                        files_info.append(file_info)
            return files_info
        except Exception as e:
            print(f"Error sending search request: {e}")
        return []

    def send_search_request_with_keyword(self, keyword)->list[FileInfo]:
        try:
            files_info=[]
            for connection in self.active_connections.values():
                connection.sendall(f"search by keyword {keyword}".encode())
                data = connection.recv(1024).decode()
                if data:
                    files_info_str = data.strip().split('\n')
                    for file_info_str in files_info_str:
                        file_info = self.file_service.parse_file_info(file_info_str)
                        files_info.append(file_info)
            return files_info
        except Exception as e:
            print(f"Error sending search request: {e}")
        return []