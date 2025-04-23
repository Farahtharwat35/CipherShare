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
    def __init__(self, username, server_ip, server_port, self_tcp_port = TCP_PORT, self_udp_port = UDP_PORT):
        self.server_address = (server_ip, server_port)
        self.username=username
        self.file_service = FileService(self)
        self.running = False
        self.available_peers = {} #username-> (ip, port)
        self.active_incoming_connections:dict[str, socket.socket] = {} #username-> socket
        self.active_outgoing_connections: dict[str, socket.socket] = {} #username-> (socket)
        self.connection_lock = threading.Lock()
        self.tcp_port = self_tcp_port
        self.udp_port = self_udp_port
        self.sessionKey = None
        
        self.rendezvous_server_socket = None

    def start(self):
        self.running = True
        self.initialize_peer_server_socket()
        threading.Thread(target=self.listen_for_other_peers, daemon=True).start()
        threading.Thread(target=self._registration_sequence, daemon=True).start()
        self.file_service.start()

    def _registration_sequence(self):
        try:
            self.register_with_server()
            self.start_heartbeat_thread()
            self.request_peer_list()
        except Exception as e:
            logging.error(f"Error in registration sequence: {e}")
            self.running = False
    
    def register_with_server(self):
        try:
            self.rendezvous_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.rendezvous_server_socket.connect(self.server_address)
            self.rendezvous_server_socket.sendall(f"#JOIN {self.username} {self._get_local_ip_address()} {self.tcp_port}#".encode())
            response = self.rendezvous_server_socket.recv(1024).decode()
            responseParts = response.split()
            print(f"Received from server: {responseParts}")
            if response.startswith("join-success") and len(responseParts) == 2:
                sessionKey = responseParts[1]
                self.sessionKey = sessionKey
                print("Registered with server\n")
            else:
                print("Failed to register with server")
        except Exception as e:
            print(f"Error registering with server: {e}")

    def start_heartbeat_thread(self):
        def send_heartbeat():
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            while self.running:
                try:
                    udp_sock.sendto(f"Heartbeat {self.username} {self.sessionKey}\n".encode(), (self.server_address[0], UDP_PORT))
                except Exception as e:
                    print(f"Error sending heartbeat: {e}")
                time.sleep(HEARTBEAT_INTERVAL)
            udp_sock.close()
        threading.Thread(target=send_heartbeat, daemon=True).start()

    def request_peer_list(self):
        try:
            if self.rendezvous_server_socket is None:
                print("Not connected to rendezvous server")
                return
            self.rendezvous_server_socket.sendall(f"#{self._authCmd("LIST")}#".encode())
            response = self.rendezvous_server_socket.recv(4096).decode()
            if not response:
                return
            self.available_peers = {}
            if response.startswith("Online peers:"):
                peers_str = response.replace("Online peers:", "").strip()
                if peers_str: 
                    peer_list = peers_str.split(',')
                    for peer in peer_list:
                        peer_parts = peer.strip().rsplit(' ', 1)
                        if len(peer_parts) != 2:
                            raise ValueError(f"Invalid peer format: {peer}")
                        
                        username = peer_parts[0].strip()
                        address = peer_parts[1].strip().strip('()')  # Remove parentheses
                        ip, port = address.split(':')
                        port = int(port)

                        if username != self.username:
                            self.available_peers[username] = (ip, port)        
            return
        except Exception as e:
            print(f"Error requesting peer list: {e}")
            return

    def _handle_search_request(self, peer_username, client_socket, name):
        try:
            matching_files = self.file_service.get_shared_files_by_peer_and_file_name(peer_username, name)
            logging.info(f"Found {len(matching_files)} matching files for {name} for {peer_username}")
            files_info = []
            
            if not matching_files:
                client_socket.sendall("no file found".encode())
                return
            
            for file_info in matching_files:
                metadata = self.file_service.format_file_info(file_info)
                files_info.append(metadata)
            response = "\n".join(files_info)
            response = f"found {response}"
            client_socket.sendall(response.encode())
        except Exception as e:
            print(f"Error handling search request: {e}")

    def _handle_search_request_keyword(self, peer_username, client_socket, keyword):
        try:
            matching_files = self.file_service.get_shared_files_by_peer_and_keywords(peer_username, keyword)
            logging.info(f"Found {len(matching_files)} matching files for {keyword} for {peer_username}")
            files_info = []
            if not matching_files:
                client_socket.sendall("No files macthes your search".encode())
                return
            response = "\n".join(files_info)
            client_socket.sendall(response.encode())
        except Exception as e:
            print(f"Error handling search request: {e}")

    def _handle_download_request(self,peer_username, client_socket, file_id):
        self.file_service.upload_file(peer_username,file_id, client_socket)
        

    def initialize_peer_server_socket(self):
        self.peer_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.peer_server_socket.bind(('', self.tcp_port))
        self.peer_server_socket.listen(5)
        print(f"Listening for other peers on port {self.tcp_port}")
        self.peer_server_socket.settimeout(4)

    def _connect_to_peer(self, username, peer_ip, peer_port):
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((peer_ip, peer_port))
            peer_socket.sendall(f"HELLO {username} {self.username}\n".encode())
            response = peer_socket.recv(1024).decode()
            if response != "HELLO_ACK":
                print(f"Failed to connect to peer {username}")
                peer_socket.close()
                return None
            self.active_outgoing_connections[username] = peer_socket
            print(f"Connected to peer {username} at {peer_ip}:{peer_port}")
            return peer_socket
        except Exception as e:
            print(f"Error connecting to peer: {e}")
            return None
            
    def connect_to_peers(self):
        try:
            for peer_username in self.available_peers:
                peer_ip, peer_port = self.available_peers[peer_username]
                socket= self._connect_to_peer(peer_username, peer_ip, peer_port)
                if socket is None:
                    print(f"Failed to connect to peer {peer_username}")
                    continue
                self.active_outgoing_connections[peer_username] = socket
                print(f"Connected to peer {peer_username} at {peer_ip}:{peer_port}")
        except Exception as e:
            print(f"Error connecting to peer: {e}")
            return None

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
        peer_username = None
        try:
            data = client_socket.recv(1024)
            if not data:
                logging.info(f"Connection closed by {address}")
                return
           
            initial_message = data.decode().strip()
            if not initial_message.startswith("HELLO") or len(initial_message.split()) != 3 or initial_message.split()[1] != self.username:
                logging.error(f"Invalid initial message from {address}: {initial_message}")
                client_socket.close()
                return

            #print(f"Received HELLO from {address}: {initial_message}")
            client_socket.sendall("HELLO_ACK".encode())
            
            # Proceed with the connection
            peer_username = initial_message.split()[2]
            logging.info(f"Peer {peer_username} connected from {address}")
            with self.connection_lock:
                self.active_incoming_connections[peer_username] = client_socket

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
                break
        except Exception as e:
            if peer_username is not None and peer_username in self.active_incoming_connections:
                del self.active_incoming_connections[peer_username]
            logging.error(f"Error handling peer connection: {e}")

    def send_search_request_with_file_name_or_keyword(self, name, is_keyword=False)->list[FileInfo]:
        try:
            self.connect_to_peers()
            files_info=[]
            connection_to_close = []
            for username, connection in self.active_outgoing_connections.items():
                send_command = f"search by keyword {name}" if is_keyword else f"search {name}"
                connection.sendall(send_command.encode())
                data = connection.recv(1024).decode()
                if data[:5] == "found":
                    data = data[6:]
                    files_info_str = data.strip().split('\n')
                    for file_info_str in files_info_str:
                        file_info = self.file_service.parse_file_info(file_info_str)
                        files_info.append(file_info)
                else:
                    print(f"Peer {username} responded with: {data}")
                connection_to_close.append(connection)
            
            for conn in connection_to_close:
                self._close_connection(conn)
            return files_info
        except Exception as e:
            #print(f"Error sending search request: {e}")
            logging.error(f"Error sending search request: {e}")
        return []
    
    def send_download_request(self,username, file_id):
        try:
            if username not in self.available_peers:
                print(f"Peer {username} not available")
                return
            peer_ip, peer_port = self.available_peers[username]
            socket = self._connect_to_peer(username, peer_ip, peer_port)
            try:
                if socket is None:
                    print(f"Failed to connect to peer {username}")
                    return
                socket.sendall(f"download {file_id}".encode())
                self.file_service.download_file(file_id, socket)

                import os
                file_path = os.path.join("received", file_id)
                if os.path.exists(file_path):
                    print(f"File {file_id} downloaded successfully from {username}")
                else:
                    print(f"Failed to download file {file_id} from {username}")
                self._close_connection(socket)
            except Exception as e:
                print(f"Error during download request: {e}")
        except Exception as e:
            print(f"Error sending download request: {e}")

    def _close_connection(self,conn):
        try:
            conn.close()
            with self.connection_lock:
                for username, socket in self.active_outgoing_connections.items():
                    if socket == conn:
                        del self.active_outgoing_connections[username]
                        break
            logging.info(f"Connection closed")
        except Exception as e:
            logging.error(f"Error closing connection: {e}")
    
    def stop(self):
        self.running = False
        if self.rendezvous_server_socket:
            self.rendezvous_server_socket.close()
        if self.peer_server_socket:
            self.peer_server_socket.close()
        for conn in self.active_outgoing_connections.values():
            self._close_connection(conn)
        self.active_outgoing_connections.clear()
        self.active_incoming_connections.clear()
        print("Peer stopped")
    
    def _get_local_ip_address(self):
        """Get the local IP address of the machine"""
        HOST = socket.gethostname()
        try:
            HOST = socket.gethostbyname(HOST)
        except socket.gaierror:
            import netifaces as ni
            HOST = ni.ifaddresses('en0')[ni.AF_INET][0]['addr']
        return HOST

    def _authCmd(self, cmd):
        return f"{cmd}:{self.sessionKey}"