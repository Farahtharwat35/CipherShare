from concurrent.futures import thread
from os import name
import socket
import threading
import time
from typing import Tuple
from file_service import FileInfo, FileService
import logging
import os , sys
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)
from src.utils import get_local_ip_address
from src.config.config import TCP_PORT, UDP_PORT , HEARTBEAT_INTERVAL , LOGGING_LEVEL

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
            self.start_heartbeat_thread()
            self.request_peer_list()
        except Exception as e:
            logging.error(f"Error in registration sequence: {e}")
            self.running = False
    
    def register_with_server(self):
        try:
            self.rendezvous_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.rendezvous_server_socket.connect(self.server_address)
            self.rendezvous_server_socket.sendall(f"#JOIN {self.username} {get_local_ip_address()} {self.tcp_port}#".encode())
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

    def _handle_download_request(self, peer_username, client_socket, file_id):
        try:
            # First check if the peer is allowed to download this file
            if peer_username not in self.file_service.shared_files or file_id not in self.file_service.shared_files[peer_username]:
                logging.error(f"File {file_id} is not shared with {peer_username}")
                client_socket.sendall("not-allowed\n".encode())
                return
                
            # Checking if we have a shared key with this peer
            has_shared_key = hasattr(self.file_service, 'crypto') and self.file_service.crypto.has_shared_key(peer_username)
            
            if not has_shared_key:
                # We need to initiate a key exchange first
                logging.info(f"Initiating key exchange with {peer_username} before file upload")
                client_socket.sendall("key-exchange-required\n".encode())
            
                response = client_socket.recv(1024).decode().strip()
                if response != "ready-for-key-exchange":
                    logging.error(f"Peer {peer_username} rejected key exchange request")
                    client_socket.sendall("file-transfer-cancelled\n".encode())
                    return
                
                # Performng the key exchange
                success = self.initiate_key_exchange(peer_username, client_socket)
                if not success:
                    logging.error(f"Key exchange with {peer_username} failed")
                    client_socket.sendall("key-exchange-failed\n".encode())
                    return
                
                logging.info(f"Key exchange with {peer_username} successful, proceeding with file upload")
                client_socket.sendall("key-exchange-success\n".encode())
                
            # If we already have a shared key, proceed with the upload
            self.file_service.upload_file(peer_username, file_id, client_socket)
            
        except Exception as e:
            logging.error(f"Error handling download request: {e}", exc_info=True)
            try:
                client_socket.sendall("error-during-transfer\n".encode())
            except:
                pass

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
            
            if initial_message.startswith("HELLO"):
                peer_username = initial_message.split()[2]
            logging.info(f"Peer {peer_username} connected from {address}")
            with self.connection_lock:
                self.active_incoming_connections[peer_username] = client_socket

            while True:
                data = client_socket.recv(1024)
                if not data:
                    logging.info(f"Connection closed by {address}")
                    break
                
                command = data.decode().strip()
                logging.info(f"Received command from {address}: {command}")
                
                if command.startswith("search by keyword"):
                    self._handle_search_request_keyword(peer_username, client_socket, command.split()[3])
                    logging.info(f"Search request by keyword handled for {address}")
                
                elif command.startswith("search"):
                    self._handle_search_request(peer_username, client_socket, command.split()[1])
                    logging.info(f"Search request handled for {address}")
                
                elif command.startswith("download"):
                    # Processing the download request - key exchange will be handled automatically inside _handle_download_request
                    file_id = command.split()[1]
                    self._handle_download_request(peer_username, client_socket, file_id)
                    logging.info(f"Download request handled for {address}")
                
                elif command.startswith("download-proceed"):
                    # This command is sent after a successful key exchange to continue with the download
                    file_id = command.split()[1]
                    self.file_service.upload_file(peer_username, file_id, client_socket)
                    logging.info(f"File upload completed for {file_id} to {peer_username}")

                elif command.startswith("upload started"):
                    logging.info(f"Upload started for {file_id} from {peer_username}")
                    print(f"Upload started for {file_id} from {peer_username}")
                else:
                    logging.warning(f"Unknown command from {peer_username}: {command}")
        
        except Exception as e:
            if peer_username is not None and peer_username in self.active_incoming_connections:
                del self.active_incoming_connections[peer_username]
                self.file_service.crypto.remove_shared_key(peer_username)
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
            logging.error(f"Error sending search request: {e}")
        return []
    
    def send_download_request(self, username, file_id):
        try:
            if username not in self.available_peers:
                print(f"Peer {username} not available")
                return
                
            peer_ip, peer_port = self.available_peers[username]
            socket = self._connect_to_peer(username, peer_ip, peer_port)
            
            if socket is None:
                print(f"Failed to connect to peer {username}")
                return
            
            print(f"Requesting file {file_id} from {username}...")
            socket.sendall(f"download {file_id}".encode())
            
            response = socket.recv(1024).decode().strip()
            
            if response == "not-allowed":
                print(f"Not authorized to download file {file_id}")
                self._close_connection(socket)
                return
                
            elif response == "key-exchange-required":
                # Uploader wants to initiate key exchange
                print(f"Establishing secure connection with {username}...")
                
                socket.sendall("ready-for-key-exchange\n".encode())
                
                # The uploader will send "key-exchange-request"
                key_exchange_msg = socket.recv(1024).decode().strip()
                if key_exchange_msg != "key-exchange-request":
                    print(f"Unexpected message during key exchange: {key_exchange_msg}")
                    self._close_connection(socket)
                    return
                
                # Handling the key exchange initiated by the uploader
                success = self.handle_key_exchange_request(username, socket)
                if not success:
                    print(f"Key exchange with {username} failed")
                    self._close_connection(socket)
                    return
                
                # Waiting for confirmation from the uploader
                confirmation = socket.recv(1024).decode().strip()
                if confirmation != "key-exchange-success":
                    print(f"Key exchange with {username} was not successful: {confirmation}")
                    self._close_connection(socket)
                    return
                    
                print(f"Secure connection established with {username}")
                print(f"Waiting for file transfer from {username}...")
                
                # The transfer will continue below with whatever signal is sent by the uploader
                response = socket.recv(1024).decode().strip()
            
            # Handling receiving upload signal
            if response == "upload" or response == "upload started":
                print(f"Starting file download from {username}...")
                
                # Signal that I am ready to receive metadata
                socket.sendall("ready_for_metadata\n".encode())
                
                # Now proceeding with file download
                self.file_service.download_file(file_id, socket)
                
                import os
                file_path = os.path.join("received", file_id)
                if os.path.exists(file_path):
                    print(f"File {file_id} downloaded successfully from {username}")
                else:
                    print(f"Failed to download file {file_id} from {username}")
            else:
                print(f"Unexpected response from peer: {response}")
                self._close_connection(socket)
                
        except Exception as e:
            print(f"Error sending download request: {e}")
            logging.error(f"Error in download request: {e}", exc_info=True)

    def _close_connection(self,conn):
        try:
            conn.close()
            with self.connection_lock:
                for username, socket in self.active_outgoing_connections.items():
                    if socket == conn:
                        del self.active_outgoing_connections[username]
                        self.file_service.crypto.remove_shared_key(username)
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
    
    def _authCmd(self, cmd):
        return f"{cmd}:{self.sessionKey}"

    def initiate_key_exchange(self, peer_username: str, socket: socket.socket) -> bool:
        """
        Initiate a Diffie-Hellman key exchange with a peer
        """
        try:
            # Check if we already have a shared key with this peer
            if self.file_service.crypto.has_shared_key(peer_username):
                logging.info(f"Already have a shared key with peer {peer_username}, skipping key exchange")
                return True
                
            # Send key exchange request
            socket.sendall("key-exchange-request\n".encode())
            
            # Send my DH public key - using a cleaner protocol
            public_key_bytes = self.file_service.crypto.get_public_key_bytes()
            # Send the public key with a clear delimiter
            socket.sendall(b"BEGIN_PUBLIC_KEY\n")
            socket.sendall(public_key_bytes)
            socket.sendall(b"\nEND_PUBLIC_KEY\n")
            
            # Receive peer's response
            response = socket.recv(1024).decode().strip()
            if response != "key-exchange-accept":
                logging.error(f"Peer {peer_username} rejected key exchange")
                return False
                
            # Receive peer's public key using delimiter-based protocol
            peer_public_key_bytes = b""
            begin_marker_received = False
            buffer = b""
            
            # Thia will read until we find END_PUBLIC_KEY marker
            while True:
                chunk = socket.recv(4096)
                if not chunk:
                    logging.error("Connection closed while receiving public key")
                    return False
                    
                buffer += chunk
                
                # Checking if we've received the begin marker
                if not begin_marker_received:
                    if b"BEGIN_PUBLIC_KEY\n" in buffer:
                        begin_marker_received = True
                        # Extract data after the begin marker
                        _, buffer = buffer.split(b"BEGIN_PUBLIC_KEY\n", 1)
                
                # After begin marker, check for end marker
                if begin_marker_received and b"\nEND_PUBLIC_KEY\n" in buffer:
                    peer_public_key_bytes, remaining = buffer.split(b"\nEND_PUBLIC_KEY\n", 1)
                    break
            
            # Generating the shared key
            success = self.file_service.crypto.generate_shared_key(peer_username, peer_public_key_bytes)
            
            if success:
                logging.info(f"Key exchange completed successfully with peer {peer_username}")
                return True
            else:
                logging.error(f"Failed to generate shared key with peer {peer_username}")
                return False
            
        except Exception as e:
            logging.error(f"Error during key exchange with {peer_username}: {e}")
            return False
    
    def handle_key_exchange_request(self, peer_username: str, socket: socket.socket) -> bool:
        """
        Handle a key exchange request from a peer
        """
        try:
            # Reading peer's public key using delimiter-based protocol
            peer_public_key_bytes = b""
            begin_marker_received = False
            buffer = b""
            
            # Reading until we find END_PUBLIC_KEY marker
            while True:
                chunk = socket.recv(4096)
                if not chunk:
                    logging.error("Connection closed while receiving public key")
                    return False
                    
                buffer += chunk
                
                # Check if we've received the begin marker
                if not begin_marker_received:
                    if b"BEGIN_PUBLIC_KEY\n" in buffer:
                        begin_marker_received = True
                        # Extract data after the begin marker
                        _, buffer = buffer.split(b"BEGIN_PUBLIC_KEY\n", 1)
                
                # After begin marker, check for end marker
                if begin_marker_received and b"\nEND_PUBLIC_KEY\n" in buffer:
                    peer_public_key_bytes, remaining = buffer.split(b"\nEND_PUBLIC_KEY\n", 1)
                    break
                    
            socket.sendall("key-exchange-accept\n".encode())
            
            # Sending my public key with the same delimiter protocol
            public_key_bytes = self.file_service.crypto.get_public_key_bytes()
            socket.sendall(b"BEGIN_PUBLIC_KEY\n")
            socket.sendall(public_key_bytes)
            socket.sendall(b"\nEND_PUBLIC_KEY\n")
            
            # Generating shared key
            success = self.file_service.crypto.generate_shared_key(peer_username, peer_public_key_bytes)
            
            if success:
                logging.info(f"Completed key exchange with peer {peer_username}")
                return True
            else:
                logging.error(f"Failed to generate shared key with peer {peer_username}")
                return False
            
        except Exception as e:
            logging.error(f"Error handling key exchange request from {peer_username}: {e}")
            return False

    def login(self, username: str, password: str, is_register: bool = False) -> bool:
        """
        Handle login or registration with the server
        
        Args:
            username: The username to login or register with
            password: The password for authentication
            is_register: True if registering a new user, False for login
            
        Returns:
            bool: True if login/registration was successful, False otherwise
        """
        try:
            self.username = username
            local_ip = get_local_ip_address()
        
            self.rendezvous_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.rendezvous_server_socket.connect(self.server_address)
            
            if is_register:
                print("Registering...")
                request = f"#JOIN {username} {local_ip} {self.tcp_port} {password}#"
            else:
                print("Logging in...")
                request = f"#LOGIN {username} {local_ip} {self.tcp_port} {password}#"
                
            self.rendezvous_server_socket.send(request.encode())
            response = self.rendezvous_server_socket.recv(1024).decode()
            
            response_parts = response.split()
            success_prefix = "join-success" if is_register else "login-success"
            
            if success_prefix in response and len(response_parts) >= 2:
                self.sessionKey = response_parts[-1]
                action_type = "Registered" if is_register else "Logged in"
                print(f"{action_type} successfully as {username}.")
                
                key_file = f"{username}_dh_private_key.enc"
                if os.path.exists(key_file):
                    print("Loading encrypted private key...")
                    self.file_service.crypto.load_private_key_encrypted(key_file, password)
                else:
                    print("No existing private key, generating new and saving...")
                    self.file_service.crypto.save_private_key_encrypted(key_file, password)
                    print(f"Private key saved encrypted to {key_file}.")
                self.file_service.crypto.load_private_key_encrypted(key_file, password)
                print("Private key loaded and decrypted.")
                
                return True
            else:
                error_message = "Registration failed." if is_register else "Wrong Username or Password"
                print(error_message)
                # Close the connection since login failed
                if self.rendezvous_server_socket:
                    self.rendezvous_server_socket.close()
                    self.rendezvous_server_socket = None
                return False
                
        except Exception as e:
            print(f"Error during {'registration' if is_register else 'login'}: {e}")
            if self.rendezvous_server_socket:
                self.rendezvous_server_socket.close()
                self.rendezvous_server_socket = None
            return False