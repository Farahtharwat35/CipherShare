import threading
import queue
import logging
import re
import bcrypt
from udp_handler import UDPServer
from static import static
from in_memory_storage import Cache
from globals import tcp_connections, udp_connections
import socket
import uuid


class ClientThread(threading.Thread):
    def __init__(self, ip, port, tcpClientSocket, db):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.tcpClientSocket = tcpClientSocket
        self.db = db
        self.isOnline = True
        self.udpServer = None
        self.message_queue = queue.Queue()
        self.is_connected = True
        self.connection_lock = threading.Lock()
        self.handlers = {
            static.Command.JOIN.value: self.handle_peer_join,
            static.Command.LOGIN.value: self.handle_login,
            static.Command.LOGOUT.value: self.handle_logout,
            static.Command.LIST.value: self.handle_online_peers_listing
        }
        self.unauthenticated_commands = [static.Command.JOIN.value,
                                         static.Command.LOGIN.value,]
        self.cache = Cache()
        # atexit.register(self._cleanup)

        print(f"New thread started for {ip}:{port}")

    def set_disconnected(self):
        """Mark the client as disconnected to prevent further socket operations"""
        with self.connection_lock:
            self.is_connected = False
            print(f"Client {self.ip}:{self.port} marked as disconnected")

    def is_socket_valid(self):
        """Check if the socket is still valid for operations"""
        with self.connection_lock:
            return self.is_connected

    def run(self):
        print(f"Connection from: {self.ip}:{self.port}")
        try:
            while True:
                try:
                    raw_data = self.tcpClientSocket.recv(1024).decode()
                    if not raw_data:
                        print(f"Connection closed by peer {self.ip}:{self.port}")
                        break
                        
                    print(f"Received raw data from {self.ip}:{self.port}: {raw_data}")
                    messages = re.findall(r'#(.*?)#', raw_data)
                    print(f"Extracted messages: {messages}")
                    for message in messages:
                        self.message_queue.put(message)

                    while not self.message_queue.empty():
                        message = self.message_queue.get().split()
                        print(f"Processing message: {message}")
                        self.process_message(message)

                except (socket.error, OSError) as e:
                    print(f"Socket error with {self.ip}:{self.port} - {e}")
                    logging.error(f"Socket error: {e}")
                    break
        finally:
            # Clean up resources when thread exits
            self._cleanup_resources()
            print(f"Client thread for {self.ip}:{self.port} has terminated")

    def _cleanup_resources(self):
        """Clean up resources properly"""
        print(f"Cleaning up resources for {self.ip}:{self.port}")
        try:
            # Cancel any timers
            if hasattr(self, 'udpServer') and self.udpServer:
                self.udpServer.stop()
                
            # Close socket safely if still open
            if hasattr(self, 'tcpClientSocket') and self.tcpClientSocket:
                try:
                    self.tcpClientSocket.shutdown(socket.SHUT_RDWR)  # Use module constant
                except:
                    pass  # Socket might already be closed
                self.tcpClientSocket.close()

        except Exception as e:
            print(f"Error during resource cleanup: {e}")
            logging.error(f"Resource cleanup error: {e}")

    def process_message(self, message):
        if len(message) == 0:
            print("Received empty message, ignoring")
            return

        command = message[0]
        if command not in self.unauthenticated_commands:
            sessionKey = None
            if ':' in message[0]:
                command, sessionKey = message[0].split(':', 1)

            if command is None or sessionKey is None \
                    or self.cache.get(sessionKey) is None \
                    or self.cache.get(sessionKey) != self.username:
                print(f"Session key {sessionKey} not found, ignoring message")
                response = "invalid-session"
                self.tcpClientSocket.send(response.encode())
                return
            message[0] = command

        print(f"Processing command: {command}")
        if command in self.handlers:
            self.handlers[command](message)
        else:
            print(f"Unrecognized command received: {command}")
            logging.error(f"Unhandled command: {command}")

    def add_handler(self, command, handler):
        """Register a handler for a specific command"""
        print(f"Adding handler for command: {command}")
        self.handlers[command] = handler

    def handle_peer_join(self, message: list):
        print(f"Processing JOIN request from {self.ip}:{self.port}")
        if len(message) < 5:
            print(f"Invalid JOIN message format: {message}")
            logging.error("Invalid JOIN message format")
            return
        """Handle a user attempting to join"""
        if self.db.is_account_exist(message[1]):
            response = "join-exist"
            print(f"User {message[1]} already exists")
        else:
            # Hash the password before saving it
            hashed_password = bcrypt.hashpw(message[4].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            self.db.register(message[1], hashed_password)
            self.db.save_online_peer(message[1], message[2], message[3])
            sessionKey = self._generateSessionKey(message[1])
            self.username = message[1]
            response = f"join-success {sessionKey}"
            self.udpServer = UDPServer(self.port, self.db, self.username, sessionKey=sessionKey)
            udp_connections[self.username] = self.udpServer
            self.udpServer.start()
            self.udpServer.timer.start()
            print(f"New user {message[1]} successfully registered")
        logging.info(f"Send to {self.ip}:{self.port} -> {response}")
        print(f"Sending response to {self.ip}:{self.port}: {response}")
        self.tcpClientSocket.send(response.encode())

    def handle_login(self, message: list):
        """Handle user login"""
        print(f"Processing LOGIN request for user: {message[1]}")
        if not self.db.is_account_exist(message[1]):
            response = "login-account-not-exist"
            print(f"Login failed: Account {message[1]} does not exist")
        elif self.db.is_account_online(message[1]):
            response = "login-online"
            print(f"Login failed: User {message[1]} is already online")
        else:
            retrieved_hashed_pass = self.db.get_password(message[1])
            if retrieved_hashed_pass and bcrypt.checkpw(message[2].encode('utf-8'), retrieved_hashed_pass.encode('utf-8')):
                self.username = message[1]
                sessionKey = self._generateSessionKey(message[1])
                response = f"login-success {sessionKey}"
                print(f"User {message[1]} successfully logged in from {self.ip}:{self.port}")
                self.udpServer = UDPServer(self.port, self.db, self.username, sessionKey=sessionKey)
                udp_connections[self.username] = self.udpServer
                self.udpServer.start()
                self.udpServer.timer.start()
                print(f"UDP server started for user {self.username}")
            else:
                response = "login-wrong-password"
                print(f"Login failed: Incorrect password for user {message[1]}")
        logging.info(f"Send to {self.ip}:{self.port} -> {response}")
        print(f"Sending login response to {self.ip}:{self.port}: {response}")
        try:
            self.tcpClientSocket.send(response.encode())
        except socket.error as e:
            print(f"Error sending response: {e}")
            logging.error(f"Send error: {e}")

    def send_response(self, response):
        """Send a response with connection validity check"""
        if self.is_socket_valid():
            try:
                self.tcpClientSocket.send(response.encode())
            except OSError as e:
                print(f"Error sending response to {self.ip}:{self.port}: {e}")
                self.set_disconnected()

    def handle_logout(self, message: list):
        """Handle user logout"""
        print(f"Processing LOGOUT request: {message}")
        if len(message) > 1 and message[1] is not None and self.db.is_account_online(message[1]):
            print(f"User {message[1]} is logging out")
            self.db.user_logout(message[1])
            
            # we cancel UDP timer first
            if self.udpServer:
                self.udpServer.stop()
                
            # Then we invalidate session key
            sessionKey = message[2]
            self.cache.delete(sessionKey)
                
            # Then we close socket
            try:
                self.tcpClientSocket.shutdown(socket.SHUT_RDWR)
            except:
                pass
            self.tcpClientSocket.close()
            
            print(f"User {message[1]} has been logged out, connection closed")
        else:
            print(f"Invalid logout request or user not online: {message}")

    def handle_online_peers_listing(self, message: list):
        """List all online peers"""
        print(f"Processing LIST request from {self.ip}:{self.port}")
        online_peers = self.db.get_online_peers()
        response = "Online peers: " + ', '.join(
        [f"{peer['username']} ({peer['ip']}:{peer['port']})" for peer in online_peers]
        )
        print(f"Online peers: {online_peers}")
        logging.info(f"Send to {self.ip}:{self.port} -> {response}")
        print(f"Sending peer list to {self.ip}:{self.port}")
        self.tcpClientSocket.send(response.encode())

    def reset_time_out(self):
        """Reset the UDP server timeout"""
        if self.udpServer:
            print(f"Resetting timeout for user {self.username}")
            self.udpServer.reset_timer()

    def _generateSessionKey(self, username: str):
        sessionKey = str(uuid.uuid4()).replace("-", "").upper()
        self.cache.set(sessionKey, username)
        print(f"Generated session key for {username}: {sessionKey}")
        return sessionKey
