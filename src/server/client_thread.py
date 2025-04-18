import threading
import queue
import logging
import re
import bcrypt
from udp_handler import UDPServer
from static import static
import atexit


class ClientThread(threading.Thread):
    def __init__(self, ip, port, tcpClientSocket, db):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port
        self.tcpClientSocket = tcpClientSocket
        self.db = db
        self.username = None
        self.isOnline = True
        self.udpServer = None
        self.message_queue = queue.Queue()
        self.handlers = {
            static.Command.JOIN.value: self.handle_peer_join,
            static.Command.LOGIN.value: self.handle_login,
            static.Command.LOGOUT.value: self.handle_logout,
            static.Command.LIST.value: self.handle_online_peers_listing
        }
        # atexit.register(self._cleanup)

        print(f"New thread started for {ip}:{port}")

    def run(self):
        print(f"Connection from: {self.ip}:{self.port}")
        while True:
            try:
                raw_data = self.tcpClientSocket.recv(1024).decode()
                if raw_data:
                    print(f"Received raw data from {self.ip}:{self.port}: {raw_data}")
                    messages = re.findall(r'#(.*?)#', raw_data)
                    print(f"Extracted messages: {messages}")
                    for message in messages:
                        self.message_queue.put(message)

                while not self.message_queue.empty():
                    message = self.message_queue.get().split()
                    print(f"Processing message: {message}")
                    self.process_message(message)

            except OSError as oErr:
                print(f"Connection error with {self.ip}:{self.port} - {oErr}")
                logging.error(f"OSError: {oErr}")
                break

    def process_message(self, message):
        if len(message) == 0:
            print("Received empty message, ignoring")
            return

        command = message[0]
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
        if len(message) < 3:
            print(f"Invalid JOIN message format: {message}")
            logging.error("Invalid JOIN message format")
            return
        """Handle a user attempting to join"""
        if self.db.is_account_exist(message[1]):
            response = "join-exist"
            print(f"User {message[1]} already exists")
        else:
            self.db.save_online_peer(message[1], message[2],message[3])
            response = "join-success"
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
            if bcrypt.checkpw(message[2].encode('utf-8'), retrieved_hashed_pass.encode('utf-8')):
                self.username = message[1]
                self.db.user_login(message[1], self.ip, message[3])
                response = "login-success"
                print(f"User {message[1]} successfully logged in from {self.ip}:{self.port}")
                self.udpServer = UDPServer(self.username, self.tcpClientSocket,self.db)
                self.udpServer.start()
                self.udpServer.timer.start()
                print(f"UDP server started for user {self.username}")
            else:
                response = "login-wrong-password"
                print(f"Login failed: Incorrect password for user {message[1]}")
        logging.info(f"Send to {self.ip}:{self.port} -> {response}")
        print(f"Sending login response to {self.ip}:{self.port}: {response}")
        self.tcpClientSocket.send(response.encode())

    def handle_logout(self, message: list):
        """Handle user logout"""
        print(f"Processing LOGOUT request: {message}")
        if len(message) > 1 and message[1] is not None and self.db.is_account_online(message[1]):
            print(f"User {message[1]} is logging out")
            self.db.user_logout(message[1])
            self.tcpClientSocket.close()
            self.udpServer.timer.cancel()
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

    
    # def _cleanup(self):
    #     print("Performing cleanup...")
    #     try:
    #         self.tcpClientSocket.close()
    #         self.udpClientSocket.close()
    #     except Exception as e:
    #         print(f"Error during cleanup: {e}")
    #     finally:
    #         print("Cleanup completed.")


