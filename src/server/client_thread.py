import threading
import queue
import logging
import re
import bcrypt
from udp_handler import UDPServer
from static import static


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

        print(f"New thread started for {ip}:{port}")

    def run(self):
        print(f"Connection from: {self.ip}:{self.port}")
        while True:
            try:
                raw_data = self.tcpClientSocket.recv(1024).decode()
                if raw_data:
                    messages = re.findall(r'#(.*?)#', raw_data)
                    for message in messages:
                        self.message_queue.put(message)

                while not self.message_queue.empty():
                    message = self.message_queue.get().split()
                    self.process_message(message)

            except OSError as oErr:
                logging.error(f"OSError: {oErr}")
                break

    def process_message(self, message):
        if len(message) == 0:
            return

        command = message[0]
        if command in self.handlers:
            self.handlers[command](message)
        else:
            logging.error(f"Unhandled command: {command}")

    def add_handler(self, command, handler):
        """Register a handler for a specific command"""
        self.handlers[command] = handler

    def handle_peer_join(self, message: list):
        if len(message) < 3:
            logging.error("Invalid JOIN message format")
            return
        """Handle a user attempting to join"""
        if self.db.is_account_exist(message[1]):
            response = "join-exist"
        else:
            self.db.save_online_peer(message[1], message[2],message[3])
            response = "join-success"
        logging.info(f"Send to {self.ip}:{self.port} -> {response}")
        self.tcpClientSocket.send(response.encode())

    def handle_login(self, message: list):
        """Handle user login"""
        if not self.db.is_account_exist(message[1]):
            response = "login-account-not-exist"
        elif self.db.is_account_online(message[1]):
            response = "login-online"
        else:
            retrieved_hashed_pass = self.db.get_password(message[1])
            if bcrypt.checkpw(message[2].encode('utf-8'), retrieved_hashed_pass.encode('utf-8')):
                self.username = message[1]
                self.db.user_login(message[1], self.ip, message[3])
                response = "login-success"
                self.udpServer = UDPServer(self.username, self.tcpClientSocket,self.db)
                self.udpServer.start()
                self.udpServer.timer.start()
            else:
                response = "login-wrong-password"
        logging.info(f"Send to {self.ip}:{self.port} -> {response}")
        self.tcpClientSocket.send(response.encode())

    def handle_logout(self, message: list):
        """Handle user logout"""
        if len(message) > 1 and message[1] is not None and self.db.is_account_online(message[1]):
            self.db.user_logout(message[1])
            self.tcpClientSocket.close()
            self.udpServer.timer.cancel()

    def handle_online_peers_listing(self, message: list):
        """List all online peers"""
        online_peers = self.db.get_online_peers()
        response = "Online peers: " + ','.join(online_peers)
        logging.info(f"Send to {self.ip}:{self.port} -> {response}")
        self.tcpClientSocket.send(response.encode())

    def reset_time_out(self):
        """Reset the UDP server timeout"""
        if self.udpServer:
            self.udpServer.reset_timer()

