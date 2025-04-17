# import queue
# import select
# import socket
# import threading
# import logging
# import pickle
# import re
#
# import bcrypt
#
# from src.database import database
#
#
# class ClientThread(threading.Thread):
#     def __init__(self, ip, port, tcp_ClientSocket, server_state, db):
#         threading.Thread.__init__(self)
#         self.ip = ip
#         self.port = port
#         self.tcpClientSocket = tcp_ClientSocket
#         self.username = None
#         self.isOnline = True
#         self.udpServer = None
#         self.message_queue = queue.Queue()
#         self.db = db
#         self.server_state = server_state
#         print(f"New thread started for {ip}:{port}")
#
#         # Initialize the handler map
#         self.handlers = {}
#
#     def run(self):
#         self.lock = threading.Lock()
#         print(f"Connection from: {self.ip}:{self.port}")
#         print(f"IP Connected: {self.ip}")
#
#         while True:
#             try:
#                 raw_data = self.tcpClientSocket.recv(1024).decode()
#                 messages = re.findall(r'#(.*?)#', raw_data)
#                 for message in messages:
#                     self.message_queue.put(message)
#
#                 while not self.message_queue.empty():
#                     message = self.message_queue.get().split()
#                     self.process_message(message)
#
#             except OSError as oErr:
#                 logging.error(f"OSError: {oErr}")
#
#     def process_message(self, message):
#         if len(message) == 0:
#             return
#
#         command = message[0]
#         if command in self.handlers:
#             self.handlers[command](message)
#         else:
#             logging.error(f"Unhandled command: {command}")
#
#     def add_handler(self, command, handler):
#         self.handlers[command] = handler
#
#     def handle_peer_join(self, message):
#         if db.is_account_exist(message[1]):
#             response = "join-exist"
#         else:
#             db.register(message[1], message[2])
#             response = "join-success"
#         logging.info(f"Send to {self.ip}:{self.port} -> {response}")
#         self.tcpClientSocket.send(response.encode())
#
#     def handle_login(self, message):
#         if not db.is_account_exist(message[1]):
#             response = "login-account-not-exist"
#         elif db.is_account_online(message[1]):
#             response = "login-online"
#         else:
#             retrieved_hashed_pass = db.get_password(message[1])
#             if bcrypt.checkpw(message[2].encode('utf-8'), retrieved_hashed_pass.encode('utf-8')):
#                 self.username = message[1]
#                 with self.lock:
#                     tcpThreads[self.username] = self
#                 db.user_login(message[1], self.ip, message[3])
#                 response = "login-success"
#                 self.udpServer = UDPServer(self.username, self.tcpClientSocket)
#                 self.udpServer.start()
#                 self.udpServer.timer.start()
#             else:
#                 response = "login-wrong-password"
#         logging.info(f"Send to {self.ip}:{self.port} -> {response}")
#         self.tcpClientSocket.send(response.encode())
#
#     def handle_logout(self, message):
#         if len(message) > 1 and message[1] is not None and db.is_account_online(message[1]):
#             db.user_logout(message[1])
#             with self.lock:
#                 if message[1] in tcpThreads:
#                     del tcpThreads[message[1]]
#                     print(f"Removed {self.username} from online peers")
#             onlinePeers.remove(self.username)
#             self.tcpClientSocket.close()
#             self.udpServer.timer.cancel()
#
#     def handle_online_peers_listing(self):
#         response = "List of online peers: " + ', '.join(str(user) for user in onlinePeers)
#         logging.info(f"Send to {self.ip}:{self.port} -> {response}")
#         self.tcpClientSocket.send(response.encode())
#
#     def handle_port_number(self):
#         with self.lock:
#             if self.username in udpPortnumbers:
#                 udp_port = udpPortnumbers[self.username]
#                 self.tcpClientSocket.send(str(udp_port).encode())
#             else:
#                 print(f"Username '{self.username}' not found in udpPortnumbers")
#
#
#
# # tcp and udp server port initializations
# print("\033[31mRegisty started...\033[0m")
# port = 15600
# portUDP = 15500
#
# # db initialization
# db = database.DB()
#
# # gets the ip address of this peer
# # first checks to get it for windows devices
# # if the device that runs this application is not windows
# # it checks to get it for macos devices
# hostname = socket.gethostname()
# try:
#     host = socket.gethostbyname(hostname)
# except socket.gaierror:
#     import netifaces as ni
#
#     host = ni.ifaddresses('en0')[ni.AF_INET][0]['addr']
#
# print("\033[96mRegistry IP address:\033[0m " + host)
# print("\033[96mRegistry port number: \033[0m" + str(port))
#
#
# # onlinePeers list for online account
# onlinePeers = []
# # accounts list for accounts
# accounts = []
# # tcpThreads list for online client's thread
# tcpThreads = {}
# # udp port number of each peer
# udpPortnumbers = {}
#
# # tcp and udp socket initializations
# tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# tcpSocket.bind((host, port))
# udpSocket.bind((host, portUDP))
# tcpSocket.listen(5)
# db.delete_all_online_peers()
#
#
# # input sockets that are listened
# inputs = [tcpSocket, udpSocket]
#
# # lock
# lock=threading.Lock()
#
# # log file initialization
# logging.basicConfig(filename="registry.log", level=logging.INFO)
#
# # as long as at least a socket exists to listen registry runs
# while inputs:
#
#     print("\n\033[92mListening for incoming connections...\033[0m")
#     # monitors for the incoming connections
#     readable, writable, exceptional = select.select(inputs, [], [])
#     for s in readable:
#         # if the message received comes to the tcp socket
#         # the connection is accepted and a thread is created for it, and that thread is started
#         if s is tcpSocket:
#             tcpClientSocket, addr = tcpSocket.accept()
#             newThread = ClientThread(addr[0], addr[1], tcpClientSocket)
#             newThread.start()
#         # if the message received comes to the udp socket
#         elif s is udpSocket:
#             # received the incoming udp message and parses it
#             message, clientAddress = s.recvfrom(1024)
#             message = message.decode().split()
#             print("UDP PORT IS:", clientAddress[1], "PORT NUMBER IS:", clientAddress[0])
#
#             # checks if it is a hello message
#             if message[0] == "HELLO":
#                 with lock:  # Acquire the lock before accessing shared data
#                     # checks if the account that this hello message is sent from is online
#                     if message[1] in tcpThreads:
#                         print("Hello is received from " + message[1])
#                         logging.info(
#                             "Received from " + clientAddress[0] + ":" + str(clientAddress[1]) + " -> " + " ".join(
#                                 message))
#                         # sending to the client its udp port which he sent from the message for future usage
#                         # Check if the username is already in udpPortnumbers
#                         if message[1] not in udpPortnumbers:
#                             udpPortnumbers[message[1]] = int(clientAddress[1])
#                             print("Peer port entered UDP : " , udpPortnumbers[message[1]])
#                         # resets the timeout for that peer since the hello message is received
#                         tcpThreads[message[1]].resetTimeout()
#                         # Send acknowledgment to the client
#                         s.sendto("HELLO_ACK".encode(), clientAddress)
#
# # registry tcp socket is closed
# tcpSocket.close()
# udpSocket.close()
#
#
