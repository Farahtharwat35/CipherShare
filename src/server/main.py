# server.py

import socket
import select

from globals import udp_port_numbers
from src.database.database import DB
from src.server.client_thread import ClientThread
from src.server.globals import tcpThreads
from threading import Lock

print("\033[31mRegistry started...\033[0m")

# Server ports
TCP_PORT = 15600
UDP_PORT = 15500

# Get host IP address
hostname = socket.gethostname()
try:
    HOST = socket.gethostbyname(hostname)
except socket.gaierror:
    import netifaces as ni
    HOST = ni.ifaddresses('en0')[ni.AF_INET][0]['addr']

print(f"\033[96mRegistry IP address:\033[0m {HOST}")
print(f"\033[96mRegistry port number:\033[0m {TCP_PORT}")

# Database setup
db = DB()
db.delete_all_online_peers()

# Socket setup
tcpSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tcpSocket.bind((HOST, TCP_PORT))
udpSocket.bind((HOST, UDP_PORT))
tcpSocket.listen(5)

inputs = [tcpSocket, udpSocket]
lock = Lock()

while inputs:
    print("\n\033[92mListening for incoming connections...\033[0m")
    readable, _, _ = select.select(inputs, [], [])

    for s in readable:
        if s is tcpSocket:
            clientSock, addr = tcpSocket.accept()
            thread = ClientThread(addr[0], addr[1], clientSock, db)
            thread.start()

        elif s is udpSocket:
            message, clientAddr = s.recvfrom(1024)
            message = message.decode().split()
            print(f"UDP MESSAGE FROM {clientAddr[0]}:{clientAddr[1]} -> {message}")

            if message[0] == "HELLO":
                username = message[1]
                with lock:
                    if username in tcpThreads:
                        if username not in udp_port_numbers:
                            udp_port_numbers[username] = clientAddr[1]
                            print(f"UDP port recorded for {username}: {clientAddr[1]}")
                        tcpThreads[username].reset_time_out()
                        udpSocket.sendto("HELLO_ACK".encode(), clientAddr)

# Cleanup
tcpSocket.close()
udpSocket.close()
