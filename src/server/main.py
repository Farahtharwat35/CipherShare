import os
import socket
import select
import sys

from database import DB
from client_thread import ClientThread
from globals import tcp_connections,udp_connections
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)
from src.config.config import TCP_PORT, UDP_PORT
from threading import Lock
from udp_handler import UDPServer

print("\033[31mRegistry started...\033[0m")


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
            tcp_connections[addr[0]] = clientSock
            thread.start()

        elif s is udpSocket:
            message, clientAddr = s.recvfrom(1024)
            message = message.decode().split()
            print(f"UDP MESSAGE FROM {clientAddr[0]}:{clientAddr[1]} -> {message}")

            if message[0] == "Heartbeat":
                ip_addr = clientAddr[0]
                with lock:
                    if ip_addr in tcp_connections:
                        if ip_addr not in udp_connections:
                            thread = UDPServer(ip_addr,tcp_connections[ip_addr],db)
                            udp_connections[ip_addr] = thread
                            thread.start()
                            thread.timer.start()
                        else:
                            udp_connections[ip_addr].reset_timer()
                        udpSocket.sendto("HELLO_ACK".encode(), clientAddr)

# Cleanup
tcpSocket.close()
udpSocket.close()
