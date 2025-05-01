import os
import socket
import select
import sys

from database import DB
from client_thread import ClientThread
from globals import tcp_connections, udp_connections
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)
from src.config.config import TCP_PORT, UDP_PORT
from threading import Lock
from in_memory_storage import Cache
from src.utils import get_local_ip_address


def main():
    print("\033[31mRegistry started...\033[0m")

    HOST =  get_local_ip_address()

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
    
    cache = Cache()

    try:
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

                    if message[0] == "Heartbeat":
                        if len(message) < 3:
                            print("Invalid Heartbeat message format")
                            continue
                        username = message[1]
                        sessionKey = message[2]
                        if cache.get(sessionKey) is None or username != cache.get(sessionKey):
                            print(f"Invalid sessionKey for user {username}: {sessionKey}")
                            udpSocket.sendto("INVALID_SESSION_KEY".encode(), clientAddr)
                            continue
                        print(f"Heartbeat from {username}")
                        with lock:
                                if username not in udp_connections:
                                    udpSocket.sendto("SESSION_NOT_FOUND".encode(), clientAddr)
                                    print(f"Session not found for user {username}")
                                else:
                                    udp_connections[username].reset_timer(sessionKey)
                                    udpSocket.sendto("HELLO_ACK".encode(), clientAddr)
    finally:
        # Cleanup
        tcpSocket.close()
        udpSocket.close()

if __name__ == "__main__":
    main()
