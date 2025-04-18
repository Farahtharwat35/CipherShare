import os
import sys
import threading
import socket  # Make sure to import socket module
from globals import tcp_connections, udp_connections
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)
from src.config.config import PEER_TIMEOUT


class UDPServer(threading.Thread):
    def __init__(self, ip_addr, clientSocket, db, client_thread=None):
        threading.Thread.__init__(self)
        self.ip_addr = ip_addr
        self.timer = threading.Timer(PEER_TIMEOUT, self.remove_inactive_peer)
        self.tcpClientSocket = clientSocket
        self.lock = threading.Lock()
        self.db = db
        self.client_thread = client_thread
        self.is_stopped = False
        print(f"UDP Server initialized for user's ip_addr: {ip_addr}")

    def remove_inactive_peer(self):
        if self.is_stopped:
            return

        print(f"Timer expired for {self.ip_addr} - checking if peer should be removed")
        if self.ip_addr is not None:
            print(f"Removing inactive peer: {self.ip_addr}")
            # First, we safely close the socket
            try:
                if self.ip_addr in tcp_connections:
                    sock = tcp_connections[self.ip_addr]
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
            except Exception as e:
                print("")

            # Then we remove from dictionaries and DB
            with self.lock:
                if self.ip_addr in tcp_connections:
                    print(f"Cleaning up resources for {self.ip_addr}")
                    # Notify client thread about disconnection
                    if self.client_thread:
                        self.client_thread.set_disconnected()

                    # Cleaning up resources
                    del tcp_connections[self.ip_addr]
                    del udp_connections[self.ip_addr]
                    self.db.user_logout(self.ip_addr)
                    print(f"Resources for {self.ip_addr} removed from memory")
        else:
            print("Error: username or udpServer is not properly initialized.")

    def reset_timer(self):
        if self.is_stopped:
            return
            
        print(f"Resetting activity timer for {self.ip_addr}")
        self.timer.cancel()
        print(f"Previous timer canceled for {self.ip_addr}")
        self.timer = threading.Timer(PEER_TIMEOUT, self.remove_inactive_peer)
        self.timer.start()
        print(f"New timer started for {self.ip_addr}")
    
    def stop(self):
        """Stop the UDP server and cancel timer"""
        self.is_stopped = True
        if self.timer:
            self.timer.cancel()
