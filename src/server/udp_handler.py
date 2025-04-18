import os
import sys
import threading
from globals  import tcp_connections, udp_connections
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)
from src.config.config import PEER_TIMEOUT


class UDPServer(threading.Thread):
    def __init__(self, ip_addr, clientSocket , db):
        threading.Thread.__init__(self)
        self.ip_addr = ip_addr
        self.timer = threading.Timer(PEER_TIMEOUT, self.remove_inactive_peer)
        self.tcpClientSocket = clientSocket
        self.lock = threading.Lock()
        self.db = db
        print(f"UDP Server initialized for user's ip_addr: {ip_addr}")

    def remove_inactive_peer(self):
        print(f"Timer expired for {self.ip_addr} - checking if peer should be removed")
        if self.ip_addr is not None:
            print(f"Removing inactive peer: {self.ip_addr}")
            with self.lock:
                if self.ip_addr in tcp_connections:
                    print(f"Cleaning up resources for {self.ip_addr}")
                    del tcp_connections[self.ip_addr]
                    del udp_connections[self.ip_addr]
                    self.db.user_logout(self.ip_addr)
                    print(f"Resources for {self.ip_addr} removed from memory")
        else:
            print("Error: username or udpServer is not properly initialized.")

    # resets the timer for udp server
    def reset_timer(self):
        print(f"Resetting activity timer for {self.ip_addr}")
        self.timer.cancel()
        print(f"Previous timer canceled for {self.ip_addr}")
        self.timer = threading.Timer(PEER_TIMEOUT, self.remove_inactive_peer)
        self.timer.start()
        print(f"New 30-second timer started for {self.ip_addr}")
