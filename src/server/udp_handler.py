import os
import sys
import threading
from globals import tcp_connections, udp_connections
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)
from src.config.config import PEER_TIMEOUT


class UDPServer(threading.Thread):
    def __init__(self, port_number, database , username):
        threading.Thread.__init__(self)
        self.port_number = port_number
        self.timer = threading.Timer(80, self.remove_inactive_peer)
        self.lock = threading.Lock()
        self.db = database
        self.username = username
        print(f"UDP Server initialized for {self.username}")

    def remove_inactive_peer(self):
        print(f"Timer expired for {self.username} - checking if peer should be removed")
        if self.port_number is not None:
            print(f"Removing inactive peer: {self.username}")
            with self.lock:
                if self.port_number in udp_connections:
                    print(f"Cleaning up resources for {self.username}")
                    del udp_connections[self.port_number]
                    self.db.user_logout(self.username)
                    print(f"DB: {self.db}")
                    print(f"Resources for {self.username} removed from memory")
        else:
            print("Error: username or udpServer is not properly initialized.")

    # resets the timer for udp server
    def reset_timer(self):
        print(f"Resetting activity timer for {self.username}")
        self.timer.cancel()
        print(f"Previous timer canceled for port {self.username}")
        self.timer = threading.Timer(PEER_TIMEOUT, self.remove_inactive_peer)
        self.timer.start()
        print(f"New {PEER_TIMEOUT}-second timer started for {self.username}")
