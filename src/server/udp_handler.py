import os
import sys
import threading
from globals import tcp_connections, udp_connections
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)
from src.config.config import PEER_TIMEOUT
from in_memory_storage import Cache


class UDPServer(threading.Thread):
    def __init__(self, port_number, database , username, sessionKey):
        threading.Thread.__init__(self)
        self.port_number = port_number
        self.timer = threading.Timer(80, self.remove_inactive_peer)
        self.lock = threading.Lock()
        self.db = database
        self.username = username
        self.sessionKey = sessionKey
        self.cache = Cache()
        print(f"UDP Server initialized for {self.username}")

    def remove_inactive_peer(self):
        print(f"Timer expired for {self.username} - checking if peer should be removed")
        if self.port_number is not None:
            print(f"Removing inactive peer: {self.username}")
            with self.lock:
                print(udp_connections)
                print(self.port_number)
                if self.username in udp_connections:
                    print(f"Cleaning up resources for {self.username}")
                    del udp_connections[self.username]
                    self.db.user_logout(self.username)
                    self.cache.delete(self.sessionKey)
                    print(f"Cache deleted for {self.username}")
                    print(f"Resources for {self.username} removed from memory")
        else:
            print("Error: username or udpServer is not properly initialized.")

    # resets the timer for udp server
    def reset_timer(self, sessionKey):
        if sessionKey != self.sessionKey:
            print(f"Invalid sessionKey for user {self.username}: {sessionKey} - expected {self.sessionKey}")
            return
        print(f"Resetting activity timer for {self.username}")
        self.timer.cancel()
        print(f"Previous timer canceled for port {self.username}")
        self.timer = threading.Timer(PEER_TIMEOUT, self.remove_inactive_peer)
        self.timer.start()
        self.cache.refresh(self.sessionKey)
        print(f"New {PEER_TIMEOUT}-second timer started for {self.username}")
