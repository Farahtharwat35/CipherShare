import threading

from globals import udp_port_numbers
from globals  import tcpThreads, onlinePeers


class UDPServer(threading.Thread):
    def __init__(self, username, clientSocket , db):
        threading.Thread.__init__(self)
        self.username = username
        self.timer = threading.Timer(80, self.remove_inactive_peer)
        self.tcpClientSocket = clientSocket
        self.lock = threading.Lock()
        self.db = db
        print(f"UDP Server initialized for user: {username}")

    def remove_inactive_peer(self):
        print(f"Timer expired for {self.username} - checking if peer should be removed")
        if self.username is not None:
            print(f"Removing inactive peer: {self.username}")
            with self.lock:
                print(f"Acquired lock for removing {self.username}")
                self.db.user_logout(self.username)
                print(f"User {self.username} logged out from database")
                if self.username in tcpThreads:
                    print(f"Cleaning up resources for {self.username}")
                    del tcpThreads[self.username]
                    del udp_port_numbers[self.username]
                    onlinePeers.remove(self.username)
                    print(f"Resources for {self.username} removed from memory")
            self.tcpClientSocket.close()
            print(f"TCP socket for {self.username} closed")
            print(f"Successfully removed {self.username} from online peers")
        else:
            print("Error: username or udpServer is not properly initialized.")

    # resets the timer for udp server
    def reset_timer(self):
        print(f"Resetting inactivity timer for {self.username}")
        self.timer.cancel()
        print(f"Previous timer canceled for {self.username}")
        self.timer = threading.Timer(30, self.remove_inactive_peer)
        self.timer.start()
        print(f"New 30-second timer started for {self.username}")
