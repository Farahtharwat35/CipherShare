import threading

from src.server.globals import udp_port_numbers
from src.server.globals  import tcpThreads, onlinePeers


class UDPServer(threading.Thread):


    def __init__(self, username, clientSocket , db):
        threading.Thread.__init__(self)
        self.username = username
        self.timer = threading.Timer(80, self.remove_inactive_peer)
        self.tcpClientSocket = clientSocket
        self.lock = threading.Lock()
        self.db = db

    def remove_inactive_peer(self):
        if self.username is not None:
            with self.lock:
                self.db.user_logout(self.username)
                if self.username in tcpThreads:
                    del tcpThreads[self.username]
                    del udp_port_numbers[self.username]
                    onlinePeers.remove(self.username)
            self.tcpClientSocket.close()
            print("Removed " + self.username + " from online peers")
        else:
            print("Error: username or udpServer is not properly initialized.")

    # resets the timer for udp server
    def reset_timer(self):
        self.timer.cancel()
        self.timer = threading.Timer(30, self.remove_inactive_peer)
        self.timer.start()
