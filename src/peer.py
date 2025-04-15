import socket
import threading
import time

from src.file_service import FileService

UDP_PORT = 5001
TCP_PORT = 5000
HEARTBEAT_INTERVAL = 3


class Peer:
    def __init__(self, server_address, local_peer_port):
        self.server_address = server_address
        self.local_peer_port = local_peer_port
        self.file_service = FileService(self)
        self.running = False
        self.peers = {}

    def start(self):
        self.running = True
        self.register_with_server()
        self.start_heartbeat_thread()
        self.peers = self.request_peer_list()
        self.file_service.start()

    def register_with_server(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.server_address, TCP_PORT))
            s.sendall(f"register {self.local_peer_port}\n".encode())
            response = s.recv(1024).decode()
            if response == "registered\n":
                print("Registered with server")
            else:
                print("Failed to register with server")
            s.close()
        except Exception as e:
            print(f"Error registering with server: {e}")

    def start_heartbeat_thread(self):
        def send_heartbeat():
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            while self.running:
                try:
                    udp_sock.sendto(f"heartbeat {self.local_peer_port}\n".encode(), (self.server_address, UDP_PORT))
                except Exception as e:
                    print(f"Error sending heartbeat: {e}")
                time.sleep(HEARTBEAT_INTERVAL)
            udp_sock.close()
        threading.Thread(target=send_heartbeat, daemon=True).start()

    def request_peer_list(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.server_address, TCP_PORT))
            s.sendall("list-peers\n".encode())
            response = s.recv(4096).decode()
            if not response:
                return []
            peer_list = response.strip().split('\n')
            peers = []
            for peer in peer_list:
                ip, port = peer.split(':')
                peers.append((ip, int(port)))
            return peers
        except Exception as e:
            print(f"Error requesting peer list: {e}")
            return []

        
    def 
