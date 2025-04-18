from peer import Peer
from random import randint

self_tcp_port = randint(15000, 16000)
self_udp_port = randint(16000, 17000)

print(f"TCP Port: {self_tcp_port}, UDP Port: {self_udp_port}")

username = input("Enter your username: ")

p = Peer(username, '127.0.1.1', 15601, self_tcp_port, self_udp_port)
p.start()
