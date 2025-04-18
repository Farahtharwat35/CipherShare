import threading

onlinePeers = []
tcp_connections = {}
udp_connections = {}
udp_port_numbers = {}
lock = threading.Lock()
