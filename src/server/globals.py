import threading

onlinePeers = []
tcpThreads = {}
udp_port_numbers = {}
lock = threading.Lock()
