import threading

onlinePeers = []
tcpThreads = {}
udpThreads = {}
udp_port_numbers = {}
lock = threading.Lock()
