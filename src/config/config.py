import socket , logging

SERVER_HOST = socket.gethostname()
try:
    SERVER_HOST = socket.gethostbyname(SERVER_HOST)
except socket.gaierror:
    import netifaces as ni
    SERVER_HOST = ni.ifaddresses('en0')[ni.AF_INET][0]['addr']

TCP_PORT = 5000
UDP_PORT = 5001
PEER_TIMEOUT = 10 # in seconds --> satisfies 3x+1 seconds where x is the interval in seconds between heartbeats (from peers)
HEARTBEAT_INTERVAL = 3
LOGGING_LEVEL = logging.basicConfig(
    filename="peer_connections.log",  
    level=logging.INFO,              
    format="%(asctime)s - %(levelname)s - %(message)s"  
)