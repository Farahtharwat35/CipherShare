import socket
import threading
import time
from src.server.peer_registry import PeerRegistry
from src.server.config import SERVER_HOST, SERVER_UDP_PORT, SERVER_TCP_PORT , PEER_TIMEOUT

command_handlers = {}

def register_command(cmd):
    def decorator(func):
        command_handlers[cmd] = func
        return func
    return decorator

def send_response(conn_or_sock, msg, addr=None, protocol='tcp'):
    data = msg.encode()
    if protocol == 'udp':
        conn_or_sock.sendto(data, addr)
    else:
        conn_or_sock.send(data)

@register_command("HELLO")
def handle_peer_join(args, addr, conn, peer_registry, protocol='tcp'):
    if len(args) != 1:
        send_response(conn, "ERROR: Usage HELLO <peer_id>", addr, protocol)
        return
    peer_registry.update_peer(addr[0], addr[1], args[0])
    send_response(conn, "WELCOME", addr, protocol)

@register_command("LIST")
def handle_peers_list(args, addr, conn, peer_registry, protocol='tcp'):
    peers = peer_registry.get_peer_list()
    lines = [f"{pid} {ip}:{port}" for ip, port, pid in peers if (ip, port) != addr]
    msg = "\n".join(lines) if lines else "NO OTHER PEERS"
    send_response(conn, msg, addr, protocol)

@register_command("REQUEST_PEER")
def handle_find_peer_request(args, addr, conn, peer_registry, protocol='tcp'):
    if len(args) != 1:
        send_response(conn, "ERROR: Usage REQUEST <peer_id>", addr, protocol)
        return
    result = peer_registry.get_peer_by_id(args[0])
    if result:
        ip, port = result
        send_response(conn, f"{ip}:{port}", addr, protocol)
    else:
        send_response(conn, "ERROR: Peer not found", addr, protocol)

@register_command("HEARTBEAT")
def handle_heartbeat(args, addr, sock, peer_registry):
    if len(args) != 1:
        sock.sendto("ERROR: Usage HEARTBEAT <peer_id>".encode(), addr)
        return
    peer_registry.update_peer(addr[0], addr[1], args[0])
    sock.sendto("ACK".encode(), addr)

@register_command("BYE")
def handle_peer_exit(args, addr, conn, peer_registry, protocol='tcp'):
    if len(args) != 1:
        send_response(conn, "ERROR: Usage BYE <peer_id>", addr, protocol)
        return
    peer_id = args[0]
    peer = peer_registry.get_peer_by_id(peer_id)
    if peer:
        del peer_registry.peers[peer]
        send_response(conn, f"Peer {peer_id} removed.", addr, protocol)
    else:
        send_response(conn, "ERROR: Peer not found", addr, protocol)

def inactive_peers_cleanup_loop(registry):
    while True:
        registry.remove_inactive_peers(PEER_TIMEOUT)
        time.sleep(3)

def run_udp_server(registry):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((SERVER_HOST, SERVER_UDP_PORT))
    print(f"[UDP Server] Listening for HEARTBEAT on {SERVER_HOST}:{SERVER_UDP_PORT}")

    while True:
        data, addr = udp_sock.recvfrom(1024)
        msg = data.decode().strip()
        parts = msg.split()

        if not parts:
            continue

        cmd, args = parts[0], parts[1:]

        if cmd == "HEARTBEAT":
            handle_heartbeat(args, addr, udp_sock, registry)
        else:
            udp_sock.sendto("ERROR: Unsupported over UDP".encode(), addr)

def handle_tcp_client(conn, addr, peerRegistry):
    try:
        data = conn.recv(1024)
        if not data:
            conn.close()
            return

        msg = data.decode().strip()
        parts = msg.split()
        if not parts:
            conn.send("ERROR: Empty command".encode())
            conn.close()
            return

        cmd, args = parts[0], parts[1:]
        handler = command_handlers.get(cmd)

        if handler and cmd != "HEARTBEAT":
            handler(args, addr, conn, peerRegistry, protocol='tcp')
        else:
            conn.send("ERROR: Unknown or unsupported command on TCP".encode())
    except Exception as e:
        print(f"[TCP Client Error] {e}")
    finally:
        conn.close()

def run_tcp_server(registry):
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.bind((SERVER_HOST, SERVER_TCP_PORT))
    tcp_sock.listen()
    print(f"[TCP Server] Listening on {SERVER_HOST}:{SERVER_TCP_PORT}")

    while True:
        conn, addr = tcp_sock.accept()
        threading.Thread(target=handle_tcp_client, args=(conn, addr, registry), daemon=True).start()

def run_server():
    peer_registry = PeerRegistry()
    threading.Thread(target=inactive_peers_cleanup_loop, args=(peer_registry,), daemon=True).start()
    threading.Thread(target=run_udp_server, args=(peer_registry,), daemon=True).start()
    run_tcp_server(peer_registry)
