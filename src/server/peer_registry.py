import time

class PeerRegistry:
    def __init__(self):
        self.peers = {}  # (ip, port): { 'last_seen': timestamp, 'id': peer_id }

    def update_peer(self, ip, port, peer_id):
        self.peers[(ip, port)] = {
            'last_seen': time.time(),
            'id': peer_id
        }

    def get_peers(self):
        return [(ip, port, data['id']) for (ip, port), data in self.peers.items()]

    def get_peer_by_id(self, peer_id):
        for (ip, port), data in self.peers.items():
            if data['id'] == peer_id:
                return ip, port
        return None

    def remove_inactive_peers(self, timeout):
        now = time.time()
        before = len(self.peers)
        self.peers = {
            addr: data for addr, data in self.peers.items()
            if now - data['last_seen'] <= timeout
        }
        after = len(self.peers)
        if before != after:
            print(f"[Cleanup] Removed {before - after} inactive peer(s).")
