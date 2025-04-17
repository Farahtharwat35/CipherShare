import os
import sys
import threading
import time
from src.peer import Peer
from src.file_service import SHARED_DIR

def setup_test_files(peer_id):
    """Create some test files in the peer's shared directory"""
    peer_dir = f"{SHARED_DIR}_{peer_id}"
    os.makedirs(peer_dir, exist_ok=True)
    
    # Create a test file
    test_file_path = os.path.join(peer_dir, "test.txt")
    with open(test_file_path, "w") as f:
        f.write(f"This is a test file from peer {peer_id}")
    
    # Share the file using FileService
    return test_file_path

def run_peer(peer_id, port, known_peers=None):
    # Initialize peer with localhost and known peers
    peer = Peer("localhost", f"peer_{peer_id}")
    peer.tcp_port = port
    
    # Convert known_peers to proper format (host, port) tuples
    if known_peers:
        peer.peers = [("localhost", p) for p in known_peers]
        print(f"Setting known peers: {peer.peers}")
    
    # Start the peer
    peer.start()
    
    # Setup and share test files
    test_file_path = setup_test_files(peer_id)
    print(f"Sharing file: {test_file_path}")
    file_info = peer.file_service.share_file(test_file_path, keywords=["test"], description=f"Test file from peer {peer_id}")
    print(f"Shared files: {peer.file_service.shared_files}")
    print(f"Shared files info: {peer.file_service.shared_files_info}")
    
    print(f"\nPeer {peer_id} started on port {port}")
    print("Known peers:", peer.peers)
    print("\nAvailable commands:")
    print("- search <keyword>: Search for files")
    print("- peers: List connected peers")
    print("- quit: Exit the peer")
    
    try:
        while True:
            cmd = input(f"\nPeer {peer_id}> ").strip()
            if cmd == "quit":
                break
            elif cmd.startswith("search"):
                _, keyword = cmd.split(maxsplit=1)
                results = peer.send_search_request_with_file_name(keyword)
                if results:
                    print("\nFound files:")
                    for file_info in results:
                        print(f"- {file_info.name} ({file_info.size} bytes)")
                else:
                    print("No files found")
            elif cmd == "peers":
                print(f"Connected peers: {peer.peers}")
            elif cmd == "help":
                print("Available commands:")
                print("- search <keyword>: Search for files")
                print("- peers: List connected peers")
                print("- quit: Exit the peer")
    finally:
        peer.running = False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python test_direct_peers.py <peer_id> <port>")
        print("Example: python test_direct_peers.py 1 5000")
        sys.exit(1)
    
    peer_id = int(sys.argv[1])
    port = int(sys.argv[2])
    
    # Define known peers (you can modify this based on which peers are running)
    other_peers = []
    if peer_id == 1:
        other_peers = [5001]  # Knows about peer 2's port
    elif peer_id == 2:
        other_peers = [5000]  # Knows about peer 1's port
    
    run_peer(peer_id, port, other_peers)
