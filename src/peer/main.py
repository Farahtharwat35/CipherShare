import os
import sys
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)
from peer import Peer
from random import randint
from src.config.config import SERVER_HOST, TCP_PORT



def show_help():
    print("\nAvailable commands:")
    print("  share <file-path> <peers-username> - Share specfic file with specfic peers")
    print("  search <filename> - Search for files by name")
    print("  keyword <keyword> - Search for files by keyword")
    print("  download <username> <file-id> - Download a file from a peer")
    print("  list - Request updated peer list")
    print("  list-shared - List all shared files")
    print("  help - Show this help message")
    print("  exit - Quit the program")

def main():
    self_tcp_port = randint(15000, 16000)
    self_udp_port = randint(16000, 17000)

    print(f"TCP Port: {self_tcp_port}, UDP Port: {self_udp_port}")

    username = input("Enter your username: ")

    p = Peer(username, SERVER_HOST, TCP_PORT, self_tcp_port, self_udp_port)
    p.start()
    
    print("\n=== P2P File Sharing System ===")
    show_help()
    
    while p.running:
        try:
            command = input("\n> ").strip()
            parts = command.split(maxsplit=1)
            cmd = parts[0].lower() if parts else ""
            
            if cmd == "exit":
                print("Exiting...")
                p.stop()
                break
                
            elif cmd == "share":
                if len(parts) > 1:
                    share_parts = parts[1].split(maxsplit=1)
                    file_path = share_parts[0]
                    peers = share_parts[1].split(',') if len(share_parts) > 1 else None
                    if peers:
                        print(f"Sharing file: {file_path} with peers: {', '.join(peers)}")
                    else:
                        print(f"Sharing file: {file_path} with all peers")
                    
                    p.file_service.share_file(file_path, peer_list=peers)
                else:
                    print("Invalid command. Usage: share <file-path> [peers-username,...]")
            elif cmd == "search" and len(parts) > 1:
                filename = parts[1]
                print(f"Searching for files with name: {filename}")
                results = p.send_search_request_with_file_name_or_keyword(filename, is_keyword=False)
                print(f"Found {len(results)} files:")
                for i, file_info in enumerate(results):
                    print(f"  [{i+1}] {file_info.name} {file_info.id} {file_info.owner_id} ({file_info.size} bytes)")
            
            elif cmd == "keyword" and len(parts) > 1:
                keyword = parts[1]
                print(f"Searching for files with keyword: {keyword}")
                results = p.send_search_request_with_file_name_or_keyword(keyword, is_keyword=True)
                print(f"Found {len(results)} files:")
                for i, file_info in enumerate(results):
                    print(f"  [{i+1}] {file_info.name} {file_info.owner_id} {file_info.id} ({file_info.size}  bytes)")
            elif cmd == "download" and len(parts) > 1:
                download_parts = parts[1].split(maxsplit=1)
                if len(download_parts) == 2:
                    peer_username = download_parts[0]
                    file_id = download_parts[1]
                    print(f"Downloading file {file_id} from peer {peer_username}...")
                    p.send_download_request(peer_username, file_id)
                else:
                    print("Invalid command. Usage: download <username> <file-id>")
            elif cmd == "list":
                print("Requesting updated peer list...")
                p.request_peer_list()
                print(f"Available peers: {', '.join(p.available_peers.keys()) if p.available_peers else 'None'}")
                # print(f"shared files: {p.file_service.shared_files}")
                # print(f"files info : {p.file_service.shared_files_info}")
            elif cmd == "list-shared":
                print("Listing all shared files...")
                shared_files = p.file_service.get_shared_files()
                if not shared_files:
                    print("No files shared.")
                else:
                    print(f"Shared files ({len(shared_files)}):\n")
                    for file_info in shared_files:
                        print(f"  - {file_info.name} ({file_info.size} bytes)\n")
            elif cmd == "connect":
                print("Connecting to available peers...")
                p.connect_to_peers()
                
            elif cmd == "help":
                show_help()
                
            else:
                print("Unknown command. Type 'help' for available commands.")
                
        except Exception as e:
            print(f"Error processing command: {e}")

if __name__ == "__main__":
    main()
