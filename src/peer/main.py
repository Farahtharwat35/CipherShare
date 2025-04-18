from peer import Peer
from random import randint

def show_help():
    print("\nAvailable commands:")
    print("  search <filename> - Search for files by name")
    print("  keyword <keyword> - Search for files by keyword")
    print("  list - Request updated peer list")
    print("  connect - Connect to all available peers")
    print("  help - Show this help message")
    print("  exit - Quit the program")

def main():
    self_tcp_port = randint(15000, 16000)
    self_udp_port = randint(16000, 17000)

    print(f"TCP Port: {self_tcp_port}, UDP Port: {self_udp_port}")

    username = input("Enter your username: ")

    p = Peer(username, '127.0.1.1', 15601, self_tcp_port, self_udp_port)
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
                p.running = False
                break
                
            elif cmd == "search" and len(parts) > 1:
                filename = parts[1]
                print(f"Searching for files with name: {filename}")
                results = p.send_search_request_with_file_name_or_keyword(filename, is_keyword=False)
                print(f"Found {len(results)} files:")
                for i, file_info in enumerate(results):
                    print(f"  [{i+1}] {file_info.name} ({file_info.size} bytes)")
            
            elif cmd == "keyword" and len(parts) > 1:
                keyword = parts[1]
                print(f"Searching for files with keyword: {keyword}")
                results = p.send_search_request_with_file_name_or_keyword(keyword, is_keyword=True)
                print(f"Found {len(results)} files:")
                for i, file_info in enumerate(results):
                    print(f"  [{i+1}] {file_info.name} ({file_info.size} bytes)")
            
            elif cmd == "list":
                print("Requesting updated peer list...")
                p.request_peer_list()
                print(f"Available peers: {', '.join(p.available_peers.keys()) if p.available_peers else 'None'}")
            
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
