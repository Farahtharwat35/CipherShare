import os
import sys
import getpass  # For secure password input
import socket
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)
from src.utils import get_local_ip_address
from peer import Peer
from random import randint
from src.config.config import SERVER_HOST, TCP_PORT
from src.peer.crypto.crypto_utils import CryptoUtils

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

    # Creating a Peer instance with temporary username
    p = Peer("", SERVER_HOST, TCP_PORT, self_tcp_port, self_udp_port)
    
    login_success = None
    saved_users = CryptoUtils.list_saved_credentials()
    if saved_users:
        print(f"Saved credentials found for users: {', '.join(saved_users)}")
        use_autofill = input("Do you want to autofill from saved credentials? (y/n): ").strip().lower()
        if use_autofill == 'y':
            for idx, user in enumerate(saved_users):
                print(f"[{idx+1}] {user}")
            while True:
                try:
                    choice_idx = int(input(f"Select a user (1-{len(saved_users)}), or 0 to cancel: ").strip())
                    if choice_idx == 0:
                        print("Autofill cancelled, proceeding to manual login...")
                        break
                    if 1 <= choice_idx <= len(saved_users):
                        selected_user = saved_users[choice_idx - 1]
                        passphrase = getpass.getpass(f"Enter passphrase for '{selected_user}': ").strip()
                        username, password = CryptoUtils.load_encrypted_credentials(selected_user, passphrase)
                        if username and password:
                            print(f"Attempting auto-login for {username}...")
                            p = Peer("", SERVER_HOST, TCP_PORT, self_tcp_port, self_udp_port)
                            login_success = p.login(username, password, is_register=False)
                            if login_success:
                                print("Auto-login successful.")
                                break
                            else:
                                print("Auto-login failed. Proceeding to manual login.")
                                break
                        else:
                            print("Failed to decrypt credentials or wrong passphrase.")
                    else:
                        print("Invalid selection.")
                except ValueError:
                    print("Invalid input.")


    # Looping until successful login or user cancellation
    while True and not login_success:
        try:
            choice = input("Enter 0 to login or 1 to register: ").strip()
            if choice not in ["0", "1"]:
                print("Invalid choice. Please enter 0 or 1.")
                continue

            username = input("Enter your username: ").strip()
            password = getpass.getpass("Enter your password: ").strip()

            is_register = (choice == "1")
            login_success = p.login(username, password, is_register)
            
            if login_success:
                save_choice = input("Do you want to save your credentials for future autofill? (y/n): ").strip().lower()
                if save_choice == 'y':
                    passphrase = getpass.getpass("Enter a passphrase to encrypt your credentials: ").strip()
                    CryptoUtils.save_encrypted_credentials(username, password, passphrase)
                break
        except Exception as e:
            print(f"Error: {e}")
            continue
            
    # Starting the peer after successful login/registration : no waste of resources 
    p.start()
    
    print("\n=== CipherShare P2P File Sharing System ===")
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

            elif cmd == "list-shared":
                print("Listing all shared files...")
                shared_files = p.file_service.get_shared_files()
                if not shared_files:
                    print("No files shared.")
                else:
                    print(f"Shared files ({len(shared_files)}):")
                    for file_info in shared_files:
                        print(f"  - {file_info.name} ({file_info.size} bytes)\n")
            elif cmd == "connect":
                print("Connecting to available peers...")
                p.connect_to_available_peers()          
            elif cmd == "help":
                show_help()
            else:
                print("Unknown command. Type 'help' for available commands.")
                
        except Exception as e:
            print(f"Error processing command: {e}")

if __name__ == "__main__":
    main()
