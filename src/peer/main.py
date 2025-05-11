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
from colorama import Fore, Style, init

init(autoreset=True)

def show_help():
    print(f"\n{Fore.CYAN}📜 Available Commands:")
    print(f"  {Fore.YELLOW}🔗 share <file-path> <peers-username>{Style.RESET_ALL} - Share a file with specific peers")
    print(f"  {Fore.YELLOW}🔍 search <filename>{Style.RESET_ALL} - Search for files by name")
    print(f"  {Fore.YELLOW}🔑 keyword <keyword>{Style.RESET_ALL} - Search for files by keyword")
    print(f"  {Fore.YELLOW}⬇️  download <username> <file-id>{Style.RESET_ALL} - Download a file from a peer")
    print(f"  {Fore.YELLOW}📋 list{Style.RESET_ALL} - Request updated peer list")
    print(f"  {Fore.YELLOW}📂 list-shared{Style.RESET_ALL} - List all shared files")
    print(f"  {Fore.YELLOW}❓ help{Style.RESET_ALL} - Show this help message")
    print(f"  {Fore.YELLOW}🚪 exit{Style.RESET_ALL} - Quit the program")

def main():
    self_tcp_port = randint(15000, 16000)
    self_udp_port = randint(16000, 17000)

    print(f"{Fore.GREEN}🌐 Starting CipherShare...")
    print(f"{Fore.BLUE}🔌 TCP Port: {self_tcp_port}, UDP Port: {self_udp_port}")

    p = Peer("", SERVER_HOST, TCP_PORT, self_tcp_port, self_udp_port)
    
    login_success = None
    saved_users = CryptoUtils.list_saved_credentials()
    if saved_users:
        print(f"{Fore.CYAN}💾 Saved credentials found for users: {', '.join(saved_users)}")
        use_autofill = input(f"{Fore.YELLOW}🤔 Do you want to autofill from saved credentials? (y/n): ").strip().lower()
        if use_autofill == 'y':
            for idx, user in enumerate(saved_users):
                print(f"{Fore.CYAN}[{idx+1}] {user}")
            while True:
                try:
                    choice_idx = int(input(f"{Fore.YELLOW}👉 Select a user (1-{len(saved_users)}), or 0 to cancel: ").strip())
                    if choice_idx == 0:
                        print(f"{Fore.RED}❌ Autofill cancelled. Proceeding to manual login...")
                        break
                    if 1 <= choice_idx <= len(saved_users):
                        selected_user = saved_users[choice_idx - 1]
                        passphrase = getpass.getpass(f"{Fore.YELLOW}🔑 Enter passphrase for '{selected_user}': ").strip()
                        username, password = CryptoUtils.load_encrypted_credentials(selected_user, passphrase)
                        if username and password:
                            print(f"{Fore.GREEN}🔐 Attempting auto-login for {username}...")
                            p = Peer("", SERVER_HOST, TCP_PORT, self_tcp_port, self_udp_port)
                            login_success = p.login(username, password, is_register=False)
                            if login_success:
                                print(f"{Fore.GREEN}✅ Auto-login successful!")
                                break
                            else:
                                print(f"{Fore.RED}❌ Auto-login failed. Proceeding to manual login.")
                                break
                        else:
                            print(f"{Fore.RED}❌ Failed to decrypt credentials or wrong passphrase.")
                    else:
                        print(f"{Fore.RED}❌ Invalid selection.")
                except ValueError:
                    print(f"{Fore.RED}❌ Invalid input.")

    while True and not login_success:
        try:
            choice = input(f"{Fore.YELLOW}👉 Enter 0 to login or 1 to register: ").strip()
            if choice not in ["0", "1"]:
                print(f"{Fore.RED}❌ Invalid choice. Please enter 0 or 1.")
                continue

            username = input(f"{Fore.YELLOW}👤 Enter your username: ").strip()
            password = getpass.getpass(f"{Fore.YELLOW}🔑 Enter your password: ").strip()

            is_register = (choice == "1")
            login_success = p.login(username, password, is_register)
            
            if login_success:
                save_choice = input(f"{Fore.YELLOW}💾 Do you want to save your credentials for future autofill? (y/n): ").strip().lower()
                if save_choice == 'y':
                    passphrase = getpass.getpass(f"{Fore.YELLOW}🔒 Enter a passphrase to encrypt your credentials: ").strip()
                    CryptoUtils.save_encrypted_credentials(username, password, passphrase)
                break
        except Exception as e:
            print(f"{Fore.RED}❌ Error: {e}")
            continue
            
    # Starting the peer after successful login/registration
    p.start()
    
    print(f"\n{Fore.GREEN}=== 🚀 Welcome to CipherShare P2P File Sharing System ===")
    show_help()
    
    while p.running:
        try:
            command = input(f"\n{Fore.YELLOW}> ").strip()
            parts = command.split(maxsplit=1)
            cmd = parts[0].lower() if parts else ""
            
            if cmd == "exit":
                print(f"{Fore.RED}🚪 Exiting...")
                p.stop()
                break
                
            elif cmd == "share":
                if len(parts) > 1:
                    share_parts = parts[1].split(maxsplit=1)
                    file_path = share_parts[0]
                    peers = share_parts[1].split(',') if len(share_parts) > 1 else None
                    if peers:
                        print(f"{Fore.GREEN}📤 Sharing file: {file_path} with peers: {', '.join(peers)}")
                    else:
                        print(f"{Fore.GREEN}📤 Sharing file: {file_path} with all peers")
                    
                    p.file_service.share_file(file_path, peer_list=peers)
                else:
                    print(f"{Fore.RED}❌ Invalid command. Usage: share <file-path> [peers-username,...]")
            elif cmd == "search" and len(parts) > 1:
                filename = parts[1]
                print(f"{Fore.CYAN}🔍 Searching for files with name: {filename}")
                results = p.send_search_request_with_file_name_or_keyword(filename, is_keyword=False)
                print(f"{Fore.GREEN}✅ Found {len(results)} files:")
                for i, file_info in enumerate(results):
                    print(f"  [{i+1}] {file_info.name} {file_info.id} {file_info.owner_id} ({file_info.size} bytes)")
            
            elif cmd == "keyword" and len(parts) > 1:
                keyword = parts[1]
                print(f"{Fore.CYAN}🔍 Searching for files with keyword: {keyword}")
                results = p.send_search_request_with_file_name_or_keyword(keyword, is_keyword=True)
                print(f"{Fore.GREEN}✅ Found {len(results)} files:")
                for i, file_info in enumerate(results):
                    print(f"  [{i+1}] {file_info.name} {file_info.owner_id} {file_info.id} ({file_info.size} bytes)")
            elif cmd == "download" and len(parts) > 1:
                download_parts = parts[1].split(maxsplit=1)
                if len(download_parts) == 2:
                    peer_username = download_parts[0]
                    file_id = download_parts[1]
                    print(f"{Fore.CYAN}⬇️ Downloading file {file_id} from peer {peer_username}...")
                    p.send_download_request(peer_username, file_id)
                else:
                    print(f"{Fore.RED}❌ Invalid command. Usage: download <username> <file-id>")
            elif cmd == "list":
                print(f"{Fore.CYAN}📋 Requesting updated peer list...")
                p.request_peer_list()
                print(f"{Fore.GREEN}✅ Available peers: {', '.join(p.available_peers.keys()) if p.available_peers else 'None'}")

            elif cmd == "list-shared":
                print(f"{Fore.CYAN}📂 Listing all shared files...")
                shared_files = p.file_service.get_shared_files()
                if not shared_files:
                    print(f"{Fore.RED}❌ No files shared.")
                else:
                    print(f"{Fore.GREEN}✅ Shared files ({len(shared_files)}):")
                    for file_info in shared_files:
                        print(f"  - {file_info.name} ({file_info.size} bytes)")
            elif cmd == "connect":
                print(f"{Fore.CYAN}🔗 Connecting to available peers...")
                p.connect_to_available_peers()          
            elif cmd == "help":
                show_help()
            else:
                print(f"{Fore.RED}❌ Unknown command. Type 'help' for available commands.")
                
        except Exception as e:
            print(f"{Fore.RED}❌ Error processing command: {e}")

if __name__ == "__main__":
    main()
