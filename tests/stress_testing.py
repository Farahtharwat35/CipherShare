import os
import sys
import getpass  # For secure password input
import socket
import threading
import time
from random import randint

# Set the project root correctly from test folder
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

# Now import from src
from src.utils import get_local_ip_address
from src.peer.peer import Peer  # Fixed path
from src.config.config import SERVER_HOST, TCP_PORT
from src.peer.crypto.crypto_utils import CryptoUtils

def simulate_peer(peer_id, login_times):
    try:
        self_tcp_port = randint(15000, 16000)
        self_udp_port = randint(16000, 17000)

        p = Peer("", SERVER_HOST, TCP_PORT, self_tcp_port, self_udp_port)

        username = f"user_{peer_id}"
        password = f"pass_{peer_id}"

        print(f"Simulating Peer {peer_id} with username: {username}, password: {password}, TCP Port: {self_tcp_port}, UDP Port: {self_udp_port}")

        start_time = time.time()
        login_success = p.login(username, password, is_register=True)
        end_time = time.time()

        login_time = end_time - start_time
        login_times.append(login_time)

        if login_success:
            print(f"Peer {peer_id} registered successfully. Login time: {login_time:.2f} seconds.")
        else:
            print(f"Peer {peer_id} failed to register. Login time: {login_time:.2f} seconds.")

        p.start()
        time.sleep(500)
        p.stop()
    except Exception as e:
        print(f"Error in Peer {peer_id}: {e}")

def main():
    num_peers = int(input("Enter the number of peers to simulate: "))
    threads = []
    login_times = []
    average_times = []

    for i in range(num_peers):
        thread = threading.Thread(target=simulate_peer, args=(i, login_times))
        threads.append(thread)
        thread.start()
        time.sleep(0.1)

        if (i + 1) % 100 == 0:
            for thread in threads:
                thread.join()
            avg_time = sum(login_times) / len(login_times)
            average_times.append(avg_time)
            print(f"Average login time for users {i - 99} to {i}: {avg_time:.2f} seconds.")
            login_times.clear()
            threads = []

    for thread in threads:
        thread.join()

    if login_times:
        avg_time = sum(login_times) / len(login_times)
        average_times.append(avg_time)
        print(f"Average login time for remaining users: {avg_time:.2f} seconds.")

    print("Stress test completed.")
    print(f"Average login times for each batch of 100 users: {average_times}")

if __name__ == "__main__":
    main()
