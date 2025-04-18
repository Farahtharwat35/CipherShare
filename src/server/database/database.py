from pymongo import MongoClient

class DB:
    def __init__(self):
        self.client = MongoClient('mongodb://localhost:27017')
        self.db = self.client['peer_registry']

    def is_account_exist(self, username):
        return self.db.accounts.count_documents({'username': username}) > 0

    def register(self, username, password):
        account = {
            "username": username,
            "password": password
        }
        self.db.accounts.insert_one(account)

    def get_password(self, username):
        user = self.db.accounts.find_one({"username": username})
        return user["password"] if user else None

    def is_account_online(self, username):
        return self.db.online_peers.count_documents({"username": username}) > 0

    def save_online_peer(self, username, ip, port):
        online_peer = {
            "username": username,
            "ip": ip,
            "port": port
        }
        self.db.online_peers.insert_one(online_peer)

    def user_logout(self, username):
        self.db.online_peers.delete_one({"username": username})

    def get_peer_ip_and_port(self, username):
        res = self.db.online_peers.find_one({"username": username})
        return (res["ip"], res["port"]) if res else (None, None)

    def delete_all_online_peers(self):
        self.db.online_peers.delete_many({})
