from enum import Enum

class Command(Enum):
    """Enum for command types."""
    JOIN = "JOIN"
    LOGIN =  "LOGIN"
    LOGOUT =  "LOGOUT"
    LIST_ONLINE_PEERS = "LIST ONLINE PEERS"