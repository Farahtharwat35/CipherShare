import os
import socket   

def get_local_ip_address():
        """Get the local IP address of the machine"""
        HOST = socket.gethostname()
        try:
            HOST = socket.gethostbyname(HOST)
        except socket.gaierror:
            import netifaces as ni
            HOST = ni.ifaddresses('en0')[ni.AF_INET][0]['addr']
        return HOST