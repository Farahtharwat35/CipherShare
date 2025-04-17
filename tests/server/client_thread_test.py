import unittest
from unittest.mock import Mock, MagicMock, patch
import threading
import queue
import bcrypt
import sys
import os

from src.types import types

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

mock_globals = MagicMock()
mock_globals.udp_port_numbers = {}
mock_globals.lock = threading.Lock()
mock_globals.onlinePeers = []
mock_globals.tcpThreads = {}
sys.modules['globals'] = mock_globals


from src.server.client_thread import ClientThread


class ClientThreadTest(unittest.TestCase):
    def setUp(self):
        self.mock_socket = MagicMock()
        self.mock_db = MagicMock()
        
        self.client_thread = ClientThread('127.0.0.1', 12345, self.mock_socket, self.mock_db)
        
    def test_init(self):
        """Test the initialization of ClientThread"""
        self.assertEqual(self.client_thread.ip, '127.0.0.1')
        self.assertEqual(self.client_thread.port, 12345)
        self.assertEqual(self.client_thread.tcpClientSocket, self.mock_socket)
        self.assertEqual(self.client_thread.db, self.mock_db)
        self.assertIsNone(self.client_thread.username)
        self.assertTrue(self.client_thread.isOnline)
        self.assertIsInstance(self.client_thread.message_queue, queue.Queue)
        self.assertIsInstance(self.client_thread.handlers, dict)
        self.assertEqual(self.client_thread.handlers[types.Command.JOIN], self.client_thread.handle_peer_join)
        self.assertEqual(self.client_thread.handlers[types.Command.LOGIN], self.client_thread.handle_login)
        self.assertEqual(self.client_thread.handlers[types.Command.LOGOUT], self.client_thread.handle_logout)
        self.assertEqual(self.client_thread.handlers[types.Command.LIST_ONLINE_PEERS], self.client_thread.handle_online_peers_listing)
        
    def test_add_handler(self):
        """Test adding command handlers"""
        mock_handler = MagicMock()
        
        self.client_thread.add_handler('test_command', mock_handler)
        
        self.assertIn('test_command', self.client_thread.handlers)
        self.assertEqual(self.client_thread.handlers['test_command'], mock_handler)
        
    def test_process_message_with_handler(self):
        """Test processing a message with a registered handler"""
        mock_handler = MagicMock()
        
        self.client_thread.add_handler('test_command', mock_handler)
        
        self.client_thread.process_message(['test_command', 'arg1', 'arg2'])
        
        mock_handler.assert_called_once_with(['test_command', 'arg1', 'arg2'])
        
    def test_process_message_without_handler(self):
        """Test processing a message without a registered handler"""
        with patch('logging.error') as mock_log:
            self.client_thread.process_message(['unknown_command'])
            mock_log.assert_called_once()
            
    def test_process_message_empty_message(self):
        """Test processing an empty message"""
        mock_handler = MagicMock()
        self.client_thread.add_handler('test_command', mock_handler)
        
        self.client_thread.process_message([])
        
        mock_handler.assert_not_called()
        
    @patch('src.server.client_thread.UDPServer')
    def test_handle_login_success(self, mock_udp_server_class):
        """Test successful login"""
        self.mock_db.is_account_exist.return_value = True
        self.mock_db.is_account_online.return_value = False
        hashed_pass = bcrypt.hashpw(b'password123', bcrypt.gensalt()).decode('utf-8')
        self.mock_db.get_password.return_value = hashed_pass

        mock_udp_instance = MagicMock()
        mock_udp_server_class.return_value = mock_udp_instance

        message = ['login', 'testuser', 'password123', '5000']
        self.client_thread.handle_login(message)

        self.mock_db.is_account_exist.assert_called_once_with('testuser')
        self.mock_db.is_account_online.assert_called_once_with('testuser')
        self.mock_db.get_password.assert_called_once_with('testuser')
        self.mock_db.user_login.assert_called_once_with('testuser', '127.0.0.1', '5000')

        self.mock_socket.send.assert_called_once_with(b'login-success')

        self.assertEqual(self.client_thread.username, 'testuser')

        mock_udp_server_class.assert_called_once_with('testuser', self.mock_socket, self.mock_db)

        mock_udp_instance.start.assert_called_once()
        mock_udp_instance.timer.start.assert_called_once()

    def test_handle_login_account_not_exist(self):
        """Test login with non-existent account"""
        self.mock_db.is_account_exist.return_value = False
        
        message = ['login', 'nonexistent', 'password123', '5000']
        self.client_thread.handle_login(message)
        
        self.mock_db.is_account_exist.assert_called_once_with('nonexistent')
        
        self.mock_socket.send.assert_called_once_with(b'login-account-not-exist')
        
    def test_handle_login_already_online(self):
        """Test login with already online account"""
        self.mock_db.is_account_exist.return_value = True
        self.mock_db.is_account_online.return_value = True
        
        message = ['login', 'testuser', 'password123', '5000']
        self.client_thread.handle_login(message)
        
        self.mock_db.is_account_exist.assert_called_once_with('testuser')
        self.mock_db.is_account_online.assert_called_once_with('testuser')
        
        self.mock_socket.send.assert_called_once_with(b'login-online')
        
    def test_handle_login_wrong_password(self):
        """Test login with wrong password"""
        self.mock_db.is_account_exist.return_value = True
        self.mock_db.is_account_online.return_value = False
        hashed_pass = bcrypt.hashpw(b'correctpassword', bcrypt.gensalt()).decode('utf-8')
        self.mock_db.get_password.return_value = hashed_pass
        
        message = ['login', 'testuser', 'wrongpassword', '5000']
        self.client_thread.handle_login(message)
        
        self.mock_db.is_account_exist.assert_called_once_with('testuser')
        self.mock_db.is_account_online.assert_called_once_with('testuser')
        self.mock_db.get_password.assert_called_once_with('testuser')
        
        self.mock_socket.send.assert_called_once_with(b'login-wrong-password')
        
    def test_handle_peer_join_exists(self):
        """Test joining as a user that already exists"""
        self.mock_db.is_account_exist.return_value = True
        
        message = ['join', 'existinguser', 'password123']
        self.client_thread.handle_peer_join(message)
        
        self.mock_db.is_account_exist.assert_called_once_with('existinguser')
        
        self.mock_socket.send.assert_called_once_with(b'join-exist')
        
    def test_handle_peer_join_success(self):
        """Test successful user registration"""
        self.mock_db.is_account_exist.return_value = False
        
        message = ['join', 'newuser', 'ip_address', 'udp_port']
        self.client_thread.handle_peer_join(message)
        
        self.mock_db.is_account_exist.assert_called_once_with('newuser')
        self.mock_db.save_online_peer.assert_called_once_with('newuser', 'ip_address', 'udp_port')
        
        self.mock_socket.send.assert_called_once_with(b'join-success')
        
    @patch('src.server.client_thread.UDPServer')  
    def test_handle_logout(self, mock_udp_server_class):
        """Test user logout"""
        self.mock_db.is_account_online.return_value = True
        
        mock_udp_instance = MagicMock()
        self.client_thread.udpServer = mock_udp_instance
        
        message = ['logout', 'testuser']
        self.client_thread.handle_logout(message)
        
        self.mock_db.is_account_online.assert_called_once_with('testuser')
        self.mock_db.user_logout.assert_called_once_with('testuser')
        
        self.mock_socket.close.assert_called_once()
        mock_udp_instance.timer.cancel.assert_called_once()
        
    def test_handle_logout_invalid(self):
        """Test logout with invalid parameters"""
        message = ['logout']
        self.client_thread.handle_logout(message)
        
        self.mock_db.is_account_online.assert_not_called()
        self.mock_db.user_logout.assert_not_called()
        
    def test_handle_online_peers_listing(self):
        """Test listing online peers"""
        self.mock_db.get_online_peers.return_value = ['user1', 'user2', 'user3']
        
        self.client_thread.handle_online_peers_listing()
        
        self.mock_db.get_online_peers.assert_called_once()
        
        expected_response = "Online peers: user1, user2, user3"
        self.mock_socket.send.assert_called_once_with(expected_response.encode())
        
    def test_reset_time_out(self):
        """Test resetting the UDP server timeout"""
        mock_udp_server = MagicMock()
        self.client_thread.udpServer = mock_udp_server
        
        self.client_thread.reset_time_out()
        
        mock_udp_server.reset_timer.assert_called_once()
        
    def test_reset_time_out_no_udp_server(self):
        """Test resetting timeout when UDP server is None"""
        self.client_thread.udpServer = None
        self.client_thread.reset_time_out()


if __name__ == '__main__':
    unittest.main()
