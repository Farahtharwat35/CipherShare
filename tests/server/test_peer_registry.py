import time
import pytest
from src.server.peer_registry import PeerRegistry


@pytest.fixture
def registry():
    return PeerRegistry()


def test_update_peer_adds_peer(registry):
    registry.update_peer('127.0.0.1', 5000, 'peer1')
    peers = registry.get_peers()
    assert len(peers) == 1
    assert peers[0] == ('127.0.0.1', 5000, 'peer1')


def test_get_peer_by_id(registry):
    registry.update_peer('192.168.1.10', 6000, 'peer42')
    result = registry.get_peer_by_id('peer42')
    assert result == ('192.168.1.10', 6000)


def test_get_peer_by_id_not_found(registry):
    assert registry.get_peer_by_id('unknown') is None


def test_remove_inactive_peers_removes_old_entries(registry):
    registry.update_peer('10.0.0.1', 4000, 'peer_old')
    time.sleep(1)
    registry.update_peer('10.0.0.2', 4001, 'peer_new')

    registry.peers[('10.0.0.1', 4000)]['last_seen'] -= 5  # simulate old peer

    registry.remove_inactive_peers(timeout=2)

    peers = registry.get_peers()
    assert len(peers) == 1
    assert peers[0][2] == 'peer_new'


def test_remove_inactive_peers_keeps_recent_peers(registry):
    registry.update_peer('10.0.0.3', 5001, 'peer_recent')
    registry.remove_inactive_peers(timeout=10)
    assert len(registry.get_peers()) == 1
