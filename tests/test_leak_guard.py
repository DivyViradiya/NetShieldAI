import unittest
from unittest.mock import patch, MagicMock
from Services.anonymity.leak_guard import patch_dns_over_socks, KillswitchGuard

class TestLeakGuard(unittest.TestCase):
    @patch('Services.anonymity.leak_guard.socks.socksocket')
    def test_patch_dns_over_socks(self, mock_socksocket):
        import socket
        # Test monkey-patching socket logic
        original_socket = socket.socket
        patch_dns_over_socks("127.0.0.1", 9050)
        self.assertNotEqual(socket.socket, original_socket)
        # Restore
        socket.socket = original_socket

    @patch('subprocess.run')
    def test_killswitch_guard_linux(self, mock_run):
        import sys
        if sys.platform != 'linux':
            self.skipTest("iptables test is Linux only")

        with KillswitchGuard(9050):
            mock_run.assert_called()

if __name__ == '__main__':
    unittest.main()
