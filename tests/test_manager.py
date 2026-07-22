import unittest
import os
from unittest.mock import patch, MagicMock
from Services.anonymity.manager import AnonymityManager

class TestAnonymityManager(unittest.TestCase):
    def setUp(self):
        # Prevent actually touching environment variables during test init
        with patch.dict(os.environ, {"ANONYMITY_MODE": "off"}):
            self.manager = AnonymityManager()

    def test_initialization(self):
        self.assertFalse(self.manager.enabled)
        self.assertEqual(self.manager.mode, "off")

    def test_get_scan_flags_nmap(self):
        self.manager.mode = "tor"
        self.manager.socks_port = "9050"
        self.manager.proxy_host = "127.0.0.1"

        flags = self.manager.get_scan_flags("nmap")
        self.assertIn("-sT", flags)
        self.assertIn("socks4://127.0.0.1:9050", flags)

if __name__ == '__main__':
    unittest.main()
