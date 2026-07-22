import unittest
from unittest.mock import patch, MagicMock
from Services.anonymity.verifier import IdentityVerifier

class TestIdentityVerifier(unittest.TestCase):
    def setUp(self):
        self.verifier = IdentityVerifier("socks5://127.0.0.1:9050", strict=True)

    @patch('requests.Session.get')
    def test_proxy_alive(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "1.2.3.4"
        mock_get.return_value = mock_response
        self.assertTrue(self.verifier._check_proxy_alive().passed)

    @patch('requests.Session.get')
    def test_proxy_alive_failure(self, mock_get):
        mock_get.side_effect = Exception("Connection Refused")
        self.assertFalse(self.verifier._check_proxy_alive().passed)

if __name__ == '__main__':
    unittest.main()
