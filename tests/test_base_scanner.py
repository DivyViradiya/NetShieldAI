import unittest
from unittest.mock import MagicMock, patch
from Services.base_scanner import BaseScanner

class TestBaseScanner(unittest.TestCase):
    @patch('Services.scan_logger.log_scan_start')
    def test_start_scan(self, mock_log_start):
        mock_log_start.return_value = 123
        scanner = BaseScanner(user_id=1, tool_name="TestTool", target="127.0.0.1")
        
        log_id = scanner.start_scan(scan_type="Deep")
        
        self.assertEqual(log_id, 123)
        self.assertEqual(scanner.log_id, 123)
        mock_log_start.assert_called_once_with(1, "TestTool", "127.0.0.1", scan_type="Deep", origin="manual")

    @patch('Services.scan_logger.log_scan_end')
    @patch('Services.pdf_generator.enqueue_pdf_task')
    def test_finalize_scan(self, mock_enqueue, mock_log_end):
        scanner = BaseScanner(user_id=1, tool_name="TestTool", target="127.0.0.1")
        scanner.log_id = 123
        
        scanner.finalize_scan(
            status="Completed",
            finding_count=5,
            result_data={"data": "test"},
            timestamp="20260409",
            scanner_type_key="test_scan"
        )
        
        mock_log_end.assert_called_once()
        mock_enqueue.assert_called_once_with(123, "test_scan", {"data": "test"}, 1, "127.0.0.1", "20260409")

if __name__ == '__main__':
    unittest.main()
