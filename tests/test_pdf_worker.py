import unittest
from unittest.mock import MagicMock, patch
import queue
import time
import os

# Set up environment variables for test
os.environ['NETSHIELD_DATA_DIR'] = '.data_test'

from Services import pdf_generator

class TestPDFWorker(unittest.TestCase):
    def test_enqueue_task(self):
        """Verify that enqueuing a task adds it to the queue."""
        # Clear queue first
        while not pdf_generator.pdf_task_queue.empty():
            pdf_generator.pdf_task_queue.get()
            
        pdf_generator.enqueue_pdf_task(
            log_id=1,
            scanner_type='nmap',
            source_data={'test': 'data'},
            user_id=1,
            target='127.0.0.1',
            timestamp='20260409_120000'
        )
        
        self.assertFalse(pdf_generator.pdf_task_queue.empty())
        task = pdf_generator.pdf_task_queue.get()
        self.assertEqual(task['log_id'], 1)
        self.assertEqual(task['scanner_type'], 'nmap')

if __name__ == '__main__':
    unittest.main()
