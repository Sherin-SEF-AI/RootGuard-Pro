"""
Unit tests for Process Detector module.
"""

import unittest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from detection.process_detector import ProcessDetector


class TestProcessDetector(unittest.TestCase):
    """Test cases for ProcessDetector class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = ProcessDetector()
    
    def test_is_suspicious_process(self):
        """Test suspicious process detection."""
        # Normal processes
        self.assertFalse(self.detector.is_suspicious_process('notepad.exe', 'C:\\Windows\\notepad.exe'))
        self.assertFalse(self.detector.is_suspicious_process('explorer.exe', 'C:\\Windows\\explorer.exe'))
        
        # Suspicious processes
        self.assertTrue(self.detector.is_suspicious_process('keylogger.exe', 'C:\\temp\\keylogger.exe'))
        self.assertTrue(self.detector.is_suspicious_process('x', 'C:\\temp\\x'))
        self.assertTrue(self.detector.is_suspicious_process('test.tmp', 'C:\\temp\\test.tmp'))
    
    def test_enumerate_toolhelp32(self):
        """Test toolhelp32 process enumeration."""
        processes = self.detector.enumerate_toolhelp32()
        
        # Should return a list
        self.assertIsInstance(processes, list)
        
        # Should contain at least some processes
        self.assertGreater(len(processes), 0)
        
        # Each process should have required fields
        if processes:
            proc = processes[0]
            required_fields = ['pid', 'name', 'ppid', 'source']
            for field in required_fields:
                self.assertIn(field, proc)
    
    def test_enumerate_wmi(self):
        """Test WMI process enumeration."""
        processes = self.detector.enumerate_wmi()
        
        # Should return a list (may be empty if WMI not available)
        self.assertIsInstance(processes, list)
        
        # If WMI is available, should contain processes
        if processes:
            proc = processes[0]
            required_fields = ['pid', 'name', 'source']
            for field in required_fields:
                self.assertIn(field, proc)
    
    def test_compare_process_lists(self):
        """Test process list comparison."""
        # Create mock process lists
        list1 = [
            {'pid': 1234, 'name': 'test1.exe', 'source': 'toolhelp32'},
            {'pid': 5678, 'name': 'test2.exe', 'source': 'toolhelp32'}
        ]
        
        list2 = [
            {'pid': 1234, 'name': 'test1.exe', 'source': 'wmi'},
            {'pid': 9999, 'name': 'hidden.exe', 'source': 'wmi'}
        ]
        
        list3 = [
            {'pid': 1234, 'name': 'test1.exe', 'source': 'eprocess'},
            {'pid': 5678, 'name': 'test2.exe', 'source': 'eprocess'}
        ]
        
        result = self.detector.compare_process_lists(list1, list2, list3)
        
        # Should return a list
        self.assertIsInstance(result, list)
        
        # Should contain all unique processes
        self.assertGreaterEqual(len(result), 3)
        
        # Check that sources are properly tracked
        for proc in result:
            self.assertIn('sources', proc)
            self.assertIsInstance(proc['sources'], list)


if __name__ == '__main__':
    unittest.main()