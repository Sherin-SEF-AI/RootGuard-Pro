"""
Logging Module
Secure logging system for the rootkit detection application.
"""

import logging
import os
import datetime
import hashlib
import json
from typing import Dict, Any


class SecureLogger:
    """Secure logger that prevents tampering and provides audit trails."""
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = log_dir
        self.ensure_log_dir()
        self.setup_loggers()
        
    def ensure_log_dir(self):
        """Create log directory if it doesn't exist."""
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
    
    def setup_loggers(self):
        """Setup different loggers for different purposes."""
        # Main application logger
        self.app_logger = logging.getLogger('rootkit_detector')
        self.app_logger.setLevel(logging.INFO)
        
        # Security events logger
        self.security_logger = logging.getLogger('security_events')
        self.security_logger.setLevel(logging.WARNING)
        
        # Audit logger
        self.audit_logger = logging.getLogger('audit')
        self.audit_logger.setLevel(logging.INFO)
        
        # Setup file handlers
        app_handler = logging.FileHandler(
            os.path.join(self.log_dir, f"app_{datetime.date.today().strftime('%Y%m%d')}.log")
        )
        security_handler = logging.FileHandler(
            os.path.join(self.log_dir, f"security_{datetime.date.today().strftime('%Y%m%d')}.log")
        )
        audit_handler = logging.FileHandler(
            os.path.join(self.log_dir, f"audit_{datetime.date.today().strftime('%Y%m%d')}.log")
        )
        
        # Setup formatters
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        app_handler.setFormatter(formatter)
        security_handler.setFormatter(formatter)
        audit_handler.setFormatter(formatter)
        
        # Add handlers to loggers
        if not self.app_logger.handlers:
            self.app_logger.addHandler(app_handler)
        if not self.security_logger.handlers:
            self.security_logger.addHandler(security_handler)
        if not self.audit_logger.handlers:
            self.audit_logger.addHandler(audit_handler)
    
    def log_info(self, message: str, extra_data: Dict = None):
        """Log informational message."""
        if extra_data:
            message += f" | Data: {json.dumps(extra_data)}"
        self.app_logger.info(message)
    
    def log_warning(self, message: str, extra_data: Dict = None):
        """Log warning message."""
        if extra_data:
            message += f" | Data: {json.dumps(extra_data)}"
        self.app_logger.warning(message)
    
    def log_error(self, message: str, extra_data: Dict = None):
        """Log error message."""
        if extra_data:
            message += f" | Data: {json.dumps(extra_data)}"
        self.app_logger.error(message)
    
    def log_security_event(self, event_type: str, details: Dict):
        """Log security-related events."""
        event_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'event_type': event_type,
            'details': details,
            'checksum': self.calculate_checksum(details)
        }
        
        self.security_logger.warning(f"SECURITY_EVENT: {json.dumps(event_data)}")
    
    def log_audit_event(self, action: str, user: str, details: Dict):
        """Log audit events for compliance."""
        audit_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'action': action,
            'user': user,
            'details': details
        }
        
        self.audit_logger.info(f"AUDIT: {json.dumps(audit_data)}")
    
    def calculate_checksum(self, data: Any) -> str:
        """Calculate checksum for data integrity verification."""
        data_string = json.dumps(data, sort_keys=True)
        return hashlib.sha256(data_string.encode()).hexdigest()
    
    def verify_log_integrity(self, log_file_path: str) -> bool:
        """Verify the integrity of a log file."""
        try:
            with open(log_file_path, 'r') as f:
                lines = f.readlines()
            
            # Check for tampering indicators
            for line in lines:
                if 'SECURITY_EVENT:' in line:
                    try:
                        # Extract JSON data
                        json_start = line.find('{')
                        if json_start > 0:
                            event_data = json.loads(line[json_start:])
                            
                            # Recalculate checksum
                            expected_checksum = self.calculate_checksum(event_data.get('details', {}))
                            actual_checksum = event_data.get('checksum', '')
                            
                            if expected_checksum != actual_checksum:
                                return False
                                
                    except (json.JSONDecodeError, KeyError):
                        continue
            
            return True
            
        except Exception as e:
            print(f"Error verifying log integrity: {e}")
            return False


# Global logger instance
security_logger = SecureLogger()