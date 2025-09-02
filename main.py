#!/usr/bin/env python3
"""
Rootkit Detection Application
A comprehensive tool for detecting hidden processes, services, and network connections.
"""

import sys
import os
from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt
from src.ui.main_window import MainWindow

def is_root():
    """Check if the application is running with root privileges."""
    return os.geteuid() == 0

def main():
    """Main application entry point."""
    app = QApplication(sys.argv)
    app.setApplicationName("Linux Rootkit Detection Tool")
    app.setApplicationVersion("1.0.0")
    
    # Check for root privileges
    if not is_root():
        # Try to provide helpful guidance for privilege escalation
        current_dir = os.getcwd()
        script_path = os.path.abspath(__file__)
        
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle("Root Privileges Required")
        msg.setText("This application requires root privileges to access system information.")
        msg.setInformativeText(
            f"Please restart the application with root privileges:\n\n"
            f"sudo python {script_path}\n\n"
            f"Or from the current directory:\n"
            f"sudo python main.py\n\n"
            f"Advanced features like memory forensics, file integrity monitoring, "
            f"and behavioral analysis require root access to function properly."
        )
        
        # Add buttons for user choice
        msg.setStandardButtons(QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
        msg.setDefaultButton(QMessageBox.StandardButton.Ok)
        
        result = msg.exec()
        
        if result == QMessageBox.StandardButton.Ok:
            # Try to restart with sudo (won't work in GUI context, but show command)
            print(f"\nTo run with root privileges, execute:")
            print(f"sudo python {script_path}")
            print(f"\nOr from {current_dir}:")
            print(f"sudo python main.py")
        
        return 1
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    return app.exec()

if __name__ == "__main__":
    sys.exit(main())