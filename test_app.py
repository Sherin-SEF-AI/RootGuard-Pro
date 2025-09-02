#!/usr/bin/env python3
"""
Test version of the rootkit detection app (bypasses root check for testing)
"""

import sys
import os
sys.path.append('src')

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt
from ui.main_window import MainWindow

def main():
    """Main application entry point."""
    app = QApplication(sys.argv)
    app.setApplicationName("Linux Rootkit Detection Tool (Test Mode)")
    app.setApplicationVersion("1.0.0")
    
    print("Starting Rootkit Detection Tool in test mode...")
    print("Note: Some features may require root privileges for full functionality")
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    return app.exec()

if __name__ == "__main__":
    sys.exit(main())