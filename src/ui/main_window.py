"""
Main Window for Rootkit Detection Application
"""

from PyQt6.QtWidgets import (QMainWindow, QTabWidget, QVBoxLayout, QHBoxLayout, 
                             QWidget, QMenuBar, QStatusBar, QSystemTrayIcon, 
                             QMenu, QMessageBox, QProgressBar, QLabel, QApplication)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QAction, QIcon

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from ui.tabs.process_tab import ProcessTab
from ui.tabs.service_tab import ServiceTab
from ui.tabs.network_tab import NetworkTab
from ui.tabs.hooks_tab import HooksTab
from ui.tabs.integrity_tab import IntegrityTab
from ui.tabs.signatures_tab import SignaturesTab
from ui.tabs.kernel_tab import KernelTab
from ui.tabs.yara_tab import YaraTab
from ui.tabs.ml_tab import MLTab
from ui.tabs.timeline_tab import TimelineTab
from ui.tabs.intelligence_tab import IntelligenceTab
from ui.tabs.reports_tab import ReportsTab
from ui.styles import DARK_THEME


class MainWindow(QMainWindow):
    """Main application window with tabbed interface."""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.setup_status_timer()
        
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Rootkit Detection Tool v1.0")
        self.setGeometry(100, 100, 1400, 900)
        self.setMinimumSize(1200, 700)
        
        # Apply dark theme
        self.setStyleSheet(DARK_THEME)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.process_tab = ProcessTab()
        self.service_tab = ServiceTab()
        self.network_tab = NetworkTab()
        self.hooks_tab = HooksTab()
        self.integrity_tab = IntegrityTab()
        self.signatures_tab = SignaturesTab()
        self.kernel_tab = KernelTab()
        self.yara_tab = YaraTab()
        self.ml_tab = MLTab()
        self.timeline_tab = TimelineTab()
        self.intelligence_tab = IntelligenceTab()
        self.reports_tab = ReportsTab()
        
        # Add tabs to widget
        self.tab_widget.addTab(self.process_tab, "Process Analysis")
        self.tab_widget.addTab(self.service_tab, "Service Analysis")
        self.tab_widget.addTab(self.network_tab, "Network Analysis")
        self.tab_widget.addTab(self.hooks_tab, "System Hooks")
        self.tab_widget.addTab(self.integrity_tab, "File Integrity")
        self.tab_widget.addTab(self.signatures_tab, "Signatures")
        self.tab_widget.addTab(self.kernel_tab, "Kernel Integrity")
        self.tab_widget.addTab(self.yara_tab, "YARA Scanner")
        self.tab_widget.addTab(self.ml_tab, "ML Anomaly Detection")
        self.tab_widget.addTab(self.timeline_tab, "Timeline Analysis")
        self.tab_widget.addTab(self.intelligence_tab, "Threat Intelligence")
        self.tab_widget.addTab(self.reports_tab, "Reports")
        
        # Create status bar
        self.create_status_bar()
        
    def create_menu_bar(self):
        """Create the application menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        new_scan_action = QAction("New Scan", self)
        new_scan_action.setShortcut("Ctrl+N")
        new_scan_action.triggered.connect(self.new_scan)
        file_menu.addAction(new_scan_action)
        
        file_menu.addSeparator()
        
        export_action = QAction("Export Results...", self)
        export_action.setShortcut("Ctrl+E")
        export_action.triggered.connect(self.export_results)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        settings_action = QAction("Settings...", self)
        settings_action.triggered.connect(self.show_settings)
        tools_menu.addAction(settings_action)
        
        tools_menu.addSeparator()
        
        realtime_action = QAction("Enable Real-time Monitoring", self)
        realtime_action.setCheckable(True)
        realtime_action.triggered.connect(self.toggle_realtime_monitoring)
        tools_menu.addAction(realtime_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def create_status_bar(self):
        """Create the status bar with system information."""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Status label
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label)
        
        # Progress bar for operations
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
        # System info label
        self.system_info_label = QLabel("Windows System")
        self.status_bar.addPermanentWidget(self.system_info_label)
        
    def setup_system_tray(self):
        """Setup system tray icon for notifications."""
        self.tray_icon = QSystemTrayIcon(self)
        
        # Create tray menu
        tray_menu = QMenu()
        
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)
        
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(QApplication.instance().quit)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        
    def setup_status_timer(self):
        """Setup timer for updating status information."""
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(5000)  # Update every 5 seconds
        
    def update_status(self):
        """Update status bar information."""
        try:
            import psutil
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            self.system_info_label.setText(f"CPU: {cpu_percent}% | RAM: {memory.percent}%")
        except ImportError:
            self.system_info_label.setText("System monitoring unavailable")
    
    def new_scan(self):
        """Start a new comprehensive scan."""
        self.status_label.setText("Starting comprehensive scan...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Trigger scans in all tabs
        current_tab = self.tab_widget.currentWidget()
        if hasattr(current_tab, 'start_scan'):
            current_tab.start_scan()
    
    def export_results(self):
        """Export scan results to file."""
        current_tab = self.tab_widget.currentWidget()
        if hasattr(current_tab, 'export_results'):
            current_tab.export_results()
    
    def show_settings(self):
        """Show application settings dialog."""
        from .dialogs.settings_dialog import SettingsDialog
        dialog = SettingsDialog(self)
        dialog.exec()
    
    def toggle_realtime_monitoring(self, enabled):
        """Toggle real-time monitoring on/off."""
        if enabled:
            self.status_label.setText("Real-time monitoring enabled")
            # Start monitoring in all tabs
            for i in range(self.tab_widget.count()):
                tab = self.tab_widget.widget(i)
                if hasattr(tab, 'start_monitoring'):
                    tab.start_monitoring()
        else:
            self.status_label.setText("Real-time monitoring disabled")
            # Stop monitoring in all tabs
            for i in range(self.tab_widget.count()):
                tab = self.tab_widget.widget(i)
                if hasattr(tab, 'stop_monitoring'):
                    tab.stop_monitoring()
    
    def show_about(self):
        """Show about dialog."""
        QMessageBox.about(self, "About Rootkit Detection Tool",
                         "Rootkit Detection Tool v1.0\n\n"
                         "A comprehensive security tool for detecting hidden processes,\n"
                         "services, and network connections that may indicate rootkit presence.\n\n"
                         "Developed for defensive security analysis.")
    
    def show_notification(self, title, message):
        """Show notification via status bar."""
        self.status_label.setText(f"{title}: {message}")
        # Also show as a message box for important alerts
        if "Critical" in title or "Suspicious" in title:
            QMessageBox.warning(self, title, message)
    
    def set_status(self, message):
        """Update status bar message."""
        self.status_label.setText(message)
    
    def set_progress(self, value):
        """Update progress bar value."""
        self.progress_bar.setValue(value)
        if value >= 100:
            self.progress_bar.setVisible(False)
        else:
            self.progress_bar.setVisible(True)