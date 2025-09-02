"""
Settings Dialog
Application configuration and preferences.
"""

from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTabWidget,
                             QWidget, QPushButton, QLabel, QSpinBox, QCheckBox,
                             QLineEdit, QGroupBox, QSlider, QComboBox, QTextEdit)
from PyQt6.QtCore import Qt
import json
import os


class SettingsDialog(QDialog):
    """Settings and configuration dialog."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setModal(True)
        self.setFixedSize(600, 500)
        self.init_ui()
        self.load_settings()
        
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Create tab widget
        tab_widget = QTabWidget()
        
        # General settings tab
        general_tab = self.create_general_tab()
        tab_widget.addTab(general_tab, "General")
        
        # Monitoring settings tab
        monitoring_tab = self.create_monitoring_tab()
        tab_widget.addTab(monitoring_tab, "Monitoring")
        
        # Detection settings tab
        detection_tab = self.create_detection_tab()
        tab_widget.addTab(detection_tab, "Detection")
        
        layout.addWidget(tab_widget)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.save_btn = QPushButton("Save")
        self.save_btn.clicked.connect(self.save_settings)
        button_layout.addWidget(self.save_btn)
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_btn)
        
        self.defaults_btn = QPushButton("Reset to Defaults")
        self.defaults_btn.clicked.connect(self.reset_defaults)
        button_layout.addWidget(self.defaults_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
    def create_general_tab(self) -> QWidget:
        """Create general settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Scan intervals
        interval_group = QGroupBox("Scan Intervals")
        interval_layout = QVBoxLayout(interval_group)
        
        # Process scan interval
        proc_layout = QHBoxLayout()
        proc_layout.addWidget(QLabel("Process Scan Interval (seconds):"))
        self.process_interval = QSpinBox()
        self.process_interval.setRange(1, 3600)
        self.process_interval.setValue(30)
        proc_layout.addWidget(self.process_interval)
        proc_layout.addStretch()
        interval_layout.addLayout(proc_layout)
        
        # Service scan interval
        svc_layout = QHBoxLayout()
        svc_layout.addWidget(QLabel("Service Scan Interval (seconds):"))
        self.service_interval = QSpinBox()
        self.service_interval.setRange(1, 3600)
        self.service_interval.setValue(60)
        svc_layout.addWidget(self.service_interval)
        svc_layout.addStretch()
        interval_layout.addLayout(svc_layout)
        
        # Network scan interval
        net_layout = QHBoxLayout()
        net_layout.addWidget(QLabel("Network Scan Interval (seconds):"))
        self.network_interval = QSpinBox()
        self.network_interval.setRange(1, 3600)
        self.network_interval.setValue(15)
        net_layout.addWidget(self.network_interval)
        net_layout.addStretch()
        interval_layout.addLayout(net_layout)
        
        layout.addWidget(interval_group)
        
        # Notification settings
        notif_group = QGroupBox("Notifications")
        notif_layout = QVBoxLayout(notif_group)
        
        self.enable_notifications = QCheckBox("Enable system tray notifications")
        self.enable_notifications.setChecked(True)
        notif_layout.addWidget(self.enable_notifications)
        
        self.notify_hidden_processes = QCheckBox("Notify on hidden processes")
        self.notify_hidden_processes.setChecked(True)
        notif_layout.addWidget(self.notify_hidden_processes)
        
        self.notify_suspicious_connections = QCheckBox("Notify on suspicious network connections")
        self.notify_suspicious_connections.setChecked(True)
        notif_layout.addWidget(self.notify_suspicious_connections)
        
        layout.addWidget(notif_group)
        
        layout.addStretch()
        return tab
    
    def create_monitoring_tab(self) -> QWidget:
        """Create monitoring settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Real-time monitoring
        realtime_group = QGroupBox("Real-time Monitoring")
        realtime_layout = QVBoxLayout(realtime_group)
        
        self.enable_realtime = QCheckBox("Enable real-time monitoring")
        self.enable_realtime.setChecked(False)
        realtime_layout.addWidget(self.enable_realtime)
        
        self.monitor_processes = QCheckBox("Monitor process creation/termination")
        self.monitor_processes.setChecked(True)
        realtime_layout.addWidget(self.monitor_processes)
        
        self.monitor_services = QCheckBox("Monitor service changes")
        self.monitor_services.setChecked(True)
        realtime_layout.addWidget(self.monitor_services)
        
        self.monitor_network = QCheckBox("Monitor network connections")
        self.monitor_network.setChecked(True)
        realtime_layout.addWidget(self.monitor_network)
        
        layout.addWidget(realtime_group)
        
        # Logging settings
        logging_group = QGroupBox("Logging")
        logging_layout = QVBoxLayout(logging_group)
        
        log_level_layout = QHBoxLayout()
        log_level_layout.addWidget(QLabel("Log Level:"))
        self.log_level = QComboBox()
        self.log_level.addItems(["ERROR", "WARNING", "INFO", "DEBUG"])
        self.log_level.setCurrentText("INFO")
        log_level_layout.addWidget(self.log_level)
        log_level_layout.addStretch()
        logging_layout.addLayout(log_level_layout)
        
        self.enable_file_logging = QCheckBox("Enable file logging")
        self.enable_file_logging.setChecked(True)
        logging_layout.addWidget(self.enable_file_logging)
        
        layout.addWidget(logging_group)
        
        layout.addStretch()
        return tab
    
    def create_detection_tab(self) -> QWidget:
        """Create detection settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Detection sensitivity
        sensitivity_group = QGroupBox("Detection Sensitivity")
        sensitivity_layout = QVBoxLayout(sensitivity_group)
        
        sens_layout = QHBoxLayout()
        sens_layout.addWidget(QLabel("Sensitivity Level:"))
        self.sensitivity_slider = QSlider(Qt.Orientation.Horizontal)
        self.sensitivity_slider.setRange(1, 5)
        self.sensitivity_slider.setValue(3)
        self.sensitivity_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.sensitivity_slider.setTickInterval(1)
        sens_layout.addWidget(self.sensitivity_slider)
        
        self.sensitivity_label = QLabel("Normal")
        sens_layout.addWidget(self.sensitivity_label)
        sensitivity_layout.addLayout(sens_layout)
        
        # Update sensitivity label
        self.sensitivity_slider.valueChanged.connect(self.update_sensitivity_label)
        
        layout.addWidget(sensitivity_group)
        
        # Whitelist settings
        whitelist_group = QGroupBox("Process Whitelist")
        whitelist_layout = QVBoxLayout(whitelist_group)
        
        whitelist_layout.addWidget(QLabel("Whitelisted processes (one per line):"))
        self.whitelist_text = QTextEdit()
        self.whitelist_text.setMaximumHeight(100)
        self.whitelist_text.setPlainText("explorer.exe\nwinlogon.exe\nservices.exe\nsvchost.exe")
        whitelist_layout.addWidget(self.whitelist_text)
        
        layout.addWidget(whitelist_group)
        
        # Scan depth
        depth_group = QGroupBox("Scan Depth")
        depth_layout = QVBoxLayout(depth_group)
        
        self.quick_scan = QCheckBox("Quick scan (basic enumeration)")
        depth_layout.addWidget(self.quick_scan)
        
        self.deep_scan = QCheckBox("Deep scan (comprehensive analysis)")
        self.deep_scan.setChecked(True)
        depth_layout.addWidget(self.deep_scan)
        
        self.kernel_scan = QCheckBox("Kernel-level analysis (requires debug privileges)")
        depth_layout.addWidget(self.kernel_scan)
        
        layout.addWidget(depth_group)
        
        layout.addStretch()
        return tab
    
    def update_sensitivity_label(self, value):
        """Update sensitivity level label."""
        labels = {1: "Very Low", 2: "Low", 3: "Normal", 4: "High", 5: "Very High"}
        self.sensitivity_label.setText(labels.get(value, "Normal"))
    
    def load_settings(self):
        """Load settings from configuration file."""
        settings_file = "config/settings.json"
        
        if os.path.exists(settings_file):
            try:
                with open(settings_file, 'r') as f:
                    settings = json.load(f)
                    
                # Apply loaded settings
                self.process_interval.setValue(settings.get('process_interval', 30))
                self.service_interval.setValue(settings.get('service_interval', 60))
                self.network_interval.setValue(settings.get('network_interval', 15))
                self.enable_notifications.setChecked(settings.get('enable_notifications', True))
                self.sensitivity_slider.setValue(settings.get('sensitivity', 3))
                
                whitelist = settings.get('whitelist', [])
                self.whitelist_text.setPlainText('\n'.join(whitelist))
                
            except Exception as e:
                print(f"Error loading settings: {e}")
    
    def save_settings(self):
        """Save settings to configuration file."""
        settings = {
            'process_interval': self.process_interval.value(),
            'service_interval': self.service_interval.value(),
            'network_interval': self.network_interval.value(),
            'enable_notifications': self.enable_notifications.isChecked(),
            'notify_hidden_processes': self.notify_hidden_processes.isChecked(),
            'notify_suspicious_connections': self.notify_suspicious_connections.isChecked(),
            'enable_realtime': self.enable_realtime.isChecked(),
            'monitor_processes': self.monitor_processes.isChecked(),
            'monitor_services': self.monitor_services.isChecked(),
            'monitor_network': self.monitor_network.isChecked(),
            'log_level': self.log_level.currentText(),
            'enable_file_logging': self.enable_file_logging.isChecked(),
            'sensitivity': self.sensitivity_slider.value(),
            'whitelist': [line.strip() for line in self.whitelist_text.toPlainText().split('\n') if line.strip()],
            'quick_scan': self.quick_scan.isChecked(),
            'deep_scan': self.deep_scan.isChecked(),
            'kernel_scan': self.kernel_scan.isChecked()
        }
        
        # Create config directory if it doesn't exist
        os.makedirs("config", exist_ok=True)
        
        try:
            with open("config/settings.json", 'w') as f:
                json.dump(settings, f, indent=4)
            
            self.accept()
            
        except Exception as e:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.critical(self, "Error", f"Failed to save settings: {str(e)}")
    
    def reset_defaults(self):
        """Reset all settings to default values."""
        self.process_interval.setValue(30)
        self.service_interval.setValue(60)
        self.network_interval.setValue(15)
        self.enable_notifications.setChecked(True)
        self.notify_hidden_processes.setChecked(True)
        self.notify_suspicious_connections.setChecked(True)
        self.enable_realtime.setChecked(False)
        self.monitor_processes.setChecked(True)
        self.monitor_services.setChecked(True)
        self.monitor_network.setChecked(True)
        self.log_level.setCurrentText("INFO")
        self.enable_file_logging.setChecked(True)
        self.sensitivity_slider.setValue(3)
        self.whitelist_text.setPlainText("explorer.exe\nwinlogon.exe\nservices.exe\nsvchost.exe")
        self.quick_scan.setChecked(False)
        self.deep_scan.setChecked(True)
        self.kernel_scan.setChecked(False)