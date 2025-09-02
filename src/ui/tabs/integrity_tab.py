"""
File Integrity Monitoring Tab
Interface for managing file integrity baselines and monitoring.
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                             QTableWidgetItem, QPushButton, QLabel, QComboBox,
                             QMessageBox, QHeaderView, QTextEdit, QGroupBox,
                             QListWidget, QProgressBar, QCheckBox, QLineEdit,
                             QFileDialog, QSplitter)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QFont

import sys
import os
import json
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from detection.file_integrity_monitor import FileIntegrityMonitor
from datetime import datetime


class BaselineCreationThread(QThread):
    """Background thread for creating file baselines."""
    
    progress_updated = pyqtSignal(int)
    baseline_completed = pyqtSignal(bool)
    status_updated = pyqtSignal(str)
    
    def __init__(self, fim, paths):
        super().__init__()
        self.fim = fim
        self.paths = paths
    
    def run(self):
        """Create baselines for specified paths."""
        try:
            self.status_updated.emit("Creating file baselines...")
            self.progress_updated.emit(25)
            
            success = self.fim.create_baseline(self.paths)
            
            self.progress_updated.emit(100)
            self.baseline_completed.emit(success)
            
        except Exception as e:
            self.status_updated.emit(f"Error: {str(e)}")
            self.baseline_completed.emit(False)


class IntegrityScanThread(QThread):
    """Background thread for integrity scanning."""
    
    progress_updated = pyqtSignal(int)
    scan_completed = pyqtSignal(dict)
    alert_found = pyqtSignal(dict)
    
    def __init__(self, fim):
        super().__init__()
        self.fim = fim
    
    def run(self):
        """Run integrity scan."""
        try:
            results = self.fim.bulk_integrity_check()
            
            for alert in results.get('alerts', []):
                self.alert_found.emit(alert)
            
            self.scan_completed.emit(results)
            
        except Exception as e:
            self.scan_completed.emit({'error': str(e)})


class IntegrityTab(QWidget):
    """File integrity monitoring tab widget."""
    
    def __init__(self):
        super().__init__()
        self.fim = FileIntegrityMonitor()
        self.init_ui()
        self.baseline_thread = None
        self.scan_thread = None
        
        # Setup real-time update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_summary)
        self.update_timer.start(30000)  # Update every 30 seconds
        
        # Setup FIM alert callback
        self.fim.add_alert_callback(self.handle_integrity_alert)
        
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Create splitter for main layout
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Controls and monitoring
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        # Baseline management group
        baseline_group = QGroupBox("Baseline Management")
        baseline_layout = QVBoxLayout(baseline_group)
        
        # Path selection
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("Monitor Paths:"))
        self.path_list = QListWidget()
        self.path_list.setMaximumHeight(100)
        
        # Add default critical paths
        default_paths = ['/etc/passwd', '/etc/shadow', '/etc/sudoers', '/boot', '/usr/bin']
        for path in default_paths:
            self.path_list.addItem(path)
        
        baseline_layout.addWidget(self.path_list)
        
        # Path management buttons
        path_btn_layout = QHBoxLayout()
        
        self.add_path_btn = QPushButton("Add Path")
        self.add_path_btn.clicked.connect(self.add_monitoring_path)
        path_btn_layout.addWidget(self.add_path_btn)
        
        self.remove_path_btn = QPushButton("Remove Path")
        self.remove_path_btn.clicked.connect(self.remove_monitoring_path)
        path_btn_layout.addWidget(self.remove_path_btn)
        
        baseline_layout.addLayout(path_btn_layout)
        
        # Baseline creation
        baseline_btn_layout = QHBoxLayout()
        
        self.create_baseline_btn = QPushButton("Create Baseline")
        self.create_baseline_btn.clicked.connect(self.create_baseline)
        baseline_btn_layout.addWidget(self.create_baseline_btn)
        
        self.baseline_progress = QProgressBar()
        self.baseline_progress.setVisible(False)
        baseline_btn_layout.addWidget(self.baseline_progress)
        
        baseline_layout.addLayout(baseline_btn_layout)
        left_layout.addWidget(baseline_group)
        
        # Monitoring controls group
        monitoring_group = QGroupBox("Real-time Monitoring")
        monitoring_layout = QVBoxLayout(monitoring_group)
        
        monitor_btn_layout = QHBoxLayout()
        
        self.start_monitor_btn = QPushButton("Start Monitoring")
        self.start_monitor_btn.clicked.connect(self.start_monitoring)
        monitor_btn_layout.addWidget(self.start_monitor_btn)
        
        self.stop_monitor_btn = QPushButton("Stop Monitoring")
        self.stop_monitor_btn.clicked.connect(self.stop_monitoring)
        self.stop_monitor_btn.setEnabled(False)
        monitor_btn_layout.addWidget(self.stop_monitor_btn)
        
        monitoring_layout.addLayout(monitor_btn_layout)
        
        # Monitoring status
        self.monitoring_status = QLabel("Monitoring Status: Stopped")
        monitoring_layout.addWidget(self.monitoring_status)
        
        left_layout.addWidget(monitoring_group)
        
        # Scan controls group
        scan_group = QGroupBox("Integrity Scanning")
        scan_layout = QVBoxLayout(scan_group)
        
        scan_btn_layout = QHBoxLayout()
        
        self.scan_btn = QPushButton("Run Integrity Scan")
        self.scan_btn.clicked.connect(self.run_integrity_scan)
        scan_btn_layout.addWidget(self.scan_btn)
        
        self.export_btn = QPushButton("Export Report")
        self.export_btn.clicked.connect(self.export_report)
        scan_btn_layout.addWidget(self.export_btn)
        
        scan_layout.addLayout(scan_btn_layout)
        left_layout.addWidget(scan_group)
        
        # Summary display
        summary_group = QGroupBox("Monitoring Summary")
        summary_layout = QVBoxLayout(summary_group)
        
        self.summary_text = QTextEdit()
        self.summary_text.setMaximumHeight(150)
        self.summary_text.setFont(QFont("Consolas", 9))
        self.summary_text.setReadOnly(True)
        summary_layout.addWidget(self.summary_text)
        
        left_layout.addWidget(summary_group)
        left_layout.addStretch()
        
        # Right panel - Alerts table
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "Critical", "High", "Medium", "Low"])
        self.severity_filter.currentTextChanged.connect(self.filter_alerts)
        filter_layout.addWidget(self.severity_filter)
        
        self.alert_type_filter = QComboBox()
        self.alert_type_filter.addItems(["All Types", "Content Changed", "Permissions Changed", 
                                        "Ownership Changed", "File Deleted", "Size Changed"])
        self.alert_type_filter.currentTextChanged.connect(self.filter_alerts)
        filter_layout.addWidget(self.alert_type_filter)
        
        filter_layout.addStretch()
        right_layout.addLayout(filter_layout)
        
        # Alerts table
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(6)
        self.alerts_table.setHorizontalHeaderLabels([
            "Timestamp", "File Path", "Alert Type", "Severity", "Description", "Details"
        ])
        
        # Configure table
        header = self.alerts_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        
        self.alerts_table.setAlternatingRowColors(True)
        self.alerts_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.alerts_table.itemDoubleClicked.connect(self.view_alert_details)
        
        right_layout.addWidget(self.alerts_table)
        
        # Add widgets to splitter
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([300, 700])  # 30% left, 70% right
        
        layout.addWidget(splitter)
        
        # Status label
        self.status_label = QLabel("Ready for file integrity monitoring")
        layout.addWidget(self.status_label)
        
        # Load initial data
        self.update_summary()
        self.load_recent_alerts()
    
    def add_monitoring_path(self):
        """Add path to monitoring list."""
        path = QFileDialog.getExistingDirectory(self, "Select Directory to Monitor")
        if path:
            self.path_list.addItem(path)
            self.fim.add_path_to_monitor(path)
    
    def remove_monitoring_path(self):
        """Remove selected path from monitoring."""
        current_item = self.path_list.currentItem()
        if current_item:
            path = current_item.text()
            self.fim.remove_path_from_monitor(path)
            self.path_list.takeItem(self.path_list.row(current_item))
    
    def create_baseline(self):
        """Create integrity baseline for selected paths."""
        if self.baseline_thread and self.baseline_thread.isRunning():
            return
        
        # Get paths from list
        paths = []
        for i in range(self.path_list.count()):
            paths.append(self.path_list.item(i).text())
        
        if not paths:
            QMessageBox.warning(self, "No Paths", "Please add paths to monitor first.")
            return
        
        self.create_baseline_btn.setEnabled(False)
        self.baseline_progress.setVisible(True)
        self.baseline_progress.setValue(0)
        
        self.baseline_thread = BaselineCreationThread(self.fim, paths)
        self.baseline_thread.progress_updated.connect(self.baseline_progress.setValue)
        self.baseline_thread.status_updated.connect(self.status_label.setText)
        self.baseline_thread.baseline_completed.connect(self.baseline_created)
        self.baseline_thread.start()
    
    def baseline_created(self, success):
        """Handle baseline creation completion."""
        self.create_baseline_btn.setEnabled(True)
        self.baseline_progress.setVisible(False)
        
        if success:
            self.status_label.setText("Baseline created successfully")
            self.update_summary()
            QMessageBox.information(self, "Baseline Created", 
                                  "File integrity baseline has been created successfully.")
        else:
            self.status_label.setText("Baseline creation failed")
            QMessageBox.critical(self, "Baseline Creation Failed", 
                               "Failed to create file integrity baseline.")
    
    def start_monitoring(self):
        """Start real-time file monitoring."""
        try:
            self.fim.start_realtime_monitoring()
            self.start_monitor_btn.setEnabled(False)
            self.stop_monitor_btn.setEnabled(True)
            self.monitoring_status.setText("Monitoring Status: Active")
            self.status_label.setText("Real-time file monitoring started")
            
        except Exception as e:
            QMessageBox.critical(self, "Monitoring Error", f"Failed to start monitoring: {str(e)}")
    
    def stop_monitoring(self):
        """Stop real-time file monitoring."""
        try:
            self.fim.stop_realtime_monitoring()
            self.start_monitor_btn.setEnabled(True)
            self.stop_monitor_btn.setEnabled(False)
            self.monitoring_status.setText("Monitoring Status: Stopped")
            self.status_label.setText("Real-time file monitoring stopped")
            
        except Exception as e:
            QMessageBox.critical(self, "Monitoring Error", f"Failed to stop monitoring: {str(e)}")
    
    def run_integrity_scan(self):
        """Run manual integrity scan."""
        if self.scan_thread and self.scan_thread.isRunning():
            return
        
        self.scan_btn.setEnabled(False)
        self.alerts_table.setRowCount(0)
        self.status_label.setText("Running integrity scan...")
        
        self.scan_thread = IntegrityScanThread(self.fim)
        self.scan_thread.alert_found.connect(self.add_alert_row)
        self.scan_thread.scan_completed.connect(self.scan_completed)
        self.scan_thread.start()
    
    def scan_completed(self, results):
        """Handle integrity scan completion."""
        self.scan_btn.setEnabled(True)
        
        if 'error' in results:
            self.status_label.setText(f"Scan failed: {results['error']}")
            QMessageBox.critical(self, "Scan Error", results['error'])
        else:
            files_checked = results.get('files_checked', 0)
            alerts_count = results.get('alerts_generated', 0)
            self.status_label.setText(f"Scan completed: {files_checked} files checked, {alerts_count} alerts")
            
            if alerts_count > 0:
                # Find main window to show notification
                main_window = self.parent()
                while main_window and not hasattr(main_window, 'show_notification'):
                    main_window = main_window.parent()
                
                if main_window:
                    main_window.show_notification(
                        "File Integrity Violations",
                        f"Found {alerts_count} file integrity violations"
                    )
        
        self.update_summary()
    
    def add_alert_row(self, alert_data):
        """Add alert to the table."""
        row = self.alerts_table.rowCount()
        self.alerts_table.insertRow(row)
        
        # Timestamp
        timestamp = datetime.fromtimestamp(alert_data['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        self.alerts_table.setItem(row, 0, QTableWidgetItem(timestamp))
        
        # File path
        file_path = alert_data['file_path']
        path_item = QTableWidgetItem(os.path.basename(file_path))
        path_item.setToolTip(file_path)  # Full path in tooltip
        self.alerts_table.setItem(row, 1, path_item)
        
        # Alert type
        alert_type = alert_data['alert_type'].replace('_', ' ').title()
        self.alerts_table.setItem(row, 2, QTableWidgetItem(alert_type))
        
        # Severity
        severity = alert_data['severity'].title()
        severity_item = QTableWidgetItem(severity)
        
        # Color code by severity
        if severity == 'Critical':
            severity_item.setBackground(QColor(255, 0, 0, 100))
        elif severity == 'High':
            severity_item.setBackground(QColor(255, 100, 0, 100))
        elif severity == 'Medium':
            severity_item.setBackground(QColor(255, 255, 0, 100))
        
        self.alerts_table.setItem(row, 3, severity_item)
        
        # Description
        self.alerts_table.setItem(row, 4, QTableWidgetItem(alert_data['description']))
        
        # Details button
        details_text = f"{alert_data['old_value']} → {alert_data['new_value']}"
        self.alerts_table.setItem(row, 5, QTableWidgetItem(details_text))
    
    def handle_integrity_alert(self, alert_data):
        """Handle real-time integrity alerts."""
        self.add_alert_row(alert_data)
        
        # Update summary
        self.update_summary()
    
    def load_recent_alerts(self):
        """Load recent alerts from database."""
        try:
            alerts = self.fim.get_recent_alerts(24)  # Last 24 hours
            
            self.alerts_table.setRowCount(0)
            for alert in alerts:
                self.add_alert_row(alert)
                
        except Exception as e:
            self.status_label.setText(f"Error loading alerts: {str(e)}")
    
    def update_summary(self):
        """Update monitoring summary display."""
        try:
            summary = self.fim.get_integrity_summary()
            
            summary_text = f"""File Integrity Monitoring Summary
=====================================

Total Baselines: {summary['total_baselines']}
Recent Alerts (24h): {summary['recent_alerts']}
Monitoring Status: {summary['monitoring_status'].title()}

Alert Breakdown:
  Critical: {summary['severity_breakdown']['critical']}
  High:     {summary['severity_breakdown']['high']}
  Medium:   {summary['severity_breakdown']['medium']}
  Low:      {summary['severity_breakdown']['low']}

Most Changed Files:"""
            
            for file_info in summary.get('most_changed_files', [])[:5]:
                summary_text += f"\n  {os.path.basename(file_info['path'])}: {file_info['changes']} changes"
            
            self.summary_text.setPlainText(summary_text)
            
        except Exception as e:
            self.summary_text.setPlainText(f"Error updating summary: {str(e)}")
    
    def filter_alerts(self):
        """Filter alerts based on current filter settings."""
        severity_filter = self.severity_filter.currentText()
        type_filter = self.alert_type_filter.currentText()
        
        for row in range(self.alerts_table.rowCount()):
            severity_item = self.alerts_table.item(row, 3)
            type_item = self.alerts_table.item(row, 2)
            
            if not all([severity_item, type_item]):
                continue
            
            severity = severity_item.text()
            alert_type = type_item.text()
            
            show_row = True
            
            if severity_filter != "All Severities" and severity != severity_filter:
                show_row = False
            
            if type_filter != "All Types" and alert_type != type_filter:
                show_row = False
            
            self.alerts_table.setRowHidden(row, not show_row)
    
    def view_alert_details(self, item):
        """View detailed information about an alert."""
        row = item.row()
        
        timestamp = self.alerts_table.item(row, 0).text()
        file_path = self.alerts_table.item(row, 1).toolTip() or self.alerts_table.item(row, 1).text()
        alert_type = self.alerts_table.item(row, 2).text()
        severity = self.alerts_table.item(row, 3).text()
        description = self.alerts_table.item(row, 4).text()
        details = self.alerts_table.item(row, 5).text()
        
        details_text = f"""File Integrity Alert Details
=============================

Timestamp: {timestamp}
File Path: {file_path}
Alert Type: {alert_type}
Severity: {severity}

Description: {description}

Change Details: {details}

Recommendations:
- Verify if the change was authorized
- Check system logs for related activities
- Investigate processes that accessed the file
- Consider restoring from backup if unauthorized
"""
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Alert Details")
        msg_box.setText(details_text)
        msg_box.exec()
    
    def export_report(self):
        """Export integrity monitoring report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"integrity_report_{timestamp}.json"
        
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Export Integrity Report", default_filename, 
            "JSON Files (*.json);;All Files (*)"
        )
        
        if output_path:
            try:
                self.fim.export_integrity_report(output_path, include_baselines=True)
                QMessageBox.information(self, "Export Successful", 
                                      f"Report exported to: {output_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", 
                                   f"Failed to export report: {str(e)}")
    
    def start_monitoring(self):
        """Start real-time monitoring."""
        try:
            self.fim.start_realtime_monitoring()
            self.start_monitor_btn.setEnabled(False)
            self.stop_monitor_btn.setEnabled(True)
            self.monitoring_status.setText("Monitoring Status: Active")
            self.status_label.setText("Real-time file monitoring started")
        except Exception as e:
            QMessageBox.critical(self, "Monitoring Error", f"Failed to start monitoring: {str(e)}")
        
    def stop_monitoring(self):
        """Stop real-time monitoring."""
        try:
            self.fim.stop_realtime_monitoring()
            self.start_monitor_btn.setEnabled(True)
            self.stop_monitor_btn.setEnabled(False)
            self.monitoring_status.setText("Monitoring Status: Stopped")
            self.status_label.setText("Real-time file monitoring stopped")
        except Exception as e:
            QMessageBox.critical(self, "Monitoring Error", f"Failed to stop monitoring: {str(e)}")
        
    def export_results(self):
        """Export current results."""
        self.export_report()