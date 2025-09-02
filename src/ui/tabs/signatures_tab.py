"""
Signature Database Management Tab
Interface for managing rootkit signatures and IOCs.
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                             QTableWidgetItem, QPushButton, QLabel, QComboBox,
                             QMessageBox, QHeaderView, QTextEdit, QGroupBox,
                             QLineEdit, QFileDialog, QSplitter, QProgressBar)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont

import sys
import os
import json
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from detection.signature_database import SignatureDatabase
from datetime import datetime


class SignatureScanThread(QThread):
    """Background thread for signature scanning."""
    
    progress_updated = pyqtSignal(int)
    detection_found = pyqtSignal(dict)
    scan_completed = pyqtSignal(dict)
    
    def __init__(self, sig_db, scan_paths):
        super().__init__()
        self.sig_db = sig_db
        self.scan_paths = scan_paths
    
    def run(self):
        """Run signature scan."""
        try:
            results = self.sig_db.bulk_scan_filesystem(self.scan_paths)
            
            for detection in results.get('detections', []):
                self.detection_found.emit(detection)
            
            self.scan_completed.emit(results)
            
        except Exception as e:
            self.scan_completed.emit({'error': str(e)})


class SignaturesTab(QWidget):
    """Signature database management tab widget."""
    
    def __init__(self):
        super().__init__()
        self.sig_db = SignatureDatabase()
        self.init_ui()
        self.scan_thread = None
        
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Create splitter for main layout
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Database management
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        # Database stats group
        stats_group = QGroupBox("Database Statistics")
        stats_layout = QVBoxLayout(stats_group)
        
        self.stats_text = QTextEdit()
        self.stats_text.setMaximumHeight(150)
        self.stats_text.setFont(QFont("Consolas", 9))
        self.stats_text.setReadOnly(True)
        stats_layout.addWidget(self.stats_text)
        
        # Refresh stats button
        refresh_stats_btn = QPushButton("Refresh Statistics")
        refresh_stats_btn.clicked.connect(self.update_statistics)
        stats_layout.addWidget(refresh_stats_btn)
        
        left_layout.addWidget(stats_group)
        
        # Signature management group
        mgmt_group = QGroupBox("Signature Management")
        mgmt_layout = QVBoxLayout(mgmt_group)
        
        # Import/Export buttons
        import_export_layout = QHBoxLayout()
        
        import_btn = QPushButton("Import Signatures")
        import_btn.clicked.connect(self.import_signatures)
        import_export_layout.addWidget(import_btn)
        
        export_btn = QPushButton("Export Signatures")
        export_btn.clicked.connect(self.export_signatures)
        import_export_layout.addWidget(export_btn)
        
        mgmt_layout.addLayout(import_export_layout)
        
        # Update signatures
        update_btn = QPushButton("Update from Feeds")
        update_btn.clicked.connect(self.update_signatures)
        mgmt_layout.addWidget(update_btn)
        
        left_layout.addWidget(mgmt_group)
        
        # Scanning group
        scan_group = QGroupBox("Signature Scanning")
        scan_layout = QVBoxLayout(scan_group)
        
        # Scan path input
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("Scan Path:"))
        
        self.scan_path_input = QLineEdit()
        self.scan_path_input.setText("/usr/bin,/usr/sbin,/bin,/sbin")
        path_layout.addWidget(self.scan_path_input)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_scan_path)
        path_layout.addWidget(browse_btn)
        
        scan_layout.addLayout(path_layout)
        
        # Scan controls
        scan_btn_layout = QHBoxLayout()
        
        self.scan_btn = QPushButton("Start Signature Scan")
        self.scan_btn.clicked.connect(self.start_signature_scan)
        scan_btn_layout.addWidget(self.scan_btn)
        
        self.comprehensive_scan_btn = QPushButton("Comprehensive Scan")
        self.comprehensive_scan_btn.clicked.connect(self.run_comprehensive_scan)
        scan_btn_layout.addWidget(self.comprehensive_scan_btn)
        
        scan_layout.addLayout(scan_btn_layout)
        
        # Progress bar
        self.scan_progress = QProgressBar()
        self.scan_progress.setVisible(False)
        scan_layout.addWidget(self.scan_progress)
        
        left_layout.addWidget(scan_group)
        
        # Search group
        search_group = QGroupBox("Signature Search")
        search_layout = QVBoxLayout(search_group)
        
        search_input_layout = QHBoxLayout()
        search_input_layout.addWidget(QLabel("Search:"))
        
        self.search_input = QLineEdit()
        self.search_input.textChanged.connect(self.search_signatures)
        search_input_layout.addWidget(self.search_input)
        
        search_layout.addLayout(search_input_layout)
        
        # Search results (mini table)
        self.search_results = QTableWidget()
        self.search_results.setColumnCount(3)
        self.search_results.setHorizontalHeaderLabels(["Name", "Family", "Severity"])
        self.search_results.setMaximumHeight(150)
        search_layout.addWidget(self.search_results)
        
        left_layout.addWidget(search_group)
        left_layout.addStretch()
        
        # Right panel - Detections
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        # Detection filters
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        
        self.detection_filter = QComboBox()
        self.detection_filter.addItems(["All Detections", "Critical", "High", "Medium", "Low"])
        self.detection_filter.currentTextChanged.connect(self.filter_detections)
        filter_layout.addWidget(self.detection_filter)
        
        self.method_filter = QComboBox()
        self.method_filter.addItems(["All Methods", "Hash Match", "Pattern Match", "Behavior Match", "IOC Match"])
        self.method_filter.currentTextChanged.connect(self.filter_detections)
        filter_layout.addWidget(self.method_filter)
        
        filter_layout.addStretch()
        right_layout.addLayout(filter_layout)
        
        # Detections table
        self.detections_table = QTableWidget()
        self.detections_table.setColumnCount(7)
        self.detections_table.setHorizontalHeaderLabels([
            "Timestamp", "Signature", "Target", "Method", "Confidence", "Severity", "Details"
        ])
        
        # Configure table
        header = self.detections_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        
        self.detections_table.setAlternatingRowColors(True)
        self.detections_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.detections_table.itemDoubleClicked.connect(self.view_detection_details)
        
        right_layout.addWidget(self.detections_table)
        
        # Add widgets to splitter
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([400, 600])
        
        layout.addWidget(splitter)
        
        # Status label
        self.status_label = QLabel("Ready for signature analysis")
        layout.addWidget(self.status_label)
        
        # Load initial data
        self.update_statistics()
        self.load_recent_detections()
    
    def update_statistics(self):
        """Update signature database statistics."""
        try:
            stats = self.sig_db.get_signature_stats()
            
            stats_text = f"""Signature Database Statistics
==============================

Signatures: {stats['total_signatures']}
IOCs: {stats['total_iocs']}
Recent Detections (24h): {stats['recent_detections']}
Last Update: {stats['last_update']}

Signature Types:"""
            
            for sig_type, count in stats.get('signature_types', {}).items():
                stats_text += f"\n  {sig_type}: {count}"
            
            stats_text += "\n\nSeverity Breakdown:"
            for severity, count in stats.get('severity_breakdown', {}).items():
                stats_text += f"\n  {severity}: {count}"
            
            stats_text += "\n\nIOC Types:"
            for ioc_type, count in stats.get('ioc_types', {}).items():
                stats_text += f"\n  {ioc_type}: {count}"
            
            self.stats_text.setPlainText(stats_text)
            
        except Exception as e:
            self.stats_text.setPlainText(f"Error loading statistics: {str(e)}")
    
    def import_signatures(self):
        """Import signatures from file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Signatures", "", "JSON Files (*.json);;All Files (*)"
        )
        
        if file_path:
            try:
                success = self.sig_db.import_signatures(file_path)
                if success:
                    QMessageBox.information(self, "Import Successful", 
                                          "Signatures imported successfully.")
                    self.update_statistics()
                    self.load_recent_detections()
                else:
                    QMessageBox.critical(self, "Import Failed", 
                                       "Failed to import signatures.")
            except Exception as e:
                QMessageBox.critical(self, "Import Error", f"Error importing: {str(e)}")
    
    def export_signatures(self):
        """Export signatures to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"signatures_export_{timestamp}.json"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Signatures", default_filename, "JSON Files (*.json);;All Files (*)"
        )
        
        if file_path:
            try:
                success = self.sig_db.export_signatures(file_path)
                if success:
                    QMessageBox.information(self, "Export Successful", 
                                          f"Signatures exported to: {file_path}")
                else:
                    QMessageBox.critical(self, "Export Failed", 
                                       "Failed to export signatures.")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Error exporting: {str(e)}")
    
    def update_signatures(self):
        """Update signatures from threat feeds."""
        try:
            self.status_label.setText("Updating signatures from feeds...")
            success = self.sig_db.update_signatures_from_feeds()
            
            if success:
                self.status_label.setText("Signatures updated successfully")
                self.update_statistics()
                QMessageBox.information(self, "Update Successful", 
                                      "Signature database updated from threat feeds.")
            else:
                self.status_label.setText("Signature update failed")
                QMessageBox.warning(self, "Update Failed", 
                                  "Failed to update signatures from feeds.")
                
        except Exception as e:
            self.status_label.setText("Signature update error")
            QMessageBox.critical(self, "Update Error", f"Error updating signatures: {str(e)}")
    
    def browse_scan_path(self):
        """Browse for scan path."""
        path = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if path:
            current_paths = self.scan_path_input.text()
            if current_paths:
                self.scan_path_input.setText(f"{current_paths},{path}")
            else:
                self.scan_path_input.setText(path)
    
    def start_signature_scan(self):
        """Start signature-based filesystem scan."""
        if self.scan_thread and self.scan_thread.isRunning():
            return
        
        paths_text = self.scan_path_input.text()
        if not paths_text:
            QMessageBox.warning(self, "No Paths", "Please specify paths to scan.")
            return
        
        scan_paths = [path.strip() for path in paths_text.split(',') if path.strip()]
        
        self.scan_btn.setEnabled(False)
        self.scan_progress.setVisible(True)
        self.scan_progress.setValue(0)
        self.detections_table.setRowCount(0)
        self.status_label.setText("Running signature scan...")
        
        self.scan_thread = SignatureScanThread(self.sig_db, scan_paths)
        self.scan_thread.detection_found.connect(self.add_detection_row)
        self.scan_thread.scan_completed.connect(self.scan_completed)
        self.scan_thread.start()
    
    def run_comprehensive_scan(self):
        """Run comprehensive system scan."""
        try:
            self.status_label.setText("Running comprehensive signature scan...")
            self.comprehensive_scan_btn.setEnabled(False)
            
            results = self.sig_db.comprehensive_system_scan()
            
            # Clear and populate detections table
            self.detections_table.setRowCount(0)
            
            # Add filesystem detections
            for detection in results.get('filesystem_scan', {}).get('detections', []):
                self.add_detection_row(detection)
            
            # Add process detections
            for detection in results.get('process_scan', {}).get('detections', []):
                self.add_detection_row(detection)
            
            # Add network detections
            for detection in results.get('network_scan', {}).get('detections', []):
                self.add_detection_row(detection)
            
            total_detections = results.get('total_detections', 0)
            high_confidence = results.get('high_confidence_detections', 0)
            
            self.status_label.setText(f"Comprehensive scan completed: {total_detections} detections, {high_confidence} high confidence")
            
            if total_detections > 0:
                # Find main window to show notification
                main_window = self.parent()
                while main_window and not hasattr(main_window, 'show_notification'):
                    main_window = main_window.parent()
                
                if main_window:
                    main_window.show_notification(
                        "Signature Detections Found",
                        f"Found {total_detections} signature matches ({high_confidence} high confidence)"
                    )
            
            self.comprehensive_scan_btn.setEnabled(True)
            
        except Exception as e:
            self.status_label.setText("Comprehensive scan failed")
            QMessageBox.critical(self, "Scan Error", f"Error running comprehensive scan: {str(e)}")
            self.comprehensive_scan_btn.setEnabled(True)
    
    def scan_completed(self, results):
        """Handle signature scan completion."""
        self.scan_btn.setEnabled(True)
        self.scan_progress.setVisible(False)
        
        if 'error' in results:
            self.status_label.setText(f"Scan failed: {results['error']}")
            QMessageBox.critical(self, "Scan Error", results['error'])
        else:
            files_scanned = results.get('files_scanned', 0)
            detections_count = len(results.get('detections', []))
            self.status_label.setText(f"Scan completed: {files_scanned} files scanned, {detections_count} detections")
            
            if detections_count > 0:
                # Find main window to show notification
                main_window = self.parent()
                while main_window and not hasattr(main_window, 'show_notification'):
                    main_window = main_window.parent()
                
                if main_window:
                    main_window.show_notification(
                        "Rootkit Signatures Detected",
                        f"Found {detections_count} signature matches"
                    )
    
    def add_detection_row(self, detection_data):
        """Add detection to the table."""
        row = self.detections_table.rowCount()
        self.detections_table.insertRow(row)
        
        # Timestamp
        if 'timestamp' in detection_data:
            timestamp = datetime.fromtimestamp(detection_data['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        else:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.detections_table.setItem(row, 0, QTableWidgetItem(timestamp))
        
        # Signature name
        sig_name = detection_data.get('signature_name', detection_data.get('name', 'Unknown'))
        self.detections_table.setItem(row, 1, QTableWidgetItem(sig_name))
        
        # Target (file path or PID)
        target = detection_data.get('file_path', f"PID {detection_data.get('target_pid', 'N/A')}")
        target_item = QTableWidgetItem(os.path.basename(target) if target.startswith('/') else target)
        target_item.setToolTip(target)
        self.detections_table.setItem(row, 2, target_item)
        
        # Detection method
        method = detection_data.get('detection_method', 'unknown').replace('_', ' ').title()
        self.detections_table.setItem(row, 3, QTableWidgetItem(method))
        
        # Confidence
        confidence = detection_data.get('confidence', 0.0)
        confidence_item = QTableWidgetItem(f"{confidence:.2f}")
        if confidence > 0.8:
            confidence_item.setBackground(QColor(0, 255, 0, 100))
        elif confidence > 0.6:
            confidence_item.setBackground(QColor(255, 255, 0, 100))
        self.detections_table.setItem(row, 4, confidence_item)
        
        # Severity
        severity = detection_data.get('severity', 'low').title()
        severity_item = QTableWidgetItem(severity)
        
        if severity == 'Critical':
            severity_item.setBackground(QColor(255, 0, 0, 100))
        elif severity == 'High':
            severity_item.setBackground(QColor(255, 100, 0, 100))
        elif severity == 'Medium':
            severity_item.setBackground(QColor(255, 255, 0, 100))
        
        self.detections_table.setItem(row, 5, severity_item)
        
        # Details
        details = detection_data.get('description', detection_data.get('matched_pattern', 'No details'))
        self.detections_table.setItem(row, 6, QTableWidgetItem(details[:50] + "..." if len(details) > 50 else details))
    
    def load_recent_detections(self):
        """Load recent detections from database."""
        try:
            detections = self.sig_db.get_recent_detections(24)  # Last 24 hours
            
            self.detections_table.setRowCount(0)
            for detection in detections:
                self.add_detection_row(detection)
                
        except Exception as e:
            self.status_label.setText(f"Error loading detections: {str(e)}")
    
    def search_signatures(self):
        """Search signatures based on input."""
        query = self.search_input.text()
        if len(query) < 2:
            self.search_results.setRowCount(0)
            return
        
        try:
            results = self.sig_db.search_signatures(query)
            
            self.search_results.setRowCount(len(results))
            for i, result in enumerate(results):
                self.search_results.setItem(i, 0, QTableWidgetItem(result['name']))
                self.search_results.setItem(i, 1, QTableWidgetItem(result['family']))
                
                severity_item = QTableWidgetItem(result['severity'].title())
                if result['severity'] == 'critical':
                    severity_item.setBackground(QColor(255, 0, 0, 100))
                elif result['severity'] == 'high':
                    severity_item.setBackground(QColor(255, 100, 0, 100))
                
                self.search_results.setItem(i, 2, severity_item)
                
        except Exception as e:
            print(f"Error searching signatures: {e}")
    
    def filter_detections(self):
        """Filter detections based on current filter settings."""
        severity_filter = self.detection_filter.currentText()
        method_filter = self.method_filter.currentText()
        
        for row in range(self.detections_table.rowCount()):
            severity_item = self.detections_table.item(row, 5)
            method_item = self.detections_table.item(row, 3)
            
            if not all([severity_item, method_item]):
                continue
            
            severity = severity_item.text()
            method = method_item.text()
            
            show_row = True
            
            if severity_filter != "All Detections" and severity != severity_filter:
                show_row = False
            
            if method_filter != "All Methods" and method != method_filter:
                show_row = False
            
            self.detections_table.setRowHidden(row, not show_row)
    
    def view_detection_details(self, item):
        """View detailed information about a detection."""
        row = item.row()
        
        timestamp = self.detections_table.item(row, 0).text()
        signature = self.detections_table.item(row, 1).text()
        target = self.detections_table.item(row, 2).toolTip() or self.detections_table.item(row, 2).text()
        method = self.detections_table.item(row, 3).text()
        confidence = self.detections_table.item(row, 4).text()
        severity = self.detections_table.item(row, 5).text()
        details = self.detections_table.item(row, 6).text()
        
        details_text = f"""Signature Detection Details
============================

Detection Time: {timestamp}
Signature: {signature}
Target: {target}
Detection Method: {method}
Confidence: {confidence}
Severity: {severity}

Description: {details}

Recommendations:
- Investigate the detected file/process immediately
- Check system logs for related activities
- Consider isolating the affected system
- Verify if detection is a false positive
- Update security measures if confirmed malicious
"""
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Detection Details")
        msg_box.setText(details_text)
        msg_box.exec()
    
    def start_monitoring(self):
        """Start signature monitoring."""
        self.status_label.setText("Signature monitoring active")
        
    def stop_monitoring(self):
        """Stop signature monitoring."""
        self.status_label.setText("Signature monitoring stopped")
        
    def export_results(self):
        """Export signature results."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"signature_detections_{timestamp}.json"
        
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Export Detection Results", default_filename, 
            "JSON Files (*.json);;All Files (*)"
        )
        
        if output_path:
            try:
                # Export recent detections
                detections = self.sig_db.get_recent_detections(24)
                
                export_data = {
                    'export_timestamp': datetime.now().isoformat(),
                    'database_stats': self.sig_db.get_signature_stats(),
                    'recent_detections': detections
                }
                
                with open(output_path, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                QMessageBox.information(self, "Export Successful", 
                                      f"Results exported to: {output_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", 
                                   f"Failed to export results: {str(e)}")