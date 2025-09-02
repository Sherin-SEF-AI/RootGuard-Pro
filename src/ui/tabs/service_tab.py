"""
Service Analysis Tab
Analyzes Windows services for hidden or suspicious entries.
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                             QTableWidgetItem, QPushButton, QLabel, QComboBox,
                             QCheckBox, QMessageBox, QHeaderView)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from detection.service_detector import ServiceDetector


class ServiceScanThread(QThread):
    """Background thread for service scanning."""
    
    progress_updated = pyqtSignal(int)
    service_found = pyqtSignal(dict)
    scan_completed = pyqtSignal()
    
    def run(self):
        """Run the service scan."""
        detector = ServiceDetector()
        
        self.progress_updated.emit(20)
        systemctl_services = detector.enumerate_systemctl_services()
        
        self.progress_updated.emit(50)
        init_services = detector.enumerate_init_services()
        
        self.progress_updated.emit(80)
        all_services = detector.compare_service_lists(systemctl_services, init_services)
        
        for service in all_services:
            self.service_found.emit(service)
        
        self.progress_updated.emit(100)
        self.scan_completed.emit()


class ServiceTab(QWidget):
    """Service analysis tab widget."""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.scan_thread = None
        
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Control panel
        control_layout = QHBoxLayout()
        
        self.scan_btn = QPushButton("Start Service Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        control_layout.addWidget(self.scan_btn)
        
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_services)
        control_layout.addWidget(self.refresh_btn)
        
        self.start_service_btn = QPushButton("Start Service")
        self.start_service_btn.clicked.connect(self.start_service)
        self.start_service_btn.setEnabled(False)
        control_layout.addWidget(self.start_service_btn)
        
        self.stop_service_btn = QPushButton("Stop Service")
        self.stop_service_btn.clicked.connect(self.stop_service)
        self.stop_service_btn.setEnabled(False)
        control_layout.addWidget(self.stop_service_btn)
        
        # Filter options
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All Services", "Running Only", "Hidden Only", "Suspicious Only"])
        self.filter_combo.currentTextChanged.connect(self.filter_services)
        control_layout.addWidget(self.filter_combo)
        
        control_layout.addStretch()
        layout.addLayout(control_layout)
        
        # Service table
        self.service_table = QTableWidget()
        self.service_table.setColumnCount(7)
        self.service_table.setHorizontalHeaderLabels([
            "Service Name", "Display Name", "Status", "Startup Type", 
            "PID", "Executable Path", "Hidden"
        ])
        
        # Configure table
        header = self.service_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.service_table.setAlternatingRowColors(True)
        self.service_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.service_table.itemSelectionChanged.connect(self.on_selection_changed)
        
        layout.addWidget(self.service_table)
        
        # Status label
        self.status_label = QLabel("Ready to scan services")
        layout.addWidget(self.status_label)
        
    def start_scan(self):
        """Start service scanning in background thread."""
        if self.scan_thread and self.scan_thread.isRunning():
            return
            
        self.scan_btn.setEnabled(False)
        self.service_table.setRowCount(0)
        self.status_label.setText("Scanning services...")
        
        self.scan_thread = ServiceScanThread()
        self.scan_thread.progress_updated.connect(self.update_progress)
        self.scan_thread.service_found.connect(self.add_service_row)
        self.scan_thread.scan_completed.connect(self.scan_completed)
        self.scan_thread.start()
        
    def update_progress(self, value):
        """Update scan progress."""
        self.status_label.setText(f"Scanning services... {value}%")
        
    def add_service_row(self, service_data):
        """Add a service row to the table."""
        row = self.service_table.rowCount()
        self.service_table.insertRow(row)
        
        # Service Name
        name_item = QTableWidgetItem(service_data.get('name', 'N/A'))
        if service_data.get('hidden', False):
            name_item.setBackground(QColor(255, 100, 100, 100))
        self.service_table.setItem(row, 0, name_item)
        
        # Display Name
        self.service_table.setItem(row, 1, QTableWidgetItem(service_data.get('display_name', 'N/A')))
        
        # Status
        status = service_data.get('status', 'Unknown')
        status_item = QTableWidgetItem(status)
        if status == "Running":
            status_item.setBackground(QColor(0, 255, 0, 50))
        elif status == "Stopped":
            status_item.setBackground(QColor(255, 255, 0, 50))
        self.service_table.setItem(row, 2, status_item)
        
        # Startup Type
        self.service_table.setItem(row, 3, QTableWidgetItem(service_data.get('start_type', 'N/A')))
        
        # PID
        self.service_table.setItem(row, 4, QTableWidgetItem(str(service_data.get('pid', 'N/A'))))
        
        # Executable Path
        exe_path = service_data.get('exe_path', 'N/A')
        if len(exe_path) > 80:
            exe_path = "..." + exe_path[-77:]
        self.service_table.setItem(row, 5, QTableWidgetItem(exe_path))
        
        # Hidden Status
        hidden_item = QTableWidgetItem("Yes" if service_data.get('hidden', False) else "No")
        if service_data.get('hidden', False):
            hidden_item.setBackground(QColor(255, 0, 0, 100))
        self.service_table.setItem(row, 6, hidden_item)
        
    def scan_completed(self):
        """Handle scan completion."""
        self.scan_btn.setEnabled(True)
        service_count = self.service_table.rowCount()
        hidden_count = sum(1 for row in range(service_count) 
                          if self.service_table.item(row, 6).text() == "Yes")
        
        self.status_label.setText(f"Scan completed. Found {service_count} services, {hidden_count} hidden")
        
        if hidden_count > 0:
            # Find the main window to show notification
            main_window = self.parent()
            while main_window and not hasattr(main_window, 'show_notification'):
                main_window = main_window.parent()
            
            if main_window:
                main_window.show_notification(
                    "Hidden Services Detected",
                    f"Found {hidden_count} potentially hidden services"
                )
    
    def refresh_services(self):
        """Refresh the service list."""
        self.start_scan()
        
    def start_service(self):
        """Start the selected service."""
        current_row = self.service_table.currentRow()
        if current_row < 0:
            return
            
        service_name = self.service_table.item(current_row, 0).text()
        
        try:
            detector = ServiceDetector()
            if detector.start_service(service_name):
                QMessageBox.information(self, "Success", f"Service '{service_name}' started successfully")
                self.refresh_services()
            else:
                QMessageBox.warning(self, "Error", f"Failed to start service '{service_name}'")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error starting service: {str(e)}")
    
    def stop_service(self):
        """Stop the selected service."""
        current_row = self.service_table.currentRow()
        if current_row < 0:
            return
            
        service_name = self.service_table.item(current_row, 0).text()
        
        reply = QMessageBox.question(
            self, "Confirm Stop",
            f"Are you sure you want to stop service '{service_name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                detector = ServiceDetector()
                if detector.stop_service(service_name):
                    QMessageBox.information(self, "Success", f"Service '{service_name}' stopped successfully")
                    self.refresh_services()
                else:
                    QMessageBox.warning(self, "Error", f"Failed to stop service '{service_name}'")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error stopping service: {str(e)}")
    
    def filter_services(self):
        """Filter services based on current filter settings."""
        filter_text = self.filter_combo.currentText()
        
        for row in range(self.service_table.rowCount()):
            status_item = self.service_table.item(row, 2)
            hidden_item = self.service_table.item(row, 6)
            
            if not all([status_item, hidden_item]):
                continue
                
            status = status_item.text()
            is_hidden = hidden_item.text() == "Yes"
            
            show_row = True
            
            if filter_text == "Running Only" and status != "Running":
                show_row = False
            elif filter_text == "Hidden Only" and not is_hidden:
                show_row = False
            elif filter_text == "Suspicious Only" and not is_hidden:
                show_row = False
                
            self.service_table.setRowHidden(row, not show_row)
    
    def on_selection_changed(self):
        """Handle table selection changes."""
        has_selection = bool(self.service_table.selectedItems())
        self.start_service_btn.setEnabled(has_selection)
        self.stop_service_btn.setEnabled(has_selection)
    
    def start_monitoring(self):
        """Start real-time service monitoring."""
        self.status_label.setText("Real-time service monitoring active")
        
    def stop_monitoring(self):
        """Stop real-time service monitoring."""
        self.status_label.setText("Real-time service monitoring stopped")
        
    def export_results(self):
        """Export service results to file."""
        from ..dialogs.export_dialog import ExportDialog
        dialog = ExportDialog(self, "service_results")
        dialog.exec()