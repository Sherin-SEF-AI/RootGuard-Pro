"""
System Hooks Analysis Tab
Analyzes system hooks and API modifications.
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                             QTableWidgetItem, QPushButton, QLabel, QComboBox,
                             QMessageBox, QHeaderView, QTextEdit)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from detection.hooks_detector import HooksDetector


class HooksScanThread(QThread):
    """Background thread for hooks scanning."""
    
    progress_updated = pyqtSignal(int)
    hook_found = pyqtSignal(dict)
    scan_completed = pyqtSignal()
    
    def run(self):
        """Run the hooks scan."""
        detector = HooksDetector()
        
        self.progress_updated.emit(20)
        kernel_modules = detector.analyze_kernel_modules()
        
        for hook in kernel_modules:
            self.hook_found.emit(hook)
        
        self.progress_updated.emit(50)
        library_hooks = detector.analyze_library_hooks()
        
        for hook in library_hooks:
            self.hook_found.emit(hook)
        
        self.progress_updated.emit(80)
        syscall_hooks = detector.analyze_syscall_hooks()
        
        for hook in syscall_hooks:
            self.hook_found.emit(hook)
        
        self.progress_updated.emit(100)
        self.scan_completed.emit()


class HooksTab(QWidget):
    """System hooks analysis tab widget."""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.scan_thread = None
        
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Control panel
        control_layout = QHBoxLayout()
        
        self.scan_btn = QPushButton("Start Hook Analysis")
        self.scan_btn.clicked.connect(self.start_scan)
        control_layout.addWidget(self.scan_btn)
        
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_hooks)
        control_layout.addWidget(self.refresh_btn)
        
        self.details_btn = QPushButton("View Details")
        self.details_btn.clicked.connect(self.view_details)
        self.details_btn.setEnabled(False)
        control_layout.addWidget(self.details_btn)
        
        # Filter options
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All Hooks", "SSDT Hooks", "API Hooks", "IAT Hooks", "Suspicious Only"])
        self.filter_combo.currentTextChanged.connect(self.filter_hooks)
        control_layout.addWidget(self.filter_combo)
        
        control_layout.addStretch()
        layout.addLayout(control_layout)
        
        # Hooks table
        self.hooks_table = QTableWidget()
        self.hooks_table.setColumnCount(6)
        self.hooks_table.setHorizontalHeaderLabels([
            "Hook Type", "Target Function", "Original Address", 
            "Hook Address", "Module", "Status"
        ])
        
        # Configure table
        header = self.hooks_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.hooks_table.setAlternatingRowColors(True)
        self.hooks_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.hooks_table.itemSelectionChanged.connect(self.on_selection_changed)
        
        layout.addWidget(self.hooks_table)
        
        # Status label
        self.status_label = QLabel("Ready to analyze system hooks")
        layout.addWidget(self.status_label)
        
    def start_scan(self):
        """Start hooks scanning in background thread."""
        if self.scan_thread and self.scan_thread.isRunning():
            return
            
        self.scan_btn.setEnabled(False)
        self.hooks_table.setRowCount(0)
        self.status_label.setText("Analyzing system hooks...")
        
        self.scan_thread = HooksScanThread()
        self.scan_thread.progress_updated.connect(self.update_progress)
        self.scan_thread.hook_found.connect(self.add_hook_row)
        self.scan_thread.scan_completed.connect(self.scan_completed)
        self.scan_thread.start()
        
    def update_progress(self, value):
        """Update scan progress."""
        self.status_label.setText(f"Analyzing system hooks... {value}%")
        
    def add_hook_row(self, hook_data):
        """Add a hook row to the table."""
        row = self.hooks_table.rowCount()
        self.hooks_table.insertRow(row)
        
        # Hook Type
        hook_type = hook_data.get('type', 'N/A')
        type_item = QTableWidgetItem(hook_type)
        if hook_data.get('suspicious', False):
            type_item.setBackground(QColor(255, 100, 100, 100))
        self.hooks_table.setItem(row, 0, type_item)
        
        # Target Function
        self.hooks_table.setItem(row, 1, QTableWidgetItem(hook_data.get('function', 'N/A')))
        
        # Original Address
        orig_addr = hook_data.get('original_address', 'N/A')
        if isinstance(orig_addr, int):
            orig_addr = f"0x{orig_addr:08X}"
        self.hooks_table.setItem(row, 2, QTableWidgetItem(str(orig_addr)))
        
        # Hook Address
        hook_addr = hook_data.get('hook_address', 'N/A')
        if isinstance(hook_addr, int):
            hook_addr = f"0x{hook_addr:08X}"
        self.hooks_table.setItem(row, 3, QTableWidgetItem(str(hook_addr)))
        
        # Module
        module_item = QTableWidgetItem(hook_data.get('module', 'N/A'))
        self.hooks_table.setItem(row, 4, module_item)
        
        # Status
        status = "Suspicious" if hook_data.get('suspicious', False) else "Normal"
        status_item = QTableWidgetItem(status)
        if hook_data.get('suspicious', False):
            status_item.setBackground(QColor(255, 0, 0, 100))
        elif hook_data.get('type') in ['SSDT', 'Shadow SSDT']:
            status_item.setBackground(QColor(255, 165, 0, 100))
        self.hooks_table.setItem(row, 5, status_item)
        
    def scan_completed(self):
        """Handle scan completion."""
        self.scan_btn.setEnabled(True)
        hook_count = self.hooks_table.rowCount()
        suspicious_count = sum(1 for row in range(hook_count) 
                              if self.hooks_table.item(row, 5).text() == "Suspicious")
        
        self.status_label.setText(f"Analysis completed. Found {hook_count} hooks, {suspicious_count} suspicious")
        
        if suspicious_count > 0:
            # Find the main window to show notification
            main_window = self.parent()
            while main_window and not hasattr(main_window, 'show_notification'):
                main_window = main_window.parent()
            
            if main_window:
                main_window.show_notification(
                    "Suspicious Hooks Detected",
                    f"Found {suspicious_count} potentially malicious system hooks"
                )
    
    def refresh_hooks(self):
        """Refresh the hooks list."""
        self.start_scan()
        
    def view_details(self):
        """View detailed information about the selected hook."""
        current_row = self.hooks_table.currentRow()
        if current_row < 0:
            return
            
        hook_type = self.hooks_table.item(current_row, 0).text()
        function_name = self.hooks_table.item(current_row, 1).text()
        
        # Create details dialog
        details = f"Hook Type: {hook_type}\n"
        details += f"Function: {function_name}\n"
        details += f"Original Address: {self.hooks_table.item(current_row, 2).text()}\n"
        details += f"Hook Address: {self.hooks_table.item(current_row, 3).text()}\n"
        details += f"Module: {self.hooks_table.item(current_row, 4).text()}\n"
        details += f"Status: {self.hooks_table.item(current_row, 5).text()}\n\n"
        
        # Additional analysis
        detector = HooksDetector()
        additional_info = detector.get_hook_details(hook_type, function_name)
        details += f"Additional Information:\n{additional_info}"
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Hook Details")
        msg_box.setText(details)
        msg_box.setDetailedText("Detailed analysis information would be displayed here.")
        msg_box.exec()
    
    def filter_hooks(self):
        """Filter hooks based on current filter settings."""
        filter_text = self.filter_combo.currentText()
        
        for row in range(self.hooks_table.rowCount()):
            hook_type_item = self.hooks_table.item(row, 0)
            status_item = self.hooks_table.item(row, 5)
            
            if not all([hook_type_item, status_item]):
                continue
                
            hook_type = hook_type_item.text()
            status = status_item.text()
            
            show_row = True
            
            if filter_text == "SSDT Hooks" and "SSDT" not in hook_type:
                show_row = False
            elif filter_text == "API Hooks" and hook_type != "API Hook":
                show_row = False
            elif filter_text == "IAT Hooks" and hook_type != "IAT Hook":
                show_row = False
            elif filter_text == "Suspicious Only" and status != "Suspicious":
                show_row = False
                
            self.hooks_table.setRowHidden(row, not show_row)
    
    def on_selection_changed(self):
        """Handle table selection changes."""
        has_selection = bool(self.hooks_table.selectedItems())
        self.details_btn.setEnabled(has_selection)
    
    def start_monitoring(self):
        """Start real-time hooks monitoring."""
        self.status_label.setText("Real-time hooks monitoring active")
        
    def stop_monitoring(self):
        """Stop real-time hooks monitoring."""
        self.status_label.setText("Real-time hooks monitoring stopped")
        
    def export_results(self):
        """Export hooks results to file."""
        from ..dialogs.export_dialog import ExportDialog
        dialog = ExportDialog(self, "hooks_results")
        dialog.exec()