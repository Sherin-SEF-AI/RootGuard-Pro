"""
Process Analysis Tab
Detects hidden processes using multiple enumeration techniques.
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                             QTableWidgetItem, QPushButton, QLabel, QComboBox,
                             QCheckBox, QMessageBox, QHeaderView)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from detection.process_detector import ProcessDetector
from detection.behavioral_analyzer import BehavioralAnalyzer
from detection.memory_forensics import MemoryForensics


class ProcessScanThread(QThread):
    """Background thread for process scanning."""
    
    progress_updated = pyqtSignal(int)
    process_found = pyqtSignal(dict)
    scan_completed = pyqtSignal()
    
    def run(self):
        """Run the process scan."""
        detector = ProcessDetector()
        
        self.progress_updated.emit(10)
        proc_fs_processes = detector.enumerate_proc_filesystem()
        
        self.progress_updated.emit(30)
        ps_processes = detector.enumerate_ps_command()
        
        self.progress_updated.emit(50)
        sysfs_processes = detector.enumerate_sysfs()
        
        self.progress_updated.emit(70)
        hidden_processes = detector.compare_process_lists(
            proc_fs_processes, ps_processes, sysfs_processes
        )
        
        self.progress_updated.emit(90)
        
        for process in hidden_processes:
            self.process_found.emit(process)
        
        self.progress_updated.emit(100)
        self.scan_completed.emit()


class ProcessTab(QWidget):
    """Process analysis tab widget."""
    
    def __init__(self):
        super().__init__()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.memory_forensics = MemoryForensics()
        self.init_ui()
        self.scan_thread = None
        
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Control panel
        control_layout = QHBoxLayout()
        
        self.scan_btn = QPushButton("Start Process Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        control_layout.addWidget(self.scan_btn)
        
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_processes)
        control_layout.addWidget(self.refresh_btn)
        
        self.terminate_btn = QPushButton("Terminate Process")
        self.terminate_btn.clicked.connect(self.terminate_process)
        self.terminate_btn.setEnabled(False)
        control_layout.addWidget(self.terminate_btn)
        
        self.behavioral_btn = QPushButton("Start Behavioral Analysis")
        self.behavioral_btn.clicked.connect(self.toggle_behavioral_monitoring)
        control_layout.addWidget(self.behavioral_btn)
        
        self.memory_scan_btn = QPushButton("Memory Forensics")
        self.memory_scan_btn.clicked.connect(self.run_memory_forensics)
        control_layout.addWidget(self.memory_scan_btn)
        
        # Filter options
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All Processes", "Hidden Only", "Suspicious Only"])
        self.filter_combo.currentTextChanged.connect(self.filter_processes)
        control_layout.addWidget(self.filter_combo)
        
        self.show_system_check = QCheckBox("Show System Processes")
        self.show_system_check.setChecked(True)
        self.show_system_check.toggled.connect(self.filter_processes)
        control_layout.addWidget(self.show_system_check)
        
        control_layout.addStretch()
        layout.addLayout(control_layout)
        
        # Process table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(10)
        self.process_table.setHorizontalHeaderLabels([
            "PID", "Process Name", "Parent PID", "Command Line", 
            "Memory (MB)", "CPU %", "Anomaly Score", "Behavioral Alerts", "Hidden", "Status"
        ])
        
        # Configure table
        header = self.process_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.process_table.setAlternatingRowColors(True)
        self.process_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.process_table.itemSelectionChanged.connect(self.on_selection_changed)
        
        layout.addWidget(self.process_table)
        
        # Status label
        self.status_label = QLabel("Ready to scan processes")
        layout.addWidget(self.status_label)
        
    def start_scan(self):
        """Start process scanning in background thread."""
        if self.scan_thread and self.scan_thread.isRunning():
            return
            
        self.scan_btn.setEnabled(False)
        self.process_table.setRowCount(0)
        self.status_label.setText("Scanning processes...")
        
        self.scan_thread = ProcessScanThread()
        self.scan_thread.progress_updated.connect(self.update_progress)
        self.scan_thread.process_found.connect(self.add_process_row)
        self.scan_thread.scan_completed.connect(self.scan_completed)
        self.scan_thread.start()
        
    def update_progress(self, value):
        """Update scan progress."""
        self.status_label.setText(f"Scanning processes... {value}%")
        
    def add_process_row(self, process_data):
        """Add a process row to the table."""
        row = self.process_table.rowCount()
        self.process_table.insertRow(row)
        
        # PID
        self.process_table.setItem(row, 0, QTableWidgetItem(str(process_data.get('pid', 'N/A'))))
        
        # Process Name
        name_item = QTableWidgetItem(process_data.get('name', 'N/A'))
        if process_data.get('hidden', False):
            name_item.setBackground(QColor(255, 100, 100, 100))
        self.process_table.setItem(row, 1, name_item)
        
        # Parent PID
        self.process_table.setItem(row, 2, QTableWidgetItem(str(process_data.get('ppid', 'N/A'))))
        
        # Command Line
        cmdline = process_data.get('cmdline', 'N/A')
        if len(cmdline) > 100:
            cmdline = cmdline[:97] + "..."
        self.process_table.setItem(row, 3, QTableWidgetItem(cmdline))
        
        # Memory Usage
        memory_mb = process_data.get('memory_mb', 0)
        self.process_table.setItem(row, 4, QTableWidgetItem(f"{memory_mb:.1f}"))
        
        # CPU Usage
        cpu_percent = process_data.get('cpu_percent', 0)
        self.process_table.setItem(row, 5, QTableWidgetItem(f"{cpu_percent:.1f}"))
        
        # Anomaly Score
        pid = process_data.get('pid')
        anomaly_score = 0.0
        behavioral_alerts = 0
        
        if pid and pid in self.behavioral_analyzer.process_behaviors:
            behavior = self.behavioral_analyzer.process_behaviors[pid]
            anomaly_score = behavior.calculate_anomaly_score()
            behavioral_alerts = len(behavior.alerts)
        
        anomaly_item = QTableWidgetItem(f"{anomaly_score:.2f}")
        if anomaly_score > 0.7:
            anomaly_item.setBackground(QColor(255, 0, 0, 100))
        elif anomaly_score > 0.4:
            anomaly_item.setBackground(QColor(255, 165, 0, 100))
        self.process_table.setItem(row, 6, anomaly_item)
        
        # Behavioral Alerts
        alerts_item = QTableWidgetItem(str(behavioral_alerts))
        if behavioral_alerts > 0:
            alerts_item.setBackground(QColor(255, 100, 100, 100))
        self.process_table.setItem(row, 7, alerts_item)
        
        # Hidden Status
        hidden_item = QTableWidgetItem("Yes" if process_data.get('hidden', False) else "No")
        if process_data.get('hidden', False):
            hidden_item.setBackground(QColor(255, 0, 0, 100))
        self.process_table.setItem(row, 8, hidden_item)
        
        # Status
        status = "Suspicious" if process_data.get('suspicious', False) else "Normal"
        status_item = QTableWidgetItem(status)
        if process_data.get('suspicious', False):
            status_item.setBackground(QColor(255, 165, 0, 100))
        self.process_table.setItem(row, 9, status_item)
        
    def scan_completed(self):
        """Handle scan completion."""
        self.scan_btn.setEnabled(True)
        process_count = self.process_table.rowCount()
        hidden_count = sum(1 for row in range(process_count) 
                          if self.process_table.item(row, 6).text() == "Yes")
        
        self.status_label.setText(f"Scan completed. Found {process_count} processes, {hidden_count} hidden")
        
        if hidden_count > 0:
            # Find the main window to show notification
            main_window = self.parent()
            while main_window and not hasattr(main_window, 'show_notification'):
                main_window = main_window.parent()
            
            if main_window:
                main_window.show_notification(
                    "Hidden Processes Detected",
                    f"Found {hidden_count} potentially hidden processes"
                )
    
    def refresh_processes(self):
        """Refresh the process list."""
        self.start_scan()
        
    def terminate_process(self):
        """Terminate the selected process."""
        current_row = self.process_table.currentRow()
        if current_row < 0:
            return
            
        pid_item = self.process_table.item(current_row, 0)
        name_item = self.process_table.item(current_row, 1)
        
        if not pid_item or not name_item:
            return
            
        pid = int(pid_item.text())
        name = name_item.text()
        
        reply = QMessageBox.question(
            self, "Confirm Termination",
            f"Are you sure you want to terminate process '{name}' (PID: {pid})?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                detector = ProcessDetector()
                if detector.terminate_process(pid):
                    QMessageBox.information(self, "Success", f"Process {name} terminated successfully")
                    self.refresh_processes()
                else:
                    QMessageBox.warning(self, "Error", f"Failed to terminate process {name}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error terminating process: {str(e)}")
    
    def filter_processes(self):
        """Filter processes based on current filter settings."""
        filter_text = self.filter_combo.currentText()
        show_system = self.show_system_check.isChecked()
        
        for row in range(self.process_table.rowCount()):
            hidden_item = self.process_table.item(row, 6)
            status_item = self.process_table.item(row, 7)
            name_item = self.process_table.item(row, 1)
            
            if not all([hidden_item, status_item, name_item]):
                continue
                
            is_hidden = hidden_item.text() == "Yes"
            is_suspicious = status_item.text() == "Suspicious"
            is_system = name_item.text().lower() in ['system', 'svchost.exe', 'winlogon.exe']
            
            show_row = True
            
            if filter_text == "Hidden Only" and not is_hidden:
                show_row = False
            elif filter_text == "Suspicious Only" and not is_suspicious:
                show_row = False
            
            if not show_system and is_system:
                show_row = False
                
            self.process_table.setRowHidden(row, not show_row)
    
    def on_selection_changed(self):
        """Handle table selection changes."""
        has_selection = bool(self.process_table.selectedItems())
        self.terminate_btn.setEnabled(has_selection)
    
    def start_monitoring(self):
        """Start real-time process monitoring."""
        self.status_label.setText("Real-time monitoring active")
        
    def stop_monitoring(self):
        """Stop real-time process monitoring."""
        self.status_label.setText("Real-time monitoring stopped")
        
    def toggle_behavioral_monitoring(self):
        """Toggle behavioral analysis monitoring."""
        if not self.behavioral_analyzer.monitoring_active:
            self.behavioral_analyzer.start_monitoring()
            self.behavioral_btn.setText("Stop Behavioral Analysis")
            self.status_label.setText("Behavioral monitoring started")
        else:
            self.behavioral_analyzer.stop_monitoring()
            self.behavioral_btn.setText("Start Behavioral Analysis")
            self.status_label.setText("Behavioral monitoring stopped")
    
    def run_memory_forensics(self):
        """Run memory forensics on selected process."""
        current_row = self.process_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "No Selection", "Please select a process first.")
            return
        
        pid_item = self.process_table.item(current_row, 0)
        if not pid_item:
            return
        
        try:
            pid = int(pid_item.text())
            
            # Run comprehensive memory analysis
            memory_analysis = self.memory_forensics.analyze_process_memory(pid)
            hollowing_result = self.memory_forensics.detect_process_hollowing(pid)
            injection_result = self.memory_forensics.detect_dll_injection(pid)
            
            # Display results
            results_text = f"""Memory Forensics Results for PID {pid}
==========================================

Memory Analysis:
- Memory regions: {len(memory_analysis.get('memory_regions', []))}
- Suspicious regions: {len(memory_analysis.get('suspicious_regions', []))}
- Executable regions: {len(memory_analysis.get('executable_regions', []))}
- Memory anomalies: {len(memory_analysis.get('memory_anomalies', []))}

Process Hollowing Detection:
- Detected: {hollowing_result.get('hollowing_detected', False)}
- Confidence: {hollowing_result.get('confidence', 0):.2f}
- Indicators: {', '.join(hollowing_result.get('indicators', []))}

Injection Analysis:
- Detected: {injection_result.get('injection_detected', False)}
- Confidence: {injection_result.get('confidence', 0):.2f}
- Injected modules: {len(injection_result.get('injected_modules', []))}
"""
            
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Memory Forensics Results")
            msg_box.setText(results_text)
            msg_box.exec()
            
        except ValueError:
            QMessageBox.warning(self, "Invalid PID", "Selected PID is not valid.")
        except Exception as e:
            QMessageBox.critical(self, "Memory Forensics Error", f"Error running memory forensics: {str(e)}")
    
    def export_results(self):
        """Export process results to file."""
        from ..dialogs.export_dialog import ExportDialog
        dialog = ExportDialog(self, "process_results")
        dialog.exec()