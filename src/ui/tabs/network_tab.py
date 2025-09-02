"""
Network Analysis Tab
Analyzes network connections for hidden or suspicious activity.
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                             QTableWidgetItem, QPushButton, QLabel, QComboBox,
                             QCheckBox, QMessageBox, QHeaderView)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from detection.network_detector import NetworkDetector
from detection.advanced_network_analyzer import AdvancedNetworkAnalyzer


class NetworkScanThread(QThread):
    """Background thread for network scanning."""
    
    progress_updated = pyqtSignal(int)
    connection_found = pyqtSignal(dict)
    scan_completed = pyqtSignal()
    
    def run(self):
        """Run the network scan."""
        detector = NetworkDetector()
        
        self.progress_updated.emit(25)
        netstat_connections = detector.enumerate_netstat()
        
        self.progress_updated.emit(50)
        api_connections = detector.enumerate_api_connections()
        
        self.progress_updated.emit(75)
        all_connections = detector.compare_connection_lists(netstat_connections, api_connections)
        
        for connection in all_connections:
            self.connection_found.emit(connection)
        
        self.progress_updated.emit(100)
        self.scan_completed.emit()


class NetworkTab(QWidget):
    """Network analysis tab widget."""
    
    def __init__(self):
        super().__init__()
        self.advanced_analyzer = AdvancedNetworkAnalyzer()
        self.init_ui()
        self.scan_thread = None
        
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Control panel
        control_layout = QHBoxLayout()
        
        self.scan_btn = QPushButton("Start Network Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        control_layout.addWidget(self.scan_btn)
        
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_connections)
        control_layout.addWidget(self.refresh_btn)
        
        self.lookup_btn = QPushButton("IP Lookup")
        self.lookup_btn.clicked.connect(self.lookup_ip)
        self.lookup_btn.setEnabled(False)
        control_layout.addWidget(self.lookup_btn)
        
        self.advanced_analysis_btn = QPushButton("Advanced Analysis")
        self.advanced_analysis_btn.clicked.connect(self.run_advanced_analysis)
        control_layout.addWidget(self.advanced_analysis_btn)
        
        self.monitor_traffic_btn = QPushButton("Start Traffic Monitoring")
        self.monitor_traffic_btn.clicked.connect(self.toggle_traffic_monitoring)
        control_layout.addWidget(self.monitor_traffic_btn)
        
        # Filter options
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All Connections", "TCP Only", "UDP Only", "External Only", "Hidden Only"])
        self.filter_combo.currentTextChanged.connect(self.filter_connections)
        control_layout.addWidget(self.filter_combo)
        
        self.show_local_check = QCheckBox("Show Local Connections")
        self.show_local_check.setChecked(True)
        self.show_local_check.toggled.connect(self.filter_connections)
        control_layout.addWidget(self.show_local_check)
        
        control_layout.addStretch()
        layout.addLayout(control_layout)
        
        # Connection table
        self.connection_table = QTableWidget()
        self.connection_table.setColumnCount(8)
        self.connection_table.setHorizontalHeaderLabels([
            "Protocol", "Local Address", "Remote Address", "State", 
            "Process Name", "PID", "Hidden", "Country"
        ])
        
        # Configure table
        header = self.connection_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.connection_table.setAlternatingRowColors(True)
        self.connection_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.connection_table.itemSelectionChanged.connect(self.on_selection_changed)
        
        layout.addWidget(self.connection_table)
        
        # Status label
        self.status_label = QLabel("Ready to scan network connections")
        layout.addWidget(self.status_label)
        
    def start_scan(self):
        """Start network scanning in background thread."""
        if self.scan_thread and self.scan_thread.isRunning():
            return
            
        self.scan_btn.setEnabled(False)
        self.connection_table.setRowCount(0)
        self.status_label.setText("Scanning network connections...")
        
        self.scan_thread = NetworkScanThread()
        self.scan_thread.progress_updated.connect(self.update_progress)
        self.scan_thread.connection_found.connect(self.add_connection_row)
        self.scan_thread.scan_completed.connect(self.scan_completed)
        self.scan_thread.start()
        
    def update_progress(self, value):
        """Update scan progress."""
        self.status_label.setText(f"Scanning network connections... {value}%")
        
    def add_connection_row(self, conn_data):
        """Add a connection row to the table."""
        row = self.connection_table.rowCount()
        self.connection_table.insertRow(row)
        
        # Protocol
        protocol_item = QTableWidgetItem(conn_data.get('protocol', 'N/A'))
        self.connection_table.setItem(row, 0, protocol_item)
        
        # Local Address
        local_addr = f"{conn_data.get('local_ip', '')}:{conn_data.get('local_port', '')}"
        self.connection_table.setItem(row, 1, QTableWidgetItem(local_addr))
        
        # Remote Address
        remote_addr = f"{conn_data.get('remote_ip', '')}:{conn_data.get('remote_port', '')}"
        remote_item = QTableWidgetItem(remote_addr)
        if conn_data.get('is_external', False):
            remote_item.setBackground(QColor(255, 165, 0, 50))
        self.connection_table.setItem(row, 2, remote_item)
        
        # State
        state_item = QTableWidgetItem(conn_data.get('state', 'N/A'))
        if conn_data.get('state') == 'ESTABLISHED':
            state_item.setBackground(QColor(0, 255, 0, 50))
        self.connection_table.setItem(row, 3, state_item)
        
        # Process Name
        process_item = QTableWidgetItem(conn_data.get('process_name', 'N/A'))
        if conn_data.get('suspicious', False):
            process_item.setBackground(QColor(255, 100, 100, 100))
        self.connection_table.setItem(row, 4, process_item)
        
        # PID
        self.connection_table.setItem(row, 5, QTableWidgetItem(str(conn_data.get('pid', 'N/A'))))
        
        # Hidden Status
        hidden_item = QTableWidgetItem("Yes" if conn_data.get('hidden', False) else "No")
        if conn_data.get('hidden', False):
            hidden_item.setBackground(QColor(255, 0, 0, 100))
        self.connection_table.setItem(row, 6, hidden_item)
        
        # Country
        self.connection_table.setItem(row, 7, QTableWidgetItem(conn_data.get('country', 'N/A')))
        
    def scan_completed(self):
        """Handle scan completion."""
        self.scan_btn.setEnabled(True)
        connection_count = self.connection_table.rowCount()
        hidden_count = sum(1 for row in range(connection_count) 
                          if self.connection_table.item(row, 6).text() == "Yes")
        
        self.status_label.setText(f"Scan completed. Found {connection_count} connections, {hidden_count} hidden")
        
        if hidden_count > 0:
            # Find the main window to show notification
            main_window = self.parent()
            while main_window and not hasattr(main_window, 'show_notification'):
                main_window = main_window.parent()
            
            if main_window:
                main_window.show_notification(
                    "Hidden Connections Detected",
                    f"Found {hidden_count} potentially hidden network connections"
                )
    
    def refresh_connections(self):
        """Refresh the connection list."""
        self.start_scan()
        
    def lookup_ip(self):
        """Perform IP lookup for selected connection."""
        current_row = self.connection_table.currentRow()
        if current_row < 0:
            return
            
        remote_addr = self.connection_table.item(current_row, 2).text()
        if ':' in remote_addr:
            ip = remote_addr.split(':')[0]
            
            detector = NetworkDetector()
            ip_info = detector.lookup_ip_info(ip)
            
            if ip_info.get('error'):
                QMessageBox.warning(self, "Lookup Failed", f"Failed to lookup IP: {ip_info['error']}")
            else:
                info_text = f"IP: {ip}\n"
                info_text += f"Country: {ip_info.get('country', 'Unknown')}\n"
                info_text += f"Region: {ip_info.get('region', 'Unknown')}\n"
                info_text += f"City: {ip_info.get('city', 'Unknown')}\n"
                info_text += f"ISP: {ip_info.get('isp', 'Unknown')}\n"
                info_text += f"Organization: {ip_info.get('org', 'Unknown')}"
                
                QMessageBox.information(self, "IP Information", info_text)
    
    def filter_connections(self):
        """Filter connections based on current filter settings."""
        filter_text = self.filter_combo.currentText()
        show_local = self.show_local_check.isChecked()
        
        for row in range(self.connection_table.rowCount()):
            protocol_item = self.connection_table.item(row, 0)
            remote_item = self.connection_table.item(row, 2)
            hidden_item = self.connection_table.item(row, 6)
            
            if not all([protocol_item, remote_item, hidden_item]):
                continue
                
            protocol = protocol_item.text()
            remote_addr = remote_item.text()
            is_hidden = hidden_item.text() == "Yes"
            is_local = remote_addr.startswith('127.') or remote_addr.startswith('192.168.') or remote_addr.startswith('10.')
            
            show_row = True
            
            if filter_text == "TCP Only" and protocol != "TCP":
                show_row = False
            elif filter_text == "UDP Only" and protocol != "UDP":
                show_row = False
            elif filter_text == "External Only" and is_local:
                show_row = False
            elif filter_text == "Hidden Only" and not is_hidden:
                show_row = False
            
            if not show_local and is_local:
                show_row = False
                
            self.connection_table.setRowHidden(row, not show_row)
    
    def on_selection_changed(self):
        """Handle table selection changes."""
        has_selection = bool(self.connection_table.selectedItems())
        self.lookup_btn.setEnabled(has_selection)
    
    def start_monitoring(self):
        """Start real-time network monitoring."""
        self.status_label.setText("Real-time network monitoring active")
        
    def stop_monitoring(self):
        """Stop real-time network monitoring."""
        self.status_label.setText("Real-time network monitoring stopped")
        
    def run_advanced_analysis(self):
        """Run advanced network forensics analysis."""
        try:
            # Run comprehensive network analysis
            analysis_results = self.advanced_analyzer.analyze_network_forensics()
            rootkit_indicators = self.advanced_analyzer.detect_network_rootkit_indicators()
            
            # Display results
            results_text = f"""Advanced Network Analysis Results
========================================

Connection Analysis:
- Total connections: {analysis_results.get('connection_analysis', {}).get('total_connections', 0)}
- Established: {analysis_results.get('connection_analysis', {}).get('established_connections', 0)}
- External connections: {analysis_results.get('connection_analysis', {}).get('external_connections', 0)}
- Listening ports: {analysis_results.get('connection_analysis', {}).get('listening_ports', 0)}

Protocol Distribution:
"""
            
            for protocol, count in analysis_results.get('protocol_breakdown', {}).items():
                results_text += f"- {protocol}: {count}\n"
            
            results_text += f"\nSecurity Indicators Found: {len(analysis_results.get('security_indicators', []))}\n"
            
            for indicator in analysis_results.get('security_indicators', [])[:5]:
                results_text += f"- {indicator['type']}: {indicator['description']}\n"
            
            results_text += f"\nRootkit Network Indicators: {len(rootkit_indicators)}\n"
            
            for indicator in rootkit_indicators[:5]:
                results_text += f"- {indicator['type']}: {indicator['description']}\n"
            
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Advanced Network Analysis")
            msg_box.setText(results_text)
            msg_box.exec()
            
        except Exception as e:
            QMessageBox.critical(self, "Analysis Error", f"Error running advanced analysis: {str(e)}")
    
    def toggle_traffic_monitoring(self):
        """Toggle advanced traffic monitoring."""
        if not self.advanced_analyzer.monitoring_active:
            self.advanced_analyzer.start_monitoring()
            self.monitor_traffic_btn.setText("Stop Traffic Monitoring")
            self.status_label.setText("Advanced traffic monitoring started")
            
            # Setup anomaly callback
            self.advanced_analyzer.add_anomaly_callback(self.handle_network_anomaly)
        else:
            self.advanced_analyzer.stop_monitoring()
            self.monitor_traffic_btn.setText("Start Traffic Monitoring")
            self.status_label.setText("Advanced traffic monitoring stopped")
    
    def handle_network_anomaly(self, anomaly_data):
        """Handle network anomaly alerts."""
        # Find main window to show notification
        main_window = self.parent()
        while main_window and not hasattr(main_window, 'show_notification'):
            main_window = main_window.parent()
        
        if main_window:
            main_window.show_notification(
                f"Network Anomaly: {anomaly_data['anomaly_type']}",
                anomaly_data['description']
            )
    
    def export_results(self):
        """Export network results to file."""
        from ..dialogs.export_dialog import ExportDialog
        dialog = ExportDialog(self, "network_results")
        dialog.exec()