"""
YARA Scanner Tab
Interface for YARA rule management and malware scanning.
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                             QTableWidgetItem, QPushButton, QLabel, QComboBox,
                             QMessageBox, QHeaderView, QTextEdit, QGroupBox,
                             QLineEdit, QFileDialog, QSplitter, QProgressBar,
                             QListWidget, QCheckBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont

import sys
import os
import json
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from detection.yara_scanner import YaraScanner
from datetime import datetime


class YaraScanThread(QThread):
    """Background thread for YARA scanning."""
    
    progress_updated = pyqtSignal(int)
    match_found = pyqtSignal(dict)
    scan_completed = pyqtSignal(dict)
    
    def __init__(self, scanner, scan_type, target_path=None):
        super().__init__()
        self.scanner = scanner
        self.scan_type = scan_type
        self.target_path = target_path
    
    def run(self):
        """Run YARA scan."""
        try:
            if self.scan_type == 'directory':
                results = self.scanner.bulk_scan_directory(self.target_path)
                
                for match in results.get('matches', []):
                    self.match_found.emit(match)
                
                self.scan_completed.emit(results)
                
            elif self.scan_type == 'processes':
                matches = self.scanner.scan_running_processes()
                
                results = {
                    'scan_type': 'processes',
                    'matches_found': len(matches),
                    'matches': [match.__dict__ if hasattr(match, '__dict__') else match for match in matches]
                }
                
                for match in matches:
                    match_dict = match.__dict__ if hasattr(match, '__dict__') else match
                    self.match_found.emit(match_dict)
                
                self.scan_completed.emit(results)
                
        except Exception as e:
            self.scan_completed.emit({'error': str(e)})


class YaraTab(QWidget):
    """YARA scanner tab widget."""
    
    def __init__(self):
        super().__init__()
        self.scanner = YaraScanner()
        self.init_ui()
        self.scan_thread = None
        
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Create splitter for main layout
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Rules and controls
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        # Rules management group
        rules_group = QGroupBox("YARA Rules Management")
        rules_layout = QVBoxLayout(rules_group)
        
        # Rules statistics
        self.rules_stats = QTextEdit()
        self.rules_stats.setMaximumHeight(120)
        self.rules_stats.setFont(QFont("Consolas", 9))
        self.rules_stats.setReadOnly(True)
        rules_layout.addWidget(self.rules_stats)
        
        # Rules management buttons
        rules_btn_layout = QHBoxLayout()
        
        load_rules_btn = QPushButton("Load Rules")
        load_rules_btn.clicked.connect(self.load_rules)
        rules_btn_layout.addWidget(load_rules_btn)
        
        update_rules_btn = QPushButton("Update Rules")
        update_rules_btn.clicked.connect(self.update_rules)
        rules_btn_layout.addWidget(update_rules_btn)
        
        create_rule_btn = QPushButton("Create Rule")
        create_rule_btn.clicked.connect(self.create_custom_rule)
        rules_btn_layout.addWidget(create_rule_btn)
        
        rules_layout.addLayout(rules_btn_layout)
        left_layout.addWidget(rules_group)
        
        # Scanning controls group
        scan_group = QGroupBox("YARA Scanning")
        scan_layout = QVBoxLayout(scan_group)
        
        # Scan target selection
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Scan Target:"))
        
        self.scan_path_input = QLineEdit()
        self.scan_path_input.setText("/usr/bin")
        target_layout.addWidget(self.scan_path_input)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_scan_target)
        target_layout.addWidget(browse_btn)
        
        scan_layout.addLayout(target_layout)
        
        # Scan options
        options_layout = QHBoxLayout()
        
        self.recursive_check = QCheckBox("Recursive Scan")
        self.recursive_check.setChecked(True)
        options_layout.addWidget(self.recursive_check)
        
        self.memory_scan_check = QCheckBox("Include Memory Scan")
        options_layout.addWidget(self.memory_scan_check)
        
        scan_layout.addLayout(options_layout)
        
        # Scan buttons
        scan_btn_layout = QHBoxLayout()
        
        self.scan_files_btn = QPushButton("Scan Files")
        self.scan_files_btn.clicked.connect(self.scan_files)
        scan_btn_layout.addWidget(self.scan_files_btn)
        
        self.scan_processes_btn = QPushButton("Scan Processes")
        self.scan_processes_btn.clicked.connect(self.scan_processes)
        scan_btn_layout.addWidget(self.scan_processes_btn)
        
        scan_layout.addLayout(scan_btn_layout)
        
        # Progress bar
        self.scan_progress = QProgressBar()
        self.scan_progress.setVisible(False)
        scan_layout.addWidget(self.scan_progress)
        
        left_layout.addWidget(scan_group)
        
        # Active rules group
        active_rules_group = QGroupBox("Active Rules")
        active_rules_layout = QVBoxLayout(active_rules_group)
        
        self.active_rules_list = QListWidget()
        self.active_rules_list.setMaximumHeight(150)
        active_rules_layout.addWidget(self.active_rules_list)
        
        left_layout.addWidget(active_rules_group)
        left_layout.addStretch()
        
        # Right panel - Scan results
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "Critical", "High", "Medium", "Low"])
        self.severity_filter.currentTextChanged.connect(self.filter_matches)
        filter_layout.addWidget(self.severity_filter)
        
        self.confidence_filter = QComboBox()
        self.confidence_filter.addItems(["All Confidence", "High (>0.8)", "Medium (>0.5)", "Low (<0.5)"])
        self.confidence_filter.currentTextChanged.connect(self.filter_matches)
        filter_layout.addWidget(self.confidence_filter)
        
        filter_layout.addStretch()
        right_layout.addLayout(filter_layout)
        
        # Matches table
        self.matches_table = QTableWidget()
        self.matches_table.setColumnCount(7)
        self.matches_table.setHorizontalHeaderLabels([
            "Rule Name", "Target", "Matched Strings", "Confidence", "Severity", "Description", "Actions"
        ])
        
        # Configure table
        header = self.matches_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        
        self.matches_table.setAlternatingRowColors(True)
        self.matches_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.matches_table.itemDoubleClicked.connect(self.view_match_details)
        
        right_layout.addWidget(self.matches_table)
        
        # Add widgets to splitter
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([350, 650])
        
        layout.addWidget(splitter)
        
        # Status label
        self.status_label = QLabel("Ready for YARA scanning")
        layout.addWidget(self.status_label)
        
        # Load initial data
        self.update_rules_statistics()
        self.update_active_rules_list()
    
    def load_rules(self):
        """Load YARA rules from directory."""
        rules_dir = QFileDialog.getExistingDirectory(
            self, "Select YARA Rules Directory", self.scanner.rules_dir
        )
        
        if rules_dir:
            try:
                rules_loaded = self.scanner.load_rules_from_directory(rules_dir)
                self.status_label.setText(f"Loaded {rules_loaded} YARA rules")
                self.update_rules_statistics()
                self.update_active_rules_list()
                
                QMessageBox.information(self, "Rules Loaded", 
                                      f"Successfully loaded {rules_loaded} YARA rules.")
            except Exception as e:
                QMessageBox.critical(self, "Load Error", f"Error loading rules: {str(e)}")
    
    def update_rules(self):
        """Update YARA rules from repository."""
        try:
            self.status_label.setText("Updating YARA rules...")
            results = self.scanner.update_rules_from_repository()
            
            downloaded = results.get('rules_downloaded', 0)
            updated = results.get('rules_updated', 0)
            errors = len(results.get('errors', []))
            
            self.status_label.setText(f"Rules updated: {downloaded} downloaded, {updated} updated, {errors} errors")
            self.update_rules_statistics()
            self.update_active_rules_list()
            
            QMessageBox.information(self, "Rules Updated", 
                                  f"Downloaded: {downloaded}\nUpdated: {updated}\nErrors: {errors}")
            
        except Exception as e:
            self.status_label.setText("Rule update failed")
            QMessageBox.critical(self, "Update Error", f"Error updating rules: {str(e)}")
    
    def create_custom_rule(self):
        """Create custom YARA rule."""
        # Simple dialog for custom rule creation
        rule_name, ok = QInputDialog.getText(self, "Rule Name", "Enter rule name:")
        if not ok or not rule_name:
            return
        
        description, ok = QInputDialog.getText(self, "Description", "Enter rule description:")
        if not ok:
            return
        
        # For simplicity, create a basic rule
        strings = ["suspicious_string"]
        condition = "$str0"
        
        try:
            success = self.scanner.create_custom_rule(rule_name, description, strings, condition)
            
            if success:
                self.status_label.setText(f"Custom rule '{rule_name}' created")
                self.update_rules_statistics()
                self.update_active_rules_list()
                QMessageBox.information(self, "Rule Created", f"Custom rule '{rule_name}' created successfully.")
            else:
                QMessageBox.critical(self, "Creation Failed", "Failed to create custom rule.")
                
        except Exception as e:
            QMessageBox.critical(self, "Creation Error", f"Error creating rule: {str(e)}")
    
    def browse_scan_target(self):
        """Browse for scan target."""
        target = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if target:
            self.scan_path_input.setText(target)
    
    def scan_files(self):
        """Start YARA file scan."""
        if self.scan_thread and self.scan_thread.isRunning():
            return
        
        target_path = self.scan_path_input.text()
        if not target_path or not os.path.exists(target_path):
            QMessageBox.warning(self, "Invalid Path", "Please specify a valid path to scan.")
            return
        
        self.scan_files_btn.setEnabled(False)
        self.scan_progress.setVisible(True)
        self.scan_progress.setValue(0)
        self.matches_table.setRowCount(0)
        self.status_label.setText("Running YARA file scan...")
        
        self.scan_thread = YaraScanThread(self.scanner, 'directory', target_path)
        self.scan_thread.match_found.connect(self.add_match_row)
        self.scan_thread.scan_completed.connect(self.file_scan_completed)
        self.scan_thread.start()
    
    def scan_processes(self):
        """Start YARA process scan."""
        if self.scan_thread and self.scan_thread.isRunning():
            return
        
        self.scan_processes_btn.setEnabled(False)
        self.scan_progress.setVisible(True)
        self.scan_progress.setValue(0)
        self.matches_table.setRowCount(0)
        self.status_label.setText("Running YARA process scan...")
        
        self.scan_thread = YaraScanThread(self.scanner, 'processes')
        self.scan_thread.match_found.connect(self.add_match_row)
        self.scan_thread.scan_completed.connect(self.process_scan_completed)
        self.scan_thread.start()
    
    def file_scan_completed(self, results):
        """Handle file scan completion."""
        self.scan_files_btn.setEnabled(True)
        self.scan_progress.setVisible(False)
        
        if 'error' in results:
            self.status_label.setText(f"Scan failed: {results['error']}")
            QMessageBox.critical(self, "Scan Error", results['error'])
        else:
            files_scanned = results.get('files_scanned', 0)
            matches_found = results.get('matches_found', 0)
            self.status_label.setText(f"File scan completed: {files_scanned} files scanned, {matches_found} matches")
            
            if matches_found > 0:
                # Find main window to show notification
                main_window = self.parent()
                while main_window and not hasattr(main_window, 'show_notification'):
                    main_window = main_window.parent()
                
                if main_window:
                    main_window.show_notification(
                        "YARA Matches Found",
                        f"Found {matches_found} YARA rule matches"
                    )
    
    def process_scan_completed(self, results):
        """Handle process scan completion."""
        self.scan_processes_btn.setEnabled(True)
        self.scan_progress.setVisible(False)
        
        if 'error' in results:
            self.status_label.setText(f"Process scan failed: {results['error']}")
            QMessageBox.critical(self, "Scan Error", results['error'])
        else:
            matches_found = results.get('matches_found', 0)
            self.status_label.setText(f"Process scan completed: {matches_found} matches")
            
            if matches_found > 0:
                # Find main window to show notification
                main_window = self.parent()
                while main_window and not hasattr(main_window, 'show_notification'):
                    main_window = main_window.parent()
                
                if main_window:
                    main_window.show_notification(
                        "YARA Process Matches",
                        f"Found {matches_found} YARA matches in running processes"
                    )
    
    def add_match_row(self, match_data):
        """Add YARA match to the table."""
        row = self.matches_table.rowCount()
        self.matches_table.insertRow(row)
        
        # Rule name
        rule_name = match_data.get('rule_name', 'Unknown')
        self.matches_table.setItem(row, 0, QTableWidgetItem(rule_name))
        
        # Target (file path or process info)
        target = match_data.get('file_path', 'Unknown')
        target_item = QTableWidgetItem(os.path.basename(target) if target.startswith('/') else target)
        target_item.setToolTip(target)
        self.matches_table.setItem(row, 1, target_item)
        
        # Matched strings
        matched_strings = match_data.get('matched_strings', [])
        strings_text = ', '.join(matched_strings[:3])
        if len(matched_strings) > 3:
            strings_text += f" (+{len(matched_strings)-3} more)"
        self.matches_table.setItem(row, 2, QTableWidgetItem(strings_text))
        
        # Confidence
        confidence = match_data.get('confidence', 0.0)
        confidence_item = QTableWidgetItem(f"{confidence:.2f}")
        
        if confidence > 0.8:
            confidence_item.setBackground(QColor(0, 255, 0, 100))
        elif confidence > 0.5:
            confidence_item.setBackground(QColor(255, 255, 0, 100))
        else:
            confidence_item.setBackground(QColor(255, 100, 100, 100))
        
        self.matches_table.setItem(row, 3, confidence_item)
        
        # Severity
        severity = match_data.get('severity', 'low').title()
        severity_item = QTableWidgetItem(severity)
        
        if severity == 'Critical':
            severity_item.setBackground(QColor(255, 0, 0, 100))
        elif severity == 'High':
            severity_item.setBackground(QColor(255, 100, 0, 100))
        elif severity == 'Medium':
            severity_item.setBackground(QColor(255, 255, 0, 100))
        
        self.matches_table.setItem(row, 4, severity_item)
        
        # Description
        description = match_data.get('description', 'No description')
        desc_item = QTableWidgetItem(description[:50] + "..." if len(description) > 50 else description)
        desc_item.setToolTip(description)
        self.matches_table.setItem(row, 5, desc_item)
        
        # Actions
        action = "Quarantine" if severity in ['Critical', 'High'] else "Monitor"
        self.matches_table.setItem(row, 6, QTableWidgetItem(action))
    
    def update_rules_statistics(self):
        """Update YARA rules statistics display."""
        try:
            stats = self.scanner.get_rule_statistics()
            
            stats_text = f"""YARA Rules Statistics
====================

Total Rules: {stats['total_rules']}
Recent Matches: {stats['recent_matches']}

Rule Types:"""
            
            for rule_type, count in stats.get('rule_types', {}).items():
                stats_text += f"\n  {rule_type}: {count}"
            
            stats_text += "\n\nRule Authors:"
            for author, count in stats.get('rule_authors', {}).items():
                stats_text += f"\n  {author}: {count}"
            
            self.rules_stats.setPlainText(stats_text)
            
        except Exception as e:
            self.rules_stats.setPlainText(f"Error updating statistics: {str(e)}")
    
    def update_active_rules_list(self):
        """Update active rules list."""
        try:
            self.active_rules_list.clear()
            
            for rule_name, rule in self.scanner.loaded_rules.items():
                item_text = f"{rule_name} - {rule.description[:50]}"
                self.active_rules_list.addItem(item_text)
                
        except Exception as e:
            print(f"Error updating active rules: {e}")
    
    def filter_matches(self):
        """Filter YARA matches based on current filter settings."""
        severity_filter = self.severity_filter.currentText()
        confidence_filter = self.confidence_filter.currentText()
        
        for row in range(self.matches_table.rowCount()):
            confidence_item = self.matches_table.item(row, 3)
            severity_item = self.matches_table.item(row, 4)
            
            if not all([confidence_item, severity_item]):
                continue
            
            confidence = float(confidence_item.text())
            severity = severity_item.text()
            
            show_row = True
            
            if severity_filter != "All Severities" and severity != severity_filter:
                show_row = False
            
            if confidence_filter != "All Confidence":
                if confidence_filter == "High (>0.8)" and confidence <= 0.8:
                    show_row = False
                elif confidence_filter == "Medium (>0.5)" and confidence <= 0.5:
                    show_row = False
                elif confidence_filter == "Low (<0.5)" and confidence >= 0.5:
                    show_row = False
            
            self.matches_table.setRowHidden(row, not show_row)
    
    def view_match_details(self, item):
        """View detailed information about a YARA match."""
        row = item.row()
        
        rule_name = self.matches_table.item(row, 0).text()
        target = self.matches_table.item(row, 1).toolTip() or self.matches_table.item(row, 1).text()
        matched_strings = self.matches_table.item(row, 2).text()
        confidence = self.matches_table.item(row, 3).text()
        severity = self.matches_table.item(row, 4).text()
        description = self.matches_table.item(row, 5).toolTip() or self.matches_table.item(row, 5).text()
        
        details_text = f"""YARA Match Details
==================

Rule Name: {rule_name}
Target: {target}
Matched Strings: {matched_strings}
Confidence: {confidence}
Severity: {severity}

Description: {description}

Analysis Recommendations:
1. Quarantine the file/process if high confidence
2. Perform additional analysis with other tools
3. Check system logs for related activities
4. Verify if detection is legitimate software
5. Update security policies based on findings

Rule Information:
- Check rule metadata for additional context
- Review rule logic and conditions
- Consider updating rule if false positive
"""
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("YARA Match Details")
        msg_box.setText(details_text)
        msg_box.exec()
    
    def start_monitoring(self):
        """Start YARA monitoring."""
        self.status_label.setText("YARA monitoring active")
        
    def stop_monitoring(self):
        """Stop YARA monitoring."""
        self.status_label.setText("YARA monitoring stopped")
        
    def export_results(self):
        """Export YARA scan results."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"yara_results_{timestamp}.json"
        
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Export YARA Results", default_filename, 
            "JSON Files (*.json);;All Files (*)"
        )
        
        if output_path:
            try:
                self.scanner.export_yara_results(output_path)
                QMessageBox.information(self, "Export Successful", 
                                      f"Results exported to: {output_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", 
                                   f"Failed to export results: {str(e)}")


# Import QInputDialog
from PyQt6.QtWidgets import QInputDialog