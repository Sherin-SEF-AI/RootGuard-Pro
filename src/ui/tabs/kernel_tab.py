"""
Kernel Integrity Analysis Tab
Interface for kernel module integrity verification and security analysis.
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                             QTableWidgetItem, QPushButton, QLabel, QComboBox,
                             QMessageBox, QHeaderView, QTextEdit, QGroupBox,
                             QSplitter, QProgressBar)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont

import sys
import os
import json
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from detection.kernel_integrity import KernelIntegrityVerifier
from datetime import datetime


class KernelAnalysisThread(QThread):
    """Background thread for kernel analysis."""
    
    progress_updated = pyqtSignal(int)
    analysis_completed = pyqtSignal(dict)
    module_analyzed = pyqtSignal(dict)
    
    def __init__(self, verifier, analysis_type):
        super().__init__()
        self.verifier = verifier
        self.analysis_type = analysis_type
    
    def run(self):
        """Run kernel analysis."""
        try:
            if self.analysis_type == 'comprehensive':
                self.progress_updated.emit(25)
                results = self.verifier.comprehensive_kernel_analysis()
                self.progress_updated.emit(100)
                self.analysis_completed.emit(results)
                
            elif self.analysis_type == 'modules':
                self.progress_updated.emit(25)
                results = self.verifier.analyze_module_integrity()
                self.progress_updated.emit(100)
                self.analysis_completed.emit(results)
                
        except Exception as e:
            self.analysis_completed.emit({'error': str(e)})


class KernelTab(QWidget):
    """Kernel integrity analysis tab widget."""
    
    def __init__(self):
        super().__init__()
        self.verifier = KernelIntegrityVerifier()
        self.init_ui()
        self.analysis_thread = None
        
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Create splitter for main layout
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Controls and analysis
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        # Analysis controls group
        controls_group = QGroupBox("Kernel Analysis")
        controls_layout = QVBoxLayout(controls_group)
        
        # Analysis buttons
        analysis_btn_layout = QHBoxLayout()
        
        self.module_analysis_btn = QPushButton("Analyze Modules")
        self.module_analysis_btn.clicked.connect(self.analyze_modules)
        analysis_btn_layout.addWidget(self.module_analysis_btn)
        
        self.comprehensive_btn = QPushButton("Comprehensive Analysis")
        self.comprehensive_btn.clicked.connect(self.run_comprehensive_analysis)
        analysis_btn_layout.addWidget(self.comprehensive_btn)
        
        controls_layout.addLayout(analysis_btn_layout)
        
        # Baseline management
        baseline_btn_layout = QHBoxLayout()
        
        self.create_baseline_btn = QPushButton("Create Baseline")
        self.create_baseline_btn.clicked.connect(self.create_baseline)
        baseline_btn_layout.addWidget(self.create_baseline_btn)
        
        self.verify_symbols_btn = QPushButton("Verify Symbols")
        self.verify_symbols_btn.clicked.connect(self.verify_symbols)
        baseline_btn_layout.addWidget(self.verify_symbols_btn)
        
        controls_layout.addLayout(baseline_btn_layout)
        
        # Progress bar
        self.analysis_progress = QProgressBar()
        self.analysis_progress.setVisible(False)
        controls_layout.addWidget(self.analysis_progress)
        
        left_layout.addWidget(controls_group)
        
        # Security status group
        security_group = QGroupBox("Kernel Security Status")
        security_layout = QVBoxLayout(security_group)
        
        self.security_status = QTextEdit()
        self.security_status.setMaximumHeight(200)
        self.security_status.setFont(QFont("Consolas", 9))
        self.security_status.setReadOnly(True)
        security_layout.addWidget(self.security_status)
        
        # Refresh security status
        refresh_security_btn = QPushButton("Refresh Security Status")
        refresh_security_btn.clicked.connect(self.update_security_status)
        security_layout.addWidget(refresh_security_btn)
        
        left_layout.addWidget(security_group)
        
        # Module summary group
        summary_group = QGroupBox("Module Summary")
        summary_layout = QVBoxLayout(summary_group)
        
        self.module_summary = QTextEdit()
        self.module_summary.setMaximumHeight(150)
        self.module_summary.setFont(QFont("Consolas", 9))
        self.module_summary.setReadOnly(True)
        summary_layout.addWidget(self.module_summary)
        
        left_layout.addWidget(summary_group)
        left_layout.addStretch()
        
        # Right panel - Analysis results
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "Critical", "High", "Medium", "Low"])
        self.severity_filter.currentTextChanged.connect(self.filter_results)
        filter_layout.addWidget(self.severity_filter)
        
        self.type_filter = QComboBox()
        self.type_filter.addItems(["All Types", "Suspicious Modules", "Integrity Violations", 
                                  "Rootkit Indicators", "Configuration Issues"])
        self.type_filter.currentTextChanged.connect(self.filter_results)
        filter_layout.addWidget(self.type_filter)
        
        filter_layout.addStretch()
        right_layout.addLayout(filter_layout)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "Type", "Module/Component", "Issue", "Severity", "Details", "Action"
        ])
        
        # Configure table
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.results_table.itemDoubleClicked.connect(self.view_result_details)
        
        right_layout.addWidget(self.results_table)
        
        # Add widgets to splitter
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([400, 600])
        
        layout.addWidget(splitter)
        
        # Status label
        self.status_label = QLabel("Ready for kernel integrity analysis")
        layout.addWidget(self.status_label)
        
        # Load initial data
        self.update_security_status()
        self.update_module_summary()
    
    def analyze_modules(self):
        """Analyze kernel module integrity."""
        if self.analysis_thread and self.analysis_thread.isRunning():
            return
        
        self.module_analysis_btn.setEnabled(False)
        self.analysis_progress.setVisible(True)
        self.analysis_progress.setValue(0)
        self.results_table.setRowCount(0)
        self.status_label.setText("Analyzing kernel modules...")
        
        self.analysis_thread = KernelAnalysisThread(self.verifier, 'modules')
        self.analysis_thread.progress_updated.connect(self.analysis_progress.setValue)
        self.analysis_thread.analysis_completed.connect(self.module_analysis_completed)
        self.analysis_thread.start()
    
    def run_comprehensive_analysis(self):
        """Run comprehensive kernel security analysis."""
        if self.analysis_thread and self.analysis_thread.isRunning():
            return
        
        self.comprehensive_btn.setEnabled(False)
        self.analysis_progress.setVisible(True)
        self.analysis_progress.setValue(0)
        self.results_table.setRowCount(0)
        self.status_label.setText("Running comprehensive kernel analysis...")
        
        self.analysis_thread = KernelAnalysisThread(self.verifier, 'comprehensive')
        self.analysis_thread.progress_updated.connect(self.analysis_progress.setValue)
        self.analysis_thread.analysis_completed.connect(self.comprehensive_analysis_completed)
        self.analysis_thread.start()
    
    def module_analysis_completed(self, results):
        """Handle module analysis completion."""
        self.module_analysis_btn.setEnabled(True)
        self.analysis_progress.setVisible(False)
        
        if 'error' in results:
            self.status_label.setText(f"Analysis failed: {results['error']}")
            QMessageBox.critical(self, "Analysis Error", results['error'])
            return
        
        # Add suspicious modules to results table
        for module in results.get('suspicious_modules', []):
            self.add_result_row({
                'type': 'Suspicious Module',
                'component': module['name'],
                'issue': module['reason'],
                'severity': 'high',
                'details': f"Size: {module['size']}, Path: {module['path']}"
            })
        
        # Add integrity violations
        for violation in results.get('integrity_violations', []):
            self.add_result_row({
                'type': 'Integrity Violation',
                'component': violation['module'],
                'issue': violation['type'].replace('_', ' ').title(),
                'severity': violation['severity'],
                'details': str(violation)
            })
        
        # Add unsigned modules
        for module in results.get('unsigned_modules', []):
            self.add_result_row({
                'type': 'Unsigned Module',
                'component': module['name'],
                'issue': 'Module not digitally signed',
                'severity': 'medium',
                'details': f"Size: {module['size']}, Path: {module['path']}"
            })
        
        total_issues = (len(results.get('suspicious_modules', [])) + 
                       len(results.get('integrity_violations', [])) + 
                       len(results.get('unsigned_modules', [])))
        
        self.status_label.setText(f"Module analysis completed: {total_issues} issues found")
        
        if total_issues > 0:
            # Find main window to show notification
            main_window = self.parent()
            while main_window and not hasattr(main_window, 'show_notification'):
                main_window = main_window.parent()
            
            if main_window:
                main_window.show_notification(
                    "Kernel Module Issues",
                    f"Found {total_issues} kernel module integrity issues"
                )
    
    def comprehensive_analysis_completed(self, results):
        """Handle comprehensive analysis completion."""
        self.comprehensive_btn.setEnabled(True)
        self.analysis_progress.setVisible(False)
        
        if 'error' in results:
            self.status_label.setText(f"Analysis failed: {results['error']}")
            QMessageBox.critical(self, "Analysis Error", results['error'])
            return
        
        # Process all analysis results
        self.results_table.setRowCount(0)
        
        # Add module integrity results
        module_results = results.get('module_integrity', {})
        for module in module_results.get('suspicious_modules', []):
            self.add_result_row({
                'type': 'Suspicious Module',
                'component': module['name'],
                'issue': module['reason'],
                'severity': 'high',
                'details': f"Size: {module['size']}"
            })
        
        # Add rootkit indicators
        for indicator in results.get('rootkit_indicators', []):
            self.add_result_row({
                'type': 'Rootkit Indicator',
                'component': indicator.get('module_name', 'System'),
                'issue': indicator['type'].replace('_', ' ').title(),
                'severity': indicator['severity'],
                'details': indicator['description']
            })
        
        # Add configuration issues
        config_results = results.get('configuration_check', {})
        disabled_features = [
            feature for feature, enabled in config_results.get('security_features', {}).items()
            if not enabled
        ]
        
        for feature in disabled_features:
            self.add_result_row({
                'type': 'Configuration Issue',
                'component': 'Kernel',
                'issue': f'{feature.upper()} Disabled',
                'severity': 'medium',
                'details': f'Security feature {feature} is not enabled'
            })
        
        risk_score = results.get('overall_risk_score', 0.0)
        total_issues = self.results_table.rowCount()
        
        self.status_label.setText(f"Comprehensive analysis completed: Risk score {risk_score:.2f}, {total_issues} issues")
        
        # Update security status
        self.update_security_status()
        self.update_module_summary()
    
    def add_result_row(self, result_data):
        """Add analysis result to the table."""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        # Type
        self.results_table.setItem(row, 0, QTableWidgetItem(result_data['type']))
        
        # Component
        self.results_table.setItem(row, 1, QTableWidgetItem(result_data['component']))
        
        # Issue
        self.results_table.setItem(row, 2, QTableWidgetItem(result_data['issue']))
        
        # Severity
        severity = result_data['severity'].title()
        severity_item = QTableWidgetItem(severity)
        
        if severity == 'Critical':
            severity_item.setBackground(QColor(255, 0, 0, 100))
        elif severity == 'High':
            severity_item.setBackground(QColor(255, 100, 0, 100))
        elif severity == 'Medium':
            severity_item.setBackground(QColor(255, 255, 0, 100))
        
        self.results_table.setItem(row, 3, severity_item)
        
        # Details
        details = result_data['details']
        details_item = QTableWidgetItem(details[:50] + "..." if len(details) > 50 else details)
        details_item.setToolTip(details)
        self.results_table.setItem(row, 4, details_item)
        
        # Action
        action = "Investigate" if severity in ['Critical', 'High'] else "Monitor"
        self.results_table.setItem(row, 5, QTableWidgetItem(action))
    
    def create_baseline(self):
        """Create kernel module baseline."""
        try:
            self.status_label.setText("Creating kernel baseline...")
            success = self.verifier.create_kernel_baseline()
            
            if success:
                self.status_label.setText("Kernel baseline created successfully")
                QMessageBox.information(self, "Baseline Created", 
                                      "Kernel module baseline has been created successfully.")
                self.update_module_summary()
            else:
                self.status_label.setText("Baseline creation failed")
                QMessageBox.critical(self, "Baseline Creation Failed", 
                                   "Failed to create kernel baseline.")
                
        except Exception as e:
            self.status_label.setText("Baseline creation error")
            QMessageBox.critical(self, "Baseline Error", f"Error creating baseline: {str(e)}")
    
    def verify_symbols(self):
        """Verify kernel symbol table integrity."""
        try:
            self.status_label.setText("Verifying kernel symbols...")
            results = self.verifier.verify_kernel_symbols()
            
            symbol_count = results.get('symbol_count', 0)
            suspicious_count = len(results.get('suspicious_symbols', []))
            conflicts_count = len(results.get('symbol_conflicts', []))
            
            results_text = f"""Kernel Symbol Verification Results
====================================

Total Symbols: {symbol_count}
Suspicious Symbols: {suspicious_count}
Symbol Conflicts: {conflicts_count}

"""
            
            if suspicious_count > 0:
                results_text += "Suspicious Symbols Found:\n"
                for sym in results.get('suspicious_symbols', [])[:5]:
                    results_text += f"- {sym['symbol']} at {sym['address']}\n"
            
            if conflicts_count > 0:
                results_text += "\nSymbol Conflicts Found:\n"
                for conflict in results.get('symbol_conflicts', [])[:3]:
                    results_text += f"- {conflict['symbol']}: {len(conflict['addresses'])} addresses\n"
            
            self.status_label.setText("Symbol verification completed")
            
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Symbol Verification Results")
            msg_box.setText(results_text)
            msg_box.exec()
            
        except Exception as e:
            self.status_label.setText("Symbol verification failed")
            QMessageBox.critical(self, "Verification Error", f"Error verifying symbols: {str(e)}")
    
    def update_security_status(self):
        """Update kernel security status display."""
        try:
            config_results = self.verifier.check_kernel_configuration()
            
            status_text = f"""Kernel Security Configuration
==============================

"""
            
            security_features = config_results.get('security_features', {})
            for feature, enabled in security_features.items():
                status = "✓ Enabled" if enabled else "✗ Disabled"
                status_text += f"{feature.upper()}: {status}\n"
            
            risk_level = config_results.get('risk_level', 'unknown')
            status_text += f"\nOverall Risk Level: {risk_level.upper()}\n"
            
            recommendations = config_results.get('recommendations', [])
            if recommendations:
                status_text += "\nRecommendations:\n"
                for rec in recommendations[:5]:
                    status_text += f"- {rec}\n"
            
            self.security_status.setPlainText(status_text)
            
        except Exception as e:
            self.security_status.setPlainText(f"Error updating security status: {str(e)}")
    
    def update_module_summary(self):
        """Update module summary display."""
        try:
            modules = self.verifier.enumerate_kernel_modules()
            
            total_modules = len(modules)
            signed_modules = len([m for m in modules if m.signature_valid])
            unsigned_modules = total_modules - signed_modules
            
            large_modules = len([m for m in modules if m.size > 1000000])  # >1MB
            unused_modules = len([m for m in modules if m.use_count == 0])
            
            summary_text = f"""Kernel Module Summary
===================

Total Loaded Modules: {total_modules}
Signed Modules: {signed_modules}
Unsigned Modules: {unsigned_modules}
Large Modules (>1MB): {large_modules}
Unused Modules: {unused_modules}

Recent Module Activity:
- Modules analyzed: {total_modules}
- Baselines available: Check database
- Last analysis: {datetime.now().strftime('%H:%M:%S')}
"""
            
            self.module_summary.setPlainText(summary_text)
            
        except Exception as e:
            self.module_summary.setPlainText(f"Error updating summary: {str(e)}")
    
    def filter_results(self):
        """Filter analysis results based on current filter settings."""
        severity_filter = self.severity_filter.currentText()
        type_filter = self.type_filter.currentText()
        
        for row in range(self.results_table.rowCount()):
            type_item = self.results_table.item(row, 0)
            severity_item = self.results_table.item(row, 3)
            
            if not all([type_item, severity_item]):
                continue
            
            result_type = type_item.text()
            severity = severity_item.text()
            
            show_row = True
            
            if severity_filter != "All Severities" and severity != severity_filter:
                show_row = False
            
            if type_filter != "All Types":
                type_match = False
                if type_filter == "Suspicious Modules" and "Suspicious Module" in result_type:
                    type_match = True
                elif type_filter == "Integrity Violations" and "Integrity Violation" in result_type:
                    type_match = True
                elif type_filter == "Rootkit Indicators" and "Rootkit Indicator" in result_type:
                    type_match = True
                elif type_filter == "Configuration Issues" and "Configuration Issue" in result_type:
                    type_match = True
                
                if not type_match:
                    show_row = False
            
            self.results_table.setRowHidden(row, not show_row)
    
    def view_result_details(self, item):
        """View detailed information about an analysis result."""
        row = item.row()
        
        result_type = self.results_table.item(row, 0).text()
        component = self.results_table.item(row, 1).text()
        issue = self.results_table.item(row, 2).text()
        severity = self.results_table.item(row, 3).text()
        details = self.results_table.item(row, 4).toolTip() or self.results_table.item(row, 4).text()
        action = self.results_table.item(row, 5).text()
        
        details_text = f"""Kernel Analysis Result Details
===============================

Type: {result_type}
Component: {component}
Issue: {issue}
Severity: {severity}

Details: {details}

Recommended Action: {action}

Investigation Steps:
1. Verify the component is legitimate
2. Check system logs for related activities
3. Research the component online
4. Consider removing if confirmed malicious
5. Update system security policies

Additional Analysis:
- Check module dependencies
- Verify digital signatures
- Analyze module behavior
- Compare with known good baselines
"""
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Analysis Result Details")
        msg_box.setText(details_text)
        msg_box.exec()
    
    def start_monitoring(self):
        """Start kernel integrity monitoring."""
        self.status_label.setText("Kernel integrity monitoring active")
        
    def stop_monitoring(self):
        """Stop kernel integrity monitoring."""
        self.status_label.setText("Kernel integrity monitoring stopped")
        
    def export_results(self):
        """Export kernel analysis results."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"kernel_analysis_{timestamp}.json"
        
        from PyQt6.QtWidgets import QFileDialog
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Export Kernel Analysis", default_filename, 
            "JSON Files (*.json);;All Files (*)"
        )
        
        if output_path:
            try:
                self.verifier.export_kernel_analysis(output_path)
                QMessageBox.information(self, "Export Successful", 
                                      f"Analysis exported to: {output_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", 
                                   f"Failed to export analysis: {str(e)}")