"""
Reports Tab
Generates and manages scan reports.
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, 
                             QPushButton, QLabel, QComboBox, QDateEdit,
                             QMessageBox, QFileDialog, QGroupBox, QCheckBox)
from PyQt6.QtCore import Qt, QDate, QThread, pyqtSignal
from PyQt6.QtGui import QFont

import sys
import os
import subprocess
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from utils.report_generator import ReportGenerator
import datetime


class ReportGenerationThread(QThread):
    """Background thread for report generation."""
    
    progress_updated = pyqtSignal(int)
    report_generated = pyqtSignal(str)
    
    def __init__(self, report_type, output_path, include_sections):
        super().__init__()
        self.report_type = report_type
        self.output_path = output_path
        self.include_sections = include_sections
    
    def run(self):
        """Generate the report."""
        try:
            generator = ReportGenerator()
            
            self.progress_updated.emit(25)
            
            if self.report_type == "PDF":
                generator.generate_pdf_report(self.output_path, self.include_sections)
            elif self.report_type == "HTML":
                generator.generate_html_report(self.output_path, self.include_sections)
            elif self.report_type == "CSV":
                generator.generate_csv_report(self.output_path, self.include_sections)
            
            self.progress_updated.emit(100)
            self.report_generated.emit(self.output_path)
            
        except Exception as e:
            self.report_generated.emit(f"Error: {str(e)}")


class ReportsTab(QWidget):
    """Reports tab widget."""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.report_thread = None
        
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Report generation section
        gen_group = QGroupBox("Generate New Report")
        gen_layout = QVBoxLayout(gen_group)
        
        # Report type selection
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Report Type:"))
        
        self.report_type_combo = QComboBox()
        self.report_type_combo.addItems(["PDF", "HTML", "CSV"])
        type_layout.addWidget(self.report_type_combo)
        
        # Date range
        type_layout.addWidget(QLabel("From:"))
        self.from_date = QDateEdit(QDate.currentDate().addDays(-7))
        self.from_date.setCalendarPopup(True)
        type_layout.addWidget(self.from_date)
        
        type_layout.addWidget(QLabel("To:"))
        self.to_date = QDateEdit(QDate.currentDate())
        self.to_date.setCalendarPopup(True)
        type_layout.addWidget(self.to_date)
        
        type_layout.addStretch()
        gen_layout.addLayout(type_layout)
        
        # Include sections
        sections_layout = QHBoxLayout()
        sections_layout.addWidget(QLabel("Include Sections:"))
        
        self.include_processes = QCheckBox("Processes")
        self.include_processes.setChecked(True)
        sections_layout.addWidget(self.include_processes)
        
        self.include_services = QCheckBox("Services")
        self.include_services.setChecked(True)
        sections_layout.addWidget(self.include_services)
        
        self.include_network = QCheckBox("Network")
        self.include_network.setChecked(True)
        sections_layout.addWidget(self.include_network)
        
        self.include_hooks = QCheckBox("Hooks")
        self.include_hooks.setChecked(True)
        sections_layout.addWidget(self.include_hooks)
        
        sections_layout.addStretch()
        gen_layout.addLayout(sections_layout)
        
        # Generate button
        button_layout = QHBoxLayout()
        self.generate_btn = QPushButton("Generate Report")
        self.generate_btn.clicked.connect(self.generate_report)
        button_layout.addWidget(self.generate_btn)
        
        self.open_folder_btn = QPushButton("Open Reports Folder")
        self.open_folder_btn.clicked.connect(self.open_reports_folder)
        button_layout.addWidget(self.open_folder_btn)
        
        button_layout.addStretch()
        gen_layout.addLayout(button_layout)
        
        layout.addWidget(gen_group)
        
        # Report preview section
        preview_group = QGroupBox("Report Preview")
        preview_layout = QVBoxLayout(preview_group)
        
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setFont(QFont("Consolas", 10))
        self.report_preview.setPlainText("Select a report type and click 'Generate Report' to create a security analysis report.")
        
        preview_layout.addWidget(self.report_preview)
        layout.addWidget(preview_group)
        
        # Status label
        self.status_label = QLabel("Ready to generate reports")
        layout.addWidget(self.status_label)
        
    def generate_report(self):
        """Generate a security report."""
        if self.report_thread and self.report_thread.isRunning():
            return
        
        # Get selected options
        report_type = self.report_type_combo.currentText()
        include_sections = {
            'processes': self.include_processes.isChecked(),
            'services': self.include_services.isChecked(),
            'network': self.include_network.isChecked(),
            'hooks': self.include_hooks.isChecked()
        }
        
        # Choose output file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"rootkit_scan_{timestamp}"
        
        if report_type == "PDF":
            file_filter = "PDF Files (*.pdf)"
            default_filename += ".pdf"
        elif report_type == "HTML":
            file_filter = "HTML Files (*.html)"
            default_filename += ".html"
        else:
            file_filter = "CSV Files (*.csv)"
            default_filename += ".csv"
        
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", default_filename, file_filter
        )
        
        if not output_path:
            return
        
        # Start report generation
        self.generate_btn.setEnabled(False)
        self.status_label.setText("Generating report...")
        
        self.report_thread = ReportGenerationThread(report_type, output_path, include_sections)
        self.report_thread.progress_updated.connect(self.update_progress)
        self.report_thread.report_generated.connect(self.report_generated)
        self.report_thread.start()
        
    def update_progress(self, value):
        """Update report generation progress."""
        self.status_label.setText(f"Generating report... {value}%")
        
    def report_generated(self, result):
        """Handle report generation completion."""
        self.generate_btn.setEnabled(True)
        
        if result.startswith("Error:"):
            self.status_label.setText("Report generation failed")
            QMessageBox.critical(self, "Report Generation Failed", result)
        else:
            self.status_label.setText(f"Report generated: {os.path.basename(result)}")
            
            reply = QMessageBox.question(
                self, "Report Generated",
                f"Report successfully generated at:\n{result}\n\nWould you like to open it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                # Linux-compatible file opening
                subprocess.run(['xdg-open', result], check=False)
        
        # Update preview
        self.update_preview()
    
    def update_preview(self):
        """Update the report preview."""
        try:
            generator = ReportGenerator()
            preview_text = generator.generate_text_preview()
            self.report_preview.setPlainText(preview_text)
        except Exception as e:
            self.report_preview.setPlainText(f"Error generating preview: {str(e)}")
    
    def open_reports_folder(self):
        """Open the reports folder in file explorer."""
        reports_dir = os.path.join(os.getcwd(), "reports")
        
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
        
        subprocess.run(['xdg-open', reports_dir], check=False)  # Linux-compatible
    
    def export_results(self):
        """Export current scan results."""
        self.generate_report()
    
    def start_monitoring(self):
        """Start real-time monitoring for reports."""
        self.status_label.setText("Continuous monitoring active - reports will be generated hourly")
        
    def stop_monitoring(self):
        """Stop real-time monitoring."""
        self.status_label.setText("Continuous monitoring stopped")