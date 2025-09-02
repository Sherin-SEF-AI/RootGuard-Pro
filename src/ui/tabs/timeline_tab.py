"""
Timeline Analysis and Forensics Tab
Interface for incident timeline reconstruction and forensic analysis.
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                             QTableWidgetItem, QPushButton, QLabel, QComboBox,
                             QMessageBox, QHeaderView, QTextEdit, QGroupBox,
                             QSplitter, QProgressBar, QDateTimeEdit, QSlider,
                             QCheckBox, QSpinBox, QTreeWidget, QTreeWidgetItem)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QDateTime
from PyQt6.QtGui import QColor, QFont

import sys
import os
import json
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from forensics.timeline_analyzer import TimelineAnalyzer
from datetime import datetime, timedelta
import time

class TimelineAnalysisThread(QThread):
    """Background thread for timeline analysis."""
    
    progress_updated = pyqtSignal(int)
    event_collected = pyqtSignal(dict)
    analysis_completed = pyqtSignal(dict)
    correlation_found = pyqtSignal(dict)
    
    def __init__(self, analyzer, start_time, end_time, analysis_type):
        super().__init__()
        self.analyzer = analyzer
        self.start_time = start_time
        self.end_time = end_time
        self.analysis_type = analysis_type
    
    def run(self):
        """Run timeline analysis."""
        try:
            if self.analysis_type == 'collect_events':
                self.progress_updated.emit(25)
                events = self.analyzer.collect_system_events(int(self.end_time - self.start_time))
                
                self.progress_updated.emit(50)
                for event in events:
                    self.event_collected.emit(event.__dict__)
                
                self.progress_updated.emit(75)
                correlations = self.analyzer.correlate_events(events)
                
                for correlation in correlations:
                    self.correlation_found.emit(correlation)
                
                self.progress_updated.emit(100)
                
                result = {
                    'events_collected': len(events),
                    'correlations_found': len(correlations)
                }
                self.analysis_completed.emit(result)
                
            elif self.analysis_type == 'incident_timeline':
                self.progress_updated.emit(25)
                timeline_report = self.analyzer.generate_incident_timeline(self.start_time, self.end_time)
                self.progress_updated.emit(100)
                self.analysis_completed.emit(timeline_report)
                
        except Exception as e:
            self.analysis_completed.emit({'error': str(e)})

class TimelineTab(QWidget):
    """Timeline analysis and forensics tab widget."""
    
    def __init__(self):
        super().__init__()
        self.analyzer = TimelineAnalyzer()
        self.init_ui()
        self.analysis_thread = None
        
        # Setup callbacks
        self.analyzer.add_analysis_callback(self.on_critical_event)
    
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Create splitter for main layout
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Analysis controls
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        # Time range selection group
        time_group = QGroupBox("Timeline Analysis Period")
        time_layout = QVBoxLayout(time_group)
        
        # Start time
        start_layout = QHBoxLayout()
        start_layout.addWidget(QLabel("Start Time:"))
        self.start_datetime = QDateTimeEdit()
        self.start_datetime.setDateTime(QDateTime.currentDateTime().addSecs(-3600))  # 1 hour ago
        start_layout.addWidget(self.start_datetime)
        time_layout.addLayout(start_layout)
        
        # End time
        end_layout = QHBoxLayout()
        end_layout.addWidget(QLabel("End Time:"))
        self.end_datetime = QDateTimeEdit()
        self.end_datetime.setDateTime(QDateTime.currentDateTime())
        end_layout.addWidget(self.end_datetime)
        time_layout.addLayout(end_layout)
        
        # Quick time selections
        quick_time_layout = QHBoxLayout()
        
        last_hour_btn = QPushButton("Last Hour")
        last_hour_btn.clicked.connect(lambda: self.set_time_range(hours=1))
        quick_time_layout.addWidget(last_hour_btn)
        
        last_day_btn = QPushButton("Last 24h")
        last_day_btn.clicked.connect(lambda: self.set_time_range(hours=24))
        quick_time_layout.addWidget(last_day_btn)
        
        time_layout.addLayout(quick_time_layout)
        left_layout.addWidget(time_group)
        
        # Analysis controls group
        analysis_group = QGroupBox("Forensic Analysis")
        analysis_layout = QVBoxLayout(analysis_group)
        
        # Analysis buttons
        analysis_btn_layout = QHBoxLayout()
        
        self.collect_events_btn = QPushButton("Collect Events")
        self.collect_events_btn.clicked.connect(self.collect_timeline_events)
        analysis_btn_layout.addWidget(self.collect_events_btn)
        
        self.incident_analysis_btn = QPushButton("Incident Analysis")
        self.incident_analysis_btn.clicked.connect(self.run_incident_analysis)
        analysis_btn_layout.addWidget(self.incident_analysis_btn)
        
        analysis_layout.addLayout(analysis_btn_layout)
        
        # Analysis options
        options_layout = QVBoxLayout()
        
        self.correlate_events_check = QCheckBox("Enable Event Correlation")
        self.correlate_events_check.setChecked(True)
        options_layout.addWidget(self.correlate_events_check)
        
        self.collect_evidence_check = QCheckBox("Auto-collect Evidence")
        self.collect_evidence_check.setChecked(True)
        options_layout.addWidget(self.collect_evidence_check)
        
        analysis_layout.addLayout(options_layout)
        
        # Progress bar
        self.analysis_progress = QProgressBar()
        self.analysis_progress.setVisible(False)
        analysis_layout.addWidget(self.analysis_progress)
        
        left_layout.addWidget(analysis_group)
        
        # Statistics group
        stats_group = QGroupBox("Timeline Statistics")
        stats_layout = QVBoxLayout(stats_group)
        
        self.stats_display = QTextEdit()
        self.stats_display.setMaximumHeight(200)
        self.stats_display.setFont(QFont("Consolas", 9))
        self.stats_display.setReadOnly(True)
        stats_layout.addWidget(self.stats_display)
        
        # Refresh stats button
        refresh_stats_btn = QPushButton("Refresh Statistics")
        refresh_stats_btn.clicked.connect(self.update_statistics)
        stats_layout.addWidget(refresh_stats_btn)
        
        left_layout.addWidget(stats_group)
        left_layout.addStretch()
        
        # Right panel - Timeline and correlations
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        
        self.event_type_filter = QComboBox()
        self.event_type_filter.addItems(["All Events", "Process Events", "Network Events", 
                                        "File Events", "System Events", "Audit Events"])
        self.event_type_filter.currentTextChanged.connect(self.filter_timeline)
        filter_layout.addWidget(self.event_type_filter)
        
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "Critical", "High", "Medium", "Low"])
        self.severity_filter.currentTextChanged.connect(self.filter_timeline)
        filter_layout.addWidget(self.severity_filter)
        
        filter_layout.addStretch()
        right_layout.addLayout(filter_layout)
        
        # Timeline events table
        self.timeline_table = QTableWidget()
        self.timeline_table.setColumnCount(6)
        self.timeline_table.setHorizontalHeaderLabels([
            "Timestamp", "Event Type", "Source", "Description", "Severity", "Correlation ID"
        ])
        
        # Configure table
        header = self.timeline_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        
        self.timeline_table.setAlternatingRowColors(True)
        self.timeline_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.timeline_table.itemDoubleClicked.connect(self.view_event_details)
        
        right_layout.addWidget(self.timeline_table)
        
        # Correlations tree
        correlations_group = QGroupBox("Event Correlations")
        correlations_layout = QVBoxLayout(correlations_group)
        
        self.correlations_tree = QTreeWidget()
        self.correlations_tree.setHeaderLabels(["Pattern/Correlation", "Confidence", "Events", "Severity"])
        self.correlations_tree.itemDoubleClicked.connect(self.view_correlation_details)
        correlations_layout.addWidget(self.correlations_tree)
        
        right_layout.addWidget(correlations_group)
        
        # Add widgets to splitter
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([350, 850])
        
        layout.addWidget(splitter)
        
        # Status label
        self.status_label = QLabel("Timeline analysis ready")
        layout.addWidget(self.status_label)
        
        # Load initial data
        self.update_statistics()
    
    def set_time_range(self, hours: int):
        """Set time range for analysis."""
        end_time = QDateTime.currentDateTime()
        start_time = end_time.addSecs(-hours * 3600)
        
        self.start_datetime.setDateTime(start_time)
        self.end_datetime.setDateTime(end_time)
    
    def collect_timeline_events(self):
        """Collect timeline events for analysis."""
        if self.analysis_thread and self.analysis_thread.isRunning():
            return
        
        start_time = self.start_datetime.dateTime().toPyDateTime().timestamp()
        end_time = self.end_datetime.dateTime().toPyDateTime().timestamp()
        
        if start_time >= end_time:
            QMessageBox.warning(self, "Invalid Time Range", "Start time must be before end time.")
            return
        
        self.collect_events_btn.setEnabled(False)
        self.analysis_progress.setVisible(True)
        self.analysis_progress.setValue(0)
        self.timeline_table.setRowCount(0)
        self.correlations_tree.clear()
        
        duration_hours = (end_time - start_time) / 3600
        self.status_label.setText(f"Collecting timeline events ({duration_hours:.1f} hours)...")
        
        self.analysis_thread = TimelineAnalysisThread(self.analyzer, start_time, end_time, 'collect_events')
        self.analysis_thread.progress_updated.connect(self.analysis_progress.setValue)
        self.analysis_thread.event_collected.connect(self.add_timeline_event)
        self.analysis_thread.correlation_found.connect(self.add_correlation_item)
        self.analysis_thread.analysis_completed.connect(self.events_collection_completed)
        self.analysis_thread.start()
    
    def run_incident_analysis(self):
        """Run comprehensive incident timeline analysis."""
        if self.analysis_thread and self.analysis_thread.isRunning():
            return
        
        start_time = self.start_datetime.dateTime().toPyDateTime().timestamp()
        end_time = self.end_datetime.dateTime().toPyDateTime().timestamp()
        
        if start_time >= end_time:
            QMessageBox.warning(self, "Invalid Time Range", "Start time must be before end time.")
            return
        
        self.incident_analysis_btn.setEnabled(False)
        self.analysis_progress.setVisible(True)
        self.analysis_progress.setValue(0)
        
        self.status_label.setText("Running comprehensive incident analysis...")
        
        self.analysis_thread = TimelineAnalysisThread(self.analyzer, start_time, end_time, 'incident_timeline')
        self.analysis_thread.progress_updated.connect(self.analysis_progress.setValue)
        self.analysis_thread.analysis_completed.connect(self.incident_analysis_completed)
        self.analysis_thread.start()
    
    def add_timeline_event(self, event_data):
        """Add timeline event to the table."""
        row = self.timeline_table.rowCount()
        self.timeline_table.insertRow(row)
        
        # Timestamp
        timestamp = event_data.get('timestamp', time.time())
        time_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        self.timeline_table.setItem(row, 0, QTableWidgetItem(time_str))
        
        # Event Type
        event_type = event_data.get('event_type', 'Unknown')
        type_display = event_type.replace('_', ' ').title()
        self.timeline_table.setItem(row, 1, QTableWidgetItem(type_display))
        
        # Source
        source = event_data.get('source', 'Unknown')
        self.timeline_table.setItem(row, 2, QTableWidgetItem(source))
        
        # Description
        description = event_data.get('description', 'No description')
        desc_item = QTableWidgetItem(description[:80] + "..." if len(description) > 80 else description)
        desc_item.setToolTip(description)
        self.timeline_table.setItem(row, 3, desc_item)
        
        # Severity
        severity = event_data.get('severity', 'low').title()
        severity_item = QTableWidgetItem(severity)
        
        if severity == 'Critical':
            severity_item.setBackground(QColor(255, 0, 0, 100))
        elif severity == 'High':
            severity_item.setBackground(QColor(255, 100, 0, 100))
        elif severity == 'Medium':
            severity_item.setBackground(QColor(255, 255, 0, 100))
        
        self.timeline_table.setItem(row, 4, severity_item)
        
        # Correlation ID
        correlation_id = event_data.get('correlation_id', '')
        self.timeline_table.setItem(row, 5, QTableWidgetItem(correlation_id))
    
    def add_correlation_item(self, correlation_data):
        """Add correlation to the tree widget."""
        pattern_name = correlation_data.get('pattern_name', 'Unknown Pattern')
        confidence = correlation_data.get('confidence', 0.0)
        event_count = correlation_data.get('event_count', 0)
        severity = correlation_data.get('severity', 'low').title()
        
        root_item = QTreeWidgetItem([
            pattern_name,
            f"{confidence:.3f}",
            str(event_count),
            severity
        ])
        
        # Color code by confidence
        if confidence > 0.8:
            root_item.setBackground(0, QColor(255, 100, 100, 100))
        elif confidence > 0.6:
            root_item.setBackground(0, QColor(255, 255, 100, 100))
        
        # Add matched events as children
        matched_events = correlation_data.get('matched_events', [])
        for event_id in matched_events:
            child_item = QTreeWidgetItem([f"Event ID: {event_id}", "", "", ""])
            root_item.addChild(child_item)
        
        self.correlations_tree.addTopLevelItem(root_item)
        self.correlations_tree.expandAll()
    
    def events_collection_completed(self, results):
        """Handle events collection completion."""
        self.collect_events_btn.setEnabled(True)
        self.analysis_progress.setVisible(False)
        
        if 'error' in results:
            self.status_label.setText(f"Collection failed: {results['error']}")
            QMessageBox.critical(self, "Collection Error", results['error'])
            return
        
        events_collected = results.get('events_collected', 0)
        correlations_found = results.get('correlations_found', 0)
        
        self.status_label.setText(
            f"Timeline collection completed: {events_collected} events, {correlations_found} correlations"
        )
        
        self.update_statistics()
        
        if correlations_found > 0:
            # Show notification for significant correlations
            main_window = self.parent()
            while main_window and not hasattr(main_window, 'show_notification'):
                main_window = main_window.parent()
            
            if main_window:
                main_window.show_notification(
                    "Timeline Correlations Found",
                    f"Found {correlations_found} event correlations"
                )
    
    def incident_analysis_completed(self, timeline_report):
        """Handle incident analysis completion."""
        self.incident_analysis_btn.setEnabled(True)
        self.analysis_progress.setVisible(False)
        
        if 'error' in timeline_report:
            self.status_label.setText(f"Analysis failed: {timeline_report['error']}")
            QMessageBox.critical(self, "Analysis Error", timeline_report['error'])
            return
        
        # Display comprehensive incident report
        self.display_incident_report(timeline_report)
        
        events_count = len(timeline_report.get('events', []))
        correlations_count = len(timeline_report.get('correlations', []))
        attack_vectors = len(timeline_report.get('attack_vectors', []))
        
        self.status_label.setText(
            f"Incident analysis completed: {events_count} events, {correlations_count} correlations, {attack_vectors} attack vectors"
        )
    
    def display_incident_report(self, timeline_report):
        """Display comprehensive incident analysis report."""
        try:
            # Clear current display
            self.timeline_table.setRowCount(0)
            self.correlations_tree.clear()
            
            # Add events to timeline
            for event_data in timeline_report.get('events', []):
                self.add_timeline_event(event_data)
            
            # Add correlations to tree
            for correlation in timeline_report.get('correlations', []):
                self.add_correlation_item(correlation)
            
            # Show summary dialog
            summary = timeline_report.get('timeline_summary', {})
            attack_vectors = timeline_report.get('attack_vectors', [])
            recommendations = timeline_report.get('recommendations', [])
            
            report_text = f"""Incident Timeline Analysis Report
================================

Analysis Period: {datetime.fromtimestamp(timeline_report['incident_window']['start']).strftime('%Y-%m-%d %H:%M:%S')} to {datetime.fromtimestamp(timeline_report['incident_window']['end']).strftime('%Y-%m-%d %H:%M:%S')}
Duration: {timeline_report['incident_window']['duration'] / 3600:.1f} hours

Event Summary:
- Total Events: {summary.get('total_events', 0)}
- Critical Events: {summary.get('severity_distribution', {}).get('critical', 0)}
- High Severity: {summary.get('severity_distribution', {}).get('high', 0)}
- Medium Severity: {summary.get('severity_distribution', {}).get('medium', 0)}

Attack Vectors Identified: {len(attack_vectors)}"""
            
            for vector in attack_vectors:
                report_text += f"\n- {vector['vector_type']}: {vector['confidence']:.2f} confidence"
            
            if recommendations:
                report_text += "\n\nInvestigation Recommendations:"
                for i, rec in enumerate(recommendations[:5], 1):
                    report_text += f"\n{i}. {rec}"
            
            # Show report dialog
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Incident Analysis Report")
            msg_box.setText(report_text)
            msg_box.exec()
            
        except Exception as e:
            print(f"Error displaying incident report: {e}")
    
    def view_event_details(self, item):
        """View detailed information about a timeline event."""
        row = item.row()
        
        timestamp = self.timeline_table.item(row, 0).text()
        event_type = self.timeline_table.item(row, 1).text()
        source = self.timeline_table.item(row, 2).text()
        description = self.timeline_table.item(row, 3).toolTip() or self.timeline_table.item(row, 3).text()
        severity = self.timeline_table.item(row, 4).text()
        correlation_id = self.timeline_table.item(row, 5).text()
        
        details_text = f"""Timeline Event Details
=====================

Timestamp: {timestamp}
Event Type: {event_type}
Source: {source}
Severity: {severity}
Correlation ID: {correlation_id}

Description: {description}

Forensic Analysis:
1. Event captured from {source} monitoring
2. Part of timeline reconstruction analysis
3. Correlation ID links related events
4. Severity indicates potential security impact

Investigation Steps:
1. Examine related events with same correlation ID
2. Check system logs around this timestamp
3. Analyze process and network context
4. Look for signs of malicious activity
5. Document findings in incident report

Evidence Collection:
- Preserve system state at time of event
- Collect relevant log files and artifacts
- Document chain of custody for legal purposes
- Correlate with other security tool findings"""
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Timeline Event Details")
        msg_box.setText(details_text)
        msg_box.exec()
    
    def view_correlation_details(self, item, column):
        """View detailed information about event correlation."""
        if item.parent() is None:  # Top-level correlation item
            pattern_name = item.text(0)
            confidence = item.text(1)
            event_count = item.text(2)
            severity = item.text(3)
            
            details_text = f"""Event Correlation Analysis
=========================

Pattern Name: {pattern_name}
Confidence Score: {confidence}
Related Events: {event_count}
Severity: {severity}

Correlation Analysis:
This pattern represents a sequence of related events that occurred within a specific timeframe, suggesting coordinated activity that may indicate:

1. Automated malware behavior
2. Coordinated attack campaign  
3. System compromise progression
4. Rootkit installation sequence

Investigation Priority:
- High confidence correlations (>0.8) require immediate investigation
- Medium confidence (0.5-0.8) should be monitored closely
- Low confidence (<0.5) may indicate normal system activity

Recommended Actions:
1. Investigate all events in this correlation cluster
2. Look for additional evidence of coordinated activity
3. Check for persistence mechanisms established during this timeframe
4. Analyze network traffic for command and control communication
5. Preserve forensic evidence of the correlated events

Timeline Context:
Events in this correlation occurred within the same timeframe and show characteristics of related malicious activity. The confidence score is based on the temporal proximity, event types, and known attack patterns."""
            
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Correlation Analysis Details")
            msg_box.setText(details_text)
            msg_box.exec()
    
    def filter_timeline(self):
        """Filter timeline events based on current filter settings."""
        event_type_filter = self.event_type_filter.currentText()
        severity_filter = self.severity_filter.currentText()
        
        for row in range(self.timeline_table.rowCount()):
            event_type_item = self.timeline_table.item(row, 1)
            severity_item = self.timeline_table.item(row, 4)
            
            if not all([event_type_item, severity_item]):
                continue
            
            event_type = event_type_item.text()
            severity = severity_item.text()
            
            show_row = True
            
            if severity_filter != "All Severities" and severity != severity_filter:
                show_row = False
            
            if event_type_filter != "All Events":
                type_match = False
                if event_type_filter == "Process Events" and "Process" in event_type:
                    type_match = True
                elif event_type_filter == "Network Events" and "Network" in event_type:
                    type_match = True
                elif event_type_filter == "File Events" and ("File" in event_type or "Filesystem" in event_type):
                    type_match = True
                elif event_type_filter == "System Events" and "System" in event_type:
                    type_match = True
                elif event_type_filter == "Audit Events" and "Audit" in event_type:
                    type_match = True
                
                if not type_match:
                    show_row = False
            
            self.timeline_table.setRowHidden(row, not show_row)
    
    def update_statistics(self):
        """Update timeline analysis statistics."""
        try:
            stats = self.analyzer.get_timeline_statistics()
            
            stats_text = f"""Timeline Analysis Statistics
===========================

Event Collection:
- Total Events: {stats.get('total_events', 0)}
- Recent Events (1h): {stats.get('recent_events', 0)}
- Critical Events: {stats.get('critical_events', 0)}
- Evidence Items: {stats.get('evidence_items', 0)}

Event Sources:"""
            
            for source, count in stats.get('event_sources', {}).items():
                stats_text += f"\n  {source}: {count} events"
            
            stats_text += f"""

Correlation Analysis:
- Patterns Found: {stats.get('correlations_found', 0)}
- Attack Vectors: Available after incident analysis
- Timeline Coverage: {len(stats.get('event_sources', {}))} sources

Forensic Readiness:
- Database Status: Active
- Real-time Monitoring: {'Active' if hasattr(self.analyzer, 'monitoring_active') and self.analyzer.monitoring_active else 'Inactive'}
- Evidence Chain: Maintained"""
            
            self.stats_display.setPlainText(stats_text)
            
        except Exception as e:
            self.stats_display.setPlainText(f"Error updating statistics: {str(e)}")
    
    def on_critical_event(self, event):
        """Handle critical timeline events."""
        try:
            # Show notification for critical events
            main_window = self.parent()
            while main_window and not hasattr(main_window, 'show_notification'):
                main_window = main_window.parent()
            
            if main_window and event.severity in ['high', 'critical']:
                main_window.show_notification(
                    "Critical Timeline Event",
                    f"{event.event_type}: {event.description[:50]}"
                )
                
        except Exception as e:
            print(f"Error handling critical event: {e}")
    
    def start_monitoring(self):
        """Start real-time timeline monitoring."""
        try:
            self.analyzer.start_realtime_timeline_monitoring()
            self.status_label.setText("Real-time timeline monitoring active")
        except Exception as e:
            QMessageBox.critical(self, "Monitoring Error", f"Failed to start monitoring: {str(e)}")
    
    def stop_monitoring(self):
        """Stop real-time timeline monitoring."""
        try:
            self.analyzer.stop_realtime_timeline_monitoring()
            self.status_label.setText("Real-time timeline monitoring stopped")
        except Exception as e:
            print(f"Error stopping monitoring: {e}")
    
    def export_results(self):
        """Export timeline analysis results."""
        start_time = self.start_datetime.dateTime().toPyDateTime().timestamp()
        end_time = self.end_datetime.dateTime().toPyDateTime().timestamp()
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"timeline_analysis_{timestamp}.json"
        
        from PyQt6.QtWidgets import QFileDialog
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Export Timeline Analysis", default_filename, 
            "JSON Files (*.json);;All Files (*)"
        )
        
        if output_path:
            try:
                self.analyzer.export_forensic_timeline(output_path, start_time, end_time)
                QMessageBox.information(self, "Export Successful", 
                                      f"Timeline analysis exported to: {output_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", 
                                   f"Failed to export timeline: {str(e)}")
    
    def create_forensic_evidence(self):
        """Create forensic evidence from selected timeline events."""
        selected_rows = set()
        for item in self.timeline_table.selectedItems():
            selected_rows.add(item.row())
        
        if not selected_rows:
            QMessageBox.information(self, "No Selection", "Please select timeline events to create evidence.")
            return
        
        try:
            evidence_count = 0
            
            for row in selected_rows:
                description_item = self.timeline_table.item(row, 3)
                if description_item:
                    description = description_item.toolTip() or description_item.text()
                    
                    # Create evidence item (simplified - would collect actual artifacts)
                    evidence_path = f"/tmp/evidence_{int(time.time())}_{row}.log"
                    with open(evidence_path, 'w') as f:
                        f.write(f"Timeline Event Evidence\n")
                        f.write(f"Timestamp: {self.timeline_table.item(row, 0).text()}\n")
                        f.write(f"Event Type: {self.timeline_table.item(row, 1).text()}\n")
                        f.write(f"Description: {description}\n")
                    
                    evidence = self.analyzer.create_forensic_evidence(
                        evidence_path, "timeline_event", f"Evidence for timeline event: {description[:50]}"
                    )
                    
                    if evidence:
                        evidence_count += 1
            
            QMessageBox.information(self, "Evidence Created", 
                                  f"Created {evidence_count} forensic evidence items.")
            self.update_statistics()
            
        except Exception as e:
            QMessageBox.critical(self, "Evidence Creation Failed", 
                               f"Failed to create evidence: {str(e)}")