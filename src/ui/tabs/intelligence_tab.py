"""
Threat Intelligence Integration Tab
Interface for threat intelligence feeds management and indicator matching.
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                             QTableWidgetItem, QPushButton, QLabel, QComboBox,
                             QMessageBox, QHeaderView, QTextEdit, QGroupBox,
                             QSplitter, QProgressBar, QLineEdit, QCheckBox,
                             QSpinBox, QTreeWidget, QTreeWidgetItem, QTabWidget)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont

import sys
import os
import json
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from intelligence.threat_feeds import ThreatIntelligenceFeeds
from datetime import datetime
import time

class ThreatIntelUpdateThread(QThread):
    """Background thread for threat intelligence updates."""
    
    progress_updated = pyqtSignal(int)
    update_completed = pyqtSignal(dict)
    status_updated = pyqtSignal(str)
    
    def __init__(self, threat_feeds, feed_names=None):
        super().__init__()
        self.threat_feeds = threat_feeds
        self.feed_names = feed_names
    
    def run(self):
        """Run threat intelligence update."""
        try:
            self.status_updated.emit("Updating threat intelligence feeds...")
            self.progress_updated.emit(25)
            
            results = self.threat_feeds.update_threat_feeds(self.feed_names)
            
            self.progress_updated.emit(75)
            self.status_updated.emit("Checking system against updated indicators...")
            
            # Check system against new indicators
            matches = self.threat_feeds.check_system_against_indicators()
            results['system_matches'] = len(matches)
            
            self.progress_updated.emit(100)
            self.update_completed.emit(results)
            
        except Exception as e:
            self.update_completed.emit({'error': str(e)})

class SystemScanThread(QThread):
    """Background thread for system scanning against threat indicators."""
    
    progress_updated = pyqtSignal(int)
    match_found = pyqtSignal(dict)
    scan_completed = pyqtSignal(dict)
    
    def __init__(self, threat_feeds):
        super().__init__()
        self.threat_feeds = threat_feeds
    
    def run(self):
        """Run system scan against threat indicators."""
        try:
            self.progress_updated.emit(25)
            matches = self.threat_feeds.check_system_against_indicators()
            
            self.progress_updated.emit(75)
            for match in matches:
                self.match_found.emit(match.__dict__)
            
            self.progress_updated.emit(100)
            
            result = {
                'matches_found': len(matches),
                'scan_timestamp': time.time()
            }
            self.scan_completed.emit(result)
            
        except Exception as e:
            self.scan_completed.emit({'error': str(e)})

class IntelligenceTab(QWidget):
    """Threat intelligence integration tab widget."""
    
    def __init__(self):
        super().__init__()
        self.threat_feeds = ThreatIntelligenceFeeds()
        self.init_ui()
        self.update_thread = None
        self.scan_thread = None
    
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Create tab widget for sub-sections
        tab_widget = QTabWidget()
        
        # Indicators tab
        indicators_tab = self.create_indicators_tab()
        tab_widget.addTab(indicators_tab, "Threat Indicators")
        
        # Matches tab
        matches_tab = self.create_matches_tab()
        tab_widget.addTab(matches_tab, "System Matches")
        
        # Feeds management tab
        feeds_tab = self.create_feeds_tab()
        tab_widget.addTab(feeds_tab, "Feed Management")
        
        layout.addWidget(tab_widget)
        
        # Status label
        self.status_label = QLabel("Threat intelligence ready")
        layout.addWidget(self.status_label)
        
        # Load initial data
        self.update_statistics()
        self.load_existing_matches()
    
    def create_indicators_tab(self):
        """Create threat indicators management tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Create splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Controls
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        # Statistics group
        stats_group = QGroupBox("Intelligence Statistics")
        stats_layout = QVBoxLayout(stats_group)
        
        self.intel_stats = QTextEdit()
        self.intel_stats.setMaximumHeight(200)
        self.intel_stats.setFont(QFont("Consolas", 9))
        self.intel_stats.setReadOnly(True)
        stats_layout.addWidget(self.intel_stats)
        
        refresh_stats_btn = QPushButton("Refresh Statistics")
        refresh_stats_btn.clicked.connect(self.update_statistics)
        stats_layout.addWidget(refresh_stats_btn)
        
        left_layout.addWidget(stats_group)
        
        # Custom indicator creation
        custom_group = QGroupBox("Create Custom Indicator")
        custom_layout = QVBoxLayout(custom_group)
        
        # Indicator type
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Type:"))
        self.indicator_type_combo = QComboBox()
        self.indicator_type_combo.addItems(["hash", "ip", "domain", "filename", "url"])
        type_layout.addWidget(self.indicator_type_combo)
        custom_layout.addLayout(type_layout)
        
        # Indicator value
        value_layout = QHBoxLayout()
        value_layout.addWidget(QLabel("Value:"))
        self.indicator_value_input = QLineEdit()
        value_layout.addWidget(self.indicator_value_input)
        custom_layout.addLayout(value_layout)
        
        # Confidence and severity
        conf_layout = QHBoxLayout()
        conf_layout.addWidget(QLabel("Confidence:"))
        self.confidence_spinbox = QSpinBox()
        self.confidence_spinbox.setRange(1, 100)
        self.confidence_spinbox.setValue(80)
        self.confidence_spinbox.setSuffix("%")
        conf_layout.addWidget(self.confidence_spinbox)
        
        conf_layout.addWidget(QLabel("Severity:"))
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["low", "medium", "high", "critical"])
        self.severity_combo.setCurrentText("medium")
        conf_layout.addWidget(self.severity_combo)
        custom_layout.addLayout(conf_layout)
        
        # Description
        desc_layout = QHBoxLayout()
        desc_layout.addWidget(QLabel("Description:"))
        self.description_input = QLineEdit()
        desc_layout.addWidget(self.description_input)
        custom_layout.addLayout(desc_layout)
        
        # Create button
        create_indicator_btn = QPushButton("Create Indicator")
        create_indicator_btn.clicked.connect(self.create_custom_indicator)
        custom_layout.addWidget(create_indicator_btn)
        
        left_layout.addWidget(custom_group)
        left_layout.addStretch()
        
        # Right panel - Indicators table
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        
        self.type_filter = QComboBox()
        self.type_filter.addItems(["All Types", "Hash", "IP", "Domain", "Filename", "URL"])
        self.type_filter.currentTextChanged.connect(self.filter_indicators)
        filter_layout.addWidget(self.type_filter)
        
        self.source_filter = QComboBox()
        self.source_filter.addItems(["All Sources", "Builtin", "Custom", "Remote Feeds"])
        self.source_filter.currentTextChanged.connect(self.filter_indicators)
        filter_layout.addWidget(self.source_filter)
        
        filter_layout.addStretch()
        right_layout.addLayout(filter_layout)
        
        # Indicators table
        self.indicators_table = QTableWidget()
        self.indicators_table.setColumnCount(6)
        self.indicators_table.setHorizontalHeaderLabels([
            "Type", "Value", "Confidence", "Severity", "Source", "Description"
        ])
        
        # Configure table
        header = self.indicators_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        
        self.indicators_table.setAlternatingRowColors(True)
        self.indicators_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.indicators_table.itemDoubleClicked.connect(self.view_indicator_details)
        
        right_layout.addWidget(self.indicators_table)
        
        # Add to splitter
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([350, 650])
        
        layout.addWidget(splitter)
        
        # Load indicators into table
        self.load_indicators_table()
        
        return widget
    
    def create_matches_tab(self):
        """Create threat matches display tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        self.scan_system_btn = QPushButton("Scan System")
        self.scan_system_btn.clicked.connect(self.scan_system_for_threats)
        controls_layout.addWidget(self.scan_system_btn)
        
        self.clear_matches_btn = QPushButton("Clear Matches")
        self.clear_matches_btn.clicked.connect(self.clear_threat_matches)
        controls_layout.addWidget(self.clear_matches_btn)
        
        controls_layout.addStretch()
        
        # Progress bar
        self.scan_progress = QProgressBar()
        self.scan_progress.setVisible(False)
        controls_layout.addWidget(self.scan_progress)
        
        layout.addLayout(controls_layout)
        
        # Matches table
        self.matches_table = QTableWidget()
        self.matches_table.setColumnCount(7)
        self.matches_table.setHorizontalHeaderLabels([
            "Time", "Indicator Type", "Matched Value", "Artifact", "Confidence", "Severity", "Actions"
        ])
        
        # Configure table
        header = self.matches_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        
        self.matches_table.setAlternatingRowColors(True)
        self.matches_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.matches_table.itemDoubleClicked.connect(self.view_match_details)
        
        layout.addWidget(self.matches_table)
        
        return widget
    
    def create_feeds_tab(self):
        """Create threat feeds management tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Feed controls
        controls_layout = QHBoxLayout()
        
        self.update_feeds_btn = QPushButton("Update All Feeds")
        self.update_feeds_btn.clicked.connect(self.update_threat_feeds)
        controls_layout.addWidget(self.update_feeds_btn)
        
        self.enable_auto_update_check = QCheckBox("Auto-Update")
        controls_layout.addWidget(self.enable_auto_update_check)
        
        controls_layout.addWidget(QLabel("Interval (hours):"))
        self.update_interval_spinbox = QSpinBox()
        self.update_interval_spinbox.setRange(1, 24)
        self.update_interval_spinbox.setValue(6)
        controls_layout.addWidget(self.update_interval_spinbox)
        
        controls_layout.addStretch()
        
        # Progress bar
        self.update_progress = QProgressBar()
        self.update_progress.setVisible(False)
        controls_layout.addWidget(self.update_progress)
        
        layout.addLayout(controls_layout)
        
        # Feeds status table
        self.feeds_table = QTableWidget()
        self.feeds_table.setColumnCount(6)
        self.feeds_table.setHorizontalHeaderLabels([
            "Feed Name", "Status", "Last Update", "Indicators", "Enabled", "Actions"
        ])
        
        # Configure table
        header = self.feeds_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        
        self.feeds_table.setAlternatingRowColors(True)
        layout.addWidget(self.feeds_table)
        
        # Load feeds status
        self.load_feeds_status()
        
        return widget
    
    def load_indicators_table(self):
        """Load threat indicators into table."""
        try:
            self.indicators_table.setRowCount(0)
            
            for indicator in self.threat_feeds.indicators.values():
                row = self.indicators_table.rowCount()
                self.indicators_table.insertRow(row)
                
                # Type
                self.indicators_table.setItem(row, 0, QTableWidgetItem(indicator.indicator_type))
                
                # Value
                value_display = indicator.value[:30] + "..." if len(indicator.value) > 30 else indicator.value
                value_item = QTableWidgetItem(value_display)
                value_item.setToolTip(indicator.value)
                self.indicators_table.setItem(row, 1, value_item)
                
                # Confidence
                confidence_item = QTableWidgetItem(f"{indicator.confidence:.2f}")
                if indicator.confidence > 0.8:
                    confidence_item.setBackground(QColor(0, 255, 0, 100))
                elif indicator.confidence > 0.6:
                    confidence_item.setBackground(QColor(255, 255, 0, 100))
                self.indicators_table.setItem(row, 2, confidence_item)
                
                # Severity
                severity_item = QTableWidgetItem(indicator.severity.title())
                if indicator.severity == 'critical':
                    severity_item.setBackground(QColor(255, 0, 0, 100))
                elif indicator.severity == 'high':
                    severity_item.setBackground(QColor(255, 100, 0, 100))
                elif indicator.severity == 'medium':
                    severity_item.setBackground(QColor(255, 255, 0, 100))
                self.indicators_table.setItem(row, 3, severity_item)
                
                # Source
                self.indicators_table.setItem(row, 4, QTableWidgetItem(indicator.source))
                
                # Description
                desc_display = indicator.description[:50] + "..." if len(indicator.description) > 50 else indicator.description
                desc_item = QTableWidgetItem(desc_display)
                desc_item.setToolTip(indicator.description)
                self.indicators_table.setItem(row, 5, desc_item)
                
        except Exception as e:
            print(f"Error loading indicators table: {e}")
    
    def load_feeds_status(self):
        """Load threat feeds status into table."""
        try:
            self.feeds_table.setRowCount(0)
            
            stats = self.threat_feeds.get_threat_intelligence_statistics()
            feed_status = stats.get('feed_status', {})
            
            for feed_name, config in self.threat_feeds.feed_sources.items():
                row = self.feeds_table.rowCount()
                self.feeds_table.insertRow(row)
                
                # Feed name
                self.feeds_table.setItem(row, 0, QTableWidgetItem(feed_name))
                
                # Status
                status = feed_status.get(feed_name, {}).get('status', 'never_updated')
                status_item = QTableWidgetItem(status.title())
                if status == 'success':
                    status_item.setBackground(QColor(0, 255, 0, 100))
                elif status == 'partial':
                    status_item.setBackground(QColor(255, 255, 0, 100))
                elif status == 'error':
                    status_item.setBackground(QColor(255, 0, 0, 100))
                self.feeds_table.setItem(row, 1, status_item)
                
                # Last update
                last_update = feed_status.get(feed_name, {}).get('last_update', 0)
                if last_update > 0:
                    update_str = datetime.fromtimestamp(last_update).strftime('%Y-%m-%d %H:%M')
                else:
                    update_str = "Never"
                self.feeds_table.setItem(row, 2, QTableWidgetItem(update_str))
                
                # Indicators count
                indicators_count = feed_status.get(feed_name, {}).get('indicators_added', 0)
                self.feeds_table.setItem(row, 3, QTableWidgetItem(str(indicators_count)))
                
                # Enabled status
                enabled = config.get('enabled', False)
                enabled_item = QTableWidgetItem("Yes" if enabled else "No")
                if enabled:
                    enabled_item.setBackground(QColor(0, 255, 0, 100))
                self.feeds_table.setItem(row, 4, enabled_item)
                
                # Actions
                self.feeds_table.setItem(row, 5, QTableWidgetItem("Configure"))
                
        except Exception as e:
            print(f"Error loading feeds status: {e}")
    
    def load_existing_matches(self):
        """Load existing threat matches into table."""
        try:
            # This would load from database in a real implementation
            # For now, we'll populate when scanning is performed
            pass
        except Exception as e:
            print(f"Error loading existing matches: {e}")
    
    def update_threat_feeds(self):
        """Update threat intelligence feeds."""
        if self.update_thread and self.update_thread.isRunning():
            return
        
        self.update_feeds_btn.setEnabled(False)
        self.update_progress.setVisible(True)
        self.update_progress.setValue(0)
        self.status_label.setText("Updating threat intelligence feeds...")
        
        self.update_thread = ThreatIntelUpdateThread(self.threat_feeds)
        self.update_thread.progress_updated.connect(self.update_progress.setValue)
        self.update_thread.status_updated.connect(self.status_label.setText)
        self.update_thread.update_completed.connect(self.feeds_update_completed)
        self.update_thread.start()
    
    def feeds_update_completed(self, results):
        """Handle threat feeds update completion."""
        self.update_feeds_btn.setEnabled(True)
        self.update_progress.setVisible(False)
        
        if 'error' in results:
            self.status_label.setText(f"Update failed: {results['error']}")
            QMessageBox.critical(self, "Update Error", results['error'])
            return
        
        feeds_updated = results.get('feeds_updated', 0)
        indicators_added = results.get('indicators_added', 0)
        indicators_updated = results.get('indicators_updated', 0)
        system_matches = results.get('system_matches', 0)
        
        self.status_label.setText(
            f"Feeds updated: {feeds_updated} feeds, {indicators_added} new indicators, {system_matches} matches"
        )
        
        # Refresh displays
        self.update_statistics()
        self.load_indicators_table()
        self.load_feeds_status()
        
        # Show notification if matches found
        if system_matches > 0:
            main_window = self.parent()
            while main_window and not hasattr(main_window, 'show_notification'):
                main_window = main_window.parent()
            
            if main_window:
                main_window.show_notification(
                    "Threat Intelligence Matches",
                    f"Found {system_matches} threat indicator matches"
                )
    
    def scan_system_for_threats(self):
        """Scan system against threat indicators."""
        if self.scan_thread and self.scan_thread.isRunning():
            return
        
        self.scan_system_btn.setEnabled(False)
        self.scan_progress.setVisible(True)
        self.scan_progress.setValue(0)
        self.matches_table.setRowCount(0)
        self.status_label.setText("Scanning system against threat indicators...")
        
        self.scan_thread = SystemScanThread(self.threat_feeds)
        self.scan_thread.progress_updated.connect(self.scan_progress.setValue)
        self.scan_thread.match_found.connect(self.add_match_row)
        self.scan_thread.scan_completed.connect(self.system_scan_completed)
        self.scan_thread.start()
    
    def system_scan_completed(self, results):
        """Handle system scan completion."""
        self.scan_system_btn.setEnabled(False)
        self.scan_progress.setVisible(False)
        
        if 'error' in results:
            self.status_label.setText(f"Scan failed: {results['error']}")
            QMessageBox.critical(self, "Scan Error", results['error'])
            return
        
        matches_found = results.get('matches_found', 0)
        self.status_label.setText(f"System scan completed: {matches_found} threat matches found")
        
        if matches_found > 0:
            QMessageBox.warning(self, "Threats Detected", 
                              f"Found {matches_found} threat indicator matches on the system. "
                              "Review the matches and take appropriate action.")
    
    def add_match_row(self, match_data):
        """Add threat match to the table."""
        row = self.matches_table.rowCount()
        self.matches_table.insertRow(row)
        
        # Time
        timestamp = match_data.get('timestamp', time.time())
        time_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
        self.matches_table.setItem(row, 0, QTableWidgetItem(time_str))
        
        # Indicator Type
        indicator = match_data.get('indicator', {})
        indicator_type = indicator.get('indicator_type', 'Unknown')
        self.matches_table.setItem(row, 1, QTableWidgetItem(indicator_type.title()))
        
        # Matched Value
        matched_value = indicator.get('value', 'Unknown')
        value_display = matched_value[:20] + "..." if len(matched_value) > 20 else matched_value
        value_item = QTableWidgetItem(value_display)
        value_item.setToolTip(matched_value)
        self.matches_table.setItem(row, 2, value_item)
        
        # Artifact
        artifact = match_data.get('matched_artifact', 'Unknown')
        artifact_display = os.path.basename(artifact) if artifact.startswith('/') else artifact
        artifact_item = QTableWidgetItem(artifact_display)
        artifact_item.setToolTip(artifact)
        self.matches_table.setItem(row, 3, artifact_item)
        
        # Confidence
        confidence = match_data.get('confidence', 0.0)
        confidence_item = QTableWidgetItem(f"{confidence:.2f}")
        
        if confidence > 0.8:
            confidence_item.setBackground(QColor(255, 0, 0, 100))
        elif confidence > 0.6:
            confidence_item.setBackground(QColor(255, 100, 0, 100))
        
        self.matches_table.setItem(row, 4, confidence_item)
        
        # Severity
        severity = indicator.get('severity', 'medium').title()
        severity_item = QTableWidgetItem(severity)
        
        if severity == 'Critical':
            severity_item.setBackground(QColor(255, 0, 0, 100))
        elif severity == 'High':
            severity_item.setBackground(QColor(255, 100, 0, 100))
        elif severity == 'Medium':
            severity_item.setBackground(QColor(255, 255, 0, 100))
        
        self.matches_table.setItem(row, 5, severity_item)
        
        # Actions
        actions = "Quarantine" if severity in ['Critical', 'High'] else "Monitor"
        self.matches_table.setItem(row, 6, QTableWidgetItem(actions))
    
    def create_custom_indicator(self):
        """Create custom threat indicator."""
        try:
            indicator_type = self.indicator_type_combo.currentText()
            value = self.indicator_value_input.text().strip()
            confidence = self.confidence_spinbox.value() / 100.0
            severity = self.severity_combo.currentText()
            description = self.description_input.text().strip()
            
            if not value:
                QMessageBox.warning(self, "Invalid Input", "Please provide an indicator value.")
                return
            
            if not description:
                description = f"Custom {indicator_type} indicator"
            
            success = self.threat_feeds.create_custom_indicator(
                indicator_type, value, confidence, severity, description
            )
            
            if success:
                self.status_label.setText(f"Created custom {indicator_type} indicator")
                self.load_indicators_table()
                self.update_statistics()
                
                # Clear inputs
                self.indicator_value_input.clear()
                self.description_input.clear()
                
                QMessageBox.information(self, "Indicator Created", 
                                      f"Custom {indicator_type} indicator created successfully.")
            else:
                QMessageBox.critical(self, "Creation Failed", "Failed to create custom indicator.")
                
        except Exception as e:
            QMessageBox.critical(self, "Creation Error", f"Error creating indicator: {str(e)}")
    
    def update_statistics(self):
        """Update threat intelligence statistics."""
        try:
            stats = self.threat_feeds.get_threat_intelligence_statistics()
            
            stats_text = f"""Threat Intelligence Statistics
=============================

Indicator Database:
- Total Indicators: {stats.get('total_indicators', 0)}
- Recent Matches (24h): {stats.get('recent_matches', 0)}

Indicator Types:"""
            
            for ind_type, count in stats.get('indicator_types', {}).items():
                stats_text += f"\n  {ind_type.title()}: {count}"
            
            stats_text += "\n\nSeverity Distribution:"
            for severity, count in stats.get('severity_distribution', {}).items():
                stats_text += f"\n  {severity.title()}: {count}"
            
            stats_text += "\n\nIntelligence Sources:"
            for source, count in stats.get('source_distribution', {}).items():
                stats_text += f"\n  {source}: {count} indicators"
            
            last_update = stats.get('last_update', 0)
            if last_update > 0:
                update_str = datetime.fromtimestamp(last_update).strftime('%Y-%m-%d %H:%M')
                stats_text += f"\n\nLast Update: {update_str}"
            else:
                stats_text += "\n\nLast Update: Never"
            
            self.intel_stats.setPlainText(stats_text)
            
        except Exception as e:
            self.intel_stats.setPlainText(f"Error updating statistics: {str(e)}")
    
    def filter_indicators(self):
        """Filter threat indicators based on current filter settings."""
        type_filter = self.type_filter.currentText()
        source_filter = self.source_filter.currentText()
        
        for row in range(self.indicators_table.rowCount()):
            type_item = self.indicators_table.item(row, 0)
            source_item = self.indicators_table.item(row, 4)
            
            if not all([type_item, source_item]):
                continue
            
            indicator_type = type_item.text()
            source = source_item.text()
            
            show_row = True
            
            if type_filter != "All Types" and indicator_type.lower() != type_filter.lower():
                show_row = False
            
            if source_filter != "All Sources":
                source_match = False
                if source_filter == "Builtin" and source == "builtin":
                    source_match = True
                elif source_filter == "Custom" and source == "custom":
                    source_match = True
                elif source_filter == "Remote Feeds" and source not in ["builtin", "custom"]:
                    source_match = True
                
                if not source_match:
                    show_row = False
            
            self.indicators_table.setRowHidden(row, not show_row)
    
    def view_indicator_details(self, item):
        """View detailed information about threat indicator."""
        row = item.row()
        
        indicator_type = self.indicators_table.item(row, 0).text()
        value = self.indicators_table.item(row, 1).toolTip() or self.indicators_table.item(row, 1).text()
        confidence = self.indicators_table.item(row, 2).text()
        severity = self.indicators_table.item(row, 3).text()
        source = self.indicators_table.item(row, 4).text()
        description = self.indicators_table.item(row, 5).toolTip() or self.indicators_table.item(row, 5).text()
        
        details_text = f"""Threat Indicator Details
=======================

Type: {indicator_type}
Value: {value}
Confidence: {confidence}
Severity: {severity}
Source: {source}

Description: {description}

Threat Intelligence Context:
This indicator has been identified as associated with malicious activity through threat intelligence analysis. The confidence score reflects the reliability of the intelligence source and the accuracy of the indicator.

Detection Guidance:
1. Monitor system for presence of this indicator
2. If found, investigate immediately based on severity level
3. Check for related indicators and attack patterns
4. Document findings for incident response

Response Actions:
- Critical/High: Immediate containment and investigation
- Medium: Enhanced monitoring and analysis
- Low: Standard monitoring and logging

Intelligence Lifecycle:
- First Seen: Check database for initial detection
- Last Updated: Monitor for intelligence updates
- Source Reliability: Verify against multiple sources
- Context Enrichment: Correlate with other security data"""
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Threat Indicator Details")
        msg_box.setText(details_text)
        msg_box.exec()
    
    def view_match_details(self, item):
        """View detailed information about threat match."""
        row = item.row()
        
        time_str = self.matches_table.item(row, 0).text()
        indicator_type = self.matches_table.item(row, 1).text()
        matched_value = self.matches_table.item(row, 2).toolTip() or self.matches_table.item(row, 2).text()
        artifact = self.matches_table.item(row, 3).toolTip() or self.matches_table.item(row, 3).text()
        confidence = self.matches_table.item(row, 4).text()
        severity = self.matches_table.item(row, 5).text()
        
        details_text = f"""Threat Intelligence Match Details
=================================

Detection Time: {time_str}
Indicator Type: {indicator_type}
Matched Value: {matched_value}
System Artifact: {artifact}
Confidence: {confidence}
Severity: {severity}

Match Analysis:
A system artifact has been matched against a known threat indicator from our intelligence database. This indicates potential malicious activity or compromise.

Immediate Actions Required:
1. Isolate the affected system component
2. Perform immediate malware analysis
3. Check for lateral movement or additional indicators
4. Document all findings for incident response
5. Update security controls to prevent recurrence

Investigation Steps:
1. Analyze the matched artifact in detail
2. Check for related files, processes, or connections
3. Review system logs for timeline of activity
4. Correlate with other security tool findings
5. Determine scope of potential compromise

Threat Context:
- Intelligence Source: Verified threat intelligence feed
- Indicator Reliability: Based on source credibility
- Attack Association: May be part of larger campaign
- Historical Context: Check for previous detections"""
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Threat Match Details")
        msg_box.setText(details_text)
        msg_box.exec()
    
    def clear_threat_matches(self):
        """Clear threat matches from display."""
        reply = QMessageBox.question(self, "Clear Matches", 
                                   "Are you sure you want to clear all threat matches?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self.matches_table.setRowCount(0)
            self.status_label.setText("Threat matches cleared")
    
    def start_monitoring(self):
        """Start threat intelligence monitoring."""
        try:
            self.threat_feeds.start_automated_updates(self.update_interval_spinbox.value() * 3600)
            self.status_label.setText("Threat intelligence monitoring active")
        except Exception as e:
            QMessageBox.critical(self, "Monitoring Error", f"Failed to start monitoring: {str(e)}")
    
    def stop_monitoring(self):
        """Stop threat intelligence monitoring."""
        try:
            self.threat_feeds.stop_automated_updates()
            self.status_label.setText("Threat intelligence monitoring stopped")
        except Exception as e:
            print(f"Error stopping monitoring: {e}")
    
    def export_results(self):
        """Export threat intelligence analysis."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"threat_intelligence_{timestamp}.json"
        
        from PyQt6.QtWidgets import QFileDialog
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Export Threat Intelligence", default_filename, 
            "JSON Files (*.json);;All Files (*)"
        )
        
        if output_path:
            try:
                self.threat_feeds.export_threat_intelligence(output_path)
                QMessageBox.information(self, "Export Successful", 
                                      f"Threat intelligence exported to: {output_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", 
                                   f"Failed to export intelligence: {str(e)}")