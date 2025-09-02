"""
Machine Learning Anomaly Detection Tab
Interface for AI-powered anomaly detection and behavioral analysis.
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                             QTableWidgetItem, QPushButton, QLabel, QComboBox,
                             QMessageBox, QHeaderView, QTextEdit, QGroupBox,
                             QSplitter, QProgressBar, QCheckBox, QSpinBox,
                             QSlider, QLCDNumber)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QFont

import sys
import os
import json
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from detection.ml_anomaly_detector import MLAnomalyDetector
from datetime import datetime
import time

class MLMonitoringThread(QThread):
    """Background thread for ML anomaly monitoring."""
    
    anomaly_detected = pyqtSignal(dict)
    features_updated = pyqtSignal(dict)
    monitoring_status = pyqtSignal(str)
    
    def __init__(self, detector, monitoring_interval):
        super().__init__()
        self.detector = detector
        self.monitoring_interval = monitoring_interval
        self.running = False
    
    def run(self):
        """Run ML monitoring loop."""
        self.running = True
        self.monitoring_status.emit("ML monitoring started")
        
        try:
            while self.running:
                # Collect features
                features = self.detector.collect_system_features()
                self.features_updated.emit(features.__dict__)
                
                # Analyze for anomalies
                anomalies = self.detector.analyze_features_for_anomalies(features)
                
                for anomaly in anomalies:
                    self.anomaly_detected.emit(anomaly.__dict__)
                
                time.sleep(self.monitoring_interval)
                
        except Exception as e:
            self.monitoring_status.emit(f"Monitoring error: {str(e)}")
    
    def stop(self):
        """Stop monitoring."""
        self.running = False

class MLTrainingThread(QThread):
    """Background thread for ML model training."""
    
    training_progress = pyqtSignal(int)
    training_completed = pyqtSignal(bool)
    training_status = pyqtSignal(str)
    
    def __init__(self, detector, training_duration):
        super().__init__()
        self.detector = detector
        self.training_duration = training_duration
    
    def run(self):
        """Run model training."""
        try:
            self.training_status.emit("Collecting training data...")
            
            # Simulate training progress
            for i in range(10):
                if i < 9:
                    self.training_progress.emit((i + 1) * 10)
                    self.training_status.emit(f"Training progress: {(i + 1) * 10}%")
                    time.sleep(self.training_duration / 10)
                else:
                    # Final training step
                    success = self.detector.train_model_on_normal_data(60)  # 1 minute for demo
                    self.training_progress.emit(100)
                    self.training_completed.emit(success)
                    
        except Exception as e:
            self.training_status.emit(f"Training failed: {str(e)}")
            self.training_completed.emit(False)

class MLTab(QWidget):
    """Machine learning anomaly detection tab widget."""
    
    def __init__(self):
        super().__init__()
        self.detector = MLAnomalyDetector()
        self.init_ui()
        self.monitoring_thread = None
        self.training_thread = None
        
        # Setup real-time updates
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_real_time_data)
        self.update_timer.start(5000)  # Update every 5 seconds
    
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Create splitter for main layout
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Controls and model info
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        # Model management group
        model_group = QGroupBox("ML Model Management")
        model_layout = QVBoxLayout(model_group)
        
        # Model statistics
        self.model_stats = QTextEdit()
        self.model_stats.setMaximumHeight(150)
        self.model_stats.setFont(QFont("Consolas", 9))
        self.model_stats.setReadOnly(True)
        model_layout.addWidget(self.model_stats)
        
        # Model management buttons
        model_btn_layout = QHBoxLayout()
        
        self.train_model_btn = QPushButton("Train Model")
        self.train_model_btn.clicked.connect(self.train_model)
        model_btn_layout.addWidget(self.train_model_btn)
        
        self.reset_model_btn = QPushButton("Reset Model")
        self.reset_model_btn.clicked.connect(self.reset_model)
        model_btn_layout.addWidget(self.reset_model_btn)
        
        model_layout.addLayout(model_btn_layout)
        
        # Training progress
        self.training_progress = QProgressBar()
        self.training_progress.setVisible(False)
        model_layout.addWidget(self.training_progress)
        
        left_layout.addWidget(model_group)
        
        # Monitoring controls group
        monitoring_group = QGroupBox("Anomaly Monitoring")
        monitoring_layout = QVBoxLayout(monitoring_group)
        
        # Monitoring controls
        monitor_controls_layout = QHBoxLayout()
        
        self.start_monitoring_btn = QPushButton("Start Monitoring")
        self.start_monitoring_btn.clicked.connect(self.start_monitoring)
        monitor_controls_layout.addWidget(self.start_monitoring_btn)
        
        self.stop_monitoring_btn = QPushButton("Stop Monitoring")
        self.stop_monitoring_btn.clicked.connect(self.stop_monitoring)
        self.stop_monitoring_btn.setEnabled(False)
        monitor_controls_layout.addWidget(self.stop_monitoring_btn)
        
        monitoring_layout.addLayout(monitor_controls_layout)
        
        # Monitoring interval
        interval_layout = QHBoxLayout()
        interval_layout.addWidget(QLabel("Interval (seconds):"))
        
        self.interval_spinbox = QSpinBox()
        self.interval_spinbox.setRange(10, 300)
        self.interval_spinbox.setValue(30)
        interval_layout.addWidget(self.interval_spinbox)
        
        monitoring_layout.addLayout(interval_layout)
        
        # Sensitivity settings
        sensitivity_layout = QHBoxLayout()
        sensitivity_layout.addWidget(QLabel("Sensitivity:"))
        
        self.sensitivity_slider = QSlider(Qt.Orientation.Horizontal)
        self.sensitivity_slider.setRange(1, 10)
        self.sensitivity_slider.setValue(5)
        self.sensitivity_slider.valueChanged.connect(self.update_sensitivity)
        sensitivity_layout.addWidget(self.sensitivity_slider)
        
        self.sensitivity_lcd = QLCDNumber(1)
        self.sensitivity_lcd.display(5)
        sensitivity_layout.addWidget(self.sensitivity_lcd)
        
        monitoring_layout.addLayout(sensitivity_layout)
        
        left_layout.addWidget(monitoring_group)
        
        # Real-time metrics group
        metrics_group = QGroupBox("Real-time System Metrics")
        metrics_layout = QVBoxLayout(metrics_group)
        
        self.metrics_display = QTextEdit()
        self.metrics_display.setMaximumHeight(200)
        self.metrics_display.setFont(QFont("Consolas", 9))
        self.metrics_display.setReadOnly(True)
        metrics_layout.addWidget(self.metrics_display)
        
        left_layout.addWidget(metrics_group)
        left_layout.addStretch()
        
        # Right panel - Anomaly results
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "Critical", "High", "Medium", "Low"])
        self.severity_filter.currentTextChanged.connect(self.filter_anomalies)
        filter_layout.addWidget(self.severity_filter)
        
        self.type_filter = QComboBox()
        self.type_filter.addItems(["All Types", "Statistical", "Pattern", "Temporal", "Behavioral"])
        self.type_filter.currentTextChanged.connect(self.filter_anomalies)
        filter_layout.addWidget(self.type_filter)
        
        filter_layout.addStretch()
        right_layout.addLayout(filter_layout)
        
        # Anomalies table
        self.anomalies_table = QTableWidget()
        self.anomalies_table.setColumnCount(7)
        self.anomalies_table.setHorizontalHeaderLabels([
            "Time", "Type", "Confidence", "Severity", "Description", "Risk Score", "Actions"
        ])
        
        # Configure table
        header = self.anomalies_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        
        self.anomalies_table.setAlternatingRowColors(True)
        self.anomalies_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.anomalies_table.itemDoubleClicked.connect(self.view_anomaly_details)
        
        right_layout.addWidget(self.anomalies_table)
        
        # Add widgets to splitter
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([400, 800])
        
        layout.addWidget(splitter)
        
        # Status label
        self.status_label = QLabel("ML anomaly detection ready")
        layout.addWidget(self.status_label)
        
        # Load initial data
        self.update_model_statistics()
        self.update_real_time_data()
    
    def train_model(self):
        """Train the ML anomaly detection model."""
        if self.training_thread and self.training_thread.isRunning():
            return
        
        self.train_model_btn.setEnabled(False)
        self.training_progress.setVisible(True)
        self.training_progress.setValue(0)
        self.status_label.setText("Training ML model on normal system behavior...")
        
        # Get training duration from user (simplified to 30 seconds for demo)
        training_duration = 30
        
        self.training_thread = MLTrainingThread(self.detector, training_duration)
        self.training_thread.training_progress.connect(self.training_progress.setValue)
        self.training_thread.training_status.connect(self.status_label.setText)
        self.training_thread.training_completed.connect(self.training_completed)
        self.training_thread.start()
    
    def training_completed(self, success):
        """Handle training completion."""
        self.train_model_btn.setEnabled(True)
        self.training_progress.setVisible(False)
        
        if success:
            self.status_label.setText("Model training completed successfully")
            self.update_model_statistics()
            QMessageBox.information(self, "Training Complete", 
                                  "ML model has been trained on normal system behavior.")
        else:
            self.status_label.setText("Model training failed")
            QMessageBox.critical(self, "Training Failed", 
                               "Failed to train the ML model.")
    
    def reset_model(self):
        """Reset the ML model to default state."""
        try:
            # Remove model file
            if os.path.exists(self.detector.model_path):
                os.remove(self.detector.model_path)
            
            # Reset detector
            self.detector._load_baseline_model()
            self.update_model_statistics()
            
            self.status_label.setText("ML model has been reset")
            QMessageBox.information(self, "Model Reset", 
                                  "ML model has been reset to default state.")
            
        except Exception as e:
            QMessageBox.critical(self, "Reset Failed", f"Failed to reset model: {str(e)}")
    
    def start_monitoring(self):
        """Start real-time ML anomaly monitoring."""
        if self.monitoring_thread and self.monitoring_thread.running:
            return
        
        self.start_monitoring_btn.setEnabled(False)
        self.stop_monitoring_btn.setEnabled(True)
        
        interval = self.interval_spinbox.value()
        
        self.monitoring_thread = MLMonitoringThread(self.detector, interval)
        self.monitoring_thread.anomaly_detected.connect(self.add_anomaly_row)
        self.monitoring_thread.features_updated.connect(self.update_metrics_display)
        self.monitoring_thread.monitoring_status.connect(self.status_label.setText)
        self.monitoring_thread.start()
        
        self.status_label.setText(f"ML anomaly monitoring active (interval: {interval}s)")
    
    def stop_monitoring(self):
        """Stop ML anomaly monitoring."""
        if self.monitoring_thread:
            self.monitoring_thread.stop()
            self.monitoring_thread.wait(5000)  # Wait up to 5 seconds
        
        self.start_monitoring_btn.setEnabled(True)
        self.stop_monitoring_btn.setEnabled(False)
        self.status_label.setText("ML anomaly monitoring stopped")
    
    def update_sensitivity(self, value):
        """Update anomaly detection sensitivity."""
        self.sensitivity_lcd.display(value)
        
        # Adjust thresholds based on sensitivity
        base_thresholds = {
            'process_spike': 2.5,
            'network_anomaly': 3.0,
            'memory_leak': 2.0,
            'file_activity': 2.5,
            'api_anomaly': 3.5
        }
        
        # Higher sensitivity = lower thresholds
        sensitivity_factor = (11 - value) / 10.0
        
        for threshold_name, base_value in base_thresholds.items():
            self.detector.anomaly_thresholds[threshold_name] = base_value * sensitivity_factor
        
        self.status_label.setText(f"Sensitivity updated to {value}/10")
    
    def add_anomaly_row(self, anomaly_data):
        """Add ML anomaly to the table."""
        row = self.anomalies_table.rowCount()
        self.anomalies_table.insertRow(row)
        
        # Time
        timestamp = anomaly_data.get('timestamp', time.time())
        time_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
        self.anomalies_table.setItem(row, 0, QTableWidgetItem(time_str))
        
        # Type
        anomaly_type = anomaly_data.get('anomaly_type', 'Unknown')
        type_display = anomaly_type.replace('_', ' ').title()
        self.anomalies_table.setItem(row, 1, QTableWidgetItem(type_display))
        
        # Confidence
        confidence = anomaly_data.get('confidence', 0.0)
        confidence_item = QTableWidgetItem(f"{confidence:.3f}")
        
        if confidence > 0.8:
            confidence_item.setBackground(QColor(255, 0, 0, 100))
        elif confidence > 0.6:
            confidence_item.setBackground(QColor(255, 100, 0, 100))
        elif confidence > 0.4:
            confidence_item.setBackground(QColor(255, 255, 0, 100))
        
        self.anomalies_table.setItem(row, 2, confidence_item)
        
        # Severity
        severity = anomaly_data.get('severity', 'low').title()
        severity_item = QTableWidgetItem(severity)
        
        if severity == 'Critical':
            severity_item.setBackground(QColor(255, 0, 0, 100))
        elif severity == 'High':
            severity_item.setBackground(QColor(255, 100, 0, 100))
        elif severity == 'Medium':
            severity_item.setBackground(QColor(255, 255, 0, 100))
        
        self.anomalies_table.setItem(row, 3, severity_item)
        
        # Description
        description = anomaly_data.get('description', 'No description')
        desc_item = QTableWidgetItem(description[:60] + "..." if len(description) > 60 else description)
        desc_item.setToolTip(description)
        self.anomalies_table.setItem(row, 4, desc_item)
        
        # Risk Score
        risk_score = anomaly_data.get('risk_score', 0.0)
        risk_item = QTableWidgetItem(f"{risk_score:.3f}")
        
        if risk_score > 0.7:
            risk_item.setBackground(QColor(255, 0, 0, 100))
        elif risk_score > 0.5:
            risk_item.setBackground(QColor(255, 100, 0, 100))
        
        self.anomalies_table.setItem(row, 5, risk_item)
        
        # Actions
        actions = anomaly_data.get('recommended_actions', [])
        action_text = "Investigate" if actions else "Monitor"
        self.anomalies_table.setItem(row, 6, QTableWidgetItem(action_text))
        
        # Auto-scroll to new anomaly
        self.anomalies_table.scrollToBottom()
        
        # Show notification for high-severity anomalies
        if severity in ['Critical', 'High']:
            main_window = self.parent()
            while main_window and not hasattr(main_window, 'show_notification'):
                main_window = main_window.parent()
            
            if main_window:
                main_window.show_notification(
                    f"ML Anomaly Detected",
                    f"{severity} anomaly: {description[:50]}"
                )
    
    def update_model_statistics(self):
        """Update ML model statistics display."""
        try:
            stats = self.detector.get_anomaly_statistics()
            
            model_info = stats.get('model_info', {})
            training_size = model_info.get('training_size', 0)
            last_training = model_info.get('last_training', 0)
            features_tracked = model_info.get('features_tracked', 0)
            
            last_training_str = "Never"
            if last_training > 0:
                last_training_str = datetime.fromtimestamp(last_training).strftime('%Y-%m-%d %H:%M')
            
            stats_text = f"""ML Model Statistics
==================

Training Data Size: {training_size} samples
Features Tracked: {features_tracked}
Last Training: {last_training_str}
Monitoring Status: {stats.get('monitoring_status', 'inactive').title()}

Recent Anomalies (24h): {stats.get('recent_anomalies', 0)}

Anomaly Types:"""
            
            for anomaly_type, count in stats.get('anomaly_types', {}).items():
                type_display = anomaly_type.replace('_', ' ').title()
                stats_text += f"\n  {type_display}: {count}"
            
            stats_text += "\n\nRisk Distribution:"
            for severity, count in stats.get('risk_distribution', {}).items():
                stats_text += f"\n  {severity.title()}: {count}"
            
            self.model_stats.setPlainText(stats_text)
            
        except Exception as e:
            self.model_stats.setPlainText(f"Error updating statistics: {str(e)}")
    
    def update_metrics_display(self, features_data):
        """Update real-time metrics display."""
        try:
            timestamp = features_data.get('timestamp', time.time())
            time_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
            
            metrics_text = f"""Real-time System Metrics
======================
Updated: {time_str}

Process Count: {features_data.get('process_count', 0)}
Network Connections: {features_data.get('network_connections', 0)}
CPU Usage: {features_data.get('cpu_usage', 0.0):.1f}%
Memory Usage: {features_data.get('memory_usage', 0.0):.1f}%

Security Metrics:
- File Operations: {features_data.get('file_operations', 0)}
- Privilege Escalations: {features_data.get('privilege_escalations', 0)}
- Suspicious API Calls: {features_data.get('suspicious_api_calls', 0)}
- System Entropy: {features_data.get('entropy_score', 0.0):.3f}

I/O Rates:
- Disk I/O: {features_data.get('disk_io_rate', 0)} bytes
- Network I/O: {features_data.get('network_io_rate', 0)} bytes"""
            
            self.metrics_display.setPlainText(metrics_text)
            
        except Exception as e:
            self.metrics_display.setPlainText(f"Error updating metrics: {str(e)}")
    
    def update_real_time_data(self):
        """Update real-time data display."""
        try:
            # Get current risk assessment
            risk_assessment = self.detector.get_real_time_risk_assessment()
            
            risk_level = risk_assessment.get('risk_level', 'unknown')
            current_risk = risk_assessment.get('current_risk_score', 0.0)
            active_anomalies = risk_assessment.get('active_anomalies', 0)
            
            # Update status with risk level
            risk_color = {
                'low': 'green',
                'medium': 'orange', 
                'high': 'red',
                'critical': 'darkred'
            }.get(risk_level, 'gray')
            
            self.status_label.setText(
                f"Risk Level: {risk_level.upper()} | "
                f"Score: {current_risk:.3f} | "
                f"Active Anomalies: {active_anomalies}"
            )
            
            # Update model statistics periodically
            if int(time.time()) % 30 == 0:  # Every 30 seconds
                self.update_model_statistics()
            
        except Exception as e:
            print(f"Error updating real-time data: {e}")
    
    def filter_anomalies(self):
        """Filter anomalies based on current filter settings."""
        severity_filter = self.severity_filter.currentText()
        type_filter = self.type_filter.currentText()
        
        for row in range(self.anomalies_table.rowCount()):
            type_item = self.anomalies_table.item(row, 1)
            severity_item = self.anomalies_table.item(row, 3)
            
            if not all([type_item, severity_item]):
                continue
            
            anomaly_type = type_item.text()
            severity = severity_item.text()
            
            show_row = True
            
            if severity_filter != "All Severities" and severity != severity_filter:
                show_row = False
            
            if type_filter != "All Types":
                type_match = False
                if type_filter == "Statistical" and "Statistical" in anomaly_type:
                    type_match = True
                elif type_filter == "Pattern" and "Pattern" in anomaly_type:
                    type_match = True
                elif type_filter == "Temporal" and ("Off Hours" in anomaly_type or "Rapid" in anomaly_type):
                    type_match = True
                elif type_filter == "Behavioral" and "Behavioral" in anomaly_type:
                    type_match = True
                
                if not type_match:
                    show_row = False
            
            self.anomalies_table.setRowHidden(row, not show_row)
    
    def view_anomaly_details(self, item):
        """View detailed information about an ML anomaly."""
        row = item.row()
        
        time_str = self.anomalies_table.item(row, 0).text()
        anomaly_type = self.anomalies_table.item(row, 1).text()
        confidence = self.anomalies_table.item(row, 2).text()
        severity = self.anomalies_table.item(row, 3).text()
        description = self.anomalies_table.item(row, 4).toolTip() or self.anomalies_table.item(row, 4).text()
        risk_score = self.anomalies_table.item(row, 5).text()
        
        details_text = f"""ML Anomaly Detection Details
============================

Detection Time: {time_str}
Anomaly Type: {anomaly_type}
Confidence: {confidence}
Severity: {severity}
Risk Score: {risk_score}

Description: {description}

Machine Learning Analysis:
1. Feature-based anomaly detection identified unusual patterns
2. Statistical analysis revealed deviations from normal behavior  
3. Behavioral modeling detected suspicious system interactions
4. Pattern recognition found sequences typical of malware

Investigation Recommendations:
1. Perform immediate system scan with other detection tools
2. Check system logs for correlated events
3. Analyze network traffic for malicious communication
4. Review recent system changes and installations
5. Consider isolating system if risk score is high

Model Information:
- Detection Algorithm: Multi-layer anomaly detection
- Training Data: {self.detector.model_data.get('training_data_size', 0)} samples
- Feature Engineering: 12 behavioral and statistical features
- Confidence Threshold: Adaptive based on historical patterns

Next Steps:
- Continue monitoring for additional anomalies
- Update model training with new normal behavior
- Correlate with other detection module findings
- Document findings for forensic analysis"""
        
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("ML Anomaly Details")
        msg_box.setText(details_text)
        msg_box.exec()
    
    def start_monitoring_method(self):
        """Start monitoring (for main window integration)."""
        self.start_monitoring()
    
    def stop_monitoring_method(self):
        """Stop monitoring (for main window integration)."""
        self.stop_monitoring()
    
    def export_results(self):
        """Export ML anomaly analysis results."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"ml_anomaly_analysis_{timestamp}.json"
        
        from PyQt6.QtWidgets import QFileDialog
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Export ML Analysis", default_filename, 
            "JSON Files (*.json);;All Files (*)"
        )
        
        if output_path:
            try:
                self.detector.export_ml_analysis(output_path)
                QMessageBox.information(self, "Export Successful", 
                                      f"ML analysis exported to: {output_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", 
                                   f"Failed to export analysis: {str(e)}")