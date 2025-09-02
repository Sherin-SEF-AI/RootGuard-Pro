"""
Export Dialog
Handles exporting scan results to various formats.
"""

from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QPushButton,
                             QLabel, QComboBox, QCheckBox, QFileDialog, QMessageBox)
from PyQt6.QtCore import Qt
import os
import datetime


class ExportDialog(QDialog):
    """Export dialog for scan results."""
    
    def __init__(self, parent=None, export_type="all_results"):
        super().__init__(parent)
        self.export_type = export_type
        self.setWindowTitle("Export Results")
        self.setModal(True)
        self.setFixedSize(400, 300)
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout(self)
        
        # Export type
        layout.addWidget(QLabel(f"Export {self.export_type.replace('_', ' ').title()}"))
        
        # Format selection
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("Format:"))
        
        self.format_combo = QComboBox()
        self.format_combo.addItems(["CSV", "JSON", "XML", "TXT"])
        format_layout.addWidget(self.format_combo)
        format_layout.addStretch()
        
        layout.addLayout(format_layout)
        
        # Options
        options_group = QVBoxLayout()
        
        self.include_headers = QCheckBox("Include column headers")
        self.include_headers.setChecked(True)
        options_group.addWidget(self.include_headers)
        
        self.include_hidden_only = QCheckBox("Export hidden items only")
        self.include_hidden_only.setChecked(False)
        options_group.addWidget(self.include_hidden_only)
        
        self.include_timestamp = QCheckBox("Include timestamp in filename")
        self.include_timestamp.setChecked(True)
        options_group.addWidget(self.include_timestamp)
        
        layout.addLayout(options_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.export_btn = QPushButton("Export")
        self.export_btn.clicked.connect(self.export_data)
        button_layout.addWidget(self.export_btn)
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
    
    def export_data(self):
        """Export the data in selected format."""
        format_type = self.format_combo.currentText()
        
        # Generate filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = self.export_type
        
        if self.include_timestamp.isChecked():
            filename = f"{base_name}_{timestamp}"
        else:
            filename = base_name
        
        # Set file extension
        extensions = {"CSV": ".csv", "JSON": ".json", "XML": ".xml", "TXT": ".txt"}
        filename += extensions[format_type]
        
        # Choose save location
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Results", filename, 
            f"{format_type} Files (*{extensions[format_type]})"
        )
        
        if not file_path:
            return
        
        try:
            # Export data based on format
            if format_type == "CSV":
                self.export_csv(file_path)
            elif format_type == "JSON":
                self.export_json(file_path)
            elif format_type == "XML":
                self.export_xml(file_path)
            else:
                self.export_txt(file_path)
            
            QMessageBox.information(self, "Export Successful", 
                                  f"Data exported successfully to:\n{file_path}")
            self.accept()
            
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Failed to export data:\n{str(e)}")
    
    def export_csv(self, file_path: str):
        """Export data to CSV format."""
        import csv
        
        # Get data from parent table
        table = self.get_parent_table()
        if not table:
            raise Exception("No data table found")
        
        with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write headers
            if self.include_headers.isChecked():
                headers = []
                for col in range(table.columnCount()):
                    header_item = table.horizontalHeaderItem(col)
                    headers.append(header_item.text() if header_item else f"Column {col}")
                writer.writerow(headers)
            
            # Write data rows
            for row in range(table.rowCount()):
                if table.isRowHidden(row):
                    continue
                    
                row_data = []
                for col in range(table.columnCount()):
                    item = table.item(row, col)
                    row_data.append(item.text() if item else "")
                
                # Filter for hidden items only if requested
                if self.include_hidden_only.isChecked():
                    hidden_col = self.get_hidden_column_index(table)
                    if hidden_col >= 0 and row_data[hidden_col] != "Yes":
                        continue
                
                writer.writerow(row_data)
    
    def export_json(self, file_path: str):
        """Export data to JSON format."""
        import json
        
        table = self.get_parent_table()
        if not table:
            raise Exception("No data table found")
        
        data = {
            'export_type': self.export_type,
            'timestamp': datetime.datetime.now().isoformat(),
            'data': []
        }
        
        # Get headers
        headers = []
        for col in range(table.columnCount()):
            header_item = table.horizontalHeaderItem(col)
            headers.append(header_item.text() if header_item else f"column_{col}")
        
        # Get data
        for row in range(table.rowCount()):
            if table.isRowHidden(row):
                continue
                
            row_dict = {}
            for col in range(table.columnCount()):
                item = table.item(row, col)
                row_dict[headers[col]] = item.text() if item else ""
            
            # Filter for hidden items only if requested
            if self.include_hidden_only.isChecked():
                if row_dict.get('Hidden', 'No') != 'Yes':
                    continue
            
            data['data'].append(row_dict)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def export_xml(self, file_path: str):
        """Export data to XML format."""
        table = self.get_parent_table()
        if not table:
            raise Exception("No data table found")
        
        xml_content = '<?xml version="1.0" encoding="UTF-8"?>\n'
        xml_content += f'<{self.export_type}>\n'
        xml_content += f'  <timestamp>{datetime.datetime.now().isoformat()}</timestamp>\n'
        xml_content += '  <data>\n'
        
        # Get headers
        headers = []
        for col in range(table.columnCount()):
            header_item = table.horizontalHeaderItem(col)
            headers.append(header_item.text().replace(' ', '_').lower() if header_item else f"column_{col}")
        
        # Write data
        for row in range(table.rowCount()):
            if table.isRowHidden(row):
                continue
                
            xml_content += '    <item>\n'
            
            for col in range(table.columnCount()):
                item = table.item(row, col)
                value = item.text() if item else ""
                # Escape XML special characters
                value = value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                xml_content += f'      <{headers[col]}>{value}</{headers[col]}>\n'
            
            xml_content += '    </item>\n'
        
        xml_content += '  </data>\n'
        xml_content += f'</{self.export_type}>\n'
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(xml_content)
    
    def export_txt(self, file_path: str):
        """Export data to plain text format."""
        table = self.get_parent_table()
        if not table:
            raise Exception("No data table found")
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f"Rootkit Detection - {self.export_type.replace('_', ' ').title()}\n")
            f.write("=" * 60 + "\n")
            f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Write headers
            if self.include_headers.isChecked():
                headers = []
                for col in range(table.columnCount()):
                    header_item = table.horizontalHeaderItem(col)
                    headers.append(header_item.text() if header_item else f"Column {col}")
                f.write(" | ".join(f"{h:15}" for h in headers) + "\n")
                f.write("-" * (len(headers) * 18) + "\n")
            
            # Write data
            for row in range(table.rowCount()):
                if table.isRowHidden(row):
                    continue
                    
                row_data = []
                for col in range(table.columnCount()):
                    item = table.item(row, col)
                    text = item.text() if item else ""
                    row_data.append(text[:15])  # Truncate for formatting
                
                # Filter for hidden items only if requested
                if self.include_hidden_only.isChecked():
                    hidden_col = self.get_hidden_column_index(table)
                    if hidden_col >= 0 and row_data[hidden_col] != "Yes":
                        continue
                
                f.write(" | ".join(f"{d:15}" for d in row_data) + "\n")
    
    def get_parent_table(self):
        """Get the table widget from the parent tab."""
        parent_widget = self.parent()
        
        # Find the table widget in the parent
        if hasattr(parent_widget, 'process_table'):
            return parent_widget.process_table
        elif hasattr(parent_widget, 'service_table'):
            return parent_widget.service_table
        elif hasattr(parent_widget, 'connection_table'):
            return parent_widget.connection_table
        elif hasattr(parent_widget, 'hooks_table'):
            return parent_widget.hooks_table
        
        return None
    
    def get_hidden_column_index(self, table):
        """Find the index of the 'Hidden' column."""
        for col in range(table.columnCount()):
            header_item = table.horizontalHeaderItem(col)
            if header_item and header_item.text() == "Hidden":
                return col
        return -1