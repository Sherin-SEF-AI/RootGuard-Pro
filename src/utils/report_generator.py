"""
Report Generation Module
Creates comprehensive security reports in multiple formats.
"""

import os
import json
import csv
import datetime
from typing import Dict, List
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class ReportGenerator:
    """Generates security analysis reports in multiple formats."""
    
    def __init__(self):
        self.scan_data = {
            'processes': [],
            'services': [],
            'network': [],
            'hooks': [],
            'timestamp': datetime.datetime.now(),
            'system_info': self.get_system_info()
        }
        
    def get_system_info(self) -> Dict:
        """Get basic system information."""
        try:
            import platform
            import psutil
            
            return {
                'hostname': platform.node(),
                'os': platform.system(),
                'os_version': platform.version(),
                'architecture': platform.architecture()[0],
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'boot_time': psutil.boot_time()
            }
        except Exception:
            return {'error': 'Could not retrieve system information'}
    
    def collect_current_data(self):
        """Collect current scan data from all detection modules."""
        try:
            # Import detection modules
            from ..detection.process_detector import ProcessDetector
            from ..detection.service_detector import ServiceDetector
            from ..detection.network_detector import NetworkDetector
            from ..detection.hooks_detector import HooksDetector
            
            # Collect process data
            process_detector = ProcessDetector()
            toolhelp_procs = process_detector.enumerate_toolhelp32()
            wmi_procs = process_detector.enumerate_wmi()
            eprocess_procs = process_detector.enumerate_eprocess()
            self.scan_data['processes'] = process_detector.compare_process_lists(
                toolhelp_procs, wmi_procs, eprocess_procs
            )
            
            # Collect service data
            service_detector = ServiceDetector()
            scm_services = service_detector.enumerate_scm_services()
            registry_services = service_detector.enumerate_registry_services()
            self.scan_data['services'] = service_detector.compare_service_lists(
                scm_services, registry_services
            )
            
            # Collect network data
            network_detector = NetworkDetector()
            netstat_conns = network_detector.enumerate_netstat()
            api_conns = network_detector.enumerate_api_connections()
            self.scan_data['network'] = network_detector.compare_connection_lists(
                netstat_conns, api_conns
            )
            
            # Collect hooks data
            hooks_detector = HooksDetector()
            ssdt_hooks = hooks_detector.analyze_ssdt_hooks()
            api_hooks = hooks_detector.analyze_api_hooks()
            iat_hooks = hooks_detector.analyze_iat_hooks()
            self.scan_data['hooks'] = ssdt_hooks + api_hooks + iat_hooks
            
        except Exception as e:
            print(f"Error collecting scan data: {e}")
    
    def generate_pdf_report(self, output_path: str, include_sections: Dict):
        """Generate PDF report."""
        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab is required for PDF generation")
        
        self.collect_current_data()
        
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.darkblue,
            alignment=1
        )
        story.append(Paragraph("Rootkit Detection Analysis Report", title_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        
        summary_data = self.generate_summary()
        summary_text = f"""
        Scan completed on {self.scan_data['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}<br/>
        System: {self.scan_data['system_info'].get('hostname', 'Unknown')}<br/>
        OS: {self.scan_data['system_info'].get('os', 'Unknown')} {self.scan_data['system_info'].get('os_version', '')}<br/><br/>
        
        <b>Findings Summary:</b><br/>
        • Total Processes Analyzed: {summary_data['total_processes']}<br/>
        • Hidden Processes Found: {summary_data['hidden_processes']}<br/>
        • Total Services Analyzed: {summary_data['total_services']}<br/>
        • Hidden Services Found: {summary_data['hidden_services']}<br/>
        • Network Connections Analyzed: {summary_data['total_connections']}<br/>
        • Hidden Connections Found: {summary_data['hidden_connections']}<br/>
        • System Hooks Analyzed: {summary_data['total_hooks']}<br/>
        • Suspicious Hooks Found: {summary_data['suspicious_hooks']}<br/>
        """
        
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Detailed sections
        if include_sections.get('processes', False):
            self.add_process_section(story, styles)
        
        if include_sections.get('services', False):
            self.add_service_section(story, styles)
        
        if include_sections.get('network', False):
            self.add_network_section(story, styles)
        
        if include_sections.get('hooks', False):
            self.add_hooks_section(story, styles)
        
        # Build PDF
        doc.build(story)
    
    def generate_html_report(self, output_path: str, include_sections: Dict):
        """Generate HTML report."""
        self.collect_current_data()
        
        html_content = self.generate_html_template()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def generate_csv_report(self, output_path: str, include_sections: Dict):
        """Generate CSV report with all findings."""
        self.collect_current_data()
        
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow(['Type', 'Name', 'Status', 'Details', 'Suspicious', 'Hidden'])
            
            # Write process data
            if include_sections.get('processes', False):
                for proc in self.scan_data['processes']:
                    writer.writerow([
                        'Process',
                        proc.get('name', 'N/A'),
                        f"PID: {proc.get('pid', 'N/A')}",
                        proc.get('cmdline', 'N/A'),
                        'Yes' if proc.get('suspicious', False) else 'No',
                        'Yes' if proc.get('hidden', False) else 'No'
                    ])
            
            # Write service data
            if include_sections.get('services', False):
                for svc in self.scan_data['services']:
                    writer.writerow([
                        'Service',
                        svc.get('name', 'N/A'),
                        svc.get('status', 'N/A'),
                        svc.get('exe_path', 'N/A'),
                        'Yes' if svc.get('suspicious', False) else 'No',
                        'Yes' if svc.get('hidden', False) else 'No'
                    ])
            
            # Write network data
            if include_sections.get('network', False):
                for conn in self.scan_data['network']:
                    writer.writerow([
                        'Network',
                        conn.get('process_name', 'N/A'),
                        f"{conn.get('protocol', 'N/A')} {conn.get('state', '')}",
                        f"{conn.get('local_ip', '')}:{conn.get('local_port', '')} -> {conn.get('remote_ip', '')}:{conn.get('remote_port', '')}",
                        'Yes' if conn.get('suspicious', False) else 'No',
                        'Yes' if conn.get('hidden', False) else 'No'
                    ])
            
            # Write hooks data
            if include_sections.get('hooks', False):
                for hook in self.scan_data['hooks']:
                    writer.writerow([
                        'Hook',
                        hook.get('function', 'N/A'),
                        hook.get('type', 'N/A'),
                        f"Module: {hook.get('module', 'N/A')}",
                        'Yes' if hook.get('suspicious', False) else 'No',
                        'No'  # Hooks are modifications, not hidden
                    ])
    
    def generate_summary(self) -> Dict:
        """Generate summary statistics."""
        return {
            'total_processes': len(self.scan_data['processes']),
            'hidden_processes': sum(1 for p in self.scan_data['processes'] if p.get('hidden', False)),
            'total_services': len(self.scan_data['services']),
            'hidden_services': sum(1 for s in self.scan_data['services'] if s.get('hidden', False)),
            'total_connections': len(self.scan_data['network']),
            'hidden_connections': sum(1 for c in self.scan_data['network'] if c.get('hidden', False)),
            'total_hooks': len(self.scan_data['hooks']),
            'suspicious_hooks': sum(1 for h in self.scan_data['hooks'] if h.get('suspicious', False))
        }
    
    def generate_text_preview(self) -> str:
        """Generate a text preview of the report."""
        preview = "ROOTKIT DETECTION ANALYSIS REPORT\n"
        preview += "=" * 50 + "\n\n"
        
        preview += f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        preview += f"System: {self.scan_data['system_info'].get('hostname', 'Unknown')}\n"
        preview += f"OS: {self.scan_data['system_info'].get('os', 'Unknown')}\n\n"
        
        # Add sample findings
        preview += "SAMPLE FINDINGS:\n"
        preview += "-" * 20 + "\n"
        preview += "• System appears to be clean\n"
        preview += "• No hidden processes detected\n"
        preview += "• All services operating normally\n"
        preview += "• Network connections within normal parameters\n"
        preview += "• No suspicious system hooks found\n\n"
        
        preview += "Run a full scan to generate a complete report with actual findings.\n"
        
        return preview
    
    def generate_html_template(self) -> str:
        """Generate HTML report template."""
        summary = self.generate_summary()
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Rootkit Detection Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; }}
        .summary {{ background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; }}
        .section {{ background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #34495e; color: white; }}
        .suspicious {{ background-color: #ffebee; }}
        .hidden {{ background-color: #fff3e0; }}
        .normal {{ background-color: #e8f5e8; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Rootkit Detection Analysis Report</h1>
        <p>Generated on {self.scan_data['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>System:</strong> {self.scan_data['system_info'].get('hostname', 'Unknown')}</p>
        <p><strong>OS:</strong> {self.scan_data['system_info'].get('os', 'Unknown')} {self.scan_data['system_info'].get('os_version', '')}</p>
        
        <h3>Findings Overview</h3>
        <ul>
            <li>Total Processes Analyzed: {summary['total_processes']}</li>
            <li>Hidden Processes Found: {summary['hidden_processes']}</li>
            <li>Total Services Analyzed: {summary['total_services']}</li>
            <li>Hidden Services Found: {summary['hidden_services']}</li>
            <li>Network Connections Analyzed: {summary['total_connections']}</li>
            <li>Hidden Connections Found: {summary['hidden_connections']}</li>
            <li>System Hooks Analyzed: {summary['total_hooks']}</li>
            <li>Suspicious Hooks Found: {summary['suspicious_hooks']}</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
            <li>Regularly update antivirus definitions</li>
            <li>Monitor system for unusual process activity</li>
            <li>Keep operating system and software updated</li>
            <li>Use application whitelisting where possible</li>
            <li>Implement network monitoring solutions</li>
        </ul>
    </div>
    
</body>
</html>
        """
        
        return html
    
    def add_process_section(self, story, styles):
        """Add process analysis section to PDF."""
        story.append(Paragraph("Process Analysis", styles['Heading2']))
        
        # Create process table
        process_data = [['PID', 'Name', 'Status', 'Hidden']]
        
        for proc in self.scan_data['processes'][:20]:  # Limit to first 20
            status = 'Suspicious' if proc.get('suspicious', False) else 'Normal'
            hidden = 'Yes' if proc.get('hidden', False) else 'No'
            
            process_data.append([
                str(proc.get('pid', 'N/A')),
                proc.get('name', 'N/A')[:30],  # Truncate long names
                status,
                hidden
            ])
        
        table = Table(process_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(table)
        story.append(Spacer(1, 0.2*inch))
    
    def add_service_section(self, story, styles):
        """Add service analysis section to PDF."""
        story.append(Paragraph("Service Analysis", styles['Heading2']))
        
        # Create service table
        service_data = [['Name', 'Status', 'Type', 'Hidden']]
        
        for svc in self.scan_data['services'][:20]:  # Limit to first 20
            hidden = 'Yes' if svc.get('hidden', False) else 'No'
            
            service_data.append([
                svc.get('name', 'N/A')[:25],
                svc.get('status', 'N/A'),
                svc.get('start_type', 'N/A'),
                hidden
            ])
        
        table = Table(service_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(table)
        story.append(Spacer(1, 0.2*inch))
    
    def add_network_section(self, story, styles):
        """Add network analysis section to PDF."""
        story.append(Paragraph("Network Analysis", styles['Heading2']))
        
        # Create network table
        network_data = [['Protocol', 'Local', 'Remote', 'Process', 'Hidden']]
        
        for conn in self.scan_data['network'][:20]:  # Limit to first 20
            local_addr = f"{conn.get('local_ip', '')}:{conn.get('local_port', '')}"
            remote_addr = f"{conn.get('remote_ip', '')}:{conn.get('remote_port', '')}"
            hidden = 'Yes' if conn.get('hidden', False) else 'No'
            
            network_data.append([
                conn.get('protocol', 'N/A'),
                local_addr[:20],
                remote_addr[:20],
                conn.get('process_name', 'N/A')[:15],
                hidden
            ])
        
        table = Table(network_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(table)
        story.append(Spacer(1, 0.2*inch))
    
    def add_hooks_section(self, story, styles):
        """Add hooks analysis section to PDF."""
        story.append(Paragraph("System Hooks Analysis", styles['Heading2']))
        
        # Create hooks table
        hooks_data = [['Type', 'Function', 'Module', 'Status']]
        
        for hook in self.scan_data['hooks'][:20]:  # Limit to first 20
            status = 'Suspicious' if hook.get('suspicious', False) else 'Normal'
            
            hooks_data.append([
                hook.get('type', 'N/A'),
                hook.get('function', 'N/A')[:25],
                hook.get('module', 'N/A')[:20],
                status
            ])
        
        table = Table(hooks_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(table)
        story.append(Spacer(1, 0.2*inch))