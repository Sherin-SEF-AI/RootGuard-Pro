"""
Service Detection Module
Implements service enumeration and analysis for detecting hidden services on Linux.
"""

import subprocess
import os
import glob
import psutil
from typing import List, Dict
try:
    import systemd.daemon
    SYSTEMD_AVAILABLE = True
except ImportError:
    SYSTEMD_AVAILABLE = False


class ServiceDetector:
    """Service detection and analysis class for Linux systems."""
    
    def __init__(self):
        self.suspicious_indicators = [
            'rootkit', 'keylogger', 'backdoor', 'trojan', 'stealth',
            'hidden', 'inject', 'hook', 'bypass', 'remote', 'miner'
        ]
        
    def enumerate_systemctl_services(self) -> List[Dict]:
        """Enumerate services using systemctl."""
        services = []
        
        try:
            # Get all systemd services
            result = subprocess.run(['systemctl', 'list-units', '--type=service', '--all', '--no-pager'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                return services
            
            lines = result.stdout.strip().split('\n')
            
            # Skip header lines and footer
            for line in lines[1:]:
                if line.strip() and not line.startswith('●') and 'UNIT' not in line:
                    try:
                        parts = line.split()
                        if len(parts) >= 4:
                            unit_name = parts[0]
                            load_state = parts[1]
                            active_state = parts[2]
                            sub_state = parts[3]
                            description = ' '.join(parts[4:]) if len(parts) > 4 else 'N/A'
                            
                            # Get additional service details
                            service_details = self.get_systemctl_service_details(unit_name)
                            
                            service_info = {
                                'name': unit_name,
                                'display_name': description,
                                'status': f"{active_state}/{sub_state}",
                                'start_type': service_details.get('enabled_state', 'Unknown'),
                                'exe_path': service_details.get('exec_start', 'N/A'),
                                'pid': service_details.get('main_pid', 0),
                                'description': description,
                                'source': 'systemctl',
                                'hidden': False,
                                'suspicious': self.is_suspicious_service(unit_name, service_details.get('exec_start', ''))
                            }
                            services.append(service_info)
                            
                    except (ValueError, IndexError):
                        continue
                        
        except Exception as e:
            print(f"Error in systemctl enumeration: {e}")
            
        return services
    
    def enumerate_init_services(self) -> List[Dict]:
        """Enumerate services by checking init.d and systemd unit files."""
        services = []
        
        try:
            # Check /etc/systemd/system/ and /lib/systemd/system/
            systemd_dirs = ['/etc/systemd/system/', '/lib/systemd/system/', '/usr/lib/systemd/system/']
            
            for systemd_dir in systemd_dirs:
                if not os.path.exists(systemd_dir):
                    continue
                    
                service_files = glob.glob(os.path.join(systemd_dir, '*.service'))
                
                for service_file in service_files:
                    try:
                        service_name = os.path.basename(service_file)
                        
                        # Parse service file
                        service_config = self.parse_systemd_service(service_file)
                        
                        service_info = {
                            'name': service_name,
                            'display_name': service_config.get('description', service_name),
                            'status': 'Unknown',  # Will be determined by comparison
                            'start_type': 'Manual',  # Default
                            'exe_path': service_config.get('exec_start', 'N/A'),
                            'pid': 0,
                            'description': service_config.get('description', 'N/A'),
                            'source': 'init_files',
                            'hidden': False,
                            'suspicious': self.is_suspicious_service(service_name, service_config.get('exec_start', ''))
                        }
                        
                        services.append(service_info)
                        
                    except Exception:
                        continue
            
            # Also check /etc/init.d/ for SysV init scripts
            init_d_dir = '/etc/init.d/'
            if os.path.exists(init_d_dir):
                init_scripts = [f for f in os.listdir(init_d_dir) 
                               if os.path.isfile(os.path.join(init_d_dir, f)) and not f.startswith('.')]
                
                for script_name in init_scripts:
                    service_info = {
                        'name': f"{script_name} (init.d)",
                        'display_name': script_name,
                        'status': 'Unknown',
                        'start_type': 'Manual',
                        'exe_path': os.path.join(init_d_dir, script_name),
                        'pid': 0,
                        'description': 'SysV init script',
                        'source': 'init_d',
                        'hidden': False,
                        'suspicious': self.is_suspicious_service(script_name, script_name)
                    }
                    
                    services.append(service_info)
                    
        except Exception as e:
            print(f"Error in init enumeration: {e}")
            
        return services
    
    def get_systemctl_service_details(self, unit_name: str) -> Dict:
        """Get detailed information about a systemctl service."""
        try:
            result = subprocess.run(['systemctl', 'show', unit_name], 
                                  capture_output=True, text=True, timeout=10)
            
            details = {}
            for line in result.stdout.split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    details[key.lower()] = value
            
            return {
                'enabled_state': details.get('unitfilestate', 'Unknown'),
                'exec_start': details.get('execstart', 'N/A'),
                'main_pid': int(details.get('mainpid', '0')),
                'active_state': details.get('activestate', 'Unknown')
            }
        except Exception:
            return {}
    
    def parse_systemd_service(self, service_file: str) -> Dict:
        """Parse a systemd service file."""
        config = {}
        try:
            with open(service_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('Description='):
                        config['description'] = line.split('=', 1)[1]
                    elif line.startswith('ExecStart='):
                        config['exec_start'] = line.split('=', 1)[1]
        except Exception:
            pass
        return config
    
    def compare_service_lists(self, systemctl_services: List[Dict], init_services: List[Dict]) -> List[Dict]:
        """Compare service lists to identify discrepancies."""
        # Create dictionaries for quick lookup
        systemctl_dict = {svc['name']: svc for svc in systemctl_services}
        init_dict = {svc['name']: svc for svc in init_services}
        
        # Get all unique service names
        all_service_names = set(systemctl_dict.keys()) | set(init_dict.keys())
        
        result_services = []
        
        for service_name in all_service_names:
            systemctl_service = systemctl_dict.get(service_name)
            init_service = init_dict.get(service_name)
            
            if systemctl_service and init_service:
                # Service exists in both - merge information
                merged_service = systemctl_service.copy()
                merged_service['init_path'] = init_service['exe_path']
                merged_service['sources'] = ['systemctl', 'init_files']
                
                # Check for discrepancies
                if systemctl_service['exe_path'] != init_service['exe_path']:
                    merged_service['suspicious'] = True
                    merged_service['discrepancy'] = 'Path mismatch'
                    
            elif systemctl_service:
                # Only in systemctl - normal systemd service
                merged_service = systemctl_service.copy()
                merged_service['sources'] = ['systemctl']
                
            else:
                # Only in init files - might be orphaned or custom service
                merged_service = init_service.copy()
                merged_service['sources'] = ['init_files']
                merged_service['status'] = 'Not Active'
                merged_service['hidden'] = True
                merged_service['missing_from'] = ['systemctl']
                
            result_services.append(merged_service)
        
        return result_services
    
    def is_suspicious_service(self, name: str, path: str) -> bool:
        """Check if a service exhibits suspicious characteristics."""
        name_lower = name.lower()
        path_lower = path.lower()
        
        # Check for suspicious keywords
        for indicator in self.suspicious_indicators:
            if indicator in name_lower or indicator in path_lower:
                return True
        
        # Check for suspicious patterns
        suspicious_patterns = [
            path_lower.startswith('c:\\temp\\'),
            path_lower.startswith('c:\\users\\'),
            '.tmp' in path_lower,
            name_lower.startswith('~'),
            len(name) == 1,
            'powershell' in path_lower and '-encoded' in path_lower,
        ]
        
        return any(suspicious_patterns)
    
    def start_service(self, service_name: str) -> bool:
        """Start a service by name."""
        try:
            import subprocess
            result = subprocess.run(['sc', 'start', service_name], 
                                  capture_output=True, text=True, timeout=30)
            return result.returncode == 0
        except Exception as e:
            print(f"Error starting service {service_name}: {e}")
            return False
    
    def stop_service(self, service_name: str) -> bool:
        """Stop a service by name."""
        try:
            import subprocess
            result = subprocess.run(['sc', 'stop', service_name], 
                                  capture_output=True, text=True, timeout=30)
            return result.returncode == 0
        except Exception as e:
            print(f"Error stopping service {service_name}: {e}")
            return False
    
    def get_service_details(self, service_name: str) -> Dict:
        """Get detailed information about a specific service."""
        try:
            if WMI_AVAILABLE:
                c = wmi.WMI()
                services = c.Win32_Service(Name=service_name)
                
                if services:
                    service = services[0]
                    return {
                        'name': service.Name,
                        'display_name': service.DisplayName,
                        'description': service.Description,
                        'status': service.State,
                        'start_type': service.StartMode,
                        'exe_path': service.PathName,
                        'pid': service.ProcessId,
                        'service_type': service.ServiceType,
                        'error_control': service.ErrorControl,
                        'start_name': service.StartName,
                        'dependencies': service.ServicesDependedOn or [],
                        'dependents': service.ServicesDependingOn or []
                    }
        except Exception as e:
            return {'error': str(e)}
        
        return {'error': 'Service not found'}