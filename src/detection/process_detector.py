"""
Process Detection Module
Implements multiple process enumeration techniques to detect hidden processes on Linux.
"""

import os
import glob
import subprocess
import psutil
import time
from typing import List, Dict, Set


class ProcessDetector:
    """Process detection and analysis class for Linux systems."""
    
    def __init__(self):
        self.suspicious_indicators = [
            'rootkit', 'keylogger', 'backdoor', 'trojan', 'stealth',
            'hidden', 'inject', 'hook', 'bypass', 'evasion', 'miner'
        ]
        
    def enumerate_proc_filesystem(self) -> List[Dict]:
        """Enumerate processes using /proc filesystem."""
        processes = []
        
        try:
            # Get all PID directories in /proc
            proc_dirs = glob.glob('/proc/[0-9]*')
            
            for proc_dir in proc_dirs:
                try:
                    pid = int(os.path.basename(proc_dir))
                    
                    # Read process information from /proc/PID/
                    stat_file = os.path.join(proc_dir, 'stat')
                    cmdline_file = os.path.join(proc_dir, 'cmdline')
                    exe_link = os.path.join(proc_dir, 'exe')
                    
                    if not os.path.exists(stat_file):
                        continue
                    
                    # Parse /proc/PID/stat
                    with open(stat_file, 'r') as f:
                        stat_data = f.read().strip().split()
                    
                    if len(stat_data) < 4:
                        continue
                    
                    process_name = stat_data[1].strip('()')
                    state = stat_data[2]
                    ppid = int(stat_data[3])
                    
                    # Get command line
                    cmdline = 'N/A'
                    try:
                        with open(cmdline_file, 'r') as f:
                            cmdline_raw = f.read()
                            cmdline = cmdline_raw.replace('\x00', ' ').strip()
                            if not cmdline:
                                cmdline = f'[{process_name}]'
                    except (FileNotFoundError, PermissionError):
                        pass
                    
                    # Get executable path
                    exe_path = 'N/A'
                    try:
                        exe_path = os.readlink(exe_link)
                    except (FileNotFoundError, PermissionError, OSError):
                        pass
                    
                    # Get additional info using psutil
                    try:
                        proc = psutil.Process(pid)
                        memory_mb = proc.memory_info().rss / 1024 / 1024
                        cpu_percent = proc.cpu_percent()
                        create_time = proc.create_time()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        memory_mb = 0
                        cpu_percent = 0
                        create_time = 0
                    
                    process_info = {
                        'pid': pid,
                        'ppid': ppid,
                        'name': process_name,
                        'cmdline': cmdline,
                        'exe_path': exe_path,
                        'state': state,
                        'memory_mb': memory_mb,
                        'cpu_percent': cpu_percent,
                        'create_time': create_time,
                        'source': 'proc_fs',
                        'hidden': False,
                        'suspicious': self.is_suspicious_process(process_name, cmdline)
                    }
                    
                    processes.append(process_info)
                    
                except (ValueError, FileNotFoundError, PermissionError):
                    continue
                    
        except Exception as e:
            print(f"Error in /proc enumeration: {e}")
            
        return processes
    
    def enumerate_ps_command(self) -> List[Dict]:
        """Enumerate processes using ps command."""
        processes = []
        
        try:
            # Use ps command with detailed output
            result = subprocess.run(['ps', 'auxww'], capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                return processes
            
            lines = result.stdout.strip().split('\n')
            
            # Skip header line
            for line in lines[1:]:
                try:
                    parts = line.split(None, 10)  # Split into max 11 parts
                    if len(parts) < 11:
                        continue
                    
                    pid = int(parts[1])
                    cpu_percent = float(parts[2])
                    memory_percent = float(parts[3])
                    command = parts[10]
                    
                    # Extract process name from command
                    process_name = command.split()[0] if command else 'Unknown'
                    if '/' in process_name:
                        process_name = os.path.basename(process_name)
                    
                    # Get additional info
                    try:
                        proc = psutil.Process(pid)
                        memory_mb = proc.memory_info().rss / 1024 / 1024
                        ppid = proc.ppid()
                        create_time = proc.create_time()
                        exe_path = proc.exe()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        memory_mb = 0
                        ppid = 0
                        create_time = 0
                        exe_path = 'N/A'
                    
                    process_info = {
                        'pid': pid,
                        'ppid': ppid,
                        'name': process_name,
                        'cmdline': command,
                        'exe_path': exe_path,
                        'memory_mb': memory_mb,
                        'cpu_percent': cpu_percent,
                        'create_time': create_time,
                        'source': 'ps_command',
                        'hidden': False,
                        'suspicious': self.is_suspicious_process(process_name, command)
                    }
                    
                    processes.append(process_info)
                    
                except (ValueError, IndexError):
                    continue
                    
        except Exception as e:
            print(f"Error in ps enumeration: {e}")
            
        return processes
    
    def enumerate_sysfs(self) -> List[Dict]:
        """Enumerate processes using sysfs and kernel task structures."""
        processes = []
        
        # Use psutil as the most reliable method for Linux
        # In a real implementation, this could involve reading /sys/kernel/debug/
        try:
            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline']):
                try:
                    process_info = {
                        'pid': proc.info['pid'],
                        'ppid': proc.info['ppid'] or 0,
                        'name': proc.info['name'] or 'Unknown',
                        'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else 'N/A',
                        'memory_mb': proc.memory_info().rss / 1024 / 1024,
                        'cpu_percent': proc.cpu_percent(),
                        'source': 'sysfs',
                        'hidden': False,
                        'suspicious': self.is_suspicious_process(proc.info['name'] or '', 
                                                               ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else '')
                    }
                    
                    processes.append(process_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"Error in sysfs enumeration: {e}")
            
        return processes
    
    def compare_process_lists(self, proc_fs_procs: List[Dict], 
                            ps_procs: List[Dict], 
                            sysfs_procs: List[Dict]) -> List[Dict]:
        """Compare process lists to identify discrepancies and hidden processes."""
        # Create sets of PIDs from each enumeration method
        proc_fs_pids = {proc['pid'] for proc in proc_fs_procs}
        ps_pids = {proc['pid'] for proc in ps_procs}
        sysfs_pids = {proc['pid'] for proc in sysfs_procs}
        
        # Find all unique PIDs
        all_pids = proc_fs_pids | ps_pids | sysfs_pids
        
        # Create comprehensive process list
        process_dict = {}
        
        # Add processes from all sources
        for proc_list in [proc_fs_procs, ps_procs, sysfs_procs]:
            for proc in proc_list:
                pid = proc['pid']
                if pid not in process_dict:
                    process_dict[pid] = proc.copy()
                    process_dict[pid]['sources'] = [proc['source']]
                else:
                    if proc['source'] not in process_dict[pid]['sources']:
                        process_dict[pid]['sources'].append(proc['source'])
        
        # Mark potentially hidden processes
        result_processes = []
        for pid, proc in process_dict.items():
            sources = proc['sources']
            
            # Process is potentially hidden if it's not visible in all enumeration methods
            expected_sources = ['proc_fs', 'ps_command', 'sysfs']
            
            missing_sources = set(expected_sources) - set(sources)
            
            if missing_sources:
                proc['hidden'] = True
                proc['missing_from'] = list(missing_sources)
            else:
                proc['hidden'] = False
                
            # Additional suspicious behavior checks
            if self.check_process_anomalies(proc):
                proc['suspicious'] = True
                
            result_processes.append(proc)
        
        return result_processes
    
    def is_suspicious_process(self, name: str, cmdline: str) -> bool:
        """Check if a process exhibits suspicious characteristics."""
        name_lower = name.lower()
        cmdline_lower = cmdline.lower()
        
        # Check for suspicious keywords
        for indicator in self.suspicious_indicators:
            if indicator in name_lower or indicator in cmdline_lower:
                return True
        
        # Check for suspicious patterns
        suspicious_patterns = [
            len(name) == 1,  # Single character process names
            name_lower.endswith('.tmp'),  # Temporary file extensions
            name_lower.startswith('~'),  # Hidden file prefix
            'powershell' in cmdline_lower and '-encoded' in cmdline_lower,  # Encoded PowerShell
            len(cmdline) > 1000,  # Extremely long command lines
        ]
        
        return any(suspicious_patterns)
    
    def check_process_anomalies(self, process: Dict) -> bool:
        """Check for process anomalies that might indicate malicious behavior."""
        try:
            pid = process['pid']
            proc = psutil.Process(pid)
            
            # Check for process hollowing indicators
            if proc.name() != process['name']:
                return True
                
            # Check for unusual parent-child relationships
            try:
                parent = proc.parent()
                if parent and parent.name().lower() in ['explorer.exe', 'winlogon.exe']:
                    if process['name'].lower() not in ['cmd.exe', 'powershell.exe', 'notepad.exe']:
                        return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
                
            # Check for processes with no modules (possible process hollowing)
            try:
                modules = proc.memory_maps()
                if not modules:
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
                
        except Exception:
            pass
            
        return False
    
    def terminate_process(self, pid: int) -> bool:
        """Terminate a process by PID."""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            
            # Wait for termination
            try:
                proc.wait(timeout=5)
                return True
            except psutil.TimeoutExpired:
                proc.kill()
                return True
                
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"Error terminating process {pid}: {e}")
            return False
    
    def get_process_details(self, pid: int) -> Dict:
        """Get detailed information about a specific process."""
        try:
            proc = psutil.Process(pid)
            
            details = {
                'pid': pid,
                'name': proc.name(),
                'exe': proc.exe(),
                'cmdline': proc.cmdline(),
                'cwd': proc.cwd(),
                'create_time': proc.create_time(),
                'cpu_percent': proc.cpu_percent(),
                'memory_info': proc.memory_info()._asdict(),
                'status': proc.status(),
                'username': proc.username(),
                'connections': [conn._asdict() for conn in proc.connections()],
                'open_files': [f.path for f in proc.open_files()],
                'threads': len(proc.threads()),
            }
            
            # Get parent process info
            try:
                parent = proc.parent()
                details['parent'] = {
                    'pid': parent.pid,
                    'name': parent.name()
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                details['parent'] = None
                
            # Get child processes
            details['children'] = [
                {'pid': child.pid, 'name': child.name()} 
                for child in proc.children(recursive=False)
            ]
            
            return details
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {'error': str(e)}
    
    def monitor_process_creation(self, callback):
        """Monitor for new process creation (basic implementation)."""
        known_pids = set(proc.pid for proc in psutil.process_iter())
        
        while True:
            time.sleep(1)  # Check every second
            
            current_pids = set(proc.pid for proc in psutil.process_iter())
            new_pids = current_pids - known_pids
            
            for pid in new_pids:
                try:
                    proc = psutil.Process(pid)
                    process_info = {
                        'pid': pid,
                        'name': proc.name(),
                        'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else 'N/A',
                        'ppid': proc.ppid(),
                        'create_time': proc.create_time(),
                        'suspicious': self.is_suspicious_process(proc.name(), 
                                                               ' '.join(proc.cmdline()) if proc.cmdline() else '')
                    }
                    callback(process_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            known_pids = current_pids