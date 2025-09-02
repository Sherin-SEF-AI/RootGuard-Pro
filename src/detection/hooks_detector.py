"""
System Hooks Detection Module
Analyzes system call hooks and kernel module modifications on Linux.
"""

import os
import subprocess
import glob
import psutil
from typing import List, Dict


class HooksDetector:
    """System hooks detection and analysis class for Linux."""
    
    def __init__(self):
        # Common system calls that may be hooked on Linux
        self.critical_syscalls = [
            'sys_open', 'sys_openat', 'sys_read', 'sys_write', 'sys_close',
            'sys_execve', 'sys_fork', 'sys_clone', 'sys_kill', 'sys_getdents',
            'sys_mount', 'sys_umount', 'sys_socket', 'sys_connect', 'sys_accept'
        ]
        
        # Suspicious kernel modules
        self.suspicious_modules = [
            'rootkit', 'hidden', 'stealth', 'backdoor', 'keylogger',
            'unknown', 'unnamed', 'temp', 'malware'
        ]
    
    def analyze_kernel_modules(self) -> List[Dict]:
        """Analyze loaded kernel modules for suspicious entries."""
        hooks = []
        
        try:
            # Check /proc/modules for loaded kernel modules
            with open('/proc/modules', 'r') as f:
                modules = f.readlines()
            
            for line in modules:
                parts = line.strip().split()
                if len(parts) >= 6:
                    module_name = parts[0]
                    size = int(parts[1])
                    use_count = int(parts[2])
                    dependencies = parts[3] if parts[3] != '-' else 'None'
                    state = parts[4]
                    memory_offset = parts[5]
                    
                    hook_info = {
                        'type': 'Kernel Module',
                        'function': module_name,
                        'original_address': memory_offset,
                        'hook_address': f"Size: {size}",
                        'module': module_name,
                        'suspicious': self.is_suspicious_module(module_name),
                        'confidence': 'Medium' if self.is_suspicious_module(module_name) else 'Low'
                    }
                    
                    hooks.append(hook_info)
                
        except Exception as e:
            print(f"Error in kernel module analysis: {e}")
            
        return hooks
    
    def analyze_library_hooks(self) -> List[Dict]:
        """Analyze shared library hooks and LD_PRELOAD."""
        hooks = []
        
        try:
            # Check for LD_PRELOAD environment variable
            ld_preload = os.environ.get('LD_PRELOAD', '')
            if ld_preload:
                for lib in ld_preload.split(':'):
                    if lib.strip():
                        hook_info = {
                            'type': 'LD_PRELOAD Hook',
                            'function': lib,
                            'original_address': 'N/A',
                            'hook_address': 'Preloaded',
                            'module': os.path.basename(lib),
                            'suspicious': self.is_suspicious_library(lib),
                            'confidence': 'High'
                        }
                        hooks.append(hook_info)
            
            # Check for common shared libraries that might be hooked
            critical_libs = ['/lib/x86_64-linux-gnu/libc.so.6', 
                           '/lib/x86_64-linux-gnu/libdl.so.2',
                           '/lib/x86_64-linux-gnu/libpthread.so.0']
            
            for lib_path in critical_libs:
                if os.path.exists(lib_path):
                    # Check library modification time and size
                    stat = os.stat(lib_path)
                    
                    hook_info = {
                        'type': 'System Library',
                        'function': os.path.basename(lib_path),
                        'original_address': lib_path,
                        'hook_address': f"Size: {stat.st_size}",
                        'module': os.path.basename(lib_path),
                        'suspicious': self.check_library_integrity(lib_path),
                        'confidence': 'Medium'
                    }
                    
                    hooks.append(hook_info)
                    
        except Exception as e:
            print(f"Error in library hook analysis: {e}")
            
        return hooks
    
    def analyze_syscall_hooks(self) -> List[Dict]:
        """Analyze system call hooks via /proc/kallsyms."""
        hooks = []
        
        try:
            # Check /proc/kallsyms for system call addresses
            if os.path.exists('/proc/kallsyms'):
                with open('/proc/kallsyms', 'r') as f:
                    symbols = f.readlines()
                
                for line in symbols[:100]:  # Limit to first 100 for demo
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        address = parts[0]
                        symbol_type = parts[1]
                        symbol_name = parts[2]
                        
                        # Look for system call symbols
                        if symbol_name.startswith('sys_') and symbol_name in self.critical_syscalls:
                            hook_info = {
                                'type': 'System Call',
                                'function': symbol_name,
                                'original_address': f"0x{address}",
                                'hook_address': 'Unknown',
                                'module': 'kernel',
                                'suspicious': self.is_suspicious_syscall(symbol_name),
                                'confidence': 'Low'
                            }
                            
                            hooks.append(hook_info)
                            
        except Exception as e:
            print(f"Error in syscall analysis: {e}")
            
        return hooks
    
    def is_suspicious_module(self, module_name: str) -> bool:
        """Check if a kernel module name is suspicious."""
        name_lower = module_name.lower()
        return any(indicator in name_lower for indicator in self.suspicious_modules)
    
    def is_suspicious_library(self, lib_path: str) -> bool:
        """Check if a library path is suspicious."""
        path_lower = lib_path.lower()
        suspicious_paths = ['/tmp/', '/dev/shm/', '/var/tmp/', '..']
        return any(path in path_lower for path in suspicious_paths)
    
    def is_suspicious_syscall(self, syscall_name: str) -> bool:
        """Check if a system call is commonly hooked."""
        commonly_hooked = ['sys_open', 'sys_getdents', 'sys_read', 'sys_write']
        return syscall_name in commonly_hooked
    
    def check_library_integrity(self, lib_path: str) -> bool:
        """Check library file integrity (simplified)."""
        try:
            stat = os.stat(lib_path)
            # Very basic check - libraries under 1KB are suspicious
            return stat.st_size < 1024
        except:
            return True
    
    def check_function_integrity(self, function_name: str) -> bool:
        """Check if a function appears to be hooked (simplified)."""
        # This is a placeholder for actual function integrity checking
        # Real implementation would require reading function prologue bytes
        
        # Simple heuristic: check if function name contains suspicious patterns
        suspicious_patterns = ['hook', 'patch', 'redirect', 'fake']
        return any(pattern in function_name.lower() for pattern in suspicious_patterns)
    
    def check_inline_hook(self, function_address: int) -> bool:
        """Check for inline API hooks (simplified detection)."""
        try:
            # Read first few bytes of function
            # Real implementation would analyze assembly instructions
            
            # Placeholder: randomly mark some functions as hooked for demonstration
            return function_address % 7 == 0  # Simple heuristic
            
        except Exception:
            return False
    
    def check_process_iat(self, pid: int, process_name: str) -> List[Dict]:
        """Check Import Address Table for a specific process."""
        hooks = []
        
        try:
            # This would require reading process memory and parsing PE headers
            # Simplified implementation for demonstration
            
            common_imports = ['CreateFileW', 'CreateProcessW', 'RegOpenKeyW', 'WSAStartup']
            
            for import_func in common_imports:
                hook_info = {
                    'type': 'IAT Hook',
                    'function': f"{process_name}!{import_func}",
                    'original_address': f"0x{hash(import_func) & 0xFFFFFFFF:08X}",
                    'hook_address': 'Unknown',
                    'module': process_name,
                    'suspicious': False,
                    'confidence': 'Low',
                    'pid': pid
                }
                
                # Simple suspicious check
                if self.is_suspicious_import_hook(import_func, process_name):
                    hook_info['suspicious'] = True
                    hook_info['hook_address'] = 'Modified'
                    hook_info['confidence'] = 'Medium'
                
                hooks.append(hook_info)
                
        except Exception as e:
            print(f"Error checking IAT for PID {pid}: {e}")
            
        return hooks
    
    def is_suspicious_import_hook(self, function_name: str, process_name: str) -> bool:
        """Check if an import hook is suspicious."""
        # Check for unusual process/function combinations
        suspicious_combinations = [
            ('notepad.exe', 'CreateProcessW'),  # Notepad shouldn't create processes
            ('calc.exe', 'RegOpenKeyW'),       # Calculator shouldn't access registry extensively
        ]
        
        return (process_name, function_name) in suspicious_combinations
    
    def get_hook_details(self, hook_type: str, function_name: str) -> str:
        """Get detailed information about a specific hook."""
        details = f"Analyzing {hook_type} for {function_name}:\n\n"
        
        if hook_type == 'SSDT Hook':
            details += "SSDT (System Service Descriptor Table) hooks intercept system calls at the kernel level.\n"
            details += "These hooks can be used by rootkits to hide files, processes, or registry keys.\n"
            details += f"Function {function_name} may be redirected to malicious code.\n"
            
        elif hook_type == 'API Hook':
            details += "API hooks intercept function calls in user-mode DLLs.\n"
            details += "Common technique used by malware to monitor or modify program behavior.\n"
            details += f"Function {function_name} may have inline modifications.\n"
            
        elif hook_type == 'IAT Hook':
            details += "IAT (Import Address Table) hooks modify function pointers in process memory.\n"
            details += "Used to redirect API calls to malicious code.\n"
            details += f"Function {function_name} import may be redirected.\n"
        
        details += "\nRecommendations:\n"
        details += "- Verify the hooking module is legitimate\n"
        details += "- Check process that installed the hook\n"
        details += "- Consider using process monitor to analyze behavior\n"
        
        return details
    
    def get_module_info(self, module_name: str) -> Dict:
        """Get information about a module that may contain hooks."""
        try:
            # Check if module file exists and get its properties
            module_path = os.path.join(os.environ.get('SYSTEM32', ''), module_name)
            
            if os.path.exists(module_path):
                stat = os.stat(module_path)
                return {
                    'path': module_path,
                    'size': stat.st_size,
                    'modified': stat.st_mtime,
                    'exists': True,
                    'suspicious': module_name.lower() in self.suspicious_modules
                }
            else:
                return {
                    'path': 'Not found',
                    'exists': False,
                    'suspicious': True
                }
                
        except Exception as e:
            return {'error': str(e)}
    
    def check_critical_files_integrity(self) -> List[Dict]:
        """Check integrity of critical system files."""
        critical_files = [
            'ntoskrnl.exe', 'hal.dll', 'ntdll.dll', 'kernel32.dll',
            'advapi32.dll', 'user32.dll', 'gdi32.dll'
        ]
        
        results = []
        system32_path = os.environ.get('SYSTEM32', r'C:\Windows\System32')
        
        for filename in critical_files:
            filepath = os.path.join(system32_path, filename)
            
            try:
                if os.path.exists(filepath):
                    stat = os.stat(filepath)
                    file_info = {
                        'filename': filename,
                        'path': filepath,
                        'size': stat.st_size,
                        'modified': stat.st_mtime,
                        'suspicious': False,
                        'status': 'OK'
                    }
                    
                    # Simple integrity checks
                    if stat.st_size < 1000:  # Suspiciously small system file
                        file_info['suspicious'] = True
                        file_info['status'] = 'Suspicious size'
                    
                    results.append(file_info)
                else:
                    results.append({
                        'filename': filename,
                        'path': filepath,
                        'suspicious': True,
                        'status': 'Missing',
                        'size': 0,
                        'modified': 0
                    })
                    
            except Exception as e:
                results.append({
                    'filename': filename,
                    'path': filepath,
                    'suspicious': True,
                    'status': f'Error: {str(e)}',
                    'size': 0,
                    'modified': 0
                })
        
        return results