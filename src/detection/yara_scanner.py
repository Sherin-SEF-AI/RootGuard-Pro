"""
YARA Rule Integration
Advanced malware detection using YARA rules for rootkit identification.
"""

import os
import json
import threading
import time
import hashlib
import subprocess
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime

@dataclass
class YaraRule:
    """YARA rule information."""
    name: str
    content: str
    description: str
    author: str
    date: str
    version: str
    tags: List[str]
    file_path: str

@dataclass
class YaraMatch:
    """YARA rule match result."""
    rule_name: str
    file_path: str
    matched_strings: List[str]
    confidence: float
    severity: str
    description: str
    metadata: Dict

class YaraScanner:
    """YARA-based malware and rootkit scanner."""
    
    def __init__(self, rules_dir: str = "yara_rules"):
        self.rules_dir = rules_dir
        self.loaded_rules = {}
        self.scan_results = []
        self.match_callbacks = []
        
        # Built-in YARA rules for common rootkit patterns
        self.builtin_rules = {
            'linux_rootkit_general': '''
rule Linux_Rootkit_General
{
    meta:
        description = "Generic Linux rootkit detection"
        author = "Rootkit Detection Tool"
        date = "2024-01-01"
        version = "1.0"
        
    strings:
        $hide_proc = "hide_proc" nocase
        $hide_file = "hide_file" nocase
        $hide_module = "hide_module" nocase
        $rootkit = "rootkit" nocase
        $backdoor = "backdoor" nocase
        $keylogger = "keylogger" nocase
        $stealth = "stealth" nocase
        
    condition:
        any of them
}
''',
            'kernel_module_rootkit': '''
rule Kernel_Module_Rootkit
{
    meta:
        description = "Kernel module rootkit detection"
        author = "Rootkit Detection Tool"
        date = "2024-01-01"
        
    strings:
        $sys_call_table = "sys_call_table"
        $kallsyms_lookup = "kallsyms_lookup_name"
        $module_hide = "module_hide"
        $proc_hide = "/proc/" 
        $lkm_init = "init_module"
        $lkm_cleanup = "cleanup_module"
        
    condition:
        ($sys_call_table and $kallsyms_lookup) or
        ($module_hide and $lkm_init) or
        (3 of them)
}
''',
            'suspicious_elf_binary': '''
rule Suspicious_ELF_Binary
{
    meta:
        description = "Suspicious ELF binary characteristics"
        author = "Rootkit Detection Tool"
        
    strings:
        $elf_header = { 7F 45 4C 46 }
        $ptrace_call = "ptrace"
        $proc_access = "/proc/"
        $mem_access = "/dev/mem"
        $kmem_access = "/dev/kmem"
        $hidden_dir = "/.hidden"
        
    condition:
        $elf_header at 0 and
        (($ptrace_call and $proc_access) or
         $mem_access or $kmem_access or $hidden_dir)
}
''',
            'network_backdoor': '''
rule Network_Backdoor
{
    meta:
        description = "Network backdoor detection"
        author = "Rootkit Detection Tool"
        
    strings:
        $bind_shell = "bind_shell" nocase
        $reverse_shell = "reverse_shell" nocase
        $socket_create = "socket("
        $bind_call = "bind("
        $listen_call = "listen("
        $accept_call = "accept("
        $nc_exec = "/bin/sh"
        $bash_exec = "/bin/bash"
        
    condition:
        ($socket_create and $bind_call and $listen_call) or
        ($reverse_shell and ($nc_exec or $bash_exec)) or
        ($bind_shell and $accept_call)
}
'''
        }
        
        self._init_rules_directory()
        self._load_builtin_rules()
    
    def _init_rules_directory(self):
        """Initialize YARA rules directory."""
        os.makedirs(self.rules_dir, exist_ok=True)
    
    def _load_builtin_rules(self):
        """Load built-in YARA rules."""
        for rule_name, rule_content in self.builtin_rules.items():
            rule_path = os.path.join(self.rules_dir, f"{rule_name}.yar")
            
            # Write rule to file if it doesn't exist
            if not os.path.exists(rule_path):
                with open(rule_path, 'w') as f:
                    f.write(rule_content)
            
            # Parse and store rule
            rule_info = self._parse_yara_rule(rule_content, rule_path)
            if rule_info:
                self.loaded_rules[rule_name] = rule_info
    
    def _parse_yara_rule(self, rule_content: str, file_path: str) -> Optional[YaraRule]:
        """Parse YARA rule content and extract metadata."""
        try:
            lines = rule_content.split('\n')
            
            # Extract rule name
            rule_name = ""
            for line in lines:
                if line.strip().startswith('rule '):
                    rule_name = line.strip().split()[1]
                    break
            
            # Extract metadata
            meta_section = False
            description = ""
            author = ""
            date = ""
            version = ""
            tags = []
            
            for line in lines:
                line = line.strip()
                if line == 'meta:':
                    meta_section = True
                    continue
                elif line.startswith('strings:') or line.startswith('condition:'):
                    meta_section = False
                    continue
                
                if meta_section:
                    if 'description =' in line:
                        description = line.split('=', 1)[1].strip().strip('"')
                    elif 'author =' in line:
                        author = line.split('=', 1)[1].strip().strip('"')
                    elif 'date =' in line:
                        date = line.split('=', 1)[1].strip().strip('"')
                    elif 'version =' in line:
                        version = line.split('=', 1)[1].strip().strip('"')
            
            return YaraRule(
                name=rule_name,
                content=rule_content,
                description=description,
                author=author,
                date=date,
                version=version,
                tags=tags,
                file_path=file_path
            )
            
        except Exception as e:
            print(f"Error parsing YARA rule: {e}")
            return None
    
    def load_rules_from_directory(self, directory: str = None) -> int:
        """Load YARA rules from directory."""
        if directory is None:
            directory = self.rules_dir
        
        rules_loaded = 0
        
        try:
            if not os.path.exists(directory):
                return 0
            
            for filename in os.listdir(directory):
                if filename.endswith(('.yar', '.yara')):
                    rule_path = os.path.join(directory, filename)
                    
                    try:
                        with open(rule_path, 'r') as f:
                            rule_content = f.read()
                        
                        rule_info = self._parse_yara_rule(rule_content, rule_path)
                        if rule_info:
                            self.loaded_rules[rule_info.name] = rule_info
                            rules_loaded += 1
                            
                    except Exception as e:
                        print(f"Error loading rule {filename}: {e}")
                        continue
                        
        except Exception as e:
            print(f"Error loading rules from directory: {e}")
        
        return rules_loaded
    
    def scan_file_with_yara(self, file_path: str, rules: List[str] = None) -> List[YaraMatch]:
        """Scan file using YARA rules (simulation - would use actual YARA in production)."""
        matches = []
        
        try:
            if not os.path.exists(file_path):
                return matches
            
            # Read file content for pattern matching
            with open(file_path, 'rb') as f:
                file_content = f.read(1024 * 1024)  # Read first 1MB
            
            # Convert to string for pattern matching (simplified)
            try:
                content_str = file_content.decode('utf-8', errors='ignore').lower()
            except:
                content_str = str(file_content).lower()
            
            # Check each loaded rule
            rules_to_check = rules or list(self.loaded_rules.keys())
            
            for rule_name in rules_to_check:
                if rule_name not in self.loaded_rules:
                    continue
                
                rule = self.loaded_rules[rule_name]
                match_result = self._simulate_yara_match(rule, content_str, file_path)
                
                if match_result:
                    matches.append(match_result)
                    
        except Exception as e:
            print(f"Error scanning file with YARA: {e}")
        
        return matches
    
    def _simulate_yara_match(self, rule: YaraRule, content: str, file_path: str) -> Optional[YaraMatch]:
        """Simulate YARA rule matching (simplified implementation)."""
        try:
            # Extract string patterns from rule content
            patterns = []
            in_strings_section = False
            
            for line in rule.content.split('\n'):
                line = line.strip()
                if line == 'strings:':
                    in_strings_section = True
                    continue
                elif line.startswith('condition:'):
                    in_strings_section = False
                    break
                
                if in_strings_section and '=' in line:
                    # Extract string pattern
                    if '"' in line:
                        pattern = line.split('"')[1].lower()
                        patterns.append(pattern)
            
            # Check if any patterns match
            matched_patterns = []
            for pattern in patterns:
                if pattern in content:
                    matched_patterns.append(pattern)
            
            # Determine if rule matches based on simple logic
            if matched_patterns:
                # Calculate confidence based on number of matches
                confidence = min(len(matched_patterns) / len(patterns), 1.0) if patterns else 0.5
                
                # Determine severity based on rule content
                severity = "medium"
                if "critical" in rule.description.lower() or "rootkit" in rule.name.lower():
                    severity = "high"
                elif "backdoor" in rule.name.lower():
                    severity = "critical"
                
                return YaraMatch(
                    rule_name=rule.name,
                    file_path=file_path,
                    matched_strings=matched_patterns,
                    confidence=confidence,
                    severity=severity,
                    description=rule.description,
                    metadata={
                        'author': rule.author,
                        'version': rule.version,
                        'tags': rule.tags
                    }
                )
                
        except Exception as e:
            print(f"Error in YARA rule simulation: {e}")
        
        return None
    
    def bulk_scan_directory(self, scan_dir: str, recursive: bool = True, 
                           max_files: int = 1000) -> Dict:
        """Perform bulk YARA scan on directory."""
        scan_results = {
            'scan_timestamp': time.time(),
            'scan_directory': scan_dir,
            'files_scanned': 0,
            'matches_found': 0,
            'matches': [],
            'errors': [],
            'rules_used': list(self.loaded_rules.keys())
        }
        
        try:
            files_to_scan = []
            
            if recursive:
                for root, dirs, files in os.walk(scan_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if self._should_scan_file(file_path):
                            files_to_scan.append(file_path)
                            
                            if len(files_to_scan) >= max_files:
                                break
                    if len(files_to_scan) >= max_files:
                        break
            else:
                if os.path.isdir(scan_dir):
                    for file in os.listdir(scan_dir):
                        file_path = os.path.join(scan_dir, file)
                        if os.path.isfile(file_path) and self._should_scan_file(file_path):
                            files_to_scan.append(file_path)
            
            # Scan files
            for file_path in files_to_scan:
                try:
                    matches = self.scan_file_with_yara(file_path)
                    scan_results['files_scanned'] += 1
                    
                    for match in matches:
                        scan_results['matches'].append(asdict(match))
                        scan_results['matches_found'] += 1
                        
                        # Notify callbacks
                        for callback in self.match_callbacks:
                            callback(asdict(match))
                            
                except Exception as e:
                    scan_results['errors'].append({
                        'file': file_path,
                        'error': str(e)
                    })
                    
        except Exception as e:
            scan_results['error'] = str(e)
        
        return scan_results
    
    def _should_scan_file(self, file_path: str) -> bool:
        """Determine if file should be scanned with YARA."""
        try:
            # Skip very large files for performance
            if os.path.getsize(file_path) > 50 * 1024 * 1024:  # 50MB
                return False
            
            # Scan executable files and suspicious extensions
            suspicious_extensions = {'.ko', '.so', '.bin', '.exe', '.dll', '.sys'}
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext in suspicious_extensions:
                return True
            
            # Scan files without extensions in suspicious locations
            if not file_ext:
                suspicious_dirs = ['/tmp', '/dev/shm', '/var/tmp']
                if any(sus_dir in file_path for sus_dir in suspicious_dirs):
                    return True
            
            # Check if file is executable
            try:
                stat = os.stat(file_path)
                if stat.st_mode & 0o111:  # Has execute permissions
                    return True
            except OSError:
                pass
            
        except OSError:
            return False
        
        return False
    
    def scan_process_memory(self, pid: int) -> List[YaraMatch]:
        """Scan process memory using YARA rules."""
        matches = []
        
        try:
            # Read process memory maps
            maps_file = f'/proc/{pid}/maps'
            if not os.path.exists(maps_file):
                return matches
            
            with open(maps_file, 'r') as f:
                maps_lines = f.readlines()
            
            # Scan executable memory regions
            for line in maps_lines:
                if 'x' in line:  # Executable region
                    parts = line.strip().split()
                    if len(parts) >= 1:
                        addr_range = parts[0]
                        start_addr, end_addr = addr_range.split('-')
                        start_addr = int(start_addr, 16)
                        end_addr = int(end_addr, 16)
                        
                        # Limit scan size for performance
                        scan_size = min(end_addr - start_addr, 1024 * 1024)  # Max 1MB
                        
                        try:
                            mem_file = f'/proc/{pid}/mem'
                            with open(mem_file, 'rb') as f:
                                f.seek(start_addr)
                                memory_data = f.read(scan_size)
                            
                            # Scan memory content
                            temp_file = f'/tmp/mem_scan_{pid}_{start_addr:x}.tmp'
                            with open(temp_file, 'wb') as f:
                                f.write(memory_data)
                            
                            memory_matches = self.scan_file_with_yara(temp_file)
                            for match in memory_matches:
                                match.file_path = f"PID {pid} Memory {addr_range}"
                                matches.append(match)
                            
                            # Clean up temp file
                            try:
                                os.unlink(temp_file)
                            except:
                                pass
                                
                        except (FileNotFoundError, PermissionError, OSError):
                            continue
                            
        except Exception as e:
            print(f"Error scanning process memory: {e}")
        
        return matches
    
    def create_custom_rule(self, rule_name: str, description: str, 
                          strings: List[str], condition: str) -> bool:
        """Create custom YARA rule."""
        try:
            rule_content = f'''rule {rule_name}
{{
    meta:
        description = "{description}"
        author = "Custom Rule"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        
    strings:
'''
            
            for i, string_pattern in enumerate(strings):
                rule_content += f'        $str{i} = "{string_pattern}"\n'
            
            rule_content += f'''
    condition:
        {condition}
}}
'''
            
            # Save rule to file
            rule_path = os.path.join(self.rules_dir, f"{rule_name}.yar")
            with open(rule_path, 'w') as f:
                f.write(rule_content)
            
            # Load rule
            rule_info = self._parse_yara_rule(rule_content, rule_path)
            if rule_info:
                self.loaded_rules[rule_name] = rule_info
                return True
                
        except Exception as e:
            print(f"Error creating custom rule: {e}")
        
        return False
    
    def update_rules_from_repository(self, repo_url: str = None) -> Dict:
        """Update YARA rules from online repository."""
        update_results = {
            'timestamp': time.time(),
            'rules_downloaded': 0,
            'rules_updated': 0,
            'errors': []
        }
        
        try:
            # Simulate downloading rules from repository
            # In a real implementation, this would download from sources like:
            # - https://github.com/Yara-Rules/rules
            # - https://github.com/Neo23x0/signature-base
            
            # For demonstration, create some additional rules
            additional_rules = {
                'advanced_rootkit': '''
rule Advanced_Rootkit_Detection
{
    meta:
        description = "Advanced rootkit detection patterns"
        author = "Security Research"
        date = "2024-01-01"
        
    strings:
        $syscall_hook = { 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0 }
        $inline_hook = { E9 ?? ?? ?? ?? 90 90 90 90 90 }
        $rootkit_string = "rootkit" nocase
        $hide_function = "hide_" nocase
        
    condition:
        $syscall_hook or ($inline_hook and ($rootkit_string or $hide_function))
}
''',
                'persistence_mechanism': '''
rule Persistence_Mechanism
{
    meta:
        description = "Rootkit persistence mechanisms"
        author = "Security Research"
        
    strings:
        $cron_entry = "/etc/cron"
        $systemd_service = "/etc/systemd/system"
        $init_script = "/etc/init.d"
        $bashrc_mod = ".bashrc"
        $profile_mod = ".profile"
        $ld_preload = "LD_PRELOAD"
        
    condition:
        any of them
}
'''
            }
            
            for rule_name, rule_content in additional_rules.items():
                rule_path = os.path.join(self.rules_dir, f"{rule_name}.yar")
                
                try:
                    with open(rule_path, 'w') as f:
                        f.write(rule_content)
                    
                    rule_info = self._parse_yara_rule(rule_content, rule_path)
                    if rule_info:
                        self.loaded_rules[rule_name] = rule_info
                        update_results['rules_downloaded'] += 1
                        
                        if rule_name in self.loaded_rules:
                            update_results['rules_updated'] += 1
                        
                except Exception as e:
                    update_results['errors'].append({
                        'rule': rule_name,
                        'error': str(e)
                    })
                    
        except Exception as e:
            update_results['error'] = str(e)
        
        return update_results
    
    def scan_running_processes(self) -> List[YaraMatch]:
        """Scan all running processes with YARA rules."""
        matches = []
        
        try:
            import psutil
            
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    pid = proc.info['pid']
                    exe_path = proc.info['exe']
                    
                    # Scan executable file
                    if exe_path and os.path.exists(exe_path):
                        file_matches = self.scan_file_with_yara(exe_path)
                        matches.extend(file_matches)
                    
                    # Scan process memory (limited for performance)
                    if pid > 1:  # Skip kernel processes
                        memory_matches = self.scan_process_memory(pid)
                        matches.extend(memory_matches)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as e:
                    print(f"Error scanning process {proc.info.get('pid', 'unknown')}: {e}")
                    continue
                    
        except Exception as e:
            print(f"Error scanning running processes: {e}")
        
        return matches
    
    def get_rule_statistics(self) -> Dict:
        """Get YARA rule statistics."""
        stats = {
            'total_rules': len(self.loaded_rules),
            'rule_types': {},
            'rule_authors': {},
            'recent_matches': 0,
            'rules_by_severity': {}
        }
        
        try:
            for rule_name, rule in self.loaded_rules.items():
                # Count by type (based on rule name)
                if 'rootkit' in rule_name.lower():
                    rule_type = 'rootkit'
                elif 'backdoor' in rule_name.lower():
                    rule_type = 'backdoor'
                elif 'kernel' in rule_name.lower():
                    rule_type = 'kernel'
                else:
                    rule_type = 'general'
                
                stats['rule_types'][rule_type] = stats['rule_types'].get(rule_type, 0) + 1
                stats['rule_authors'][rule.author] = stats['rule_authors'].get(rule.author, 0) + 1
            
            # Count recent matches (would be from database in real implementation)
            stats['recent_matches'] = len(self.scan_results)
            
        except Exception as e:
            stats['error'] = str(e)
        
        return stats
    
    def export_yara_results(self, output_path: str):
        """Export YARA scan results."""
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'rule_statistics': self.get_rule_statistics(),
            'loaded_rules': [asdict(rule) for rule in self.loaded_rules.values()],
            'scan_results': self.scan_results[-1000:]  # Last 1000 results
        }
        
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
    
    def add_match_callback(self, callback):
        """Add callback for YARA matches."""
        self.match_callbacks = getattr(self, 'match_callbacks', [])
        self.match_callbacks.append(callback)
    
    def validate_rule_syntax(self, rule_content: str) -> Dict:
        """Validate YARA rule syntax."""
        validation_result = {
            'valid': False,
            'errors': [],
            'warnings': []
        }
        
        try:
            # Basic syntax validation
            if 'rule ' not in rule_content:
                validation_result['errors'].append("No rule definition found")
                return validation_result
            
            if '{' not in rule_content or '}' not in rule_content:
                validation_result['errors'].append("Missing rule braces")
                return validation_result
            
            if 'condition:' not in rule_content:
                validation_result['errors'].append("No condition section found")
                return validation_result
            
            # Check for common issues
            lines = rule_content.split('\n')
            brace_count = 0
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                if '{' in line:
                    brace_count += line.count('{')
                if '}' in line:
                    brace_count -= line.count('}')
                
                # Check for unbalanced quotes
                if line.count('"') % 2 != 0:
                    validation_result['warnings'].append(f"Line {line_num}: Unbalanced quotes")
            
            if brace_count != 0:
                validation_result['errors'].append("Unbalanced braces")
            
            if not validation_result['errors']:
                validation_result['valid'] = True
                
        except Exception as e:
            validation_result['errors'].append(f"Validation error: {str(e)}")
        
        return validation_result