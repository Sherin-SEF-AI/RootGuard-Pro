"""
Kernel Module Integrity Verification
Advanced kernel security analysis and module integrity verification.
"""

import os
import re
import hashlib
import subprocess
import sqlite3
import time
import json
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime
import struct

@dataclass
class KernelModule:
    """Kernel module information."""
    name: str
    size: int
    use_count: int
    dependencies: List[str]
    state: str
    memory_address: str
    file_path: str
    signature_valid: bool
    integrity_hash: str
    load_timestamp: float

@dataclass
class KernelIntegrityAlert:
    """Kernel integrity violation alert."""
    timestamp: float
    alert_type: str
    module_name: str
    description: str
    severity: str
    details: Dict

class KernelIntegrityVerifier:
    """Kernel module integrity verification and analysis."""
    
    def __init__(self, db_path: str = "kernel_integrity.db"):
        self.db_path = db_path
        self.known_good_modules = set()
        self.module_baselines = {}
        self.alert_callbacks = []
        
        # Critical kernel modules that should always be present
        self.critical_modules = {
            'ext4', 'vfat', 'nfs', 'tcp_diag', 'inet_diag',
            'netlink_diag', 'unix_diag', 'af_packet_diag'
        }
        
        # Suspicious module name patterns
        self.suspicious_patterns = [
            r'.*rootkit.*', r'.*backdoor.*', r'.*hidden.*',
            r'.*stealth.*', r'.*keylog.*', r'.*inject.*',
            r'^[0-9]+$', r'^[a-f0-9]{8,}$'  # Random hex names
        ]
        
        # Known legitimate module prefixes
        self.legitimate_prefixes = {
            'usbhid', 'snd_', 'nvidia', 'i915', 'radeon',
            'ath', 'iwl', 'rtl', 'r8169', 'e1000',
            'ext', 'xfs', 'btrfs', 'nf_', 'ip_',
            'bridge', 'veth', 'tun', 'kvm'
        }
        
        self._init_database()
        self._load_system_baselines()
    
    def _init_database(self):
        """Initialize kernel integrity database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS module_baselines (
                    name TEXT PRIMARY KEY,
                    size INTEGER,
                    file_path TEXT,
                    integrity_hash TEXT,
                    signature_status TEXT,
                    baseline_timestamp REAL,
                    version_info TEXT
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS integrity_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    alert_type TEXT,
                    module_name TEXT,
                    description TEXT,
                    severity TEXT,
                    details TEXT
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS kernel_config (
                    parameter TEXT PRIMARY KEY,
                    value TEXT,
                    baseline_value TEXT,
                    security_impact TEXT,
                    baseline_timestamp REAL
                )
            ''')
            
            conn.commit()
    
    def _load_system_baselines(self):
        """Load system kernel module baselines."""
        try:
            modules = self.enumerate_kernel_modules()
            
            with sqlite3.connect(self.db_path) as conn:
                for module in modules:
                    # Check if baseline exists
                    cursor = conn.execute(
                        'SELECT name FROM module_baselines WHERE name = ?', 
                        (module.name,)
                    )
                    
                    if not cursor.fetchone():
                        # Create new baseline
                        conn.execute('''
                            INSERT INTO module_baselines 
                            (name, size, file_path, integrity_hash, signature_status, baseline_timestamp, version_info)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            module.name, module.size, module.file_path, module.integrity_hash,
                            'valid' if module.signature_valid else 'invalid',
                            time.time(), self._get_module_version(module.name)
                        ))
                
                conn.commit()
                
        except Exception as e:
            print(f"Error loading baselines: {e}")
    
    def enumerate_kernel_modules(self) -> List[KernelModule]:
        """Enumerate all loaded kernel modules."""
        modules = []
        
        try:
            with open('/proc/modules', 'r') as f:
                module_lines = f.readlines()
            
            for line in module_lines:
                parts = line.strip().split()
                if len(parts) >= 6:
                    name = parts[0]
                    size = int(parts[1])
                    use_count = int(parts[2])
                    dependencies = parts[3].split(',') if parts[3] != '-' else []
                    state = parts[4]
                    memory_addr = parts[5]
                    
                    # Find module file path
                    module_path = self._find_module_path(name)
                    
                    # Calculate integrity hash if file exists
                    integrity_hash = ''
                    if module_path and os.path.exists(module_path):
                        integrity_hash = self._calculate_module_hash(module_path)
                    
                    # Check signature validity
                    signature_valid = self._verify_module_signature(name, module_path)
                    
                    module = KernelModule(
                        name=name,
                        size=size,
                        use_count=use_count,
                        dependencies=dependencies,
                        state=state,
                        memory_address=memory_addr,
                        file_path=module_path or 'Unknown',
                        signature_valid=signature_valid,
                        integrity_hash=integrity_hash,
                        load_timestamp=time.time()
                    )
                    
                    modules.append(module)
                    
        except Exception as e:
            print(f"Error enumerating kernel modules: {e}")
        
        return modules
    
    def _find_module_path(self, module_name: str) -> Optional[str]:
        """Find filesystem path for kernel module."""
        try:
            # Check common module locations
            kernel_version = os.uname().release
            module_dirs = [
                f'/lib/modules/{kernel_version}/kernel',
                f'/lib/modules/{kernel_version}/extra',
                f'/lib/modules/{kernel_version}/updates',
                '/lib/modules/*/kernel',
                '/lib/modules/*/extra'
            ]
            
            for module_dir in module_dirs:
                # Use find command to locate module
                try:
                    result = subprocess.run(
                        ['find', module_dir, '-name', f'{module_name}.ko*', '-type', 'f'],
                        capture_output=True, text=True, timeout=10
                    )
                    
                    if result.returncode == 0 and result.stdout.strip():
                        return result.stdout.strip().split('\n')[0]
                        
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue
            
            # Try modinfo command
            try:
                result = subprocess.run(
                    ['modinfo', '-F', 'filename', module_name],
                    capture_output=True, text=True, timeout=5
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
                    
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
                
        except Exception as e:
            print(f"Error finding module path for {module_name}: {e}")
        
        return None
    
    def _calculate_module_hash(self, module_path: str) -> str:
        """Calculate SHA256 hash of kernel module file."""
        try:
            hasher = hashlib.sha256()
            with open(module_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ''
    
    def _verify_module_signature(self, module_name: str, module_path: str) -> bool:
        """Verify kernel module signature."""
        try:
            if not module_path or not os.path.exists(module_path):
                return False
            
            # Use modinfo to check signature
            result = subprocess.run(
                ['modinfo', '-F', 'sig_id', module_name],
                capture_output=True, text=True, timeout=5
            )
            
            # If sig_id exists, module is signed
            return result.returncode == 0 and result.stdout.strip()
            
        except Exception:
            return False
    
    def _get_module_version(self, module_name: str) -> str:
        """Get kernel module version information."""
        try:
            result = subprocess.run(
                ['modinfo', '-F', 'version', module_name],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
                
        except Exception:
            pass
        
        return 'Unknown'
    
    def analyze_module_integrity(self, module_name: str = None) -> Dict:
        """Analyze integrity of kernel modules."""
        analysis_results = {
            'timestamp': time.time(),
            'modules_analyzed': 0,
            'integrity_violations': [],
            'suspicious_modules': [],
            'unsigned_modules': [],
            'unknown_modules': [],
            'summary': {
                'total_loaded': 0,
                'signed': 0,
                'unsigned': 0,
                'suspicious': 0
            }
        }
        
        try:
            modules = self.enumerate_kernel_modules()
            if module_name:
                modules = [m for m in modules if m.name == module_name]
            
            analysis_results['modules_analyzed'] = len(modules)
            analysis_results['summary']['total_loaded'] = len(modules)
            
            for module in modules:
                # Check signature status
                if module.signature_valid:
                    analysis_results['summary']['signed'] += 1
                else:
                    analysis_results['summary']['unsigned'] += 1
                    analysis_results['unsigned_modules'].append({
                        'name': module.name,
                        'size': module.size,
                        'path': module.file_path
                    })
                
                # Check if module is suspicious
                if self._is_suspicious_module(module):
                    analysis_results['summary']['suspicious'] += 1
                    analysis_results['suspicious_modules'].append({
                        'name': module.name,
                        'reason': self._get_suspicion_reason(module),
                        'size': module.size,
                        'path': module.file_path
                    })
                
                # Check integrity against baseline
                integrity_issues = self._check_module_baseline(module)
                analysis_results['integrity_violations'].extend(integrity_issues)
                
        except Exception as e:
            analysis_results['error'] = str(e)
        
        return analysis_results
    
    def _is_suspicious_module(self, module: KernelModule) -> bool:
        """Determine if a kernel module is suspicious."""
        # Check name patterns
        for pattern in self.suspicious_patterns:
            if re.match(pattern, module.name, re.IGNORECASE):
                return True
        
        # Check if module is not from legitimate sources
        is_legitimate = any(module.name.startswith(prefix) for prefix in self.legitimate_prefixes)
        if not is_legitimate and not module.signature_valid:
            return True
        
        # Check unusual characteristics
        if module.use_count == 0 and module.size > 1000000:  # Large unused module
            return True
        
        # Check if module file is in unusual location
        if module.file_path and any(suspicious in module.file_path for suspicious in ['/tmp/', '/dev/shm/', '/var/tmp/']):
            return True
        
        return False
    
    def _get_suspicion_reason(self, module: KernelModule) -> str:
        """Get reason why module is considered suspicious."""
        reasons = []
        
        # Check name patterns
        for pattern in self.suspicious_patterns:
            if re.match(pattern, module.name, re.IGNORECASE):
                reasons.append(f"Suspicious name pattern: {pattern}")
        
        if not module.signature_valid:
            reasons.append("Module is not signed")
        
        if module.use_count == 0 and module.size > 1000000:
            reasons.append("Large unused module")
        
        if module.file_path and any(suspicious in module.file_path for suspicious in ['/tmp/', '/dev/shm/']):
            reasons.append("Module in suspicious location")
        
        return "; ".join(reasons) if reasons else "General suspicion indicators"
    
    def _check_module_baseline(self, module: KernelModule) -> List[Dict]:
        """Check module against baseline integrity."""
        violations = []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'SELECT * FROM module_baselines WHERE name = ?', 
                    (module.name,)
                )
                baseline_row = cursor.fetchone()
                
                if baseline_row:
                    baseline_size = baseline_row[1]
                    baseline_hash = baseline_row[3]
                    
                    # Check size changes
                    if module.size != baseline_size:
                        violations.append({
                            'type': 'size_mismatch',
                            'module': module.name,
                            'baseline_size': baseline_size,
                            'current_size': module.size,
                            'severity': 'medium'
                        })
                    
                    # Check hash changes
                    if module.integrity_hash and module.integrity_hash != baseline_hash:
                        violations.append({
                            'type': 'hash_mismatch',
                            'module': module.name,
                            'baseline_hash': baseline_hash[:16] + "...",
                            'current_hash': module.integrity_hash[:16] + "...",
                            'severity': 'high'
                        })
                else:
                    # New module not in baseline
                    violations.append({
                        'type': 'new_module',
                        'module': module.name,
                        'description': 'Module not present in baseline',
                        'severity': 'medium'
                    })
                    
        except Exception as e:
            print(f"Error checking module baseline: {e}")
        
        return violations
    
    def verify_kernel_symbols(self) -> Dict:
        """Verify kernel symbol table integrity."""
        verification_results = {
            'timestamp': time.time(),
            'symbol_count': 0,
            'suspicious_symbols': [],
            'hook_indicators': [],
            'symbol_conflicts': []
        }
        
        try:
            if not os.path.exists('/proc/kallsyms'):
                verification_results['error'] = '/proc/kallsyms not accessible'
                return verification_results
            
            with open('/proc/kallsyms', 'r') as f:
                symbols = f.readlines()
            
            verification_results['symbol_count'] = len(symbols)
            
            # Analyze symbols for anomalies
            syscall_symbols = {}
            
            for line in symbols:
                parts = line.strip().split(maxsplit=2)
                if len(parts) >= 3:
                    address = parts[0]
                    symbol_type = parts[1]
                    symbol_name = parts[2]
                    
                    # Look for system call hooks
                    if symbol_name.startswith('sys_'):
                        if symbol_name in syscall_symbols:
                            # Duplicate symbol - potential hook
                            verification_results['symbol_conflicts'].append({
                                'symbol': symbol_name,
                                'addresses': [syscall_symbols[symbol_name], address],
                                'type': 'duplicate_syscall'
                            })
                        else:
                            syscall_symbols[symbol_name] = address
                    
                    # Look for suspicious symbol names
                    if any(pattern in symbol_name.lower() for pattern in ['hook', 'rootkit', 'hidden', 'fake']):
                        verification_results['suspicious_symbols'].append({
                            'symbol': symbol_name,
                            'address': address,
                            'type': symbol_type
                        })
            
            # Check for common rootkit hooks
            common_hooked_calls = ['sys_getdents', 'sys_getdents64', 'sys_open', 'sys_read']
            for syscall in common_hooked_calls:
                if syscall in syscall_symbols:
                    # Additional analysis could be done here
                    pass
                    
        except Exception as e:
            verification_results['error'] = str(e)
        
        return verification_results
    
    def check_kernel_configuration(self) -> Dict:
        """Check kernel security configuration."""
        config_analysis = {
            'timestamp': time.time(),
            'security_features': {},
            'recommendations': [],
            'risk_level': 'low'
        }
        
        try:
            # Check kernel security features
            security_checks = {
                'kaslr': self._check_kaslr(),
                'smep': self._check_smep(),
                'smap': self._check_smap(),
                'kpti': self._check_kpti(),
                'stack_protection': self._check_stack_protection(),
                'module_signing': self._check_module_signing()
            }
            
            config_analysis['security_features'] = security_checks
            
            # Generate recommendations
            disabled_features = [feature for feature, enabled in security_checks.items() if not enabled]
            
            if disabled_features:
                config_analysis['recommendations'] = [
                    f"Enable {feature}" for feature in disabled_features
                ]
                
                if len(disabled_features) > 3:
                    config_analysis['risk_level'] = 'high'
                elif len(disabled_features) > 1:
                    config_analysis['risk_level'] = 'medium'
            
        except Exception as e:
            config_analysis['error'] = str(e)
        
        return config_analysis
    
    def _check_kaslr(self) -> bool:
        """Check if KASLR (Kernel Address Space Layout Randomization) is enabled."""
        try:
            with open('/proc/sys/kernel/randomize_va_space', 'r') as f:
                value = int(f.read().strip())
                return value > 0
        except Exception:
            return False
    
    def _check_smep(self) -> bool:
        """Check if SMEP (Supervisor Mode Execution Prevention) is enabled."""
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
                return 'smep' in cpuinfo.lower()
        except Exception:
            return False
    
    def _check_smap(self) -> bool:
        """Check if SMAP (Supervisor Mode Access Prevention) is enabled."""
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
                return 'smap' in cpuinfo.lower()
        except Exception:
            return False
    
    def _check_kpti(self) -> bool:
        """Check if KPTI (Kernel Page Table Isolation) is enabled."""
        try:
            vuln_file = '/sys/devices/system/cpu/vulnerabilities/meltdown'
            if os.path.exists(vuln_file):
                with open(vuln_file, 'r') as f:
                    content = f.read()
                    return 'Mitigation: PTI' in content
        except Exception:
            pass
        return False
    
    def _check_stack_protection(self) -> bool:
        """Check if kernel stack protection is enabled."""
        try:
            # Check for stack canary support
            with open('/proc/config.gz', 'rb') if os.path.exists('/proc/config.gz') else open('/boot/config-' + os.uname().release, 'r') as f:
                if f.name.endswith('.gz'):
                    import gzip
                    config_content = gzip.decompress(f.read()).decode()
                else:
                    config_content = f.read()
                
                return 'CONFIG_STACKPROTECTOR=y' in config_content
        except Exception:
            return False
    
    def _check_module_signing(self) -> bool:
        """Check if kernel module signing is enforced."""
        try:
            # Check if module signing is configured
            with open('/proc/sys/kernel/modules_disabled', 'r') as f:
                modules_disabled = int(f.read().strip())
                
            # Check signature enforcement
            sig_enforce_path = '/proc/sys/kernel/module_sig_enforce'
            if os.path.exists(sig_enforce_path):
                with open(sig_enforce_path, 'r') as f:
                    sig_enforce = int(f.read().strip())
                    return sig_enforce == 1
                    
        except Exception:
            pass
        return False
    
    def detect_kernel_rootkit_indicators(self) -> List[Dict]:
        """Detect kernel-level rootkit indicators."""
        indicators = []
        
        try:
            # Check for hidden kernel modules
            hidden_modules = self._detect_hidden_modules()
            indicators.extend(hidden_modules)
            
            # Check for syscall table modifications
            syscall_hooks = self._detect_syscall_hooks()
            indicators.extend(syscall_hooks)
            
            # Check for kernel memory anomalies
            memory_anomalies = self._detect_kernel_memory_anomalies()
            indicators.extend(memory_anomalies)
            
            # Check for rootkit-specific artifacts
            rootkit_artifacts = self._detect_rootkit_artifacts()
            indicators.extend(rootkit_artifacts)
            
        except Exception as e:
            print(f"Error detecting kernel rootkit indicators: {e}")
        
        return indicators
    
    def _detect_hidden_modules(self) -> List[Dict]:
        """Detect potentially hidden kernel modules."""
        indicators = []
        
        try:
            # Compare /proc/modules with lsmod output
            proc_modules = set()
            with open('/proc/modules', 'r') as f:
                for line in f:
                    module_name = line.split()[0]
                    proc_modules.add(module_name)
            
            # Get lsmod output
            result = subprocess.run(['lsmod'], capture_output=True, text=True, timeout=10)
            lsmod_modules = set()
            
            if result.returncode == 0:
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    if line.strip():
                        module_name = line.split()[0]
                        lsmod_modules.add(module_name)
            
            # Find discrepancies
            hidden_in_proc = lsmod_modules - proc_modules
            hidden_in_lsmod = proc_modules - lsmod_modules
            
            for hidden_module in hidden_in_proc:
                indicators.append({
                    'type': 'hidden_module_proc',
                    'module_name': hidden_module,
                    'description': f'Module {hidden_module} hidden from /proc/modules',
                    'severity': 'high'
                })
            
            for hidden_module in hidden_in_lsmod:
                indicators.append({
                    'type': 'hidden_module_lsmod',
                    'module_name': hidden_module,
                    'description': f'Module {hidden_module} hidden from lsmod',
                    'severity': 'high'
                })
                
        except Exception as e:
            print(f"Error detecting hidden modules: {e}")
        
        return indicators
    
    def _detect_syscall_hooks(self) -> List[Dict]:
        """Detect system call table hooks."""
        indicators = []
        
        try:
            # This would require reading kernel memory - simplified implementation
            # Check for known syscall hook indicators in dmesg
            result = subprocess.run(['dmesg'], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                dmesg_output = result.stdout.lower()
                
                hook_indicators = ['syscall hook', 'table modified', 'hijacked', 'rootkit']
                for indicator in hook_indicators:
                    if indicator in dmesg_output:
                        indicators.append({
                            'type': 'syscall_hook_indicator',
                            'description': f'Syscall hook indicator found in dmesg: {indicator}',
                            'severity': 'high'
                        })
                        
        except Exception as e:
            print(f"Error detecting syscall hooks: {e}")
        
        return indicators
    
    def _detect_kernel_memory_anomalies(self) -> List[Dict]:
        """Detect kernel memory anomalies."""
        indicators = []
        
        try:
            # Check /proc/iomem for unusual memory regions
            with open('/proc/iomem', 'r') as f:
                iomem_lines = f.readlines()
            
            suspicious_regions = []
            for line in iomem_lines:
                if any(keyword in line.lower() for keyword in ['unknown', 'reserved', 'hidden']):
                    suspicious_regions.append(line.strip())
            
            if suspicious_regions:
                indicators.append({
                    'type': 'suspicious_memory_regions',
                    'description': f'Found {len(suspicious_regions)} suspicious memory regions',
                    'regions': suspicious_regions[:5],  # First 5
                    'severity': 'medium'
                })
                
        except Exception as e:
            print(f"Error detecting memory anomalies: {e}")
        
        return indicators
    
    def _detect_rootkit_artifacts(self) -> List[Dict]:
        """Detect specific rootkit artifacts in the kernel."""
        indicators = []
        
        try:
            # Check for common rootkit files/directories
            rootkit_paths = [
                '/lib/modules/.hidden',
                '/proc/kcore.hidden',
                '/sys/kernel/.rootkit',
                '/dev/.rootkit',
                '/tmp/.X11-lock'
            ]
            
            for path in rootkit_paths:
                if os.path.exists(path):
                    indicators.append({
                        'type': 'rootkit_artifact',
                        'path': path,
                        'description': f'Known rootkit artifact found: {path}',
                        'severity': 'critical'
                    })
            
            # Check for suspicious kernel threads
            try:
                with open('/proc/kthread', 'r') as f:
                    kthreads = f.readlines()
                    
                for thread in kthreads:
                    thread_name = thread.strip()
                    if any(suspicious in thread_name.lower() for suspicious in ['rootkit', 'hidden', 'backdoor']):
                        indicators.append({
                            'type': 'suspicious_kthread',
                            'thread_name': thread_name,
                            'description': f'Suspicious kernel thread: {thread_name}',
                            'severity': 'high'
                        })
            except FileNotFoundError:
                pass  # /proc/kthread may not exist on all systems
                
        except Exception as e:
            print(f"Error detecting rootkit artifacts: {e}")
        
        return indicators
    
    def create_kernel_baseline(self) -> bool:
        """Create integrity baseline for kernel modules."""
        try:
            modules = self.enumerate_kernel_modules()
            
            with sqlite3.connect(self.db_path) as conn:
                for module in modules:
                    conn.execute('''
                        INSERT OR REPLACE INTO module_baselines 
                        (name, size, file_path, integrity_hash, signature_status, baseline_timestamp, version_info)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        module.name, module.size, module.file_path, module.integrity_hash,
                        'valid' if module.signature_valid else 'invalid',
                        time.time(), self._get_module_version(module.name)
                    ))
                
                conn.commit()
            
            print(f"Created baseline for {len(modules)} kernel modules")
            return True
            
        except Exception as e:
            print(f"Error creating kernel baseline: {e}")
            return False
    
    def comprehensive_kernel_analysis(self) -> Dict:
        """Perform comprehensive kernel security analysis."""
        analysis_results = {
            'analysis_timestamp': time.time(),
            'module_integrity': self.analyze_module_integrity(),
            'symbol_verification': self.verify_kernel_symbols(),
            'configuration_check': self.check_kernel_configuration(),
            'rootkit_indicators': self.detect_kernel_rootkit_indicators(),
            'overall_risk_score': 0.0,
            'security_recommendations': []
        }
        
        try:
            # Calculate overall risk score
            risk_factors = []
            
            # Module integrity risks
            module_analysis = analysis_results['module_integrity']
            suspicious_count = len(module_analysis.get('suspicious_modules', []))
            unsigned_count = len(module_analysis.get('unsigned_modules', []))
            
            if suspicious_count > 0:
                risk_factors.append(suspicious_count * 0.3)
            if unsigned_count > 5:
                risk_factors.append(0.2)
            
            # Configuration risks
            config_analysis = analysis_results['configuration_check']
            disabled_features = [
                feature for feature, enabled in config_analysis.get('security_features', {}).items()
                if not enabled
            ]
            
            if len(disabled_features) > 2:
                risk_factors.append(0.3)
            
            # Rootkit indicator risks
            rootkit_indicators = analysis_results['rootkit_indicators']
            critical_indicators = [ind for ind in rootkit_indicators if ind.get('severity') == 'critical']
            high_indicators = [ind for ind in rootkit_indicators if ind.get('severity') == 'high']
            
            if critical_indicators:
                risk_factors.append(0.8)
            elif high_indicators:
                risk_factors.append(0.5)
            
            # Calculate final risk score
            analysis_results['overall_risk_score'] = min(sum(risk_factors), 1.0)
            
            # Generate recommendations
            if disabled_features:
                analysis_results['security_recommendations'].extend([
                    f"Enable kernel security feature: {feature}" for feature in disabled_features
                ])
            
            if suspicious_count > 0:
                analysis_results['security_recommendations'].append(
                    f"Investigate {suspicious_count} suspicious kernel modules"
                )
            
            if unsigned_count > 10:
                analysis_results['security_recommendations'].append(
                    "Consider enabling module signature enforcement"
                )
                
        except Exception as e:
            analysis_results['error'] = str(e)
        
        return analysis_results
    
    def add_alert_callback(self, callback):
        """Add callback for kernel integrity alerts."""
        self.alert_callbacks.append(callback)
    
    def export_kernel_analysis(self, output_path: str):
        """Export kernel analysis report."""
        analysis_data = {
            'generation_time': datetime.now().isoformat(),
            'comprehensive_analysis': self.comprehensive_kernel_analysis()
        }
        
        with open(output_path, 'w') as f:
            json.dump(analysis_data, f, indent=2, default=str)