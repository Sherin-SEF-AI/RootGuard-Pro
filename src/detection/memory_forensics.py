"""
Memory Forensics Module
Advanced memory analysis for detecting process hollowing, DLL injection, and memory-based rootkits.
"""

import os
import struct
import mmap
import psutil
import hashlib
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class MemoryRegion:
    """Memory region information."""
    start_addr: int
    end_addr: int
    size: int
    permissions: str
    backing_file: str
    is_executable: bool
    is_suspicious: bool


@dataclass
class InjectionSignature:
    """Code injection signature."""
    name: str
    pattern: bytes
    description: str
    severity: str


class MemoryForensics:
    """Advanced memory analysis for rootkit detection."""
    
    def __init__(self):
        self.injection_signatures = self._load_injection_signatures()
        self.suspicious_patterns = [
            b'\x48\x31\xc0',  # xor rax, rax (common in shellcode)
            b'\x48\x31\xdb',  # xor rbx, rbx
            b'\x48\x31\xd2',  # xor rdx, rdx
            b'\xeb\xfe',      # jmp $ (infinite loop)
            b'\x90\x90\x90\x90',  # NOP sled
            b'CreateRemoteThread',
            b'VirtualAllocEx',
            b'WriteProcessMemory',
        ]
        
    def _load_injection_signatures(self) -> List[InjectionSignature]:
        """Load known code injection signatures."""
        return [
            InjectionSignature(
                name="Classic DLL Injection",
                pattern=b'LoadLibrary.*GetProcAddress',
                description="Classic DLL injection using LoadLibrary/GetProcAddress",
                severity="high"
            ),
            InjectionSignature(
                name="Process Hollowing",
                pattern=b'NtUnmapViewOfSection.*WriteProcessMemory',
                description="Process hollowing technique",
                severity="critical"
            ),
            InjectionSignature(
                name="Reflective DLL Loading",
                pattern=b'VirtualAlloc.*memcpy.*((void\\(\\*\\)\\(\\)))',
                description="Reflective DLL loading",
                severity="high"
            ),
            InjectionSignature(
                name="Thread Hijacking",
                pattern=b'SuspendThread.*SetThreadContext.*ResumeThread',
                description="Thread context manipulation",
                severity="high"
            )
        ]
    
    def analyze_process_memory(self, pid: int) -> Dict:
        """Analyze memory layout and content of a specific process."""
        try:
            proc = psutil.Process(pid)
            
            analysis = {
                'pid': pid,
                'name': proc.name(),
                'memory_regions': [],
                'suspicious_regions': [],
                'injection_indicators': [],
                'memory_anomalies': [],
                'executable_regions': [],
                'analysis_timestamp': psutil.time.time()
            }
            
            # Analyze memory maps
            try:
                memory_maps = proc.memory_maps()
                for mmap_info in memory_maps:
                    region = self._analyze_memory_region(pid, mmap_info)
                    analysis['memory_regions'].append(region.__dict__)
                    
                    if region.is_suspicious:
                        analysis['suspicious_regions'].append(region.__dict__)
                    
                    if region.is_executable:
                        analysis['executable_regions'].append(region.__dict__)
                        
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                analysis['error'] = 'Access denied to process memory'
            
            # Check for memory anomalies
            anomalies = self._detect_memory_anomalies(analysis)
            analysis['memory_anomalies'] = anomalies
            
            # Scan for injection signatures
            injections = self._scan_for_injections(pid)
            analysis['injection_indicators'] = injections
            
            return analysis
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {'error': str(e), 'pid': pid}
    
    def _analyze_memory_region(self, pid: int, mmap_info) -> MemoryRegion:
        """Analyze individual memory region."""
        # Parse memory map information
        parts = mmap_info.path.split() if hasattr(mmap_info, 'path') else ['']
        backing_file = parts[0] if parts else str(mmap_info)
        
        # Determine if region is suspicious
        is_suspicious = self._is_suspicious_region(backing_file, mmap_info)
        
        # Check if executable
        is_executable = 'x' in str(mmap_info) or 'exec' in str(mmap_info).lower()
        
        return MemoryRegion(
            start_addr=0,  # Would need to parse from mmap_info
            end_addr=0,
            size=mmap_info.rss if hasattr(mmap_info, 'rss') else 0,
            permissions=str(mmap_info),
            backing_file=backing_file,
            is_executable=is_executable,
            is_suspicious=is_suspicious
        )
    
    def _is_suspicious_region(self, backing_file: str, mmap_info) -> bool:
        """Determine if memory region is suspicious."""
        # Anonymous executable regions
        if not backing_file or backing_file == '[heap]':
            return 'x' in str(mmap_info)
        
        # Regions in suspicious locations
        suspicious_paths = ['/tmp/', '/dev/shm/', '/var/tmp/', '..']
        if any(path in backing_file for path in suspicious_paths):
            return True
        
        # Regions with suspicious names
        suspicious_names = ['inject', 'hook', 'patch', 'fake', 'evil']
        if any(name in backing_file.lower() for name in suspicious_names):
            return True
        
        return False
    
    def _detect_memory_anomalies(self, analysis: Dict) -> List[Dict]:
        """Detect memory layout anomalies."""
        anomalies = []
        
        # Check for excessive executable regions
        exec_count = len(analysis['executable_regions'])
        if exec_count > 20:
            anomalies.append({
                'type': 'excessive_executable_regions',
                'description': f'Process has {exec_count} executable memory regions',
                'severity': 'medium'
            })
        
        # Check for suspicious region patterns
        suspicious_count = len(analysis['suspicious_regions'])
        if suspicious_count > 5:
            anomalies.append({
                'type': 'multiple_suspicious_regions',
                'description': f'Process has {suspicious_count} suspicious memory regions',
                'severity': 'high'
            })
        
        # Check for memory fragmentation
        total_regions = len(analysis['memory_regions'])
        if total_regions > 100:
            anomalies.append({
                'type': 'excessive_fragmentation',
                'description': f'Process memory highly fragmented ({total_regions} regions)',
                'severity': 'low'
            })
        
        return anomalies
    
    def _scan_for_injections(self, pid: int) -> List[Dict]:
        """Scan process memory for injection indicators."""
        indicators = []
        
        try:
            proc = psutil.Process(pid)
            
            # Check command line for injection tools
            cmdline = ' '.join(proc.cmdline()) if proc.cmdline() else ''
            injection_tools = ['gdb', 'ptrace', 'inject', 'dll', 'payload']
            
            for tool in injection_tools:
                if tool in cmdline.lower():
                    indicators.append({
                        'type': 'injection_tool_detected',
                        'indicator': tool,
                        'location': 'command_line',
                        'description': f'Process command line contains injection-related term: {tool}',
                        'severity': 'medium'
                    })
            
            # Check for loaded libraries in suspicious locations
            try:
                maps_file = f'/proc/{pid}/maps'
                if os.path.exists(maps_file):
                    with open(maps_file, 'r') as f:
                        maps_content = f.read()
                    
                    suspicious_libs = ['/tmp/', '/dev/shm/', '/var/tmp/']
                    for line in maps_content.split('\n'):
                        for sus_path in suspicious_libs:
                            if sus_path in line and ('x' in line or 'exec' in line):
                                indicators.append({
                                    'type': 'suspicious_executable_mapping',
                                    'indicator': line.strip(),
                                    'location': 'memory_map',
                                    'description': f'Executable memory mapped from suspicious location',
                                    'severity': 'high'
                                })
                                
            except (FileNotFoundError, PermissionError):
                pass
            
            # Check for LD_PRELOAD hooks specific to this process
            try:
                environ_file = f'/proc/{pid}/environ'
                if os.path.exists(environ_file):
                    with open(environ_file, 'rb') as f:
                        environ_data = f.read().decode('utf-8', errors='ignore')
                    
                    if 'LD_PRELOAD=' in environ_data:
                        preload_libs = environ_data.split('LD_PRELOAD=')[1].split('\x00')[0]
                        indicators.append({
                            'type': 'ld_preload_injection',
                            'indicator': preload_libs,
                            'location': 'environment',
                            'description': 'Process has LD_PRELOAD library injection',
                            'severity': 'high'
                        })
                        
            except (FileNotFoundError, PermissionError):
                pass
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        
        return indicators
    
    def detect_process_hollowing(self, pid: int) -> Dict:
        """Specifically detect process hollowing techniques."""
        try:
            proc = psutil.Process(pid)
            
            detection_result = {
                'pid': pid,
                'process_name': proc.name(),
                'hollowing_detected': False,
                'confidence': 0.0,
                'indicators': []
            }
            
            # Check executable path vs running process
            try:
                exe_path = proc.exe()
                cmdline = proc.cmdline()
                
                if cmdline and exe_path:
                    # Check if executable path matches command line
                    if os.path.basename(exe_path) != os.path.basename(cmdline[0]):
                        detection_result['indicators'].append('executable_name_mismatch')
                        detection_result['confidence'] += 0.3
                        
            except (psutil.AccessDenied, IndexError):
                pass
            
            # Check memory layout for hollowing indicators
            try:
                maps_file = f'/proc/{pid}/maps'
                if os.path.exists(maps_file):
                    with open(maps_file, 'r') as f:
                        maps_content = f.read()
                    
                    executable_regions = [line for line in maps_content.split('\n') 
                                        if 'x' in line and 'r' in line]
                    
                    # Look for multiple executable regions with different backing files
                    backing_files = set()
                    for region in executable_regions:
                        parts = region.split()
                        if len(parts) >= 6:
                            backing_files.add(parts[5])
                    
                    if len(backing_files) > 3:  # Multiple different executables
                        detection_result['indicators'].append('multiple_executable_regions')
                        detection_result['confidence'] += 0.2
                    
                    # Check for anonymous executable regions
                    anon_exec_count = sum(1 for region in executable_regions 
                                         if len(region.split()) < 6)
                    if anon_exec_count > 2:
                        detection_result['indicators'].append('anonymous_executable_regions')
                        detection_result['confidence'] += 0.4
                        
            except (FileNotFoundError, PermissionError):
                pass
            
            # Check process creation time vs parent
            try:
                parent = proc.parent()
                if parent:
                    time_diff = proc.create_time() - parent.create_time()
                    if time_diff < 1:  # Created very quickly after parent
                        detection_result['indicators'].append('rapid_process_creation')
                        detection_result['confidence'] += 0.1
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            # Set detection flag based on confidence
            detection_result['hollowing_detected'] = detection_result['confidence'] >= 0.5
            
            return detection_result
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {'error': str(e), 'pid': pid}
    
    def scan_memory_for_shellcode(self, pid: int) -> List[Dict]:
        """Scan process memory for potential shellcode patterns."""
        shellcode_findings = []
        
        try:
            # Read process memory maps
            maps_file = f'/proc/{pid}/maps'
            if not os.path.exists(maps_file):
                return shellcode_findings
            
            with open(maps_file, 'r') as f:
                maps_lines = f.readlines()
            
            # Analyze executable regions
            for line in maps_lines:
                if 'x' in line:  # Executable permission
                    parts = line.strip().split()
                    if len(parts) >= 1:
                        addr_range = parts[0]
                        start_addr, end_addr = addr_range.split('-')
                        start_addr = int(start_addr, 16)
                        end_addr = int(end_addr, 16)
                        
                        # Try to read memory content
                        mem_file = f'/proc/{pid}/mem'
                        if os.path.exists(mem_file):
                            finding = self._analyze_memory_content(
                                pid, mem_file, start_addr, end_addr
                            )
                            if finding:
                                shellcode_findings.append(finding)
                                
        except Exception as e:
            print(f"Error scanning memory for PID {pid}: {e}")
        
        return shellcode_findings
    
    def _analyze_memory_content(self, pid: int, mem_file: str, 
                               start_addr: int, end_addr: int) -> Optional[Dict]:
        """Analyze memory content for suspicious patterns."""
        try:
            # Limit scan size for performance
            scan_size = min(end_addr - start_addr, 1024 * 1024)  # Max 1MB
            
            with open(mem_file, 'rb') as f:
                f.seek(start_addr)
                memory_data = f.read(scan_size)
            
            # Scan for suspicious patterns
            for i, pattern in enumerate(self.suspicious_patterns):
                if pattern in memory_data:
                    return {
                        'pid': pid,
                        'address_range': f'0x{start_addr:x}-0x{end_addr:x}',
                        'pattern_found': pattern.hex() if isinstance(pattern, bytes) else str(pattern),
                        'pattern_offset': memory_data.find(pattern),
                        'description': f'Suspicious pattern #{i} detected',
                        'severity': 'medium'
                    }
            
            # Check for high entropy (possible encrypted/packed code)
            entropy = self._calculate_entropy(memory_data)
            if entropy > 7.5:  # High entropy threshold
                return {
                    'pid': pid,
                    'address_range': f'0x{start_addr:x}-0x{end_addr:x}',
                    'entropy': entropy,
                    'description': 'High entropy region (possible packed/encrypted code)',
                    'severity': 'low'
                }
                
        except (FileNotFoundError, PermissionError, OSError):
            # Expected for some processes/regions
            pass
        except Exception as e:
            print(f"Error analyzing memory content: {e}")
        
        return None
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        if not data:
            return 0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def detect_dll_injection(self, pid: int) -> Dict:
        """Detect DLL injection in a process."""
        try:
            proc = psutil.Process(pid)
            
            detection_result = {
                'pid': pid,
                'process_name': proc.name(),
                'injection_detected': False,
                'confidence': 0.0,
                'injected_modules': [],
                'indicators': []
            }
            
            # Check loaded libraries via memory maps
            try:
                maps_file = f'/proc/{pid}/maps'
                if os.path.exists(maps_file):
                    with open(maps_file, 'r') as f:
                        maps_content = f.read()
                    
                    # Look for libraries in suspicious locations
                    suspicious_locations = ['/tmp/', '/dev/shm/', '/var/tmp/', '/home/']
                    
                    for line in maps_content.split('\n'):
                        if '.so' in line:  # Shared library
                            for sus_loc in suspicious_locations:
                                if sus_loc in line:
                                    detection_result['injected_modules'].append(line.strip())
                                    detection_result['confidence'] += 0.3
                                    detection_result['indicators'].append('suspicious_library_location')
                    
                    # Check for anonymous executable regions (possible reflective loading)
                    anon_exec_lines = [line for line in maps_content.split('\n') 
                                      if 'x' in line and len(line.split()) < 6]
                    
                    if len(anon_exec_lines) > 1:
                        detection_result['confidence'] += 0.4
                        detection_result['indicators'].append('anonymous_executable_regions')
                        
            except (FileNotFoundError, PermissionError):
                pass
            
            # Check LD_PRELOAD environment variable
            try:
                environ_file = f'/proc/{pid}/environ'
                if os.path.exists(environ_file):
                    with open(environ_file, 'rb') as f:
                        environ_data = f.read().decode('utf-8', errors='ignore')
                    
                    if 'LD_PRELOAD=' in environ_data:
                        preload_value = environ_data.split('LD_PRELOAD=')[1].split('\x00')[0]
                        if preload_value:
                            detection_result['injected_modules'].append(f'LD_PRELOAD: {preload_value}')
                            detection_result['confidence'] += 0.5
                            detection_result['indicators'].append('ld_preload_injection')
                            
            except (FileNotFoundError, PermissionError):
                pass
            
            detection_result['injection_detected'] = detection_result['confidence'] >= 0.4
            
            return detection_result
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return {'error': str(e), 'pid': pid}
    
    def analyze_heap_spray_patterns(self, pid: int) -> Dict:
        """Analyze heap for spray attack patterns."""
        try:
            analysis = {
                'pid': pid,
                'spray_detected': False,
                'heap_regions': [],
                'spray_patterns': [],
                'confidence': 0.0
            }
            
            # Read memory maps to find heap regions
            maps_file = f'/proc/{pid}/maps'
            if os.path.exists(maps_file):
                with open(maps_file, 'r') as f:
                    maps_content = f.read()
                
                heap_lines = [line for line in maps_content.split('\n') 
                             if '[heap]' in line or 'heap' in line.lower()]
                
                analysis['heap_regions'] = heap_lines
                
                # Look for patterns indicative of heap spraying
                if len(heap_lines) > 10:  # Excessive heap allocations
                    analysis['confidence'] += 0.3
                    analysis['spray_patterns'].append('excessive_heap_allocations')
                
                # Check for uniform heap sizes (common in spraying)
                heap_sizes = []
                for line in heap_lines:
                    parts = line.split()
                    if parts:
                        addr_range = parts[0]
                        start, end = addr_range.split('-')
                        size = int(end, 16) - int(start, 16)
                        heap_sizes.append(size)
                
                if heap_sizes and len(set(heap_sizes)) < len(heap_sizes) / 3:
                    analysis['confidence'] += 0.4
                    analysis['spray_patterns'].append('uniform_heap_sizes')
            
            analysis['spray_detected'] = analysis['confidence'] >= 0.5
            
            return analysis
            
        except Exception as e:
            return {'error': str(e), 'pid': pid}
    
    def get_memory_protection_status(self) -> Dict:
        """Check system memory protection features."""
        protections = {
            'aslr_enabled': False,
            'dep_nx_enabled': False,
            'smep_enabled': False,
            'smap_enabled': False,
            'kpti_enabled': False,
            'details': {}
        }
        
        try:
            # Check ASLR
            with open('/proc/sys/kernel/randomize_va_space', 'r') as f:
                aslr_value = int(f.read().strip())
                protections['aslr_enabled'] = aslr_value > 0
                protections['details']['aslr_level'] = aslr_value
                
        except (FileNotFoundError, PermissionError, ValueError):
            pass
        
        try:
            # Check CPU features
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
            
            # Check for NX/DEP support
            if 'nx' in cpuinfo or 'dep' in cpuinfo:
                protections['dep_nx_enabled'] = True
            
            # Check for SMEP/SMAP
            if 'smep' in cpuinfo:
                protections['smep_enabled'] = True
            if 'smap' in cpuinfo:
                protections['smap_enabled'] = True
                
        except (FileNotFoundError, PermissionError):
            pass
        
        try:
            # Check for KPTI (Kernel Page Table Isolation)
            if os.path.exists('/sys/devices/system/cpu/vulnerabilities/meltdown'):
                with open('/sys/devices/system/cpu/vulnerabilities/meltdown', 'r') as f:
                    meltdown_status = f.read().strip()
                    protections['kpti_enabled'] = 'PTI' in meltdown_status
                    protections['details']['meltdown_mitigation'] = meltdown_status
                    
        except (FileNotFoundError, PermissionError):
            pass
        
        return protections
    
    def comprehensive_memory_scan(self, target_pids: List[int] = None) -> Dict:
        """Perform comprehensive memory analysis on specified processes."""
        if target_pids is None:
            # Scan all processes (limited for performance)
            target_pids = [proc.pid for proc in psutil.process_iter()][:50]
        
        scan_results = {
            'scan_timestamp': datetime.now().isoformat(),
            'processes_scanned': len(target_pids),
            'memory_protection_status': self.get_memory_protection_status(),
            'process_analyses': [],
            'summary': {
                'hollowing_detected': 0,
                'injections_detected': 0,
                'suspicious_regions': 0,
                'total_anomalies': 0
            }
        }
        
        for pid in target_pids:
            try:
                # Memory analysis
                memory_analysis = self.analyze_process_memory(pid)
                
                # Hollowing detection
                hollowing_result = self.detect_process_hollowing(pid)
                
                # DLL injection detection
                injection_result = self.detect_dll_injection(pid)
                
                # Heap spray analysis
                heap_analysis = self.analyze_heap_spray_patterns(pid)
                
                process_result = {
                    'pid': pid,
                    'memory_analysis': memory_analysis,
                    'hollowing_analysis': hollowing_result,
                    'injection_analysis': injection_result,
                    'heap_analysis': heap_analysis
                }
                
                scan_results['process_analyses'].append(process_result)
                
                # Update summary
                if hollowing_result.get('hollowing_detected', False):
                    scan_results['summary']['hollowing_detected'] += 1
                
                if injection_result.get('injection_detected', False):
                    scan_results['summary']['injections_detected'] += 1
                
                scan_results['summary']['suspicious_regions'] += len(
                    memory_analysis.get('suspicious_regions', [])
                )
                
                scan_results['summary']['total_anomalies'] += len(
                    memory_analysis.get('memory_anomalies', [])
                )
                
            except Exception as e:
                print(f"Error analyzing PID {pid}: {e}")
                continue
        
        return scan_results