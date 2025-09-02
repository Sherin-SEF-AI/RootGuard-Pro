"""
Behavioral Analysis Module
Advanced behavioral monitoring and anomaly detection for rootkit activities.
"""

import os
import time
import threading
import json
import hashlib
import psutil
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta


class ProcessBehavior:
    """Tracks behavioral patterns for individual processes."""
    
    def __init__(self, pid: int, name: str):
        self.pid = pid
        self.name = name
        self.start_time = time.time()
        self.cpu_history = deque(maxlen=60)  # Last 60 measurements
        self.memory_history = deque(maxlen=60)
        self.network_connections = []
        self.file_operations = []
        self.child_processes = []
        self.syscall_patterns = defaultdict(int)
        self.anomaly_score = 0.0
        self.alerts = []
    
    def update_metrics(self, cpu_percent: float, memory_mb: float, connections: List):
        """Update process metrics."""
        self.cpu_history.append((time.time(), cpu_percent))
        self.memory_history.append((time.time(), memory_mb))
        self.network_connections = connections
        
    def add_file_operation(self, operation: str, filepath: str):
        """Record file operation."""
        self.file_operations.append({
            'timestamp': time.time(),
            'operation': operation,
            'filepath': filepath
        })
        
        # Keep only recent operations
        cutoff = time.time() - 3600  # 1 hour
        self.file_operations = [op for op in self.file_operations if op['timestamp'] > cutoff]
    
    def add_child_process(self, child_pid: int, child_name: str):
        """Record child process creation."""
        self.child_processes.append({
            'pid': child_pid,
            'name': child_name,
            'timestamp': time.time()
        })
    
    def calculate_anomaly_score(self) -> float:
        """Calculate behavioral anomaly score."""
        score = 0.0
        
        # CPU spike detection
        if len(self.cpu_history) > 10:
            recent_cpu = [cpu for _, cpu in list(self.cpu_history)[-10:]]
            avg_cpu = sum(recent_cpu) / len(recent_cpu)
            if avg_cpu > 80:
                score += 0.2
        
        # Memory growth detection
        if len(self.memory_history) > 20:
            early_mem = sum(mem for _, mem in list(self.memory_history)[:10]) / 10
            recent_mem = sum(mem for _, mem in list(self.memory_history)[-10:]) / 10
            if recent_mem > early_mem * 2:  # Memory doubled
                score += 0.3
        
        # Excessive file operations
        recent_ops = sum(1 for op in self.file_operations if op['timestamp'] > time.time() - 300)
        if recent_ops > 100:  # More than 100 file ops in 5 minutes
            score += 0.2
        
        # Suspicious file patterns
        suspicious_patterns = ['/tmp/', '/dev/shm/', '/proc/', '..', 'shadow', 'passwd']
        for op in self.file_operations[-50:]:  # Check last 50 operations
            if any(pattern in op['filepath'] for pattern in suspicious_patterns):
                score += 0.1
                break
        
        # Network behavior
        external_connections = [conn for conn in self.network_connections 
                              if not self.is_local_address(conn.get('remote_ip', ''))]
        if len(external_connections) > 10:
            score += 0.2
        
        # Process spawning behavior
        recent_children = [child for child in self.child_processes 
                          if child['timestamp'] > time.time() - 600]  # Last 10 minutes
        if len(recent_children) > 5:
            score += 0.2
        
        self.anomaly_score = min(score, 1.0)  # Cap at 1.0
        return self.anomaly_score
    
    def is_local_address(self, ip: str) -> bool:
        """Check if IP address is local."""
        local_prefixes = ['127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.']
        return any(ip.startswith(prefix) for prefix in local_prefixes)


class BehavioralAnalyzer:
    """Advanced behavioral analysis engine."""
    
    def __init__(self):
        self.process_behaviors = {}
        self.monitoring_active = False
        self.monitor_thread = None
        self.baseline_patterns = {}
        self.anomaly_threshold = 0.6
        self.alert_callbacks = []
        
        # Behavioral patterns to detect
        self.malicious_patterns = {
            'process_hollowing': {
                'memory_jump': 0.5,  # 50% memory increase
                'new_connections': 3,
                'file_writes': 10
            },
            'cryptocurrency_mining': {
                'cpu_sustained': 90,  # 90% CPU for extended period
                'network_pools': ['pool', 'mine', 'crypto'],
                'process_names': ['xmrig', 'cpuminer', 'minerd']
            },
            'data_exfiltration': {
                'network_volume': 1000000,  # 1MB network traffic
                'file_reads': 50,
                'external_connections': 5
            },
            'privilege_escalation': {
                'file_patterns': ['/etc/passwd', '/etc/shadow', '/etc/sudoers'],
                'process_spawning': 5,
                'root_access_attempts': True
            }
        }
    
    def start_monitoring(self):
        """Start behavioral monitoring."""
        if self.monitoring_active:
            return
            
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop behavioral monitoring."""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
    
    def add_alert_callback(self, callback):
        """Add callback for behavioral alerts."""
        self.alert_callbacks.append(callback)
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self.monitoring_active:
            try:
                self._update_process_behaviors()
                self._analyze_behaviors()
                time.sleep(5)  # Update every 5 seconds
            except Exception as e:
                print(f"Error in behavioral monitoring: {e}")
                time.sleep(10)
    
    def _update_process_behaviors(self):
        """Update behavioral data for all processes."""
        current_pids = set()
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name']
                    current_pids.add(pid)
                    
                    # Create or update process behavior
                    if pid not in self.process_behaviors:
                        self.process_behaviors[pid] = ProcessBehavior(pid, name)
                    
                    behavior = self.process_behaviors[pid]
                    
                    # Update metrics
                    cpu_percent = proc.cpu_percent()
                    memory_mb = proc.memory_info().rss / 1024 / 1024
                    connections = []
                    
                    try:
                        connections = [
                            {
                                'local_ip': conn.laddr.ip if conn.laddr else '',
                                'local_port': conn.laddr.port if conn.laddr else 0,
                                'remote_ip': conn.raddr.ip if conn.raddr else '',
                                'remote_port': conn.raddr.port if conn.raddr else 0,
                                'status': conn.status
                            }
                            for conn in proc.connections()
                        ]
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    behavior.update_metrics(cpu_percent, memory_mb, connections)
                    
                    # Monitor file operations (simplified via open files)
                    try:
                        open_files = proc.open_files()
                        for file_info in open_files[-5:]:  # Last 5 files
                            behavior.add_file_operation('access', file_info.path)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    # Monitor child processes
                    try:
                        children = proc.children()
                        for child in children:
                            if child.pid not in [c['pid'] for c in behavior.child_processes]:
                                behavior.add_child_process(child.pid, child.name())
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            print(f"Error updating process behaviors: {e}")
        
        # Clean up terminated processes
        terminated_pids = set(self.process_behaviors.keys()) - current_pids
        for pid in terminated_pids:
            del self.process_behaviors[pid]
    
    def _analyze_behaviors(self):
        """Analyze behavioral patterns for anomalies."""
        for pid, behavior in self.process_behaviors.items():
            try:
                # Calculate anomaly score
                score = behavior.calculate_anomaly_score()
                
                if score > self.anomaly_threshold:
                    alert = {
                        'timestamp': datetime.now().isoformat(),
                        'pid': pid,
                        'process_name': behavior.name,
                        'anomaly_score': score,
                        'alert_type': 'behavioral_anomaly',
                        'details': self._get_anomaly_details(behavior)
                    }
                    
                    # Add to behavior alerts
                    behavior.alerts.append(alert)
                    
                    # Notify callbacks
                    for callback in self.alert_callbacks:
                        callback(alert)
                
                # Check for specific malicious patterns
                pattern_alerts = self._check_malicious_patterns(behavior)
                for alert in pattern_alerts:
                    behavior.alerts.append(alert)
                    for callback in self.alert_callbacks:
                        callback(alert)
                        
            except Exception as e:
                print(f"Error analyzing behavior for PID {pid}: {e}")
    
    def _get_anomaly_details(self, behavior: ProcessBehavior) -> Dict:
        """Get detailed anomaly information."""
        details = {}
        
        # CPU analysis
        if len(behavior.cpu_history) > 10:
            recent_cpu = [cpu for _, cpu in list(behavior.cpu_history)[-10:]]
            details['avg_cpu'] = sum(recent_cpu) / len(recent_cpu)
            details['max_cpu'] = max(recent_cpu)
        
        # Memory analysis
        if len(behavior.memory_history) > 20:
            early_mem = sum(mem for _, mem in list(behavior.memory_history)[:10]) / 10
            recent_mem = sum(mem for _, mem in list(behavior.memory_history)[-10:]) / 10
            details['memory_growth'] = recent_mem / early_mem if early_mem > 0 else 1.0
        
        # File operations
        details['recent_file_ops'] = len([op for op in behavior.file_operations 
                                        if op['timestamp'] > time.time() - 300])
        
        # Network connections
        details['external_connections'] = len([conn for conn in behavior.network_connections 
                                             if not behavior.is_local_address(conn.get('remote_ip', ''))])
        
        # Child processes
        details['recent_children'] = len([child for child in behavior.child_processes 
                                        if child['timestamp'] > time.time() - 600])
        
        return details
    
    def _check_malicious_patterns(self, behavior: ProcessBehavior) -> List[Dict]:
        """Check for specific malicious behavior patterns."""
        alerts = []
        
        # Process hollowing detection
        if self._detect_process_hollowing(behavior):
            alerts.append({
                'timestamp': datetime.now().isoformat(),
                'pid': behavior.pid,
                'process_name': behavior.name,
                'alert_type': 'process_hollowing',
                'severity': 'high',
                'details': 'Potential process hollowing detected'
            })
        
        # Cryptocurrency mining detection
        if self._detect_crypto_mining(behavior):
            alerts.append({
                'timestamp': datetime.now().isoformat(),
                'pid': behavior.pid,
                'process_name': behavior.name,
                'alert_type': 'crypto_mining',
                'severity': 'medium',
                'details': 'Potential cryptocurrency mining activity'
            })
        
        # Data exfiltration detection
        if self._detect_data_exfiltration(behavior):
            alerts.append({
                'timestamp': datetime.now().isoformat(),
                'pid': behavior.pid,
                'process_name': behavior.name,
                'alert_type': 'data_exfiltration',
                'severity': 'high',
                'details': 'Potential data exfiltration activity'
            })
        
        # Privilege escalation detection
        if self._detect_privilege_escalation(behavior):
            alerts.append({
                'timestamp': datetime.now().isoformat(),
                'pid': behavior.pid,
                'process_name': behavior.name,
                'alert_type': 'privilege_escalation',
                'severity': 'critical',
                'details': 'Potential privilege escalation attempt'
            })
        
        return alerts
    
    def _detect_process_hollowing(self, behavior: ProcessBehavior) -> bool:
        """Detect potential process hollowing."""
        # Check for sudden memory increase + new network connections
        if len(behavior.memory_history) < 20:
            return False
            
        early_mem = sum(mem for _, mem in list(behavior.memory_history)[:10]) / 10
        recent_mem = sum(mem for _, mem in list(behavior.memory_history)[-10:]) / 10
        
        memory_increase = recent_mem / early_mem if early_mem > 0 else 1.0
        new_connections = len(behavior.network_connections)
        recent_files = len([op for op in behavior.file_operations if op['timestamp'] > time.time() - 300])
        
        pattern = self.malicious_patterns['process_hollowing']
        return (memory_increase > pattern['memory_jump'] and 
                new_connections >= pattern['new_connections'] and 
                recent_files >= pattern['file_writes'])
    
    def _detect_crypto_mining(self, behavior: ProcessBehavior) -> bool:
        """Detect cryptocurrency mining activity."""
        # Check for sustained high CPU usage
        if len(behavior.cpu_history) < 20:
            return False
            
        recent_cpu = [cpu for _, cpu in list(behavior.cpu_history)[-20:]]
        avg_cpu = sum(recent_cpu) / len(recent_cpu)
        
        # Check process name for mining indicators
        name_lower = behavior.name.lower()
        mining_names = self.malicious_patterns['cryptocurrency_mining']['process_names']
        
        # Check network connections for mining pools
        pool_connections = any(
            any(pool_indicator in str(conn.get('remote_ip', '')).lower() 
                for pool_indicator in self.malicious_patterns['cryptocurrency_mining']['network_pools'])
            for conn in behavior.network_connections
        )
        
        return (avg_cpu > self.malicious_patterns['cryptocurrency_mining']['cpu_sustained'] or
                any(mining_name in name_lower for mining_name in mining_names) or
                pool_connections)
    
    def _detect_data_exfiltration(self, behavior: ProcessBehavior) -> bool:
        """Detect potential data exfiltration."""
        # Check for high volume of file reads + external network connections
        recent_file_ops = [op for op in behavior.file_operations if op['timestamp'] > time.time() - 600]
        file_reads = sum(1 for op in recent_file_ops if op['operation'] in ['read', 'access'])
        
        external_connections = len([conn for conn in behavior.network_connections 
                                   if not behavior.is_local_address(conn.get('remote_ip', ''))])
        
        pattern = self.malicious_patterns['data_exfiltration']
        return (file_reads >= pattern['file_reads'] and 
                external_connections >= pattern['external_connections'])
    
    def _detect_privilege_escalation(self, behavior: ProcessBehavior) -> bool:
        """Detect privilege escalation attempts."""
        # Check for access to sensitive files
        sensitive_files = self.malicious_patterns['privilege_escalation']['file_patterns']
        
        for op in behavior.file_operations[-20:]:  # Check recent operations
            if any(pattern in op['filepath'] for pattern in sensitive_files):
                return True
        
        # Check for rapid process spawning (potential exploit)
        recent_children = [child for child in behavior.child_processes 
                          if child['timestamp'] > time.time() - 300]  # Last 5 minutes
        
        return len(recent_children) >= self.malicious_patterns['privilege_escalation']['process_spawning']
    
    def get_behavioral_summary(self) -> Dict:
        """Get summary of all behavioral analysis."""
        summary = {
            'total_processes_monitored': len(self.process_behaviors),
            'high_anomaly_processes': [],
            'pattern_detections': defaultdict(int),
            'monitoring_duration': time.time() - min(b.start_time for b in self.process_behaviors.values()) if self.process_behaviors else 0
        }
        
        for pid, behavior in self.process_behaviors.items():
            if behavior.anomaly_score > self.anomaly_threshold:
                summary['high_anomaly_processes'].append({
                    'pid': pid,
                    'name': behavior.name,
                    'anomaly_score': behavior.anomaly_score,
                    'alert_count': len(behavior.alerts)
                })
            
            # Count pattern detections
            for alert in behavior.alerts:
                summary['pattern_detections'][alert['alert_type']] += 1
        
        return summary
    
    def create_baseline(self, name: str = "default") -> bool:
        """Create behavioral baseline from current system state."""
        try:
            baseline_data = {
                'timestamp': datetime.now().isoformat(),
                'process_patterns': {},
                'system_metrics': self._get_system_metrics()
            }
            
            # Capture current process patterns
            for pid, behavior in self.process_behaviors.items():
                if len(behavior.cpu_history) > 10 and len(behavior.memory_history) > 10:
                    baseline_data['process_patterns'][behavior.name] = {
                        'avg_cpu': sum(cpu for _, cpu in behavior.cpu_history) / len(behavior.cpu_history),
                        'avg_memory': sum(mem for _, mem in behavior.memory_history) / len(behavior.memory_history),
                        'typical_connections': len(behavior.network_connections),
                        'file_activity': len(behavior.file_operations)
                    }
            
            # Save baseline
            os.makedirs('baselines', exist_ok=True)
            with open(f'baselines/{name}_behavioral.json', 'w') as f:
                json.dump(baseline_data, f, indent=2)
            
            self.baseline_patterns[name] = baseline_data
            return True
            
        except Exception as e:
            print(f"Error creating baseline: {e}")
            return False
    
    def compare_with_baseline(self, baseline_name: str = "default") -> Dict:
        """Compare current behavior with baseline."""
        if baseline_name not in self.baseline_patterns:
            # Try to load from file
            try:
                with open(f'baselines/{baseline_name}_behavioral.json', 'r') as f:
                    self.baseline_patterns[baseline_name] = json.load(f)
            except FileNotFoundError:
                return {'error': 'Baseline not found'}
        
        baseline = self.baseline_patterns[baseline_name]
        comparison = {
            'baseline_date': baseline['timestamp'],
            'comparison_date': datetime.now().isoformat(),
            'deviations': [],
            'new_processes': [],
            'missing_processes': []
        }
        
        baseline_processes = set(baseline['process_patterns'].keys())
        current_processes = set(behavior.name for behavior in self.process_behaviors.values())
        
        comparison['new_processes'] = list(current_processes - baseline_processes)
        comparison['missing_processes'] = list(baseline_processes - current_processes)
        
        # Check for behavioral deviations
        for process_name, baseline_pattern in baseline['process_patterns'].items():
            current_behaviors = [b for b in self.process_behaviors.values() if b.name == process_name]
            
            if current_behaviors:
                current_behavior = current_behaviors[0]
                if len(current_behavior.cpu_history) > 10:
                    current_cpu = sum(cpu for _, cpu in current_behavior.cpu_history) / len(current_behavior.cpu_history)
                    baseline_cpu = baseline_pattern['avg_cpu']
                    
                    if abs(current_cpu - baseline_cpu) > 20:  # 20% deviation
                        comparison['deviations'].append({
                            'process': process_name,
                            'metric': 'cpu_usage',
                            'baseline': baseline_cpu,
                            'current': current_cpu,
                            'deviation': abs(current_cpu - baseline_cpu)
                        })
        
        return comparison
    
    def _get_system_metrics(self) -> Dict:
        """Get current system-wide metrics."""
        try:
            return {
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_io': psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else {},
                'network_io': psutil.net_io_counters()._asdict() if psutil.net_io_counters() else {},
                'process_count': len(psutil.pids()),
                'load_average': os.getloadavg()
            }
        except Exception:
            return {}
    
    def export_behavioral_report(self, output_path: str):
        """Export detailed behavioral analysis report."""
        report_data = {
            'generation_time': datetime.now().isoformat(),
            'summary': self.get_behavioral_summary(),
            'process_details': {}
        }
        
        # Add detailed process information
        for pid, behavior in self.process_behaviors.items():
            if behavior.anomaly_score > 0.3:  # Include processes with some anomaly
                report_data['process_details'][str(pid)] = {
                    'name': behavior.name,
                    'anomaly_score': behavior.anomaly_score,
                    'monitoring_duration': time.time() - behavior.start_time,
                    'alerts': behavior.alerts,
                    'cpu_stats': {
                        'samples': len(behavior.cpu_history),
                        'avg_cpu': sum(cpu for _, cpu in behavior.cpu_history) / len(behavior.cpu_history) if behavior.cpu_history else 0
                    },
                    'memory_stats': {
                        'samples': len(behavior.memory_history),
                        'avg_memory': sum(mem for _, mem in behavior.memory_history) / len(behavior.memory_history) if behavior.memory_history else 0
                    },
                    'network_activity': len(behavior.network_connections),
                    'file_operations': len(behavior.file_operations),
                    'child_processes': len(behavior.child_processes)
                }
        
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2)
    
    def get_top_anomalous_processes(self, limit: int = 10) -> List[Dict]:
        """Get top anomalous processes."""
        processes = []
        
        for pid, behavior in self.process_behaviors.items():
            if behavior.anomaly_score > 0:
                processes.append({
                    'pid': pid,
                    'name': behavior.name,
                    'anomaly_score': behavior.anomaly_score,
                    'alert_count': len(behavior.alerts),
                    'monitoring_duration': time.time() - behavior.start_time
                })
        
        # Sort by anomaly score
        processes.sort(key=lambda x: x['anomaly_score'], reverse=True)
        return processes[:limit]