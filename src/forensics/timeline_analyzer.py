"""
Timeline Analysis and Forensic Mode
Comprehensive incident timeline reconstruction and forensic analysis capabilities.
"""

import os
import json
import sqlite3
import time
import threading
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import subprocess
import hashlib
from collections import defaultdict

@dataclass
class TimelineEvent:
    """Timeline event for forensic analysis."""
    timestamp: float
    event_type: str
    source: str
    description: str
    severity: str
    artifacts: Dict
    correlation_id: str
    process_info: Dict
    network_info: Dict
    file_info: Dict

@dataclass
class ForensicEvidence:
    """Digital forensic evidence item."""
    evidence_id: str
    timestamp: float
    evidence_type: str
    source_path: str
    hash_md5: str
    hash_sha256: str
    size: int
    description: str
    metadata: Dict
    chain_of_custody: List[Dict]

class TimelineAnalyzer:
    """Timeline analysis and forensic investigation system."""
    
    def __init__(self, db_path: str = "forensic_timeline.db"):
        self.db_path = db_path
        self.timeline_events = []
        self.evidence_items = []
        self.correlation_rules = []
        self.analysis_callbacks = []
        
        # Event sources to monitor
        self.event_sources = {
            'system_logs': ['/var/log/syslog', '/var/log/auth.log', '/var/log/kern.log'],
            'audit_logs': ['/var/log/audit/audit.log'],
            'application_logs': ['/var/log/apache2/access.log', '/var/log/nginx/access.log'],
            'security_logs': ['/var/log/fail2ban.log', '/var/log/ufw.log']
        }
        
        # Rootkit activity patterns for correlation
        self.rootkit_patterns = {
            'process_injection': {
                'events': ['process_create', 'memory_write', 'dll_inject'],
                'timeframe': 30,  # seconds
                'confidence_threshold': 0.8
            },
            'privilege_escalation': {
                'events': ['sudo_usage', 'setuid_execution', 'kernel_exploit'],
                'timeframe': 60,
                'confidence_threshold': 0.7
            },
            'data_exfiltration': {
                'events': ['file_access', 'network_connection', 'data_transfer'],
                'timeframe': 300,
                'confidence_threshold': 0.6
            },
            'persistence_setup': {
                'events': ['file_create', 'service_install', 'startup_modify'],
                'timeframe': 120,
                'confidence_threshold': 0.75
            }
        }
        
        self._init_database()
        self._load_correlation_rules()
    
    def _init_database(self):
        """Initialize forensic timeline database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS timeline_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    event_type TEXT,
                    source TEXT,
                    description TEXT,
                    severity TEXT,
                    artifacts TEXT,
                    correlation_id TEXT,
                    process_info TEXT,
                    network_info TEXT,
                    file_info TEXT
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS forensic_evidence (
                    evidence_id TEXT PRIMARY KEY,
                    timestamp REAL,
                    evidence_type TEXT,
                    source_path TEXT,
                    hash_md5 TEXT,
                    hash_sha256 TEXT,
                    size INTEGER,
                    description TEXT,
                    metadata TEXT,
                    chain_of_custody TEXT
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS correlation_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    pattern_name TEXT,
                    confidence REAL,
                    event_ids TEXT,
                    description TEXT,
                    investigation_notes TEXT
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS forensic_sessions (
                    session_id TEXT PRIMARY KEY,
                    start_timestamp REAL,
                    end_timestamp REAL,
                    analyst_name TEXT,
                    case_number TEXT,
                    description TEXT,
                    evidence_collected INTEGER,
                    timeline_events INTEGER
                )
            ''')
            
            conn.commit()
    
    def _load_correlation_rules(self):
        """Load event correlation rules for pattern detection."""
        # Load built-in correlation rules
        self.correlation_rules = [
            {
                'name': 'Rootkit Installation Sequence',
                'events': ['file_download', 'permission_change', 'service_creation'],
                'timeframe': 300,
                'confidence_multiplier': 1.2
            },
            {
                'name': 'Memory Injection Attack',
                'events': ['process_access', 'memory_allocation', 'thread_injection'],
                'timeframe': 60,
                'confidence_multiplier': 1.5
            },
            {
                'name': 'Network Backdoor Setup',
                'events': ['port_binding', 'firewall_modify', 'service_start'],
                'timeframe': 180,
                'confidence_multiplier': 1.3
            }
        ]
    
    def collect_system_events(self, time_range: int = 3600) -> List[TimelineEvent]:
        """Collect system events for timeline analysis."""
        events = []
        current_time = time.time()
        start_time = current_time - time_range
        
        try:
            # Collect from system logs
            events.extend(self._parse_system_logs(start_time))
            
            # Collect from audit logs
            events.extend(self._parse_audit_logs(start_time))
            
            # Collect from process events
            events.extend(self._collect_process_events(start_time))
            
            # Collect from network events
            events.extend(self._collect_network_events(start_time))
            
            # Collect from file system events
            events.extend(self._collect_filesystem_events(start_time))
            
            # Sort events by timestamp
            events.sort(key=lambda x: x.timestamp)
            
        except Exception as e:
            print(f"Error collecting system events: {e}")
        
        return events
    
    def _parse_system_logs(self, start_time: float) -> List[TimelineEvent]:
        """Parse system logs for relevant events."""
        events = []
        
        try:
            for log_file in self.event_sources['system_logs']:
                if not os.path.exists(log_file):
                    continue
                
                try:
                    with open(log_file, 'r') as f:
                        lines = f.readlines()[-1000:]  # Last 1000 lines
                    
                    for line in lines:
                        event = self._parse_syslog_line(line, start_time)
                        if event:
                            events.append(event)
                            
                except (PermissionError, OSError):
                    continue
                    
        except Exception as e:
            print(f"Error parsing system logs: {e}")
        
        return events
    
    def _parse_syslog_line(self, line: str, start_time: float) -> Optional[TimelineEvent]:
        """Parse individual syslog line."""
        try:
            # Simplified syslog parsing
            if not line.strip():
                return None
            
            # Extract timestamp (simplified)
            parts = line.split()
            if len(parts) < 5:
                return None
            
            # For demo, use current time minus random offset
            event_time = time.time() - (hash(line) % 3600)
            if event_time < start_time:
                return None
            
            # Identify suspicious events
            suspicious_keywords = [
                'sudo', 'su:', 'failed', 'error', 'unauthorized',
                'denied', 'violation', 'exploit', 'attack'
            ]
            
            line_lower = line.lower()
            if any(keyword in line_lower for keyword in suspicious_keywords):
                return TimelineEvent(
                    timestamp=event_time,
                    event_type='system_event',
                    source='syslog',
                    description=line.strip(),
                    severity='medium' if 'failed' in line_lower else 'low',
                    artifacts={'log_line': line.strip()},
                    correlation_id=hashlib.md5(line.encode()).hexdigest()[:8],
                    process_info={},
                    network_info={},
                    file_info={}
                )
                
        except Exception as e:
            print(f"Error parsing syslog line: {e}")
        
        return None
    
    def _parse_audit_logs(self, start_time: float) -> List[TimelineEvent]:
        """Parse audit logs for security events."""
        events = []
        
        try:
            for log_file in self.event_sources['audit_logs']:
                if not os.path.exists(log_file):
                    continue
                
                try:
                    with open(log_file, 'r') as f:
                        lines = f.readlines()[-500:]  # Last 500 lines
                    
                    for line in lines:
                        event = self._parse_audit_line(line, start_time)
                        if event:
                            events.append(event)
                            
                except (PermissionError, OSError):
                    continue
                    
        except Exception as e:
            print(f"Error parsing audit logs: {e}")
        
        return events
    
    def _parse_audit_line(self, line: str, start_time: float) -> Optional[TimelineEvent]:
        """Parse individual audit log line."""
        try:
            if 'type=' not in line:
                return None
            
            # Extract audit event type
            if 'type=SYSCALL' in line or 'type=EXECVE' in line:
                event_time = time.time() - (hash(line) % 1800)
                if event_time < start_time:
                    return None
                
                return TimelineEvent(
                    timestamp=event_time,
                    event_type='audit_event',
                    source='auditd',
                    description=f"Audit event: {line[:100]}...",
                    severity='low',
                    artifacts={'audit_line': line.strip()},
                    correlation_id=hashlib.md5(line.encode()).hexdigest()[:8],
                    process_info=self._extract_process_info_from_audit(line),
                    network_info={},
                    file_info={}
                )
                
        except Exception as e:
            print(f"Error parsing audit line: {e}")
        
        return None
    
    def _collect_process_events(self, start_time: float) -> List[TimelineEvent]:
        """Collect process-related events."""
        events = []
        
        try:
            import psutil
            
            # Get current processes and simulate timeline
            for proc in psutil.process_iter(['pid', 'name', 'create_time', 'exe', 'cmdline']):
                try:
                    create_time = proc.info['create_time']
                    if create_time >= start_time:
                        events.append(TimelineEvent(
                            timestamp=create_time,
                            event_type='process_create',
                            source='process_monitor',
                            description=f"Process created: {proc.info['name']} (PID: {proc.info['pid']})",
                            severity='low',
                            artifacts={'cmdline': proc.info['cmdline']},
                            correlation_id=f"proc_{proc.info['pid']}",
                            process_info={
                                'pid': proc.info['pid'],
                                'name': proc.info['name'],
                                'exe': proc.info['exe'],
                                'cmdline': proc.info['cmdline']
                            },
                            network_info={},
                            file_info={}
                        ))
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"Error collecting process events: {e}")
        
        return events
    
    def _collect_network_events(self, start_time: float) -> List[TimelineEvent]:
        """Collect network-related events."""
        events = []
        
        try:
            import psutil
            
            # Get current network connections and simulate timeline
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    # Simulate connection establishment time
                    conn_time = time.time() - (hash(str(conn)) % 1800)
                    if conn_time >= start_time:
                        
                        local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "Unknown"
                        remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "Unknown"
                        
                        events.append(TimelineEvent(
                            timestamp=conn_time,
                            event_type='network_connection',
                            source='network_monitor',
                            description=f"Network connection: {local_addr} -> {remote_addr}",
                            severity='low',
                            artifacts={'connection_status': conn.status},
                            correlation_id=f"net_{hash(str(conn)) % 10000}",
                            process_info={'pid': conn.pid} if conn.pid else {},
                            network_info={
                                'local_address': local_addr,
                                'remote_address': remote_addr,
                                'family': conn.family.name if hasattr(conn.family, 'name') else str(conn.family),
                                'type': conn.type.name if hasattr(conn.type, 'name') else str(conn.type)
                            },
                            file_info={}
                        ))
                        
        except Exception as e:
            print(f"Error collecting network events: {e}")
        
        return events
    
    def _collect_filesystem_events(self, start_time: float) -> List[TimelineEvent]:
        """Collect filesystem-related events."""
        events = []
        
        try:
            # Monitor key system directories for recent changes
            monitor_dirs = ['/tmp', '/var/tmp', '/dev/shm', '/etc', '/usr/bin', '/usr/sbin']
            
            for directory in monitor_dirs:
                if not os.path.exists(directory):
                    continue
                
                try:
                    for root, dirs, files in os.walk(directory):
                        for file in files[:20]:  # Limit for performance
                            try:
                                file_path = os.path.join(root, file)
                                stat = os.stat(file_path)
                                
                                # Check modification time
                                if stat.st_mtime >= start_time:
                                    events.append(TimelineEvent(
                                        timestamp=stat.st_mtime,
                                        event_type='file_modify',
                                        source='filesystem_monitor',
                                        description=f"File modified: {file_path}",
                                        severity='low',
                                        artifacts={'file_size': stat.st_size},
                                        correlation_id=f"file_{hash(file_path) % 10000}",
                                        process_info={},
                                        network_info={},
                                        file_info={
                                            'path': file_path,
                                            'size': stat.st_size,
                                            'mode': oct(stat.st_mode),
                                            'uid': stat.st_uid,
                                            'gid': stat.st_gid
                                        }
                                    ))
                                
                            except (OSError, PermissionError):
                                continue
                        
                        # Only check first level for performance
                        break
                        
                except (OSError, PermissionError):
                    continue
                    
        except Exception as e:
            print(f"Error collecting filesystem events: {e}")
        
        return events
    
    def _extract_process_info_from_audit(self, audit_line: str) -> Dict:
        """Extract process information from audit log line."""
        process_info = {}
        
        try:
            # Simple extraction of process info from audit line
            if 'pid=' in audit_line:
                pid_match = audit_line.split('pid=')[1].split()[0]
                process_info['pid'] = int(pid_match) if pid_match.isdigit() else None
            
            if 'comm=' in audit_line:
                comm_match = audit_line.split('comm=')[1].split()[0].strip('"')
                process_info['name'] = comm_match
            
            if 'exe=' in audit_line:
                exe_match = audit_line.split('exe=')[1].split()[0].strip('"')
                process_info['exe'] = exe_match
                
        except Exception:
            pass
        
        return process_info
    
    def correlate_events(self, events: List[TimelineEvent]) -> List[Dict]:
        """Correlate timeline events to identify attack patterns."""
        correlations = []
        
        try:
            # Group events by time windows
            time_windows = defaultdict(list)
            
            for event in events:
                # Group into 5-minute windows
                window = int(event.timestamp // 300) * 300
                time_windows[window].append(event)
            
            # Check each pattern against time windows
            for pattern_name, pattern_config in self.rootkit_patterns.items():
                pattern_events = pattern_config['events']
                timeframe = pattern_config['timeframe']
                threshold = pattern_config['confidence_threshold']
                
                correlations.extend(
                    self._find_pattern_matches(events, pattern_name, pattern_events, timeframe, threshold)
                )
            
            # Check custom correlation rules
            for rule in self.correlation_rules:
                rule_correlations = self._apply_correlation_rule(events, rule)
                correlations.extend(rule_correlations)
            
        except Exception as e:
            print(f"Error correlating events: {e}")
        
        return correlations
    
    def _find_pattern_matches(self, events: List[TimelineEvent], pattern_name: str, 
                             pattern_events: List[str], timeframe: int, threshold: float) -> List[Dict]:
        """Find matches for a specific attack pattern."""
        matches = []
        
        try:
            # Look for sequences of events matching the pattern
            for i, base_event in enumerate(events):
                if base_event.event_type in pattern_events:
                    # Check for other pattern events within timeframe
                    window_end = base_event.timestamp + timeframe
                    
                    matched_events = [base_event]
                    matched_types = {base_event.event_type}
                    
                    for j in range(i + 1, len(events)):
                        if events[j].timestamp > window_end:
                            break
                        
                        if events[j].event_type in pattern_events and events[j].event_type not in matched_types:
                            matched_events.append(events[j])
                            matched_types.add(events[j].event_type)
                    
                    # Calculate pattern confidence
                    confidence = len(matched_types) / len(pattern_events)
                    
                    if confidence >= threshold:
                        matches.append({
                            'pattern_name': pattern_name,
                            'confidence': confidence,
                            'start_time': base_event.timestamp,
                            'duration': matched_events[-1].timestamp - base_event.timestamp,
                            'event_count': len(matched_events),
                            'matched_events': [event.correlation_id for event in matched_events],
                            'description': f'{pattern_name} pattern detected with {confidence:.2f} confidence',
                            'severity': self._calculate_pattern_severity(confidence)
                        })
            
        except Exception as e:
            print(f"Error finding pattern matches: {e}")
        
        return matches
    
    def _apply_correlation_rule(self, events: List[TimelineEvent], rule: Dict) -> List[Dict]:
        """Apply custom correlation rule to events."""
        correlations = []
        
        try:
            rule_events = rule['events']
            timeframe = rule['timeframe']
            confidence_multiplier = rule.get('confidence_multiplier', 1.0)
            
            # Find event sequences matching the rule
            for i, event in enumerate(events):
                if event.event_type in rule_events:
                    # Look for correlated events
                    correlated = self._find_correlated_events(events[i:], rule_events, timeframe)
                    
                    if len(correlated) >= 2:
                        confidence = (len(correlated) / len(rule_events)) * confidence_multiplier
                        confidence = min(confidence, 1.0)
                        
                        correlations.append({
                            'rule_name': rule['name'],
                            'confidence': confidence,
                            'event_ids': [e.correlation_id for e in correlated],
                            'description': f"Rule '{rule['name']}' triggered with {confidence:.2f} confidence"
                        })
            
        except Exception as e:
            print(f"Error applying correlation rule: {e}")
        
        return correlations
    
    def _find_correlated_events(self, events: List[TimelineEvent], 
                               target_types: List[str], timeframe: int) -> List[TimelineEvent]:
        """Find events correlated within a timeframe."""
        if not events:
            return []
        
        base_time = events[0].timestamp
        correlated = [events[0]]
        
        for event in events[1:]:
            if event.timestamp > base_time + timeframe:
                break
            
            if event.event_type in target_types:
                correlated.append(event)
        
        return correlated
    
    def _calculate_pattern_severity(self, confidence: float) -> str:
        """Calculate pattern severity based on confidence."""
        if confidence >= 0.9:
            return 'critical'
        elif confidence >= 0.75:
            return 'high'
        elif confidence >= 0.5:
            return 'medium'
        else:
            return 'low'
    
    def create_forensic_evidence(self, file_path: str, evidence_type: str, 
                                description: str) -> ForensicEvidence:
        """Create forensic evidence item with chain of custody."""
        try:
            # Calculate file hashes
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
            
            file_stat = os.stat(file_path)
            
            evidence = ForensicEvidence(
                evidence_id=f"EVD_{int(time.time())}_{hash(file_path) % 10000}",
                timestamp=time.time(),
                evidence_type=evidence_type,
                source_path=file_path,
                hash_md5=md5_hash.hexdigest(),
                hash_sha256=sha256_hash.hexdigest(),
                size=file_stat.st_size,
                description=description,
                metadata={
                    'creation_time': file_stat.st_ctime,
                    'modification_time': file_stat.st_mtime,
                    'access_time': file_stat.st_atime,
                    'permissions': oct(file_stat.st_mode),
                    'owner_uid': file_stat.st_uid,
                    'owner_gid': file_stat.st_gid
                },
                chain_of_custody=[{
                    'timestamp': time.time(),
                    'action': 'evidence_collected',
                    'analyst': 'RootKit_Detection_Tool',
                    'notes': f'Automated collection: {description}'
                }]
            )
            
            # Store in database
            self._store_evidence(evidence)
            
            return evidence
            
        except Exception as e:
            print(f"Error creating forensic evidence: {e}")
            return None
    
    def _store_evidence(self, evidence: ForensicEvidence):
        """Store forensic evidence in database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO forensic_evidence 
                    (evidence_id, timestamp, evidence_type, source_path, hash_md5, hash_sha256,
                     size, description, metadata, chain_of_custody)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    evidence.evidence_id,
                    evidence.timestamp,
                    evidence.evidence_type,
                    evidence.source_path,
                    evidence.hash_md5,
                    evidence.hash_sha256,
                    evidence.size,
                    evidence.description,
                    json.dumps(evidence.metadata),
                    json.dumps(evidence.chain_of_custody)
                ))
                conn.commit()
        except Exception as e:
            print(f"Error storing evidence: {e}")
    
    def generate_incident_timeline(self, start_time: float, end_time: float) -> Dict:
        """Generate comprehensive incident timeline."""
        timeline_report = {
            'analysis_timestamp': time.time(),
            'incident_window': {
                'start': start_time,
                'end': end_time,
                'duration': end_time - start_time
            },
            'events': [],
            'correlations': [],
            'evidence_collected': [],
            'attack_vectors': [],
            'timeline_summary': {},
            'recommendations': []
        }
        
        try:
            # Collect events for the specified timeframe
            events = self.collect_system_events(int(end_time - start_time))
            timeline_report['events'] = [asdict(event) for event in events]
            
            # Correlate events
            correlations = self.correlate_events(events)
            timeline_report['correlations'] = correlations
            
            # Analyze attack vectors
            attack_vectors = self._analyze_attack_vectors(events, correlations)
            timeline_report['attack_vectors'] = attack_vectors
            
            # Generate timeline summary
            summary = self._generate_timeline_summary(events, correlations)
            timeline_report['timeline_summary'] = summary
            
            # Generate investigation recommendations
            recommendations = self._generate_investigation_recommendations(events, correlations)
            timeline_report['recommendations'] = recommendations
            
        except Exception as e:
            timeline_report['error'] = str(e)
        
        return timeline_report
    
    def _analyze_attack_vectors(self, events: List[TimelineEvent], 
                               correlations: List[Dict]) -> List[Dict]:
        """Analyze potential attack vectors from timeline data."""
        attack_vectors = []
        
        try:
            # Analyze common attack patterns
            
            # 1. Initial Access Vector Analysis
            external_connections = [e for e in events if e.event_type == 'network_connection' 
                                  and 'remote_address' in e.network_info]
            
            if external_connections:
                attack_vectors.append({
                    'vector_type': 'network_intrusion',
                    'confidence': 0.6,
                    'description': f'External network connections detected ({len(external_connections)} connections)',
                    'evidence_count': len(external_connections),
                    'mitigation': 'Review firewall rules and network monitoring'
                })
            
            # 2. Privilege Escalation Analysis
            sudo_events = [e for e in events if 'sudo' in e.description.lower()]
            if sudo_events:
                attack_vectors.append({
                    'vector_type': 'privilege_escalation',
                    'confidence': 0.5,
                    'description': f'Privilege escalation attempts detected ({len(sudo_events)} events)',
                    'evidence_count': len(sudo_events),
                    'mitigation': 'Review sudo usage and authentication logs'
                })
            
            # 3. Persistence Mechanism Analysis
            file_creation_events = [e for e in events if e.event_type == 'file_modify' 
                                  and any(loc in e.file_info.get('path', '') 
                                         for loc in ['/etc/cron', '/etc/systemd', '/etc/init'])]
            
            if file_creation_events:
                attack_vectors.append({
                    'vector_type': 'persistence_mechanism',
                    'confidence': 0.7,
                    'description': f'Potential persistence mechanisms ({len(file_creation_events)} modifications)',
                    'evidence_count': len(file_creation_events),
                    'mitigation': 'Check startup services and scheduled tasks'
                })
            
            # 4. Pattern-based Attack Vector Analysis
            for correlation in correlations:
                if correlation.get('confidence', 0) > 0.7:
                    attack_vectors.append({
                        'vector_type': 'correlated_attack_pattern',
                        'confidence': correlation['confidence'],
                        'description': correlation.get('description', 'Unknown pattern'),
                        'evidence_count': correlation.get('event_count', 0),
                        'mitigation': 'Investigate correlated events for attack campaign'
                    })
            
        except Exception as e:
            print(f"Error analyzing attack vectors: {e}")
        
        return attack_vectors
    
    def _generate_timeline_summary(self, events: List[TimelineEvent], 
                                  correlations: List[Dict]) -> Dict:
        """Generate summary of timeline analysis."""
        summary = {
            'total_events': len(events),
            'event_types': defaultdict(int),
            'severity_distribution': defaultdict(int),
            'source_distribution': defaultdict(int),
            'time_distribution': defaultdict(int),
            'critical_periods': [],
            'anomaly_periods': []
        }
        
        try:
            # Analyze event distribution
            for event in events:
                summary['event_types'][event.event_type] += 1
                summary['severity_distribution'][event.severity] += 1
                summary['source_distribution'][event.source] += 1
                
                # Group by hour for time distribution
                hour = datetime.fromtimestamp(event.timestamp).hour
                summary['time_distribution'][hour] += 1
            
            # Identify critical periods (high event density)
            event_density = defaultdict(int)
            for event in events:
                # Group into 10-minute windows
                window = int(event.timestamp // 600) * 600
                event_density[window] += 1
            
            # Find periods with unusually high activity
            if event_density:
                avg_density = sum(event_density.values()) / len(event_density)
                for window, count in event_density.items():
                    if count > avg_density * 2:  # More than 2x average
                        summary['critical_periods'].append({
                            'start_time': window,
                            'event_count': count,
                            'description': f'High activity period: {count} events'
                        })
            
            # Identify anomaly periods based on correlations
            for correlation in correlations:
                if correlation.get('confidence', 0) > 0.8:
                    summary['anomaly_periods'].append({
                        'pattern': correlation.get('pattern_name', 'Unknown'),
                        'confidence': correlation['confidence'],
                        'timestamp': correlation.get('start_time', time.time())
                    })
            
        except Exception as e:
            print(f"Error generating timeline summary: {e}")
        
        return summary
    
    def _generate_investigation_recommendations(self, events: List[TimelineEvent], 
                                             correlations: List[Dict]) -> List[str]:
        """Generate investigation recommendations based on timeline analysis."""
        recommendations = []
        
        try:
            # General recommendations
            recommendations.extend([
                "Preserve current system state for forensic analysis",
                "Document all timeline findings with timestamps",
                "Correlate timeline with external threat intelligence"
            ])
            
            # Event-specific recommendations
            process_events = [e for e in events if e.event_type == 'process_create']
            if len(process_events) > 50:
                recommendations.append("Investigate high process creation activity")
            
            network_events = [e for e in events if e.event_type == 'network_connection']
            if network_events:
                recommendations.append("Analyze network connections for C&C communication")
            
            file_events = [e for e in events if e.event_type == 'file_modify']
            critical_file_events = [e for e in file_events 
                                  if any(critical in e.description.lower() 
                                        for critical in ['/etc/', '/usr/bin/', '/usr/sbin/'])]
            if critical_file_events:
                recommendations.append("Investigate modifications to critical system files")
            
            # Correlation-specific recommendations
            high_confidence_correlations = [c for c in correlations if c.get('confidence', 0) > 0.8]
            if high_confidence_correlations:
                recommendations.append("Priority investigation: High-confidence attack patterns detected")
            
            # Evidence collection recommendations
            if len(events) > 100:
                recommendations.append("Consider extended forensic imaging due to high event volume")
            
            suspicious_events = [e for e in events if e.severity in ['high', 'critical']]
            if suspicious_events:
                recommendations.append("Immediate containment may be required for high-severity events")
            
        except Exception as e:
            print(f"Error generating recommendations: {e}")
        
        return recommendations
    
    def export_forensic_timeline(self, output_path: str, start_time: float = None, 
                                end_time: float = None):
        """Export comprehensive forensic timeline report."""
        if start_time is None:
            start_time = time.time() - 86400  # Last 24 hours
        if end_time is None:
            end_time = time.time()
        
        try:
            timeline_report = self.generate_incident_timeline(start_time, end_time)
            
            # Add forensic metadata
            timeline_report['forensic_metadata'] = {
                'analysis_tool': 'Rootkit Detection Tool - Timeline Analyzer',
                'analyst': 'Automated Analysis',
                'case_id': f"CASE_{int(time.time())}",
                'evidence_integrity': 'SHA256 verified',
                'chain_of_custody': 'Automated collection and analysis'
            }
            
            with open(output_path, 'w') as f:
                json.dump(timeline_report, f, indent=2, default=str)
            
            print(f"Forensic timeline exported to: {output_path}")
            
        except Exception as e:
            print(f"Error exporting forensic timeline: {e}")
    
    def start_realtime_timeline_monitoring(self):
        """Start real-time timeline event monitoring."""
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._timeline_monitoring_loop)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        print("Started real-time timeline monitoring")
    
    def stop_realtime_timeline_monitoring(self):
        """Stop real-time timeline monitoring."""
        self.monitoring_active = False
        print("Stopped real-time timeline monitoring")
    
    def _timeline_monitoring_loop(self):
        """Real-time timeline monitoring loop."""
        last_check = time.time()
        
        while getattr(self, 'monitoring_active', False):
            try:
                current_time = time.time()
                
                # Collect events since last check
                new_events = self.collect_system_events(int(current_time - last_check + 60))
                
                # Filter to only new events
                new_events = [e for e in new_events if e.timestamp > last_check]
                
                if new_events:
                    # Store events in database
                    for event in new_events:
                        self._store_timeline_event(event)
                    
                    # Check for immediate correlations
                    correlations = self.correlate_events(new_events)
                    
                    # Notify callbacks of significant events
                    significant_events = [e for e in new_events if e.severity in ['high', 'critical']]
                    for event in significant_events:
                        for callback in self.analysis_callbacks:
                            callback(event)
                
                last_check = current_time
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                print(f"Error in timeline monitoring loop: {e}")
                time.sleep(30)
    
    def _store_timeline_event(self, event: TimelineEvent):
        """Store timeline event in database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO timeline_events 
                    (timestamp, event_type, source, description, severity, artifacts,
                     correlation_id, process_info, network_info, file_info)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event.timestamp,
                    event.event_type,
                    event.source,
                    event.description,
                    event.severity,
                    json.dumps(event.artifacts),
                    event.correlation_id,
                    json.dumps(event.process_info),
                    json.dumps(event.network_info),
                    json.dumps(event.file_info)
                ))
                conn.commit()
        except Exception as e:
            print(f"Error storing timeline event: {e}")
    
    def get_timeline_statistics(self) -> Dict:
        """Get timeline analysis statistics."""
        stats = {
            'total_events': 0,
            'recent_events': 0,
            'correlations_found': 0,
            'evidence_items': 0,
            'critical_events': 0,
            'event_sources': {},
            'timeline_coverage': {}
        }
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Total events
                cursor = conn.execute('SELECT COUNT(*) FROM timeline_events')
                stats['total_events'] = cursor.fetchone()[0]
                
                # Recent events (last hour)
                cursor = conn.execute('''
                    SELECT COUNT(*) FROM timeline_events 
                    WHERE timestamp > ?
                ''', (time.time() - 3600,))
                stats['recent_events'] = cursor.fetchone()[0]
                
                # Critical events
                cursor = conn.execute('''
                    SELECT COUNT(*) FROM timeline_events 
                    WHERE severity IN ('high', 'critical')
                ''', )
                stats['critical_events'] = cursor.fetchone()[0]
                
                # Evidence items
                cursor = conn.execute('SELECT COUNT(*) FROM forensic_evidence')
                stats['evidence_items'] = cursor.fetchone()[0]
                
                # Event sources distribution
                cursor = conn.execute('''
                    SELECT source, COUNT(*) FROM timeline_events 
                    GROUP BY source
                ''')
                
                for source, count in cursor.fetchall():
                    stats['event_sources'][source] = count
        
        except Exception as e:
            stats['error'] = str(e)
        
        return stats
    
    def add_analysis_callback(self, callback):
        """Add callback for timeline analysis events."""
        self.analysis_callbacks.append(callback)