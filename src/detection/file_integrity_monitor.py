"""
File Integrity Monitor (FIM)
Monitors critical system files for unauthorized modifications that could indicate rootkit activity.
"""

import os
import hashlib
import sqlite3
import json
import time
import threading
import inotify_simple
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

@dataclass
class FileBaseline:
    """Baseline information for a monitored file."""
    path: str
    size: int
    mtime: float
    permissions: str
    sha256_hash: str
    inode: int
    owner_uid: int
    owner_gid: int
    baseline_timestamp: float

@dataclass
class FileIntegrityAlert:
    """File integrity violation alert."""
    timestamp: float
    file_path: str
    alert_type: str
    old_value: str
    new_value: str
    severity: str
    description: str

class FileIntegrityMonitor:
    """Advanced file integrity monitoring system."""
    
    def __init__(self, db_path: str = "fim_database.db"):
        self.db_path = db_path
        self.monitoring_active = False
        self.monitor_thread = None
        self.watched_paths = set()
        self.baseline_db = {}
        self.alert_callbacks = []
        self.inotify = None
        
        # Critical system paths to monitor
        self.critical_paths = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/group',
            '/etc/hosts',
            '/etc/resolv.conf',
            '/etc/crontab',
            '/etc/sudoers',
            '/etc/ssh/sshd_config',
            '/etc/systemd/system',
            '/etc/init.d',
            '/boot',
            '/lib/modules',
            '/usr/bin',
            '/usr/sbin',
            '/bin',
            '/sbin'
        ]
        
        # Executable file extensions to monitor
        self.executable_extensions = {'.so', '.bin', '.exe', '.dll'}
        
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for baselines."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS file_baselines (
                    path TEXT PRIMARY KEY,
                    size INTEGER,
                    mtime REAL,
                    permissions TEXT,
                    sha256_hash TEXT,
                    inode INTEGER,
                    owner_uid INTEGER,
                    owner_gid INTEGER,
                    baseline_timestamp REAL
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS integrity_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    file_path TEXT,
                    alert_type TEXT,
                    old_value TEXT,
                    new_value TEXT,
                    severity TEXT,
                    description TEXT
                )
            ''')
            
            conn.commit()
    
    def add_path_to_monitor(self, path: str):
        """Add a path to the monitoring list."""
        if os.path.exists(path):
            self.watched_paths.add(os.path.abspath(path))
    
    def remove_path_from_monitor(self, path: str):
        """Remove a path from monitoring."""
        abs_path = os.path.abspath(path)
        self.watched_paths.discard(abs_path)
    
    def create_baseline(self, specific_paths: List[str] = None) -> bool:
        """Create integrity baseline for monitored files."""
        try:
            paths_to_baseline = specific_paths or list(self.watched_paths)
            if not paths_to_baseline:
                paths_to_baseline = self.critical_paths
            
            baselines_created = 0
            
            with sqlite3.connect(self.db_path) as conn:
                for path in paths_to_baseline:
                    if os.path.isdir(path):
                        # Recursively baseline directory contents
                        for root, dirs, files in os.walk(path):
                            for file in files:
                                file_path = os.path.join(root, file)
                                if self._should_monitor_file(file_path):
                                    if self._create_file_baseline(conn, file_path):
                                        baselines_created += 1
                    elif os.path.isfile(path):
                        if self._create_file_baseline(conn, path):
                            baselines_created += 1
                
                conn.commit()
            
            print(f"Created {baselines_created} file baselines")
            return True
            
        except Exception as e:
            print(f"Error creating baseline: {e}")
            return False
    
    def _create_file_baseline(self, conn, file_path: str) -> bool:
        """Create baseline for a single file."""
        try:
            if not os.path.exists(file_path):
                return False
            
            stat = os.stat(file_path)
            file_hash = self._calculate_file_hash(file_path)
            
            if not file_hash:
                return False
            
            baseline = FileBaseline(
                path=file_path,
                size=stat.st_size,
                mtime=stat.st_mtime,
                permissions=oct(stat.st_mode)[-3:],
                sha256_hash=file_hash,
                inode=stat.st_ino,
                owner_uid=stat.st_uid,
                owner_gid=stat.st_gid,
                baseline_timestamp=time.time()
            )
            
            conn.execute('''
                INSERT OR REPLACE INTO file_baselines 
                (path, size, mtime, permissions, sha256_hash, inode, owner_uid, owner_gid, baseline_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                baseline.path, baseline.size, baseline.mtime, baseline.permissions,
                baseline.sha256_hash, baseline.inode, baseline.owner_uid, 
                baseline.owner_gid, baseline.baseline_timestamp
            ))
            
            return True
            
        except Exception as e:
            print(f"Error creating baseline for {file_path}: {e}")
            return False
    
    def _should_monitor_file(self, file_path: str) -> bool:
        """Determine if file should be monitored."""
        # Skip very large files (>100MB) for performance
        try:
            if os.path.getsize(file_path) > 100 * 1024 * 1024:
                return False
        except OSError:
            return False
        
        # Monitor executables and critical config files
        file_ext = Path(file_path).suffix.lower()
        if file_ext in self.executable_extensions:
            return True
        
        # Monitor files in critical directories
        for critical_path in self.critical_paths:
            if file_path.startswith(critical_path):
                return True
        
        return False
    
    def _calculate_file_hash(self, file_path: str) -> Optional[str]:
        """Calculate SHA256 hash of file."""
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None
    
    def check_file_integrity(self, file_path: str) -> List[FileIntegrityAlert]:
        """Check integrity of a specific file against baseline."""
        alerts = []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'SELECT * FROM file_baselines WHERE path = ?', (file_path,)
                )
                baseline_row = cursor.fetchone()
                
                if not baseline_row:
                    return alerts  # No baseline exists
                
                # Reconstruct baseline
                baseline = FileBaseline(
                    path=baseline_row[0],
                    size=baseline_row[1],
                    mtime=baseline_row[2],
                    permissions=baseline_row[3],
                    sha256_hash=baseline_row[4],
                    inode=baseline_row[5],
                    owner_uid=baseline_row[6],
                    owner_gid=baseline_row[7],
                    baseline_timestamp=baseline_row[8]
                )
                
                if not os.path.exists(file_path):
                    # File was deleted
                    alert = FileIntegrityAlert(
                        timestamp=time.time(),
                        file_path=file_path,
                        alert_type="file_deleted",
                        old_value="exists",
                        new_value="deleted",
                        severity="high",
                        description=f"Critical file {file_path} has been deleted"
                    )
                    alerts.append(alert)
                    return alerts
                
                # Check current file properties
                current_stat = os.stat(file_path)
                current_hash = self._calculate_file_hash(file_path)
                
                # Check size changes
                if current_stat.st_size != baseline.size:
                    alert = FileIntegrityAlert(
                        timestamp=time.time(),
                        file_path=file_path,
                        alert_type="size_changed",
                        old_value=str(baseline.size),
                        new_value=str(current_stat.st_size),
                        severity="medium",
                        description=f"File size changed from {baseline.size} to {current_stat.st_size} bytes"
                    )
                    alerts.append(alert)
                
                # Check modification time
                if abs(current_stat.st_mtime - baseline.mtime) > 1:  # 1 second tolerance
                    alert = FileIntegrityAlert(
                        timestamp=time.time(),
                        file_path=file_path,
                        alert_type="mtime_changed",
                        old_value=datetime.fromtimestamp(baseline.mtime).isoformat(),
                        new_value=datetime.fromtimestamp(current_stat.st_mtime).isoformat(),
                        severity="low",
                        description="File modification time changed"
                    )
                    alerts.append(alert)
                
                # Check permissions
                current_perms = oct(current_stat.st_mode)[-3:]
                if current_perms != baseline.permissions:
                    alert = FileIntegrityAlert(
                        timestamp=time.time(),
                        file_path=file_path,
                        alert_type="permissions_changed",
                        old_value=baseline.permissions,
                        new_value=current_perms,
                        severity="high",
                        description=f"File permissions changed from {baseline.permissions} to {current_perms}"
                    )
                    alerts.append(alert)
                
                # Check ownership
                if (current_stat.st_uid != baseline.owner_uid or 
                    current_stat.st_gid != baseline.owner_gid):
                    alert = FileIntegrityAlert(
                        timestamp=time.time(),
                        file_path=file_path,
                        alert_type="ownership_changed",
                        old_value=f"{baseline.owner_uid}:{baseline.owner_gid}",
                        new_value=f"{current_stat.st_uid}:{current_stat.st_gid}",
                        severity="high",
                        description="File ownership changed"
                    )
                    alerts.append(alert)
                
                # Check content hash
                if current_hash and current_hash != baseline.sha256_hash:
                    alert = FileIntegrityAlert(
                        timestamp=time.time(),
                        file_path=file_path,
                        alert_type="content_changed",
                        old_value=baseline.sha256_hash[:16] + "...",
                        new_value=current_hash[:16] + "...",
                        severity="critical",
                        description="File content has been modified"
                    )
                    alerts.append(alert)
                
                # Store alerts in database
                for alert in alerts:
                    self._store_alert(conn, alert)
                
        except Exception as e:
            print(f"Error checking integrity for {file_path}: {e}")
        
        return alerts
    
    def _store_alert(self, conn, alert: FileIntegrityAlert):
        """Store alert in database."""
        conn.execute('''
            INSERT INTO integrity_alerts 
            (timestamp, file_path, alert_type, old_value, new_value, severity, description)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.timestamp, alert.file_path, alert.alert_type,
            alert.old_value, alert.new_value, alert.severity, alert.description
        ))
    
    def bulk_integrity_check(self, max_files: int = 1000) -> Dict:
        """Perform bulk integrity check on all baseline files."""
        results = {
            'scan_timestamp': time.time(),
            'files_checked': 0,
            'alerts_generated': 0,
            'alerts': [],
            'summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('SELECT path FROM file_baselines LIMIT ?', (max_files,))
                baseline_paths = [row[0] for row in cursor.fetchall()]
                
                for file_path in baseline_paths:
                    alerts = self.check_file_integrity(file_path)
                    results['files_checked'] += 1
                    results['alerts_generated'] += len(alerts)
                    
                    for alert in alerts:
                        alert_dict = asdict(alert)
                        results['alerts'].append(alert_dict)
                        results['summary'][alert.severity] += 1
                        
                        # Notify callbacks
                        for callback in self.alert_callbacks:
                            callback(alert_dict)
        
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def start_realtime_monitoring(self):
        """Start real-time file monitoring using inotify."""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_realtime_monitoring(self):
        """Stop real-time monitoring."""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        if self.inotify:
            self.inotify.close()
    
    def _monitor_loop(self):
        """Real-time monitoring loop using inotify."""
        try:
            self.inotify = inotify_simple.INotify()
            watch_descriptors = {}
            
            # Add watches for critical directories
            for path in self.critical_paths:
                if os.path.isdir(path):
                    try:
                        wd = self.inotify.add_watch(
                            path, 
                            inotify_simple.flags.MODIFY | 
                            inotify_simple.flags.ATTRIB |
                            inotify_simple.flags.DELETE |
                            inotify_simple.flags.CREATE
                        )
                        watch_descriptors[wd] = path
                    except OSError:
                        continue
            
            while self.monitoring_active:
                try:
                    # Check for events with timeout
                    events = self.inotify.read(timeout=5000)  # 5 second timeout
                    
                    for event in events:
                        file_path = os.path.join(watch_descriptors[event.wd], event.name)
                        
                        if self._should_monitor_file(file_path):
                            # File was modified, check integrity
                            alerts = self.check_file_integrity(file_path)
                            
                            for alert in alerts:
                                alert_dict = asdict(alert)
                                for callback in self.alert_callbacks:
                                    callback(alert_dict)
                                    
                except Exception as e:
                    print(f"Error in monitoring loop: {e}")
                    time.sleep(5)
                    
        except Exception as e:
            print(f"Error setting up real-time monitoring: {e}")
    
    def add_alert_callback(self, callback):
        """Add callback for integrity alerts."""
        self.alert_callbacks.append(callback)
    
    def get_recent_alerts(self, hours: int = 24) -> List[Dict]:
        """Get recent integrity alerts."""
        cutoff_time = time.time() - (hours * 3600)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT timestamp, file_path, alert_type, old_value, new_value, severity, description
                    FROM integrity_alerts 
                    WHERE timestamp > ?
                    ORDER BY timestamp DESC
                ''', (cutoff_time,))
                
                alerts = []
                for row in cursor.fetchall():
                    alerts.append({
                        'timestamp': row[0],
                        'file_path': row[1],
                        'alert_type': row[2],
                        'old_value': row[3],
                        'new_value': row[4],
                        'severity': row[5],
                        'description': row[6],
                        'formatted_time': datetime.fromtimestamp(row[0]).strftime('%Y-%m-%d %H:%M:%S')
                    })
                
                return alerts
                
        except Exception as e:
            print(f"Error retrieving alerts: {e}")
            return []
    
    def get_integrity_summary(self) -> Dict:
        """Get summary of file integrity status."""
        summary = {
            'total_baselines': 0,
            'recent_alerts': 0,
            'severity_breakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'most_changed_files': [],
            'monitoring_status': 'active' if self.monitoring_active else 'inactive'
        }
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Count total baselines
                cursor = conn.execute('SELECT COUNT(*) FROM file_baselines')
                summary['total_baselines'] = cursor.fetchone()[0]
                
                # Count recent alerts (last 24 hours)
                cutoff_time = time.time() - 86400
                cursor = conn.execute(
                    'SELECT COUNT(*) FROM integrity_alerts WHERE timestamp > ?', 
                    (cutoff_time,)
                )
                summary['recent_alerts'] = cursor.fetchone()[0]
                
                # Severity breakdown
                cursor = conn.execute('''
                    SELECT severity, COUNT(*) FROM integrity_alerts 
                    WHERE timestamp > ? 
                    GROUP BY severity
                ''', (cutoff_time,))
                
                for severity, count in cursor.fetchall():
                    if severity in summary['severity_breakdown']:
                        summary['severity_breakdown'][severity] = count
                
                # Most frequently changed files
                cursor = conn.execute('''
                    SELECT file_path, COUNT(*) as change_count 
                    FROM integrity_alerts 
                    WHERE timestamp > ?
                    GROUP BY file_path 
                    ORDER BY change_count DESC 
                    LIMIT 10
                ''', (cutoff_time,))
                
                summary['most_changed_files'] = [
                    {'path': path, 'changes': count} 
                    for path, count in cursor.fetchall()
                ]
                
        except Exception as e:
            summary['error'] = str(e)
        
        return summary
    
    def detect_suspicious_file_activities(self) -> List[Dict]:
        """Detect suspicious file-based activities."""
        suspicious_activities = []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Look for rapid successive changes to critical files
                cursor = conn.execute('''
                    SELECT file_path, COUNT(*) as change_count, MIN(timestamp) as first_change
                    FROM integrity_alerts 
                    WHERE timestamp > ? AND severity IN ('critical', 'high')
                    GROUP BY file_path
                    HAVING change_count >= 3
                ''', (time.time() - 3600,))  # Last hour
                
                for path, count, first_change in cursor.fetchall():
                    suspicious_activities.append({
                        'type': 'rapid_file_modifications',
                        'file_path': path,
                        'change_count': count,
                        'time_span': time.time() - first_change,
                        'severity': 'high',
                        'description': f'File {path} modified {count} times in short period'
                    })
                
                # Look for modifications to critical system files
                critical_file_patterns = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
                
                for pattern in critical_file_patterns:
                    cursor = conn.execute('''
                        SELECT file_path, alert_type, timestamp 
                        FROM integrity_alerts 
                        WHERE file_path LIKE ? AND timestamp > ?
                    ''', (f'%{pattern}%', time.time() - 86400))
                    
                    for path, alert_type, timestamp in cursor.fetchall():
                        suspicious_activities.append({
                            'type': 'critical_system_file_modified',
                            'file_path': path,
                            'modification_type': alert_type,
                            'timestamp': timestamp,
                            'severity': 'critical',
                            'description': f'Critical system file {path} was modified'
                        })
                
                # Look for new executable files in suspicious locations
                suspicious_dirs = ['/tmp', '/dev/shm', '/var/tmp']
                current_time = time.time()
                
                for sus_dir in suspicious_dirs:
                    if os.path.exists(sus_dir):
                        for root, dirs, files in os.walk(sus_dir):
                            for file in files:
                                file_path = os.path.join(root, file)
                                try:
                                    stat = os.stat(file_path)
                                    # Check if file is recently created and executable
                                    if (current_time - stat.st_ctime < 3600 and  # Created in last hour
                                        stat.st_mode & 0o111):  # Has execute permissions
                                        
                                        suspicious_activities.append({
                                            'type': 'suspicious_executable_created',
                                            'file_path': file_path,
                                            'creation_time': stat.st_ctime,
                                            'permissions': oct(stat.st_mode)[-3:],
                                            'severity': 'medium',
                                            'description': f'New executable file in suspicious location: {file_path}'
                                        })
                                except OSError:
                                    continue
                
        except Exception as e:
            print(f"Error detecting suspicious activities: {e}")
        
        return suspicious_activities
    
    def export_integrity_report(self, output_path: str, include_baselines: bool = False):
        """Export comprehensive integrity report."""
        report_data = {
            'generation_time': datetime.now().isoformat(),
            'summary': self.get_integrity_summary(),
            'recent_alerts': self.get_recent_alerts(24),
            'suspicious_activities': self.detect_suspicious_file_activities()
        }
        
        if include_baselines:
            report_data['baselines'] = self._get_all_baselines()
        
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
    
    def _get_all_baselines(self) -> List[Dict]:
        """Get all file baselines."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('SELECT * FROM file_baselines')
                baselines = []
                
                for row in cursor.fetchall():
                    baselines.append({
                        'path': row[0],
                        'size': row[1],
                        'mtime': row[2],
                        'permissions': row[3],
                        'sha256_hash': row[4],
                        'inode': row[5],
                        'owner_uid': row[6],
                        'owner_gid': row[7],
                        'baseline_timestamp': row[8]
                    })
                
                return baselines
                
        except Exception as e:
            print(f"Error retrieving baselines: {e}")
            return []
    
    def verify_critical_system_integrity(self) -> Dict:
        """Perform comprehensive check of critical system components."""
        verification_results = {
            'timestamp': time.time(),
            'kernel_integrity': self._check_kernel_integrity(),
            'bootloader_integrity': self._check_bootloader_integrity(),
            'system_libraries': self._check_system_libraries(),
            'configuration_files': self._check_critical_configs(),
            'package_integrity': self._check_package_integrity()
        }
        
        return verification_results
    
    def _check_kernel_integrity(self) -> Dict:
        """Check Linux kernel integrity."""
        result = {'status': 'unknown', 'details': []}
        
        try:
            # Check kernel version consistency
            with open('/proc/version', 'r') as f:
                proc_version = f.read().strip()
            
            result['proc_version'] = proc_version
            result['status'] = 'ok'
            
            # Check for unusual kernel modules
            with open('/proc/modules', 'r') as f:
                modules = f.readlines()
            
            suspicious_modules = []
            for line in modules:
                module_name = line.split()[0]
                if any(sus in module_name.lower() for sus in ['rootkit', 'hidden', 'stealth']):
                    suspicious_modules.append(module_name)
            
            if suspicious_modules:
                result['suspicious_modules'] = suspicious_modules
                result['status'] = 'suspicious'
            
        except Exception as e:
            result['error'] = str(e)
            result['status'] = 'error'
        
        return result
    
    def _check_bootloader_integrity(self) -> Dict:
        """Check bootloader integrity."""
        result = {'status': 'unknown', 'details': []}
        
        try:
            # Check common bootloader files
            bootloader_files = ['/boot/grub/grub.cfg', '/boot/grub2/grub.cfg']
            
            for bootloader_file in bootloader_files:
                if os.path.exists(bootloader_file):
                    stat = os.stat(bootloader_file)
                    result['details'].append({
                        'file': bootloader_file,
                        'size': stat.st_size,
                        'mtime': stat.st_mtime,
                        'exists': True
                    })
            
            result['status'] = 'ok'
            
        except Exception as e:
            result['error'] = str(e)
            result['status'] = 'error'
        
        return result
    
    def _check_system_libraries(self) -> Dict:
        """Check critical system libraries."""
        result = {'status': 'ok', 'libraries': []}
        
        critical_libs = [
            '/lib/x86_64-linux-gnu/libc.so.6',
            '/lib/x86_64-linux-gnu/libdl.so.2',
            '/lib/x86_64-linux-gnu/libpthread.so.0',
            '/lib/x86_64-linux-gnu/libm.so.6'
        ]
        
        try:
            for lib_path in critical_libs:
                if os.path.exists(lib_path):
                    stat = os.stat(lib_path)
                    lib_info = {
                        'path': lib_path,
                        'size': stat.st_size,
                        'mtime': stat.st_mtime,
                        'exists': True,
                        'suspicious': stat.st_size < 10000  # Suspiciously small
                    }
                    
                    if lib_info['suspicious']:
                        result['status'] = 'suspicious'
                    
                    result['libraries'].append(lib_info)
                else:
                    result['libraries'].append({
                        'path': lib_path,
                        'exists': False,
                        'suspicious': True
                    })
                    result['status'] = 'suspicious'
                    
        except Exception as e:
            result['error'] = str(e)
            result['status'] = 'error'
        
        return result
    
    def _check_critical_configs(self) -> Dict:
        """Check critical configuration files."""
        result = {'status': 'ok', 'configs': []}
        
        critical_configs = [
            '/etc/passwd', '/etc/shadow', '/etc/group',
            '/etc/sudoers', '/etc/ssh/sshd_config'
        ]
        
        try:
            for config_path in critical_configs:
                if os.path.exists(config_path):
                    alerts = self.check_file_integrity(config_path)
                    config_info = {
                        'path': config_path,
                        'alert_count': len(alerts),
                        'last_alerts': [asdict(alert) for alert in alerts[-3:]]  # Last 3 alerts
                    }
                    
                    if alerts:
                        result['status'] = 'alerts'
                    
                    result['configs'].append(config_info)
                    
        except Exception as e:
            result['error'] = str(e)
            result['status'] = 'error'
        
        return result
    
    def _check_package_integrity(self) -> Dict:
        """Check package manager integrity."""
        result = {'status': 'unknown', 'details': {}}
        
        try:
            # Check if dpkg database exists (Debian/Ubuntu)
            if os.path.exists('/var/lib/dpkg/status'):
                result['package_manager'] = 'dpkg'
                stat = os.stat('/var/lib/dpkg/status')
                result['details']['dpkg_status_size'] = stat.st_size
                result['status'] = 'ok'
            
            # Check if rpm database exists (Red Hat/CentOS)
            elif os.path.exists('/var/lib/rpm'):
                result['package_manager'] = 'rpm'
                result['status'] = 'ok'
            
            # Check for package integrity using dpkg if available
            try:
                import subprocess
                result_proc = subprocess.run(['dpkg', '--verify'], 
                                          capture_output=True, text=True, timeout=30)
                if result_proc.returncode == 0:
                    if result_proc.stdout.strip():
                        result['verification_issues'] = result_proc.stdout.strip()
                        result['status'] = 'issues_found'
                    else:
                        result['verification_status'] = 'all_packages_verified'
                        
            except (subprocess.TimeoutExpired, FileNotFoundError):
                result['verification_status'] = 'verification_unavailable'
                
        except Exception as e:
            result['error'] = str(e)
            result['status'] = 'error'
        
        return result
    
    def cleanup_old_data(self, days: int = 30):
        """Clean up old alerts and baselines."""
        cutoff_time = time.time() - (days * 86400)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Remove old alerts
                cursor = conn.execute(
                    'DELETE FROM integrity_alerts WHERE timestamp < ?', 
                    (cutoff_time,)
                )
                alerts_removed = cursor.rowcount
                
                conn.commit()
                print(f"Cleaned up {alerts_removed} old alerts")
                
        except Exception as e:
            print(f"Error cleaning up old data: {e}")