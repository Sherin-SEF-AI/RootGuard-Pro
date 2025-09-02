"""
Rootkit Signature Database
Comprehensive database of known rootkit signatures, IOCs, and detection patterns.
"""

import os
import json
import hashlib
import sqlite3
import requests
import threading
import time
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

@dataclass
class RootkitSignature:
    """Rootkit signature information."""
    id: str
    name: str
    family: str
    signature_type: str  # 'hash', 'pattern', 'behavior', 'network'
    signature_data: str
    description: str
    severity: str
    platform: str
    created_date: str
    updated_date: str
    source: str

@dataclass
class IOCIndicator:
    """Indicator of Compromise."""
    ioc_type: str  # 'ip', 'domain', 'hash', 'filename', 'registry'
    value: str
    description: str
    severity: str
    first_seen: str
    last_seen: str
    source: str

class SignatureDatabase:
    """Rootkit signature and IOC database management."""
    
    def __init__(self, db_path: str = "signatures.db"):
        self.db_path = db_path
        self.signatures = {}
        self.iocs = {}
        self.update_thread = None
        self.last_update = None
        
        # Built-in rootkit signatures
        self.builtin_signatures = [
            RootkitSignature(
                id="linux_rootkit_001",
                name="Adore-ng",
                family="Adore",
                signature_type="pattern",
                signature_data=r"adore.*\.ko",
                description="Adore-ng loadable kernel module rootkit",
                severity="high",
                platform="linux",
                created_date="2024-01-01",
                updated_date="2024-01-01",
                source="builtin"
            ),
            RootkitSignature(
                id="linux_rootkit_002",
                name="Diamorphine",
                family="Diamorphine",
                signature_type="pattern",
                signature_data=r"diamorphine.*\.ko",
                description="Diamorphine LKM rootkit for Linux",
                severity="high",
                platform="linux",
                created_date="2024-01-01",
                updated_date="2024-01-01",
                source="builtin"
            ),
            RootkitSignature(
                id="linux_rootkit_003",
                name="Reptile",
                family="Reptile",
                signature_type="pattern",
                signature_data=r"reptile.*\.ko",
                description="Reptile LKM rootkit with userland tools",
                severity="critical",
                platform="linux",
                created_date="2024-01-01",
                updated_date="2024-01-01",
                source="builtin"
            ),
            RootkitSignature(
                id="linux_rootkit_004",
                name="Umbreon",
                family="Umbreon",
                signature_type="hash",
                signature_data="a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
                description="Umbreon userland rootkit for Linux",
                severity="high",
                platform="linux",
                created_date="2024-01-01",
                updated_date="2024-01-01",
                source="builtin"
            )
        ]
        
        # Built-in IOCs
        self.builtin_iocs = [
            IOCIndicator(
                ioc_type="filename",
                value="/tmp/.X11-unix/.X1-lock",
                description="Common rootkit hiding location",
                severity="medium",
                first_seen="2024-01-01",
                last_seen="2024-01-01",
                source="builtin"
            ),
            IOCIndicator(
                ioc_type="filename",
                value="/dev/shm/.hidden",
                description="Shared memory rootkit persistence",
                severity="high",
                first_seen="2024-01-01",
                last_seen="2024-01-01",
                source="builtin"
            ),
            IOCIndicator(
                ioc_type="ip",
                value="192.0.2.100",
                description="Known C&C server IP",
                severity="critical",
                first_seen="2024-01-01",
                last_seen="2024-01-01",
                source="builtin"
            )
        ]
        
        self._init_database()
        self._load_builtin_signatures()
    
    def _init_database(self):
        """Initialize signature database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS signatures (
                    id TEXT PRIMARY KEY,
                    name TEXT,
                    family TEXT,
                    signature_type TEXT,
                    signature_data TEXT,
                    description TEXT,
                    severity TEXT,
                    platform TEXT,
                    created_date TEXT,
                    updated_date TEXT,
                    source TEXT
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type TEXT,
                    value TEXT,
                    description TEXT,
                    severity TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    source TEXT,
                    UNIQUE(ioc_type, value)
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    signature_id TEXT,
                    target_path TEXT,
                    target_pid INTEGER,
                    detection_method TEXT,
                    confidence REAL,
                    details TEXT
                )
            ''')
            
            conn.commit()
    
    def _load_builtin_signatures(self):
        """Load built-in signatures into database."""
        with sqlite3.connect(self.db_path) as conn:
            for sig in self.builtin_signatures:
                conn.execute('''
                    INSERT OR REPLACE INTO signatures 
                    (id, name, family, signature_type, signature_data, description, 
                     severity, platform, created_date, updated_date, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    sig.id, sig.name, sig.family, sig.signature_type, sig.signature_data,
                    sig.description, sig.severity, sig.platform, sig.created_date,
                    sig.updated_date, sig.source
                ))
            
            for ioc in self.builtin_iocs:
                conn.execute('''
                    INSERT OR REPLACE INTO iocs 
                    (ioc_type, value, description, severity, first_seen, last_seen, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ioc.ioc_type, ioc.value, ioc.description, ioc.severity,
                    ioc.first_seen, ioc.last_seen, ioc.source
                ))
            
            conn.commit()
    
    def scan_file_signatures(self, file_path: str) -> List[Dict]:
        """Scan file against known rootkit signatures."""
        detections = []
        
        try:
            if not os.path.exists(file_path):
                return detections
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            if not file_hash:
                return detections
            
            # Check hash signatures
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT * FROM signatures 
                    WHERE signature_type = 'hash' AND signature_data = ?
                ''', (file_hash,))
                
                for row in cursor.fetchall():
                    detection = {
                        'signature_id': row[0],
                        'signature_name': row[1],
                        'family': row[2],
                        'file_path': file_path,
                        'detection_method': 'hash_match',
                        'confidence': 1.0,
                        'severity': row[6],
                        'description': row[5]
                    }
                    detections.append(detection)
                    self._record_detection(detection)
            
            # Check pattern signatures
            if file_path.endswith(('.ko', '.so', '.bin')):
                pattern_detections = self._scan_pattern_signatures(file_path)
                detections.extend(pattern_detections)
            
        except Exception as e:
            print(f"Error scanning file signatures: {e}")
        
        return detections
    
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
    
    def _scan_pattern_signatures(self, file_path: str) -> List[Dict]:
        """Scan file for pattern-based signatures."""
        detections = []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('SELECT * FROM signatures WHERE signature_type = "pattern"')
                pattern_signatures = cursor.fetchall()
            
            filename = os.path.basename(file_path)
            
            for sig_row in pattern_signatures:
                import re
                pattern = sig_row[4]  # signature_data
                
                try:
                    if re.search(pattern, filename, re.IGNORECASE):
                        detection = {
                            'signature_id': sig_row[0],
                            'signature_name': sig_row[1],
                            'family': sig_row[2],
                            'file_path': file_path,
                            'detection_method': 'pattern_match',
                            'confidence': 0.8,
                            'severity': sig_row[6],
                            'description': sig_row[5],
                            'matched_pattern': pattern
                        }
                        detections.append(detection)
                        self._record_detection(detection)
                        
                except re.error:
                    continue
                    
        except Exception as e:
            print(f"Error scanning pattern signatures: {e}")
        
        return detections
    
    def scan_process_signatures(self, pid: int, process_name: str, cmdline: str) -> List[Dict]:
        """Scan process against behavioral signatures."""
        detections = []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('SELECT * FROM signatures WHERE signature_type = "behavior"')
                behavior_signatures = cursor.fetchall()
            
            for sig_row in behavior_signatures:
                pattern = sig_row[4]  # signature_data
                
                # Check process name and command line
                target_text = f"{process_name} {cmdline}".lower()
                
                try:
                    import re
                    if re.search(pattern, target_text, re.IGNORECASE):
                        detection = {
                            'signature_id': sig_row[0],
                            'signature_name': sig_row[1],
                            'family': sig_row[2],
                            'target_pid': pid,
                            'detection_method': 'behavior_match',
                            'confidence': 0.7,
                            'severity': sig_row[6],
                            'description': sig_row[5],
                            'matched_pattern': pattern
                        }
                        detections.append(detection)
                        self._record_detection(detection)
                        
                except re.error:
                    continue
                    
        except Exception as e:
            print(f"Error scanning process signatures: {e}")
        
        return detections
    
    def scan_network_signatures(self, remote_ip: str, remote_port: int, process_name: str) -> List[Dict]:
        """Scan network connections against IOC database."""
        detections = []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Check IP IOCs
                cursor = conn.execute('''
                    SELECT * FROM iocs WHERE ioc_type = 'ip' AND value = ?
                ''', (remote_ip,))
                
                for row in cursor.fetchall():
                    detection = {
                        'ioc_type': row[1],
                        'ioc_value': row[2],
                        'description': row[3],
                        'severity': row[4],
                        'process_name': process_name,
                        'remote_endpoint': f"{remote_ip}:{remote_port}",
                        'detection_method': 'ioc_match'
                    }
                    detections.append(detection)
                
                # Check domain IOCs (if we have domain resolution)
                # This would require reverse DNS lookup in a real implementation
                
        except Exception as e:
            print(f"Error scanning network signatures: {e}")
        
        return detections
    
    def _record_detection(self, detection: Dict):
        """Record detection in database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO detections 
                    (timestamp, signature_id, target_path, target_pid, detection_method, confidence, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    time.time(),
                    detection.get('signature_id', ''),
                    detection.get('file_path', ''),
                    detection.get('target_pid', 0),
                    detection.get('detection_method', ''),
                    detection.get('confidence', 0.0),
                    json.dumps(detection)
                ))
                conn.commit()
        except Exception as e:
            print(f"Error recording detection: {e}")
    
    def add_custom_signature(self, signature: RootkitSignature) -> bool:
        """Add custom signature to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO signatures 
                    (id, name, family, signature_type, signature_data, description, 
                     severity, platform, created_date, updated_date, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    signature.id, signature.name, signature.family, signature.signature_type,
                    signature.signature_data, signature.description, signature.severity,
                    signature.platform, signature.created_date, signature.updated_date,
                    signature.source
                ))
                conn.commit()
            return True
        except Exception as e:
            print(f"Error adding signature: {e}")
            return False
    
    def add_custom_ioc(self, ioc: IOCIndicator) -> bool:
        """Add custom IOC to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO iocs 
                    (ioc_type, value, description, severity, first_seen, last_seen, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ioc.ioc_type, ioc.value, ioc.description, ioc.severity,
                    ioc.first_seen, ioc.last_seen, ioc.source
                ))
                conn.commit()
            return True
        except Exception as e:
            print(f"Error adding IOC: {e}")
            return False
    
    def bulk_scan_filesystem(self, scan_paths: List[str] = None) -> Dict:
        """Perform bulk filesystem scan against signature database."""
        if scan_paths is None:
            scan_paths = ['/usr/bin', '/usr/sbin', '/bin', '/sbin', '/lib/modules']
        
        scan_results = {
            'scan_timestamp': time.time(),
            'paths_scanned': scan_paths,
            'files_scanned': 0,
            'detections': [],
            'summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        try:
            for scan_path in scan_paths:
                if os.path.isdir(scan_path):
                    for root, dirs, files in os.walk(scan_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            
                            # Limit scan for performance
                            if scan_results['files_scanned'] > 1000:
                                break
                                
                            try:
                                detections = self.scan_file_signatures(file_path)
                                scan_results['files_scanned'] += 1
                                
                                for detection in detections:
                                    scan_results['detections'].append(detection)
                                    severity = detection.get('severity', 'low')
                                    if severity in scan_results['summary']:
                                        scan_results['summary'][severity] += 1
                                        
                            except Exception:
                                continue
                                
                elif os.path.isfile(scan_path):
                    detections = self.scan_file_signatures(scan_path)
                    scan_results['files_scanned'] += 1
                    scan_results['detections'].extend(detections)
                    
        except Exception as e:
            scan_results['error'] = str(e)
        
        return scan_results
    
    def update_signatures_from_feeds(self) -> bool:
        """Update signatures from threat intelligence feeds."""
        try:
            # This would typically connect to threat intelligence feeds
            # For demonstration, we'll simulate some updates
            
            updated_signatures = [
                {
                    'id': 'feed_001',
                    'name': 'Kovter',
                    'family': 'Kovter',
                    'signature_type': 'hash',
                    'signature_data': 'b2d4f6e8c1a3579024681357924680135792468013579246801357924680135',
                    'description': 'Kovter fileless malware hash',
                    'severity': 'high',
                    'platform': 'linux',
                    'source': 'threat_feed'
                }
            ]
            
            updated_iocs = [
                {
                    'ioc_type': 'domain',
                    'value': 'malicious-c2.example.com',
                    'description': 'Known C&C domain',
                    'severity': 'high',
                    'source': 'threat_feed'
                }
            ]
            
            # Add to database
            current_date = datetime.now().isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                for sig_data in updated_signatures:
                    sig_data['created_date'] = current_date
                    sig_data['updated_date'] = current_date
                    
                    conn.execute('''
                        INSERT OR REPLACE INTO signatures 
                        (id, name, family, signature_type, signature_data, description, 
                         severity, platform, created_date, updated_date, source)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', tuple(sig_data.values()))
                
                for ioc_data in updated_iocs:
                    ioc_data['first_seen'] = current_date
                    ioc_data['last_seen'] = current_date
                    
                    conn.execute('''
                        INSERT OR REPLACE INTO iocs 
                        (ioc_type, value, description, severity, first_seen, last_seen, source)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        ioc_data['ioc_type'], ioc_data['value'], ioc_data['description'],
                        ioc_data['severity'], ioc_data['first_seen'], ioc_data['last_seen'],
                        ioc_data['source']
                    ))
                
                conn.commit()
            
            self.last_update = datetime.now()
            return True
            
        except Exception as e:
            print(f"Error updating signatures: {e}")
            return False
    
    def get_signature_stats(self) -> Dict:
        """Get signature database statistics."""
        stats = {
            'total_signatures': 0,
            'signature_types': {},
            'severity_breakdown': {},
            'platform_breakdown': {},
            'total_iocs': 0,
            'ioc_types': {},
            'recent_detections': 0,
            'last_update': self.last_update.isoformat() if self.last_update else 'Never'
        }
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Signature statistics
                cursor = conn.execute('SELECT COUNT(*) FROM signatures')
                stats['total_signatures'] = cursor.fetchone()[0]
                
                cursor = conn.execute('SELECT signature_type, COUNT(*) FROM signatures GROUP BY signature_type')
                for sig_type, count in cursor.fetchall():
                    stats['signature_types'][sig_type] = count
                
                cursor = conn.execute('SELECT severity, COUNT(*) FROM signatures GROUP BY severity')
                for severity, count in cursor.fetchall():
                    stats['severity_breakdown'][severity] = count
                
                cursor = conn.execute('SELECT platform, COUNT(*) FROM signatures GROUP BY platform')
                for platform, count in cursor.fetchall():
                    stats['platform_breakdown'][platform] = count
                
                # IOC statistics
                cursor = conn.execute('SELECT COUNT(*) FROM iocs')
                stats['total_iocs'] = cursor.fetchone()[0]
                
                cursor = conn.execute('SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type')
                for ioc_type, count in cursor.fetchall():
                    stats['ioc_types'][ioc_type] = count
                
                # Recent detections (last 24 hours)
                cutoff_time = time.time() - 86400
                cursor = conn.execute('SELECT COUNT(*) FROM detections WHERE timestamp > ?', (cutoff_time,))
                stats['recent_detections'] = cursor.fetchone()[0]
                
        except Exception as e:
            stats['error'] = str(e)
        
        return stats
    
    def search_signatures(self, query: str, signature_type: str = None) -> List[Dict]:
        """Search signatures by name, family, or description."""
        results = []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                sql = '''
                    SELECT * FROM signatures 
                    WHERE (name LIKE ? OR family LIKE ? OR description LIKE ?)
                '''
                params = [f'%{query}%', f'%{query}%', f'%{query}%']
                
                if signature_type:
                    sql += ' AND signature_type = ?'
                    params.append(signature_type)
                
                cursor = conn.execute(sql, params)
                
                for row in cursor.fetchall():
                    results.append({
                        'id': row[0],
                        'name': row[1],
                        'family': row[2],
                        'signature_type': row[3],
                        'signature_data': row[4],
                        'description': row[5],
                        'severity': row[6],
                        'platform': row[7],
                        'created_date': row[8],
                        'updated_date': row[9],
                        'source': row[10]
                    })
                    
        except Exception as e:
            print(f"Error searching signatures: {e}")
        
        return results
    
    def get_recent_detections(self, hours: int = 24) -> List[Dict]:
        """Get recent detections from database."""
        cutoff_time = time.time() - (hours * 3600)
        detections = []
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT d.timestamp, d.signature_id, d.target_path, d.target_pid, 
                           d.detection_method, d.confidence, d.details, s.name, s.severity
                    FROM detections d
                    LEFT JOIN signatures s ON d.signature_id = s.id
                    WHERE d.timestamp > ?
                    ORDER BY d.timestamp DESC
                ''', (cutoff_time,))
                
                for row in cursor.fetchall():
                    detections.append({
                        'timestamp': row[0],
                        'signature_id': row[1],
                        'target_path': row[2],
                        'target_pid': row[3],
                        'detection_method': row[4],
                        'confidence': row[5],
                        'details': row[6],
                        'signature_name': row[7],
                        'severity': row[8],
                        'formatted_time': datetime.fromtimestamp(row[0]).strftime('%Y-%m-%d %H:%M:%S')
                    })
                    
        except Exception as e:
            print(f"Error getting recent detections: {e}")
        
        return detections
    
    def comprehensive_system_scan(self) -> Dict:
        """Perform comprehensive system scan using all signatures."""
        scan_results = {
            'scan_timestamp': time.time(),
            'filesystem_scan': {},
            'process_scan': {},
            'network_scan': {},
            'total_detections': 0,
            'high_confidence_detections': 0
        }
        
        try:
            # Filesystem scan
            print("Scanning filesystem...")
            scan_results['filesystem_scan'] = self.bulk_scan_filesystem()
            
            # Process scan
            print("Scanning processes...")
            process_detections = []
            
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    detections = self.scan_process_signatures(
                        proc.info['pid'],
                        proc.info['name'],
                        ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                    )
                    process_detections.extend(detections)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            scan_results['process_scan'] = {
                'detections': process_detections,
                'processes_scanned': len(list(psutil.process_iter()))
            }
            
            # Network scan
            print("Scanning network connections...")
            network_detections = []
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    connections = proc.connections()
                    for conn in connections:
                        if hasattr(conn, 'raddr') and conn.raddr:
                            detections = self.scan_network_signatures(
                                conn.raddr.ip,
                                conn.raddr.port,
                                proc.info['name']
                            )
                            network_detections.extend(detections)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            scan_results['network_scan'] = {
                'detections': network_detections,
                'connections_scanned': len(network_detections)
            }
            
            # Calculate totals
            all_detections = (
                scan_results['filesystem_scan'].get('detections', []) +
                scan_results['process_scan'].get('detections', []) +
                scan_results['network_scan'].get('detections', [])
            )
            
            scan_results['total_detections'] = len(all_detections)
            scan_results['high_confidence_detections'] = len([
                d for d in all_detections if d.get('confidence', 0) > 0.8
            ])
            
        except Exception as e:
            scan_results['error'] = str(e)
        
        return scan_results
    
    def get_signature_by_id(self, signature_id: str) -> Optional[Dict]:
        """Get signature details by ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('SELECT * FROM signatures WHERE id = ?', (signature_id,))
                row = cursor.fetchone()
                
                if row:
                    return {
                        'id': row[0],
                        'name': row[1],
                        'family': row[2],
                        'signature_type': row[3],
                        'signature_data': row[4],
                        'description': row[5],
                        'severity': row[6],
                        'platform': row[7],
                        'created_date': row[8],
                        'updated_date': row[9],
                        'source': row[10]
                    }
        except Exception as e:
            print(f"Error getting signature: {e}")
        
        return None
    
    def export_signatures(self, output_path: str):
        """Export signature database to JSON file."""
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'database_stats': self.get_signature_stats(),
            'signatures': [],
            'iocs': []
        }
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Export signatures
                cursor = conn.execute('SELECT * FROM signatures')
                for row in cursor.fetchall():
                    export_data['signatures'].append({
                        'id': row[0],
                        'name': row[1],
                        'family': row[2],
                        'signature_type': row[3],
                        'signature_data': row[4],
                        'description': row[5],
                        'severity': row[6],
                        'platform': row[7],
                        'created_date': row[8],
                        'updated_date': row[9],
                        'source': row[10]
                    })
                
                # Export IOCs
                cursor = conn.execute('SELECT * FROM iocs')
                for row in cursor.fetchall():
                    export_data['iocs'].append({
                        'id': row[0],
                        'ioc_type': row[1],
                        'value': row[2],
                        'description': row[3],
                        'severity': row[4],
                        'first_seen': row[5],
                        'last_seen': row[6],
                        'source': row[7]
                    })
            
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error exporting signatures: {e}")
            return False
    
    def import_signatures(self, import_path: str) -> bool:
        """Import signatures from JSON file."""
        try:
            with open(import_path, 'r') as f:
                import_data = json.load(f)
            
            with sqlite3.connect(self.db_path) as conn:
                # Import signatures
                for sig_data in import_data.get('signatures', []):
                    conn.execute('''
                        INSERT OR REPLACE INTO signatures 
                        (id, name, family, signature_type, signature_data, description, 
                         severity, platform, created_date, updated_date, source)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        sig_data['id'], sig_data['name'], sig_data['family'],
                        sig_data['signature_type'], sig_data['signature_data'],
                        sig_data['description'], sig_data['severity'], sig_data['platform'],
                        sig_data['created_date'], sig_data['updated_date'], sig_data['source']
                    ))
                
                # Import IOCs
                for ioc_data in import_data.get('iocs', []):
                    conn.execute('''
                        INSERT OR REPLACE INTO iocs 
                        (ioc_type, value, description, severity, first_seen, last_seen, source)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        ioc_data['ioc_type'], ioc_data['value'], ioc_data['description'],
                        ioc_data['severity'], ioc_data['first_seen'], ioc_data['last_seen'],
                        ioc_data['source']
                    ))
                
                conn.commit()
            
            return True
            
        except Exception as e:
            print(f"Error importing signatures: {e}")
            return False
    
    def cleanup_old_detections(self, days: int = 30):
        """Clean up old detection records."""
        cutoff_time = time.time() - (days * 86400)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'DELETE FROM detections WHERE timestamp < ?', 
                    (cutoff_time,)
                )
                deleted_count = cursor.rowcount
                conn.commit()
                print(f"Cleaned up {deleted_count} old detection records")
                
        except Exception as e:
            print(f"Error cleaning up detections: {e}")