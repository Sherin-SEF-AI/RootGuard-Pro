"""
Database Module
SQLite database for storing historical scan results and baselines.
"""

import sqlite3
import json
import datetime
import os
from typing import List, Dict, Optional


class SecurityDatabase:
    """SQLite database manager for security scan data."""
    
    def __init__(self, db_path: str = "data/security_scans.db"):
        self.db_path = db_path
        self.ensure_database_exists()
        self.init_tables()
    
    def ensure_database_exists(self):
        """Create database directory if it doesn't exist."""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)
    
    def get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_tables(self):
        """Initialize database tables."""
        with self.get_connection() as conn:
            # Scan sessions table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    scan_type TEXT NOT NULL,
                    duration_seconds REAL,
                    total_items INTEGER,
                    suspicious_items INTEGER,
                    hidden_items INTEGER,
                    system_info TEXT
                )
            """)
            
            # Process scans table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS process_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    pid INTEGER,
                    name TEXT,
                    cmdline TEXT,
                    ppid INTEGER,
                    memory_mb REAL,
                    cpu_percent REAL,
                    hidden BOOLEAN,
                    suspicious BOOLEAN,
                    sources TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES scan_sessions (id)
                )
            """)
            
            # Service scans table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS service_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    name TEXT,
                    display_name TEXT,
                    status TEXT,
                    start_type TEXT,
                    exe_path TEXT,
                    pid INTEGER,
                    hidden BOOLEAN,
                    suspicious BOOLEAN,
                    sources TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES scan_sessions (id)
                )
            """)
            
            # Network scans table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS network_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    protocol TEXT,
                    local_ip TEXT,
                    local_port INTEGER,
                    remote_ip TEXT,
                    remote_port INTEGER,
                    state TEXT,
                    pid INTEGER,
                    process_name TEXT,
                    hidden BOOLEAN,
                    suspicious BOOLEAN,
                    country TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES scan_sessions (id)
                )
            """)
            
            # Hooks scans table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hooks_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    hook_type TEXT,
                    function_name TEXT,
                    original_address TEXT,
                    hook_address TEXT,
                    module_name TEXT,
                    suspicious BOOLEAN,
                    confidence TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES scan_sessions (id)
                )
            """)
            
            # System baselines table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS system_baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    baseline_name TEXT UNIQUE,
                    created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    process_count INTEGER,
                    service_count INTEGER,
                    connection_count INTEGER,
                    baseline_data TEXT
                )
            """)
            
            conn.commit()
    
    def create_scan_session(self, scan_type: str, system_info: Dict) -> int:
        """Create a new scan session and return its ID."""
        with self.get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO scan_sessions (scan_type, system_info)
                VALUES (?, ?)
            """, (scan_type, json.dumps(system_info)))
            
            return cursor.lastrowid
    
    def update_scan_session(self, session_id: int, duration: float, 
                           total_items: int, suspicious_items: int, hidden_items: int):
        """Update scan session with completion statistics."""
        with self.get_connection() as conn:
            conn.execute("""
                UPDATE scan_sessions 
                SET duration_seconds = ?, total_items = ?, suspicious_items = ?, hidden_items = ?
                WHERE id = ?
            """, (duration, total_items, suspicious_items, hidden_items, session_id))
    
    def store_process_scan(self, session_id: int, processes: List[Dict]):
        """Store process scan results."""
        with self.get_connection() as conn:
            for proc in processes:
                conn.execute("""
                    INSERT INTO process_scans 
                    (session_id, pid, name, cmdline, ppid, memory_mb, cpu_percent, 
                     hidden, suspicious, sources)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    session_id,
                    proc.get('pid'),
                    proc.get('name'),
                    proc.get('cmdline'),
                    proc.get('ppid'),
                    proc.get('memory_mb'),
                    proc.get('cpu_percent'),
                    proc.get('hidden', False),
                    proc.get('suspicious', False),
                    json.dumps(proc.get('sources', []))
                ))
    
    def store_service_scan(self, session_id: int, services: List[Dict]):
        """Store service scan results."""
        with self.get_connection() as conn:
            for svc in services:
                conn.execute("""
                    INSERT INTO service_scans 
                    (session_id, name, display_name, status, start_type, exe_path, 
                     pid, hidden, suspicious, sources)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    session_id,
                    svc.get('name'),
                    svc.get('display_name'),
                    svc.get('status'),
                    svc.get('start_type'),
                    svc.get('exe_path'),
                    svc.get('pid'),
                    svc.get('hidden', False),
                    svc.get('suspicious', False),
                    json.dumps(svc.get('sources', []))
                ))
    
    def store_network_scan(self, session_id: int, connections: List[Dict]):
        """Store network scan results."""
        with self.get_connection() as conn:
            for conn_data in connections:
                conn.execute("""
                    INSERT INTO network_scans 
                    (session_id, protocol, local_ip, local_port, remote_ip, remote_port,
                     state, pid, process_name, hidden, suspicious, country)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    session_id,
                    conn_data.get('protocol'),
                    conn_data.get('local_ip'),
                    conn_data.get('local_port'),
                    conn_data.get('remote_ip'),
                    conn_data.get('remote_port'),
                    conn_data.get('state'),
                    conn_data.get('pid'),
                    conn_data.get('process_name'),
                    conn_data.get('hidden', False),
                    conn_data.get('suspicious', False),
                    conn_data.get('country')
                ))
    
    def store_hooks_scan(self, session_id: int, hooks: List[Dict]):
        """Store hooks scan results."""
        with self.get_connection() as conn:
            for hook in hooks:
                conn.execute("""
                    INSERT INTO hooks_scans 
                    (session_id, hook_type, function_name, original_address, 
                     hook_address, module_name, suspicious, confidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    session_id,
                    hook.get('type'),
                    hook.get('function'),
                    hook.get('original_address'),
                    hook.get('hook_address'),
                    hook.get('module'),
                    hook.get('suspicious', False),
                    hook.get('confidence')
                ))
    
    def create_baseline(self, name: str, processes: List[Dict], 
                       services: List[Dict], connections: List[Dict]) -> bool:
        """Create a system baseline for comparison."""
        baseline_data = {
            'processes': processes,
            'services': services,
            'connections': connections,
            'created': datetime.datetime.now().isoformat()
        }
        
        try:
            with self.get_connection() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO system_baselines 
                    (baseline_name, process_count, service_count, connection_count, baseline_data)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    name,
                    len(processes),
                    len(services),
                    len(connections),
                    json.dumps(baseline_data)
                ))
                
            return True
            
        except Exception as e:
            print(f"Error creating baseline: {e}")
            return False
    
    def get_baseline(self, name: str) -> Optional[Dict]:
        """Retrieve a system baseline."""
        try:
            with self.get_connection() as conn:
                cursor = conn.execute("""
                    SELECT * FROM system_baselines WHERE baseline_name = ?
                """, (name,))
                
                row = cursor.fetchone()
                if row:
                    return {
                        'id': row['id'],
                        'name': row['baseline_name'],
                        'created_date': row['created_date'],
                        'process_count': row['process_count'],
                        'service_count': row['service_count'],
                        'connection_count': row['connection_count'],
                        'data': json.loads(row['baseline_data'])
                    }
                    
        except Exception as e:
            print(f"Error retrieving baseline: {e}")
            
        return None
    
    def compare_with_baseline(self, baseline_name: str, current_processes: List[Dict],
                             current_services: List[Dict], current_connections: List[Dict]) -> Dict:
        """Compare current scan with a baseline."""
        baseline = self.get_baseline(baseline_name)
        if not baseline:
            return {'error': 'Baseline not found'}
        
        baseline_data = baseline['data']
        
        # Compare processes
        baseline_procs = {proc['name']: proc for proc in baseline_data['processes']}
        current_procs = {proc['name']: proc for proc in current_processes}
        
        new_processes = set(current_procs.keys()) - set(baseline_procs.keys())
        removed_processes = set(baseline_procs.keys()) - set(current_procs.keys())
        
        # Compare services
        baseline_svcs = {svc['name']: svc for svc in baseline_data['services']}
        current_svcs = {svc['name']: svc for svc in current_services}
        
        new_services = set(current_svcs.keys()) - set(baseline_svcs.keys())
        removed_services = set(baseline_svcs.keys()) - set(current_svcs.keys())
        
        # Compare network connections (by process name)
        baseline_conns = {conn['process_name']: conn for conn in baseline_data['connections']}
        current_conns = {conn['process_name']: conn for conn in current_connections}
        
        new_connections = set(current_conns.keys()) - set(baseline_conns.keys())
        
        return {
            'baseline_name': baseline_name,
            'baseline_date': baseline['created_date'],
            'comparison_date': datetime.datetime.now().isoformat(),
            'changes': {
                'new_processes': list(new_processes),
                'removed_processes': list(removed_processes),
                'new_services': list(new_services),
                'removed_services': list(removed_services),
                'new_connections': list(new_connections)
            }
        }
    
    def get_scan_history(self, days: int = 30) -> List[Dict]:
        """Get scan history for the specified number of days."""
        cutoff_date = datetime.datetime.now() - datetime.timedelta(days=days)
        
        try:
            with self.get_connection() as conn:
                cursor = conn.execute("""
                    SELECT * FROM scan_sessions 
                    WHERE timestamp >= ?
                    ORDER BY timestamp DESC
                """, (cutoff_date.isoformat(),))
                
                sessions = []
                for row in cursor.fetchall():
                    sessions.append({
                        'id': row['id'],
                        'timestamp': row['timestamp'],
                        'scan_type': row['scan_type'],
                        'duration_seconds': row['duration_seconds'],
                        'total_items': row['total_items'],
                        'suspicious_items': row['suspicious_items'],
                        'hidden_items': row['hidden_items'],
                        'system_info': json.loads(row['system_info']) if row['system_info'] else {}
                    })
                
                return sessions
                
        except Exception as e:
            print(f"Error retrieving scan history: {e}")
            return []
    
    def get_trending_data(self, metric: str, days: int = 7) -> List[Dict]:
        """Get trending data for a specific metric."""
        cutoff_date = datetime.datetime.now() - datetime.timedelta(days=days)
        
        try:
            with self.get_connection() as conn:
                if metric == 'hidden_processes':
                    cursor = conn.execute("""
                        SELECT DATE(timestamp) as date, COUNT(*) as count
                        FROM process_scans 
                        WHERE hidden = 1 AND timestamp >= ?
                        GROUP BY DATE(timestamp)
                        ORDER BY date
                    """, (cutoff_date.isoformat(),))
                    
                elif metric == 'suspicious_connections':
                    cursor = conn.execute("""
                        SELECT DATE(timestamp) as date, COUNT(*) as count
                        FROM network_scans 
                        WHERE suspicious = 1 AND timestamp >= ?
                        GROUP BY DATE(timestamp)
                        ORDER BY date
                    """, (cutoff_date.isoformat(),))
                    
                elif metric == 'total_scans':
                    cursor = conn.execute("""
                        SELECT DATE(timestamp) as date, COUNT(*) as count
                        FROM scan_sessions 
                        WHERE timestamp >= ?
                        GROUP BY DATE(timestamp)
                        ORDER BY date
                    """, (cutoff_date.isoformat(),))
                else:
                    return []
                
                trends = []
                for row in cursor.fetchall():
                    trends.append({
                        'date': row['date'],
                        'count': row['count']
                    })
                
                return trends
                
        except Exception as e:
            print(f"Error retrieving trending data: {e}")
            return []
    
    def cleanup_old_data(self, days: int = 90):
        """Clean up scan data older than specified days."""
        cutoff_date = datetime.datetime.now() - datetime.timedelta(days=days)
        
        try:
            with self.get_connection() as conn:
                # Get session IDs to delete
                cursor = conn.execute("""
                    SELECT id FROM scan_sessions WHERE timestamp < ?
                """, (cutoff_date.isoformat(),))
                
                old_session_ids = [row['id'] for row in cursor.fetchall()]
                
                if old_session_ids:
                    # Delete related scan data
                    placeholders = ','.join('?' * len(old_session_ids))
                    
                    conn.execute(f"DELETE FROM process_scans WHERE session_id IN ({placeholders})", old_session_ids)
                    conn.execute(f"DELETE FROM service_scans WHERE session_id IN ({placeholders})", old_session_ids)
                    conn.execute(f"DELETE FROM network_scans WHERE session_id IN ({placeholders})", old_session_ids)
                    conn.execute(f"DELETE FROM hooks_scans WHERE session_id IN ({placeholders})", old_session_ids)
                    
                    # Delete sessions
                    conn.execute(f"DELETE FROM scan_sessions WHERE id IN ({placeholders})", old_session_ids)
                    
                    conn.commit()
                    return len(old_session_ids)
                    
        except Exception as e:
            print(f"Error cleaning up old data: {e}")
            
        return 0
    
    def get_statistics(self) -> Dict:
        """Get database statistics."""
        try:
            with self.get_connection() as conn:
                stats = {}
                
                # Total scans
                cursor = conn.execute("SELECT COUNT(*) as count FROM scan_sessions")
                stats['total_scans'] = cursor.fetchone()['count']
                
                # Total processes scanned
                cursor = conn.execute("SELECT COUNT(*) as count FROM process_scans")
                stats['total_processes_scanned'] = cursor.fetchone()['count']
                
                # Total hidden processes found
                cursor = conn.execute("SELECT COUNT(*) as count FROM process_scans WHERE hidden = 1")
                stats['total_hidden_processes'] = cursor.fetchone()['count']
                
                # Total suspicious items
                cursor = conn.execute("""
                    SELECT 
                        (SELECT COUNT(*) FROM process_scans WHERE suspicious = 1) +
                        (SELECT COUNT(*) FROM service_scans WHERE suspicious = 1) +
                        (SELECT COUNT(*) FROM network_scans WHERE suspicious = 1) +
                        (SELECT COUNT(*) FROM hooks_scans WHERE suspicious = 1) as count
                """)
                stats['total_suspicious_items'] = cursor.fetchone()['count']
                
                # Most recent scan
                cursor = conn.execute("SELECT MAX(timestamp) as last_scan FROM scan_sessions")
                result = cursor.fetchone()
                stats['last_scan'] = result['last_scan'] if result['last_scan'] else 'Never'
                
                return stats
                
        except Exception as e:
            print(f"Error retrieving statistics: {e}")
            return {'error': str(e)}
    
    def export_to_json(self, output_path: str, session_id: Optional[int] = None):
        """Export database data to JSON file."""
        try:
            with self.get_connection() as conn:
                export_data = {
                    'export_date': datetime.datetime.now().isoformat(),
                    'sessions': [],
                    'processes': [],
                    'services': [],
                    'network': [],
                    'hooks': []
                }
                
                # Export sessions
                if session_id:
                    cursor = conn.execute("SELECT * FROM scan_sessions WHERE id = ?", (session_id,))
                else:
                    cursor = conn.execute("SELECT * FROM scan_sessions ORDER BY timestamp DESC LIMIT 100")
                
                for row in cursor.fetchall():
                    export_data['sessions'].append(dict(row))
                
                # Export detailed scan data for included sessions
                session_ids = [session['id'] for session in export_data['sessions']]
                
                if session_ids:
                    placeholders = ','.join('?' * len(session_ids))
                    
                    # Export processes
                    cursor = conn.execute(f"SELECT * FROM process_scans WHERE session_id IN ({placeholders})", session_ids)
                    for row in cursor.fetchall():
                        export_data['processes'].append(dict(row))
                    
                    # Export services
                    cursor = conn.execute(f"SELECT * FROM service_scans WHERE session_id IN ({placeholders})", session_ids)
                    for row in cursor.fetchall():
                        export_data['services'].append(dict(row))
                    
                    # Export network
                    cursor = conn.execute(f"SELECT * FROM network_scans WHERE session_id IN ({placeholders})", session_ids)
                    for row in cursor.fetchall():
                        export_data['network'].append(dict(row))
                    
                    # Export hooks
                    cursor = conn.execute(f"SELECT * FROM hooks_scans WHERE session_id IN ({placeholders})", session_ids)
                    for row in cursor.fetchall():
                        export_data['hooks'].append(dict(row))
                
                # Write to file
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2, default=str)
                
                return True
                
        except Exception as e:
            print(f"Error exporting to JSON: {e}")
            return False