"""
Threat Intelligence Feeds Integration
Integration with threat intelligence sources for enhanced rootkit detection.
"""

import os
import json
import time
import threading
import requests
import hashlib
import sqlite3
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import subprocess
import urllib.parse

@dataclass
class ThreatIndicator:
    """Threat intelligence indicator."""
    indicator_id: str
    indicator_type: str  # hash, ip, domain, url, filename
    value: str
    confidence: float
    severity: str
    source: str
    first_seen: float
    last_seen: float
    description: str
    tags: List[str]
    metadata: Dict

@dataclass
class ThreatMatch:
    """Match between system artifact and threat indicator."""
    match_id: str
    timestamp: float
    indicator: ThreatIndicator
    matched_artifact: str
    artifact_type: str
    confidence: float
    context: Dict
    recommended_actions: List[str]

class ThreatIntelligenceFeeds:
    """Threat intelligence feeds management and integration."""
    
    def __init__(self, db_path: str = "threat_intelligence.db"):
        self.db_path = db_path
        self.indicators = {}
        self.feed_sources = {}
        self.update_callbacks = []
        self.match_callbacks = []
        
        # Configure threat intelligence sources
        self.configure_default_feeds()
        
        self._init_database()
        self._load_cached_indicators()
    
    def configure_default_feeds(self):
        """Configure default threat intelligence feeds."""
        self.feed_sources = {
            'alienvault_otx': {
                'url': 'https://otx.alienvault.com/api/v1/indicators/export',
                'api_key_required': True,
                'update_interval': 3600,  # 1 hour
                'enabled': False,  # Requires API key
                'indicator_types': ['hash', 'ip', 'domain']
            },
            'abuse_ch_malware': {
                'url': 'https://malware.abuse.ch/downloads/malware-samples/',
                'api_key_required': False,
                'update_interval': 7200,  # 2 hours
                'enabled': True,
                'indicator_types': ['hash']
            },
            'emergingthreats': {
                'url': 'https://rules.emergingthreats.net/open/',
                'api_key_required': False,
                'update_interval': 3600,
                'enabled': True,
                'indicator_types': ['ip', 'domain']
            },
            'local_indicators': {
                'url': 'file://local_indicators.json',
                'api_key_required': False,
                'update_interval': 300,  # 5 minutes
                'enabled': True,
                'indicator_types': ['hash', 'ip', 'domain', 'filename']
            }
        }
        
        # Built-in threat indicators for common rootkits
        self.builtin_indicators = [
            {
                'type': 'hash',
                'value': 'd41d8cd98f00b204e9800998ecf8427e',  # Example MD5
                'confidence': 0.9,
                'severity': 'high',
                'description': 'Known rootkit sample hash',
                'tags': ['rootkit', 'malware']
            },
            {
                'type': 'filename',
                'value': 'hide.ko',
                'confidence': 0.8,
                'severity': 'high',
                'description': 'Common rootkit module filename',
                'tags': ['rootkit', 'kernel_module']
            },
            {
                'type': 'domain',
                'value': 'malicious-c2.example.com',
                'confidence': 0.95,
                'severity': 'critical',
                'description': 'Known C&C domain for rootkit family',
                'tags': ['c2', 'rootkit', 'command_control']
            },
            {
                'type': 'ip',
                'value': '192.168.1.100',
                'confidence': 0.7,
                'severity': 'medium',
                'description': 'Suspicious IP associated with rootkit activity',
                'tags': ['suspicious_ip', 'rootkit']
            }
        ]
    
    def _init_database(self):
        """Initialize threat intelligence database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    indicator_id TEXT PRIMARY KEY,
                    indicator_type TEXT,
                    value TEXT,
                    confidence REAL,
                    severity TEXT,
                    source TEXT,
                    first_seen REAL,
                    last_seen REAL,
                    description TEXT,
                    tags TEXT,
                    metadata TEXT
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS threat_matches (
                    match_id TEXT PRIMARY KEY,
                    timestamp REAL,
                    indicator_id TEXT,
                    matched_artifact TEXT,
                    artifact_type TEXT,
                    confidence REAL,
                    context TEXT,
                    actions TEXT,
                    FOREIGN KEY (indicator_id) REFERENCES threat_indicators (indicator_id)
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS feed_updates (
                    feed_name TEXT PRIMARY KEY,
                    last_update REAL,
                    indicators_added INTEGER,
                    indicators_updated INTEGER,
                    update_status TEXT,
                    error_message TEXT
                )
            ''')
            
            conn.commit()
    
    def _load_cached_indicators(self):
        """Load cached threat indicators from database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('SELECT * FROM threat_indicators')
                
                for row in cursor.fetchall():
                    indicator = ThreatIndicator(
                        indicator_id=row[0],
                        indicator_type=row[1],
                        value=row[2],
                        confidence=row[3],
                        severity=row[4],
                        source=row[5],
                        first_seen=row[6],
                        last_seen=row[7],
                        description=row[8],
                        tags=json.loads(row[9]) if row[9] else [],
                        metadata=json.loads(row[10]) if row[10] else {}
                    )
                    
                    self.indicators[indicator.indicator_id] = indicator
            
            print(f"Loaded {len(self.indicators)} threat indicators from cache")
            
        except Exception as e:
            print(f"Error loading cached indicators: {e}")
    
    def load_builtin_indicators(self):
        """Load built-in threat indicators."""
        try:
            for builtin in self.builtin_indicators:
                indicator_id = hashlib.md5(f"{builtin['type']}{builtin['value']}".encode()).hexdigest()
                
                indicator = ThreatIndicator(
                    indicator_id=indicator_id,
                    indicator_type=builtin['type'],
                    value=builtin['value'],
                    confidence=builtin['confidence'],
                    severity=builtin['severity'],
                    source='builtin',
                    first_seen=time.time(),
                    last_seen=time.time(),
                    description=builtin['description'],
                    tags=builtin['tags'],
                    metadata={}
                )
                
                self.indicators[indicator_id] = indicator
                self._store_indicator(indicator)
            
            print(f"Loaded {len(self.builtin_indicators)} built-in threat indicators")
            
        except Exception as e:
            print(f"Error loading built-in indicators: {e}")
    
    def update_threat_feeds(self, feed_names: List[str] = None) -> Dict:
        """Update threat intelligence feeds."""
        update_results = {
            'timestamp': time.time(),
            'feeds_updated': 0,
            'indicators_added': 0,
            'indicators_updated': 0,
            'errors': []
        }
        
        try:
            feeds_to_update = feed_names or list(self.feed_sources.keys())
            
            for feed_name in feeds_to_update:
                if feed_name not in self.feed_sources:
                    continue
                
                feed_config = self.feed_sources[feed_name]
                if not feed_config.get('enabled', False):
                    continue
                
                try:
                    feed_results = self._update_single_feed(feed_name, feed_config)
                    
                    update_results['feeds_updated'] += 1
                    update_results['indicators_added'] += feed_results.get('added', 0)
                    update_results['indicators_updated'] += feed_results.get('updated', 0)
                    
                except Exception as e:
                    update_results['errors'].append({
                        'feed': feed_name,
                        'error': str(e)
                    })
            
            # Load built-in indicators if this is first run
            if update_results['feeds_updated'] == 0:
                self.load_builtin_indicators()
                update_results['indicators_added'] = len(self.builtin_indicators)
            
        except Exception as e:
            update_results['error'] = str(e)
        
        return update_results
    
    def _update_single_feed(self, feed_name: str, feed_config: Dict) -> Dict:
        """Update a single threat intelligence feed."""
        feed_results = {
            'added': 0,
            'updated': 0,
            'errors': []
        }
        
        try:
            url = feed_config['url']
            
            if url.startswith('file://'):
                # Local file feed
                file_path = url[7:]  # Remove 'file://' prefix
                indicators = self._load_local_feed(file_path)
            else:
                # Remote feed
                indicators = self._fetch_remote_feed(url, feed_config)
            
            # Process indicators
            for indicator_data in indicators:
                try:
                    indicator = self._create_indicator_from_data(indicator_data, feed_name)
                    
                    if indicator.indicator_id in self.indicators:
                        # Update existing indicator
                        existing = self.indicators[indicator.indicator_id]
                        existing.last_seen = indicator.last_seen
                        existing.confidence = max(existing.confidence, indicator.confidence)
                        self._store_indicator(existing)
                        feed_results['updated'] += 1
                    else:
                        # Add new indicator
                        self.indicators[indicator.indicator_id] = indicator
                        self._store_indicator(indicator)
                        feed_results['added'] += 1
                        
                except Exception as e:
                    feed_results['errors'].append(str(e))
            
            # Update feed status
            self._update_feed_status(feed_name, feed_results)
            
        except Exception as e:
            feed_results['errors'].append(str(e))
        
        return feed_results
    
    def _load_local_feed(self, file_path: str) -> List[Dict]:
        """Load indicators from local file."""
        indicators = []
        
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    
                if isinstance(data, list):
                    indicators = data
                elif isinstance(data, dict) and 'indicators' in data:
                    indicators = data['indicators']
            else:
                # Create sample local indicators file
                sample_indicators = [
                    {
                        'type': 'hash',
                        'value': hashlib.md5(b'suspicious_binary').hexdigest(),
                        'confidence': 0.8,
                        'severity': 'medium',
                        'description': 'Local suspicious binary hash'
                    }
                ]
                
                with open(file_path, 'w') as f:
                    json.dump({'indicators': sample_indicators}, f, indent=2)
                
                indicators = sample_indicators
                
        except Exception as e:
            print(f"Error loading local feed: {e}")
        
        return indicators
    
    def _fetch_remote_feed(self, url: str, feed_config: Dict) -> List[Dict]:
        """Fetch indicators from remote threat intelligence feed."""
        indicators = []
        
        try:
            # For demonstration, simulate remote feed data
            # In production, would make actual HTTP requests to threat feeds
            
            simulated_indicators = [
                {
                    'type': 'hash',
                    'value': hashlib.sha256(b'rootkit_sample_1').hexdigest(),
                    'confidence': 0.95,
                    'severity': 'high',
                    'description': 'Known rootkit sample from threat feed'
                },
                {
                    'type': 'ip',
                    'value': '10.0.0.100',
                    'confidence': 0.8,
                    'severity': 'medium',
                    'description': 'Suspicious IP from threat intelligence'
                },
                {
                    'type': 'domain',
                    'value': 'evil-rootkit.malware.test',
                    'confidence': 0.9,
                    'severity': 'high',
                    'description': 'C&C domain for rootkit family'
                }
            ]
            
            indicators = simulated_indicators
            
        except Exception as e:
            print(f"Error fetching remote feed: {e}")
        
        return indicators
    
    def _create_indicator_from_data(self, data: Dict, source: str) -> ThreatIndicator:
        """Create ThreatIndicator from feed data."""
        indicator_id = hashlib.md5(f"{data.get('type', 'unknown')}{data.get('value', '')}".encode()).hexdigest()
        
        return ThreatIndicator(
            indicator_id=indicator_id,
            indicator_type=data.get('type', 'unknown'),
            value=data.get('value', ''),
            confidence=data.get('confidence', 0.5),
            severity=data.get('severity', 'medium'),
            source=source,
            first_seen=data.get('first_seen', time.time()),
            last_seen=time.time(),
            description=data.get('description', ''),
            tags=data.get('tags', []),
            metadata=data.get('metadata', {})
        )
    
    def _store_indicator(self, indicator: ThreatIndicator):
        """Store threat indicator in database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO threat_indicators 
                    (indicator_id, indicator_type, value, confidence, severity, source,
                     first_seen, last_seen, description, tags, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    indicator.indicator_id,
                    indicator.indicator_type,
                    indicator.value,
                    indicator.confidence,
                    indicator.severity,
                    indicator.source,
                    indicator.first_seen,
                    indicator.last_seen,
                    indicator.description,
                    json.dumps(indicator.tags),
                    json.dumps(indicator.metadata)
                ))
                conn.commit()
        except Exception as e:
            print(f"Error storing indicator: {e}")
    
    def _update_feed_status(self, feed_name: str, results: Dict):
        """Update feed status in database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO feed_updates 
                    (feed_name, last_update, indicators_added, indicators_updated, update_status, error_message)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    feed_name,
                    time.time(),
                    results.get('added', 0),
                    results.get('updated', 0),
                    'success' if not results.get('errors') else 'partial',
                    json.dumps(results.get('errors', []))
                ))
                conn.commit()
        except Exception as e:
            print(f"Error updating feed status: {e}")
    
    def check_system_against_indicators(self) -> List[ThreatMatch]:
        """Check current system state against threat indicators."""
        matches = []
        
        try:
            # Check file hashes
            file_matches = self._check_file_hashes()
            matches.extend(file_matches)
            
            # Check network connections
            network_matches = self._check_network_indicators()
            matches.extend(network_matches)
            
            # Check running processes
            process_matches = self._check_process_indicators()
            matches.extend(process_matches)
            
            # Check filesystem artifacts
            file_artifact_matches = self._check_file_artifacts()
            matches.extend(file_artifact_matches)
            
            # Store matches in database
            for match in matches:
                self._store_threat_match(match)
            
        except Exception as e:
            print(f"Error checking system against indicators: {e}")
        
        return matches
    
    def _check_file_hashes(self) -> List[ThreatMatch]:
        """Check file hashes against threat indicators."""
        matches = []
        
        try:
            # Get hash-type indicators
            hash_indicators = [ind for ind in self.indicators.values() 
                             if ind.indicator_type in ['hash', 'md5', 'sha1', 'sha256']]
            
            if not hash_indicators:
                return matches
            
            # Check suspicious directories for files
            suspicious_dirs = ['/tmp', '/var/tmp', '/dev/shm', '/usr/bin', '/usr/sbin']
            
            for directory in suspicious_dirs:
                if not os.path.exists(directory):
                    continue
                
                try:
                    for file in os.listdir(directory)[:20]:  # Limit for performance
                        file_path = os.path.join(directory, file)
                        
                        if os.path.isfile(file_path):
                            try:
                                file_hash = self._calculate_file_hash(file_path)
                                
                                # Check against indicators
                                for indicator in hash_indicators:
                                    if file_hash.lower() == indicator.value.lower():
                                        match = ThreatMatch(
                                            match_id=f"hash_{int(time.time())}_{hash(file_path) % 1000}",
                                            timestamp=time.time(),
                                            indicator=indicator,
                                            matched_artifact=file_path,
                                            artifact_type='file_hash',
                                            confidence=indicator.confidence,
                                            context={
                                                'file_path': file_path,
                                                'file_size': os.path.getsize(file_path),
                                                'hash_algorithm': 'md5'
                                            },
                                            recommended_actions=[
                                                'Quarantine the file immediately',
                                                'Analyze file for malware',
                                                'Check for related files',
                                                'Review system logs for file activity'
                                            ]
                                        )
                                        matches.append(match)
                                        
                            except (OSError, PermissionError):
                                continue
                                
                except (OSError, PermissionError):
                    continue
                    
        except Exception as e:
            print(f"Error checking file hashes: {e}")
        
        return matches
    
    def _check_network_indicators(self) -> List[ThreatMatch]:
        """Check network connections against threat indicators."""
        matches = []
        
        try:
            import psutil
            
            # Get network-type indicators
            network_indicators = [ind for ind in self.indicators.values() 
                                if ind.indicator_type in ['ip', 'domain', 'url']]
            
            if not network_indicators:
                return matches
            
            # Check current network connections
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.raddr:  # Has remote address
                    remote_ip = conn.raddr.ip
                    
                    # Check against IP indicators
                    for indicator in network_indicators:
                        if indicator.indicator_type == 'ip' and indicator.value == remote_ip:
                            match = ThreatMatch(
                                match_id=f"net_{int(time.time())}_{hash(str(conn)) % 1000}",
                                timestamp=time.time(),
                                indicator=indicator,
                                matched_artifact=remote_ip,
                                artifact_type='network_connection',
                                confidence=indicator.confidence,
                                context={
                                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "Unknown",
                                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                                    'connection_status': conn.status,
                                    'process_id': conn.pid
                                },
                                recommended_actions=[
                                    'Block IP address at firewall',
                                    'Investigate process making connection',
                                    'Check for data exfiltration',
                                    'Monitor for additional connections'
                                ]
                            )
                            matches.append(match)
                            
        except Exception as e:
            print(f"Error checking network indicators: {e}")
        
        return matches
    
    def _check_process_indicators(self) -> List[ThreatMatch]:
        """Check running processes against threat indicators."""
        matches = []
        
        try:
            import psutil
            
            # Get filename-type indicators
            filename_indicators = [ind for ind in self.indicators.values() 
                                 if ind.indicator_type in ['filename', 'process_name']]
            
            if not filename_indicators:
                return matches
            
            # Check running processes
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                try:
                    process_name = proc.info['name']
                    exe_path = proc.info['exe']
                    
                    # Check process name and executable path
                    for indicator in filename_indicators:
                        if (indicator.value.lower() in process_name.lower() or
                            (exe_path and indicator.value.lower() in exe_path.lower())):
                            
                            match = ThreatMatch(
                                match_id=f"proc_{int(time.time())}_{proc.info['pid']}",
                                timestamp=time.time(),
                                indicator=indicator,
                                matched_artifact=process_name,
                                artifact_type='process_name',
                                confidence=indicator.confidence * 0.9,  # Slightly lower for name matches
                                context={
                                    'pid': proc.info['pid'],
                                    'process_name': process_name,
                                    'executable_path': exe_path,
                                    'command_line': proc.info['cmdline']
                                },
                                recommended_actions=[
                                    'Terminate suspicious process',
                                    'Analyze process executable',
                                    'Check process memory for injected code',
                                    'Review process parent/child relationships'
                                ]
                            )
                            matches.append(match)
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"Error checking process indicators: {e}")
        
        return matches
    
    def _check_file_artifacts(self) -> List[ThreatMatch]:
        """Check filesystem artifacts against threat indicators."""
        matches = []
        
        try:
            # Get filename indicators
            filename_indicators = [ind for ind in self.indicators.values() 
                                 if ind.indicator_type == 'filename']
            
            if not filename_indicators:
                return matches
            
            # Check common rootkit locations
            search_dirs = ['/tmp', '/var/tmp', '/dev/shm', '/lib/modules', '/etc']
            
            for directory in search_dirs:
                if not os.path.exists(directory):
                    continue
                
                try:
                    for file in os.listdir(directory)[:50]:  # Limit for performance
                        file_path = os.path.join(directory, file)
                        
                        for indicator in filename_indicators:
                            if indicator.value.lower() in file.lower():
                                match = ThreatMatch(
                                    match_id=f"file_{int(time.time())}_{hash(file_path) % 1000}",
                                    timestamp=time.time(),
                                    indicator=indicator,
                                    matched_artifact=file_path,
                                    artifact_type='filename',
                                    confidence=indicator.confidence,
                                    context={
                                        'file_path': file_path,
                                        'directory': directory,
                                        'file_size': os.path.getsize(file_path) if os.path.isfile(file_path) else 0
                                    },
                                    recommended_actions=[
                                        'Quarantine suspicious file',
                                        'Analyze file contents',
                                        'Check file permissions and ownership',
                                        'Search for related files'
                                    ]
                                )
                                matches.append(match)
                                
                except (OSError, PermissionError):
                    continue
                    
        except Exception as e:
            print(f"Error checking file artifacts: {e}")
        
        return matches
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate MD5 hash of file."""
        try:
            hasher = hashlib.md5()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ''
    
    def _store_threat_match(self, match: ThreatMatch):
        """Store threat match in database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO threat_matches 
                    (match_id, timestamp, indicator_id, matched_artifact, artifact_type,
                     confidence, context, actions)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    match.match_id,
                    match.timestamp,
                    match.indicator.indicator_id,
                    match.matched_artifact,
                    match.artifact_type,
                    match.confidence,
                    json.dumps(match.context),
                    json.dumps(match.recommended_actions)
                ))
                conn.commit()
        except Exception as e:
            print(f"Error storing threat match: {e}")
    
    def enrich_detection_with_threat_intel(self, detection_data: Dict) -> Dict:
        """Enrich detection results with threat intelligence."""
        enriched_data = detection_data.copy()
        enriched_data['threat_intel'] = {
            'matches_found': 0,
            'indicators_matched': [],
            'confidence_boost': 0.0,
            'severity_escalation': False,
            'intelligence_sources': []
        }
        
        try:
            # Check various detection artifacts against indicators
            artifacts_to_check = []
            
            # File hashes
            if 'file_hash' in detection_data:
                artifacts_to_check.append(('hash', detection_data['file_hash']))
            
            # Process names
            if 'process_name' in detection_data:
                artifacts_to_check.append(('filename', detection_data['process_name']))
            
            # Network addresses
            if 'remote_ip' in detection_data:
                artifacts_to_check.append(('ip', detection_data['remote_ip']))
            
            if 'domain' in detection_data:
                artifacts_to_check.append(('domain', detection_data['domain']))
            
            # Check artifacts against indicators
            for artifact_type, artifact_value in artifacts_to_check:
                matching_indicators = [
                    ind for ind in self.indicators.values()
                    if ind.indicator_type == artifact_type and ind.value.lower() == artifact_value.lower()
                ]
                
                for indicator in matching_indicators:
                    enriched_data['threat_intel']['matches_found'] += 1
                    enriched_data['threat_intel']['indicators_matched'].append({
                        'indicator_id': indicator.indicator_id,
                        'type': indicator.indicator_type,
                        'value': indicator.value,
                        'confidence': indicator.confidence,
                        'severity': indicator.severity,
                        'source': indicator.source,
                        'description': indicator.description
                    })
                    
                    # Boost confidence based on threat intel
                    confidence_boost = indicator.confidence * 0.3
                    enriched_data['threat_intel']['confidence_boost'] += confidence_boost
                    
                    # Check for severity escalation
                    if indicator.severity in ['high', 'critical']:
                        enriched_data['threat_intel']['severity_escalation'] = True
                    
                    enriched_data['threat_intel']['intelligence_sources'].append(indicator.source)
            
            # Apply threat intelligence enhancements
            if enriched_data['threat_intel']['matches_found'] > 0:
                # Boost original confidence
                original_confidence = detection_data.get('confidence', 0.5)
                boost = enriched_data['threat_intel']['confidence_boost']
                enriched_data['confidence'] = min(original_confidence + boost, 1.0)
                
                # Escalate severity if needed
                if enriched_data['threat_intel']['severity_escalation']:
                    severity_map = {'low': 'medium', 'medium': 'high', 'high': 'critical'}
                    current_severity = detection_data.get('severity', 'low')
                    if current_severity in severity_map:
                        enriched_data['severity'] = severity_map[current_severity]
            
        except Exception as e:
            enriched_data['threat_intel']['error'] = str(e)
        
        return enriched_data
    
    def get_threat_intelligence_statistics(self) -> Dict:
        """Get threat intelligence statistics."""
        stats = {
            'total_indicators': len(self.indicators),
            'indicator_types': {},
            'source_distribution': {},
            'severity_distribution': {},
            'recent_matches': 0,
            'feed_status': {},
            'last_update': 0.0
        }
        
        try:
            # Analyze loaded indicators
            for indicator in self.indicators.values():
                # Count by type
                ind_type = indicator.indicator_type
                stats['indicator_types'][ind_type] = stats['indicator_types'].get(ind_type, 0) + 1
                
                # Count by source
                source = indicator.source
                stats['source_distribution'][source] = stats['source_distribution'].get(source, 0) + 1
                
                # Count by severity
                severity = indicator.severity
                stats['severity_distribution'][severity] = stats['severity_distribution'].get(severity, 0) + 1
            
            # Get database statistics
            with sqlite3.connect(self.db_path) as conn:
                # Recent matches (last 24 hours)
                cursor = conn.execute('''
                    SELECT COUNT(*) FROM threat_matches 
                    WHERE timestamp > ?
                ''', (time.time() - 86400,))
                stats['recent_matches'] = cursor.fetchone()[0]
                
                # Feed status
                cursor = conn.execute('SELECT * FROM feed_updates')
                for row in cursor.fetchall():
                    feed_name = row[0]
                    stats['feed_status'][feed_name] = {
                        'last_update': row[1],
                        'indicators_added': row[2],
                        'indicators_updated': row[3],
                        'status': row[4]
                    }
                    
                    # Update overall last update time
                    stats['last_update'] = max(stats['last_update'], row[1])
        
        except Exception as e:
            stats['error'] = str(e)
        
        return stats
    
    def create_custom_indicator(self, indicator_type: str, value: str, confidence: float,
                              severity: str, description: str, tags: List[str] = None) -> bool:
        """Create custom threat indicator."""
        try:
            indicator_id = hashlib.md5(f"custom_{indicator_type}_{value}".encode()).hexdigest()
            
            indicator = ThreatIndicator(
                indicator_id=indicator_id,
                indicator_type=indicator_type,
                value=value,
                confidence=confidence,
                severity=severity,
                source='custom',
                first_seen=time.time(),
                last_seen=time.time(),
                description=description,
                tags=tags or [],
                metadata={'created_by': 'user'}
            )
            
            self.indicators[indicator_id] = indicator
            self._store_indicator(indicator)
            
            print(f"Created custom indicator: {indicator_type} - {value}")
            return True
            
        except Exception as e:
            print(f"Error creating custom indicator: {e}")
            return False
    
    def export_threat_intelligence(self, output_path: str):
        """Export threat intelligence report."""
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'statistics': self.get_threat_intelligence_statistics(),
            'indicators': [asdict(ind) for ind in self.indicators.values()],
            'feed_configuration': self.feed_sources
        }
        
        # Get recent matches
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT * FROM threat_matches 
                    WHERE timestamp > ?
                    ORDER BY timestamp DESC
                    LIMIT 200
                ''', (time.time() - 604800,))  # Last week
                
                matches = []
                for row in cursor.fetchall():
                    matches.append({
                        'match_id': row[0],
                        'timestamp': row[1],
                        'indicator_id': row[2],
                        'matched_artifact': row[3],
                        'artifact_type': row[4],
                        'confidence': row[5]
                    })
                
                export_data['recent_matches'] = matches
        
        except Exception as e:
            export_data['export_error'] = str(e)
        
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
    
    def add_update_callback(self, callback):
        """Add callback for threat intelligence updates."""
        self.update_callbacks.append(callback)
    
    def add_match_callback(self, callback):
        """Add callback for threat indicator matches."""
        self.match_callbacks.append(callback)
    
    def start_automated_updates(self, interval: int = 3600):
        """Start automated threat feed updates."""
        self.update_active = True
        self.update_thread = threading.Thread(target=self._automated_update_loop, args=(interval,))
        self.update_thread.daemon = True
        self.update_thread.start()
        print(f"Started automated threat intelligence updates (interval: {interval}s)")
    
    def stop_automated_updates(self):
        """Stop automated threat feed updates."""
        self.update_active = False
        print("Stopped automated threat intelligence updates")
    
    def _automated_update_loop(self, interval: int):
        """Automated update loop for threat feeds."""
        while getattr(self, 'update_active', False):
            try:
                # Update enabled feeds
                results = self.update_threat_feeds()
                
                # Notify callbacks
                for callback in self.update_callbacks:
                    callback(results)
                
                time.sleep(interval)
                
            except Exception as e:
                print(f"Error in automated update loop: {e}")
                time.sleep(interval)