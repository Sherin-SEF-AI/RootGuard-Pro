"""
Advanced Network Traffic Analyzer
Deep packet inspection and network anomaly detection for rootkit communication.
"""

import os
import socket
import struct
import threading
import time
import subprocess
import re
import json
import psutil
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import ipaddress

@dataclass
class NetworkConnection:
    """Network connection information."""
    pid: int
    process_name: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    protocol: str
    state: str
    timestamp: float
    bytes_sent: int = 0
    bytes_received: int = 0

@dataclass
class NetworkAnomaly:
    """Network anomaly detection result."""
    timestamp: float
    anomaly_type: str
    severity: str
    description: str
    connection_info: Dict
    confidence: float

class AdvancedNetworkAnalyzer:
    """Advanced network traffic analysis and anomaly detection."""
    
    def __init__(self):
        self.monitoring_active = False
        self.monitor_thread = None
        self.connections_history = deque(maxlen=10000)
        self.anomaly_callbacks = []
        self.baseline_traffic = {}
        
        # Suspicious network indicators
        self.suspicious_ports = {
            # Common C&C ports
            1337, 31337, 12345, 54321, 6666, 6667, 9999,
            # Tor default ports
            9050, 9051, 9150,
            # Mining pool ports
            3333, 4444, 8333, 8080,
            # Remote access tools
            5900, 5901, 3389, 22, 23
        }
        
        self.suspicious_domains = [
            'duckdns.org', 'no-ip.com', 'ddns.net', 'pastebin.com',
            'hastebin.com', 'ix.io', 'sprunge.us'
        ]
        
        # Known malicious IP ranges (examples)
        self.malicious_ip_ranges = [
            ipaddress.ip_network('192.0.2.0/24'),  # RFC 5737 test range
            ipaddress.ip_network('198.51.100.0/24'),  # RFC 5737 test range
        ]
        
        # Traffic pattern thresholds
        self.traffic_thresholds = {
            'high_frequency_connections': 50,  # connections per minute
            'data_volume_anomaly': 10 * 1024 * 1024,  # 10MB in short time
            'port_scan_threshold': 20,  # unique ports in short time
            'dns_query_volume': 100,  # DNS queries per minute
        }
        
        self.connection_cache = {}
        self.traffic_stats = defaultdict(lambda: {'sent': 0, 'received': 0, 'connections': 0})
    
    def start_monitoring(self):
        """Start advanced network monitoring."""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop network monitoring."""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
    
    def _monitor_loop(self):
        """Main network monitoring loop."""
        while self.monitoring_active:
            try:
                self._capture_network_state()
                self._analyze_traffic_patterns()
                self._detect_anomalies()
                time.sleep(2)  # Monitor every 2 seconds
            except Exception as e:
                print(f"Error in network monitoring: {e}")
                time.sleep(5)
    
    def _capture_network_state(self):
        """Capture current network connections state."""
        try:
            current_connections = []
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    connections = proc.connections()
                    for conn in connections:
                        if conn.status == 'ESTABLISHED':
                            net_conn = NetworkConnection(
                                pid=proc.info['pid'],
                                process_name=proc.info['name'],
                                local_addr=conn.laddr.ip if conn.laddr else '',
                                local_port=conn.laddr.port if conn.laddr else 0,
                                remote_addr=conn.raddr.ip if conn.raddr else '',
                                remote_port=conn.raddr.port if conn.raddr else 0,
                                protocol='TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                                state=conn.status,
                                timestamp=time.time()
                            )
                            current_connections.append(net_conn)
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            self.connections_history.extend(current_connections)
            
        except Exception as e:
            print(f"Error capturing network state: {e}")
    
    def _analyze_traffic_patterns(self):
        """Analyze network traffic patterns for anomalies."""
        current_time = time.time()
        recent_connections = [
            conn for conn in self.connections_history 
            if current_time - conn.timestamp < 300  # Last 5 minutes
        ]
        
        # Group by process
        process_traffic = defaultdict(list)
        for conn in recent_connections:
            process_traffic[conn.pid].append(conn)
        
        # Analyze each process's traffic
        for pid, connections in process_traffic.items():
            self._analyze_process_traffic(pid, connections)
    
    def _analyze_process_traffic(self, pid: int, connections: List[NetworkConnection]):
        """Analyze traffic patterns for a specific process."""
        if not connections:
            return
        
        process_name = connections[0].process_name
        anomalies = []
        
        # Check for high frequency connections
        connection_rate = len(connections) / 5  # per minute (5 min window)
        if connection_rate > self.traffic_thresholds['high_frequency_connections']:
            anomalies.append(NetworkAnomaly(
                timestamp=time.time(),
                anomaly_type='high_frequency_connections',
                severity='medium',
                description=f'Process {process_name} making {connection_rate:.1f} connections/min',
                connection_info={'pid': pid, 'rate': connection_rate},
                confidence=0.6
            ))
        
        # Check for port scanning behavior
        unique_ports = set(conn.remote_port for conn in connections)
        if len(unique_ports) > self.traffic_thresholds['port_scan_threshold']:
            anomalies.append(NetworkAnomaly(
                timestamp=time.time(),
                anomaly_type='port_scanning',
                severity='high',
                description=f'Process {process_name} contacted {len(unique_ports)} different ports',
                connection_info={'pid': pid, 'unique_ports': len(unique_ports)},
                confidence=0.8
            ))
        
        # Check for connections to suspicious ports
        suspicious_port_connections = [
            conn for conn in connections 
            if conn.remote_port in self.suspicious_ports
        ]
        if suspicious_port_connections:
            anomalies.append(NetworkAnomaly(
                timestamp=time.time(),
                anomaly_type='suspicious_port_communication',
                severity='high',
                description=f'Process {process_name} communicating with suspicious ports',
                connection_info={
                    'pid': pid, 
                    'suspicious_ports': list(set(conn.remote_port for conn in suspicious_port_connections))
                },
                confidence=0.7
            ))
        
        # Check for connections to malicious IP ranges
        for conn in connections:
            if self._is_malicious_ip(conn.remote_addr):
                anomalies.append(NetworkAnomaly(
                    timestamp=time.time(),
                    anomaly_type='malicious_ip_communication',
                    severity='critical',
                    description=f'Process {process_name} communicating with known malicious IP',
                    connection_info={'pid': pid, 'malicious_ip': conn.remote_addr},
                    confidence=0.9
                ))
        
        # Notify callbacks about anomalies
        for anomaly in anomalies:
            for callback in self.anomaly_callbacks:
                callback(asdict(anomaly))
    
    def _detect_anomalies(self):
        """Detect various network anomalies."""
        current_time = time.time()
        
        # DNS tunneling detection
        dns_anomalies = self._detect_dns_anomalies()
        
        # Beacon detection
        beacon_anomalies = self._detect_beaconing()
        
        # Data exfiltration detection
        exfiltration_anomalies = self._detect_data_exfiltration()
        
        # Process all detected anomalies
        all_anomalies = dns_anomalies + beacon_anomalies + exfiltration_anomalies
        
        for anomaly in all_anomalies:
            for callback in self.anomaly_callbacks:
                callback(asdict(anomaly))
    
    def _detect_dns_anomalies(self) -> List[NetworkAnomaly]:
        """Detect DNS-based anomalies like tunneling."""
        anomalies = []
        
        try:
            # Check for excessive DNS queries
            dns_connections = [
                conn for conn in self.connections_history
                if conn.remote_port == 53 and time.time() - conn.timestamp < 60
            ]
            
            if len(dns_connections) > self.traffic_thresholds['dns_query_volume']:
                # Group by process
                process_dns = defaultdict(int)
                for conn in dns_connections:
                    process_dns[conn.pid] += 1
                
                for pid, query_count in process_dns.items():
                    if query_count > 50:  # High DNS activity for single process
                        process_name = next((conn.process_name for conn in dns_connections if conn.pid == pid), 'Unknown')
                        
                        anomalies.append(NetworkAnomaly(
                            timestamp=time.time(),
                            anomaly_type='excessive_dns_queries',
                            severity='medium',
                            description=f'Process {process_name} made {query_count} DNS queries in 1 minute',
                            connection_info={'pid': pid, 'dns_queries': query_count},
                            confidence=0.6
                        ))
            
            # Check for unusual DNS servers
            dns_servers = set()
            for conn in dns_connections:
                if not self._is_local_ip(conn.remote_addr):
                    dns_servers.add(conn.remote_addr)
            
            # Flag non-standard DNS servers
            standard_dns = {'8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'}
            unusual_dns = dns_servers - standard_dns
            
            if unusual_dns:
                anomalies.append(NetworkAnomaly(
                    timestamp=time.time(),
                    anomaly_type='unusual_dns_servers',
                    severity='low',
                    description=f'Communication with non-standard DNS servers: {", ".join(unusual_dns)}',
                    connection_info={'unusual_dns_servers': list(unusual_dns)},
                    confidence=0.4
                ))
                
        except Exception as e:
            print(f"Error in DNS anomaly detection: {e}")
        
        return anomalies
    
    def _detect_beaconing(self) -> List[NetworkAnomaly]:
        """Detect beaconing patterns typical of C&C communication."""
        anomalies = []
        
        try:
            # Group connections by process and remote endpoint
            beacon_patterns = defaultdict(list)
            current_time = time.time()
            
            for conn in self.connections_history:
                if current_time - conn.timestamp < 3600:  # Last hour
                    key = (conn.pid, conn.remote_addr, conn.remote_port)
                    beacon_patterns[key].append(conn.timestamp)
            
            # Analyze patterns for regular intervals
            for (pid, remote_addr, remote_port), timestamps in beacon_patterns.items():
                if len(timestamps) < 5:  # Need multiple connections
                    continue
                
                # Calculate intervals between connections
                timestamps.sort()
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                
                if len(intervals) < 3:
                    continue
                
                # Check for regular intervals (beaconing)
                avg_interval = sum(intervals) / len(intervals)
                interval_variance = sum((interval - avg_interval) ** 2 for interval in intervals) / len(intervals)
                
                # Low variance indicates regular beaconing
                if interval_variance < (avg_interval * 0.2) ** 2 and avg_interval < 3600:  # Regular intervals under 1 hour
                    process_name = next((conn.process_name for conn in self.connections_history if conn.pid == pid), 'Unknown')
                    
                    anomalies.append(NetworkAnomaly(
                        timestamp=current_time,
                        anomaly_type='beaconing_detected',
                        severity='high',
                        description=f'Process {process_name} showing regular beaconing to {remote_addr}:{remote_port}',
                        connection_info={
                            'pid': pid,
                            'remote_endpoint': f'{remote_addr}:{remote_port}',
                            'beacon_interval': avg_interval,
                            'connection_count': len(timestamps)
                        },
                        confidence=0.8
                    ))
                    
        except Exception as e:
            print(f"Error in beacon detection: {e}")
        
        return anomalies
    
    def _detect_data_exfiltration(self) -> List[NetworkAnomaly]:
        """Detect potential data exfiltration patterns."""
        anomalies = []
        
        try:
            # Analyze network I/O statistics
            current_time = time.time()
            
            # Get network I/O for all processes
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    # Get process network connections
                    connections = proc.connections()
                    if not connections:
                        continue
                    
                    # Check for large data transfers
                    external_connections = [
                        conn for conn in connections
                        if (conn.raddr and not self._is_local_ip(conn.raddr.ip))
                    ]
                    
                    if len(external_connections) > 5:  # Multiple external connections
                        # This could indicate data exfiltration
                        anomalies.append(NetworkAnomaly(
                            timestamp=current_time,
                            anomaly_type='multiple_external_connections',
                            severity='medium',
                            description=f'Process {proc.info["name"]} has {len(external_connections)} external connections',
                            connection_info={
                                'pid': proc.info['pid'],
                                'external_connection_count': len(external_connections),
                                'remote_endpoints': [f'{conn.raddr.ip}:{conn.raddr.port}' for conn in external_connections[:5]]
                            },
                            confidence=0.5
                        ))
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"Error in data exfiltration detection: {e}")
        
        return anomalies
    
    def _is_malicious_ip(self, ip_addr: str) -> bool:
        """Check if IP address is in known malicious ranges."""
        try:
            ip = ipaddress.ip_address(ip_addr)
            for malicious_range in self.malicious_ip_ranges:
                if ip in malicious_range:
                    return True
        except ValueError:
            pass
        return False
    
    def _is_local_ip(self, ip_addr: str) -> bool:
        """Check if IP address is local/private."""
        try:
            ip = ipaddress.ip_address(ip_addr)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            return False
    
    def analyze_network_forensics(self, target_pid: int = None) -> Dict:
        """Perform comprehensive network forensics analysis."""
        analysis_results = {
            'timestamp': time.time(),
            'target_pid': target_pid,
            'connection_analysis': {},
            'traffic_patterns': {},
            'security_indicators': [],
            'protocol_breakdown': defaultdict(int),
            'geographic_analysis': {}
        }
        
        try:
            # Get current network connections
            if target_pid:
                try:
                    proc = psutil.Process(target_pid)
                    connections = proc.connections()
                    analysis_results['process_name'] = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    return {'error': f'Cannot access process {target_pid}'}
            else:
                # Analyze all connections
                connections = []
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        proc_connections = proc.connections()
                        for conn in proc_connections:
                            # Add process info to connection
                            conn.pid = proc.info['pid']
                            conn.process_name = proc.info['name']
                            connections.append(conn)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            
            # Analyze connections
            for conn in connections:
                # Protocol breakdown
                protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                analysis_results['protocol_breakdown'][protocol] += 1
                
                # Check for suspicious indicators
                if hasattr(conn, 'raddr') and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    
                    # Suspicious port check
                    if remote_port in self.suspicious_ports:
                        analysis_results['security_indicators'].append({
                            'type': 'suspicious_port',
                            'description': f'Connection to suspicious port {remote_port}',
                            'remote_endpoint': f'{remote_ip}:{remote_port}',
                            'process': getattr(conn, 'process_name', 'Unknown'),
                            'severity': 'medium'
                        })
                    
                    # Malicious IP check
                    if self._is_malicious_ip(remote_ip):
                        analysis_results['security_indicators'].append({
                            'type': 'malicious_ip',
                            'description': f'Connection to known malicious IP {remote_ip}',
                            'remote_endpoint': f'{remote_ip}:{remote_port}',
                            'process': getattr(conn, 'process_name', 'Unknown'),
                            'severity': 'critical'
                        })
                    
                    # Geographic analysis (simplified)
                    if not self._is_local_ip(remote_ip):
                        country = self._get_ip_country(remote_ip)
                        if country not in analysis_results['geographic_analysis']:
                            analysis_results['geographic_analysis'][country] = 0
                        analysis_results['geographic_analysis'][country] += 1
            
            # Connection statistics
            analysis_results['connection_analysis'] = {
                'total_connections': len(connections),
                'established_connections': len([c for c in connections if c.status == 'ESTABLISHED']),
                'listening_ports': len([c for c in connections if c.status == 'LISTEN']),
                'external_connections': len([c for c in connections if hasattr(c, 'raddr') and c.raddr and not self._is_local_ip(c.raddr.ip)])
            }
            
        except Exception as e:
            analysis_results['error'] = str(e)
        
        return analysis_results
    
    def _get_ip_country(self, ip_addr: str) -> str:
        """Get country for IP address (simplified)."""
        # This would typically use a GeoIP database
        # Simplified implementation for demonstration
        if ip_addr.startswith('8.8.'):
            return 'US'
        elif ip_addr.startswith('1.1.'):
            return 'US'
        else:
            return 'Unknown'
    
    def detect_network_rootkit_indicators(self) -> List[Dict]:
        """Detect network-based rootkit indicators."""
        indicators = []
        
        try:
            # Check for hidden network connections
            hidden_connections = self._detect_hidden_connections()
            indicators.extend(hidden_connections)
            
            # Check for suspicious network processes
            suspicious_processes = self._detect_suspicious_network_processes()
            indicators.extend(suspicious_processes)
            
            # Check for network-based covert channels
            covert_channels = self._detect_covert_channels()
            indicators.extend(covert_channels)
            
        except Exception as e:
            print(f"Error detecting network rootkit indicators: {e}")
        
        return indicators
    
    def _detect_hidden_connections(self) -> List[Dict]:
        """Detect potentially hidden network connections."""
        indicators = []
        
        try:
            # Get connections via different methods and compare
            psutil_connections = self._get_psutil_connections()
            netstat_connections = self._get_netstat_connections()
            proc_net_connections = self._get_proc_net_connections()
            
            # Find discrepancies
            psutil_set = set((conn['local_port'], conn['remote_addr'], conn['remote_port']) 
                           for conn in psutil_connections)
            netstat_set = set((conn['local_port'], conn['remote_addr'], conn['remote_port']) 
                            for conn in netstat_connections)
            
            hidden_in_psutil = netstat_set - psutil_set
            hidden_in_netstat = psutil_set - netstat_set
            
            for hidden_conn in hidden_in_psutil:
                indicators.append({
                    'type': 'hidden_connection_psutil',
                    'description': f'Connection hidden from psutil: {hidden_conn}',
                    'connection': hidden_conn,
                    'severity': 'high'
                })
            
            for hidden_conn in hidden_in_netstat:
                indicators.append({
                    'type': 'hidden_connection_netstat',
                    'description': f'Connection hidden from netstat: {hidden_conn}',
                    'connection': hidden_conn,
                    'severity': 'high'
                })
                
        except Exception as e:
            print(f"Error detecting hidden connections: {e}")
        
        return indicators
    
    def _get_psutil_connections(self) -> List[Dict]:
        """Get network connections via psutil."""
        connections = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    for conn in proc.connections():
                        if conn.status == 'ESTABLISHED' and conn.raddr:
                            connections.append({
                                'pid': proc.info['pid'],
                                'process': proc.info['name'],
                                'local_port': conn.laddr.port if conn.laddr else 0,
                                'remote_addr': conn.raddr.ip,
                                'remote_port': conn.raddr.port
                            })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"Error getting psutil connections: {e}")
        
        return connections
    
    def _get_netstat_connections(self) -> List[Dict]:
        """Get network connections via netstat command."""
        connections = []
        
        try:
            result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                
                for line in lines:
                    if 'ESTABLISHED' in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            local_addr = parts[3]
                            remote_addr = parts[4]
                            
                            try:
                                local_ip, local_port = local_addr.rsplit(':', 1)
                                remote_ip, remote_port = remote_addr.rsplit(':', 1)
                                
                                connections.append({
                                    'local_port': int(local_port),
                                    'remote_addr': remote_ip,
                                    'remote_port': int(remote_port)
                                })
                            except ValueError:
                                continue
                                
        except Exception as e:
            print(f"Error getting netstat connections: {e}")
        
        return connections
    
    def _get_proc_net_connections(self) -> List[Dict]:
        """Get network connections from /proc/net/tcp."""
        connections = []
        
        try:
            with open('/proc/net/tcp', 'r') as f:
                lines = f.readlines()
            
            for line in lines[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 3:
                    local_addr = parts[1]
                    remote_addr = parts[2]
                    state = int(parts[3], 16)
                    
                    if state == 1:  # ESTABLISHED
                        try:
                            # Parse hex addresses
                            local_ip, local_port = self._parse_hex_addr(local_addr)
                            remote_ip, remote_port = self._parse_hex_addr(remote_addr)
                            
                            if remote_ip != '0.0.0.0':
                                connections.append({
                                    'local_port': local_port,
                                    'remote_addr': remote_ip,
                                    'remote_port': remote_port
                                })
                        except Exception:
                            continue
                            
        except Exception as e:
            print(f"Error reading /proc/net/tcp: {e}")
        
        return connections
    
    def _parse_hex_addr(self, hex_addr: str) -> Tuple[str, int]:
        """Parse hexadecimal network address from /proc/net/tcp."""
        ip_hex, port_hex = hex_addr.split(':')
        
        # Convert hex IP to dotted decimal
        ip_int = int(ip_hex, 16)
        ip_bytes = struct.pack('<I', ip_int)  # Little endian
        ip_addr = socket.inet_ntoa(ip_bytes)
        
        # Convert hex port
        port = int(port_hex, 16)
        
        return ip_addr, port
    
    def _detect_suspicious_network_processes(self) -> List[Dict]:
        """Detect processes with suspicious network behavior."""
        indicators = []
        
        try:
            process_connections = defaultdict(list)
            
            # Group connections by process
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    connections = proc.connections()
                    if connections:
                        process_connections[proc.info['pid']] = {
                            'name': proc.info['name'],
                            'connections': connections
                        }
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Analyze each process
            for pid, proc_info in process_connections.items():
                connections = proc_info['connections']
                process_name = proc_info['name']
                
                # Check for processes that shouldn't have network access
                non_network_processes = ['notepad', 'calc', 'mspaint']
                if any(proc in process_name.lower() for proc in non_network_processes):
                    if any(conn.status == 'ESTABLISHED' for conn in connections):
                        indicators.append({
                            'type': 'unexpected_network_access',
                            'description': f'Non-network process {process_name} has network connections',
                            'pid': pid,
                            'process': process_name,
                            'severity': 'high'
                        })
                
                # Check for excessive connections
                established_count = sum(1 for conn in connections if conn.status == 'ESTABLISHED')
                if established_count > 20:
                    indicators.append({
                        'type': 'excessive_connections',
                        'description': f'Process {process_name} has {established_count} established connections',
                        'pid': pid,
                        'process': process_name,
                        'connection_count': established_count,
                        'severity': 'medium'
                    })
                
                # Check for connections to unusual ports
                unusual_ports = []
                for conn in connections:
                    if (hasattr(conn, 'raddr') and conn.raddr and 
                        conn.raddr.port not in range(80, 90) and  # HTTP/HTTPS
                        conn.raddr.port not in range(443, 445) and  # HTTPS/SMB
                        conn.raddr.port != 53 and  # DNS
                        conn.raddr.port not in range(20, 25)):  # FTP
                        unusual_ports.append(conn.raddr.port)
                
                if len(set(unusual_ports)) > 10:
                    indicators.append({
                        'type': 'unusual_port_communication',
                        'description': f'Process {process_name} communicating with unusual ports',
                        'pid': pid,
                        'process': process_name,
                        'unusual_ports': list(set(unusual_ports))[:10],
                        'severity': 'medium'
                    })
                    
        except Exception as e:
            print(f"Error detecting suspicious network processes: {e}")
        
        return indicators
    
    def _detect_covert_channels(self) -> List[Dict]:
        """Detect potential covert communication channels."""
        indicators = []
        
        try:
            # Check for ICMP covert channels
            icmp_indicators = self._check_icmp_anomalies()
            indicators.extend(icmp_indicators)
            
            # Check for DNS covert channels
            dns_indicators = self._check_dns_covert_channels()
            indicators.extend(dns_indicators)
            
            # Check for timing-based covert channels
            timing_indicators = self._check_timing_channels()
            indicators.extend(timing_indicators)
            
        except Exception as e:
            print(f"Error detecting covert channels: {e}")
        
        return indicators
    
    def _check_icmp_anomalies(self) -> List[Dict]:
        """Check for ICMP-based covert communications."""
        indicators = []
        
        try:
            # Check ICMP traffic statistics
            result = subprocess.run(['cat', '/proc/net/snmp'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('Icmp:') and 'InMsgs' in line:
                        # Parse ICMP statistics
                        # This is a simplified check - real implementation would be more sophisticated
                        pass
        except Exception:
            pass
        
        return indicators
    
    def _check_dns_covert_channels(self) -> List[Dict]:
        """Check for DNS-based covert channels."""
        indicators = []
        
        try:
            # Look for unusual DNS query patterns
            dns_connections = [
                conn for conn in self.connections_history
                if conn.remote_port == 53 and time.time() - conn.timestamp < 600
            ]
            
            # Group by process
            process_dns_patterns = defaultdict(list)
            for conn in dns_connections:
                process_dns_patterns[conn.pid].append(conn)
            
            for pid, connections in process_dns_patterns.items():
                if len(connections) > 20:  # High DNS activity
                    process_name = connections[0].process_name
                    
                    # Check for regular intervals (potential data exfiltration via DNS)
                    timestamps = [conn.timestamp for conn in connections]
                    timestamps.sort()
                    
                    if len(timestamps) > 3:
                        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                        avg_interval = sum(intervals) / len(intervals)
                        
                        if avg_interval < 10:  # Very frequent DNS queries
                            indicators.append({
                                'type': 'dns_covert_channel',
                                'description': f'Process {process_name} showing potential DNS covert channel',
                                'pid': pid,
                                'process': process_name,
                                'query_frequency': len(connections) / 10,  # per minute
                                'severity': 'medium'
                            })
                            
        except Exception as e:
            print(f"Error checking DNS covert channels: {e}")
        
        return indicators
    
    def _check_timing_channels(self) -> List[Dict]:
        """Check for timing-based covert channels."""
        indicators = []
        
        try:
            # Analyze connection timing patterns
            current_time = time.time()
            recent_connections = [
                conn for conn in self.connections_history
                if current_time - conn.timestamp < 1800  # Last 30 minutes
            ]
            
            # Group by remote endpoint
            endpoint_patterns = defaultdict(list)
            for conn in recent_connections:
                endpoint = f"{conn.remote_addr}:{conn.remote_port}"
                endpoint_patterns[endpoint].append(conn.timestamp)
            
            # Look for regular timing patterns
            for endpoint, timestamps in endpoint_patterns.items():
                if len(timestamps) >= 5:
                    timestamps.sort()
                    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                    
                    # Check for very regular intervals (potential timing channel)
                    if intervals:
                        avg_interval = sum(intervals) / len(intervals)
                        variance = sum((interval - avg_interval) ** 2 for interval in intervals) / len(intervals)
                        
                        if variance < 1.0 and 10 < avg_interval < 300:  # Regular intervals between 10s-5min
                            indicators.append({
                                'type': 'timing_covert_channel',
                                'description': f'Regular timing pattern detected for {endpoint}',
                                'endpoint': endpoint,
                                'interval': avg_interval,
                                'connection_count': len(timestamps),
                                'severity': 'low'
                            })
                            
        except Exception as e:
            print(f"Error checking timing channels: {e}")
        
        return indicators
    
    def add_anomaly_callback(self, callback):
        """Add callback for network anomaly alerts."""
        self.anomaly_callbacks.append(callback)
    
    def get_network_summary(self) -> Dict:
        """Get comprehensive network activity summary."""
        summary = {
            'active_connections': 0,
            'monitoring_status': 'active' if self.monitoring_active else 'inactive',
            'unique_remote_endpoints': set(),
            'protocol_distribution': defaultdict(int),
            'suspicious_activity_count': 0,
            'top_talkers': [],
            'recent_anomalies': []
        }
        
        try:
            current_time = time.time()
            recent_connections = [
                conn for conn in self.connections_history
                if current_time - conn.timestamp < 300  # Last 5 minutes
            ]
            
            summary['active_connections'] = len(recent_connections)
            
            # Analyze recent connections
            process_traffic = defaultdict(int)
            for conn in recent_connections:
                summary['unique_remote_endpoints'].add(f"{conn.remote_addr}:{conn.remote_port}")
                summary['protocol_distribution'][conn.protocol] += 1
                process_traffic[conn.process_name] += 1
            
            # Convert set to count
            summary['unique_remote_endpoints'] = len(summary['unique_remote_endpoints'])
            
            # Top talking processes
            summary['top_talkers'] = sorted(
                [{'process': proc, 'connections': count} for proc, count in process_traffic.items()],
                key=lambda x: x['connections'],
                reverse=True
            )[:10]
            
        except Exception as e:
            summary['error'] = str(e)
        
        return summary
    
    def export_network_analysis(self, output_path: str):
        """Export comprehensive network analysis report."""
        report_data = {
            'generation_time': datetime.now().isoformat(),
            'network_summary': self.get_network_summary(),
            'forensics_analysis': self.analyze_network_forensics(),
            'rootkit_indicators': self.detect_network_rootkit_indicators(),
            'connection_history': [asdict(conn) for conn in list(self.connections_history)[-1000:]]  # Last 1000 connections
        }
        
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)