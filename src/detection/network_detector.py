"""
Network Detection Module
Implements network connection enumeration and analysis.
"""

import subprocess
import socket
import psutil
import requests
import json
from typing import List, Dict


class NetworkDetector:
    """Network connection detection and analysis class."""
    
    def __init__(self):
        self.suspicious_ports = [
            1234, 1337, 1999, 2000, 3389, 4444, 5555, 6666, 7777, 8080, 8888, 9999,
            12345, 31337, 54321
        ]
        self.private_ip_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('127.0.0.0', '127.255.255.255')
        ]
        
    def enumerate_netstat(self) -> List[Dict]:
        """Enumerate connections using netstat command."""
        connections = []
        
        try:
            # Run netstat command
            result = subprocess.run(['netstat', '-ano'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                return connections
            
            lines = result.stdout.strip().split('\n')
            
            for line in lines[4:]:  # Skip header lines
                parts = line.split()
                if len(parts) < 5:
                    continue
                
                protocol = parts[0]
                if protocol not in ['TCP', 'UDP']:
                    continue
                
                local_addr = parts[1]
                remote_addr = parts[2] if len(parts) > 2 else '0.0.0.0:0'
                state = parts[3] if protocol == 'TCP' else 'N/A'
                pid = int(parts[-1]) if parts[-1].isdigit() else 0
                
                # Parse addresses
                local_ip, local_port = self.parse_address(local_addr)
                remote_ip, remote_port = self.parse_address(remote_addr)
                
                # Get process information
                process_name = 'Unknown'
                try:
                    if pid > 0:
                        proc = psutil.Process(pid)
                        process_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                
                connection_info = {
                    'protocol': protocol,
                    'local_ip': local_ip,
                    'local_port': local_port,
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'state': state,
                    'pid': pid,
                    'process_name': process_name,
                    'source': 'netstat',
                    'hidden': False,
                    'is_external': not self.is_private_ip(remote_ip),
                    'suspicious': self.is_suspicious_connection(remote_ip, remote_port, process_name)
                }
                
                connections.append(connection_info)
                
        except Exception as e:
            print(f"Error in netstat enumeration: {e}")
            
        return connections
    
    def enumerate_api_connections(self) -> List[Dict]:
        """Enumerate connections using Windows API calls."""
        connections = []
        
        try:
            # Use psutil which wraps Windows API calls
            for conn in psutil.net_connections(kind='inet'):
                try:
                    # Get process information
                    process_name = 'Unknown'
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            process_name = proc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    
                    local_ip = conn.laddr.ip if conn.laddr else '0.0.0.0'
                    local_port = conn.laddr.port if conn.laddr else 0
                    remote_ip = conn.raddr.ip if conn.raddr else '0.0.0.0'
                    remote_port = conn.raddr.port if conn.raddr else 0
                    
                    connection_info = {
                        'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                        'local_ip': local_ip,
                        'local_port': local_port,
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'state': conn.status if conn.status else 'N/A',
                        'pid': conn.pid or 0,
                        'process_name': process_name,
                        'source': 'api',
                        'hidden': False,
                        'is_external': not self.is_private_ip(remote_ip),
                        'suspicious': self.is_suspicious_connection(remote_ip, remote_port, process_name)
                    }
                    
                    connections.append(connection_info)
                    
                except Exception:
                    continue
                    
        except Exception as e:
            print(f"Error in API enumeration: {e}")
            
        return connections
    
    def compare_connection_lists(self, netstat_conns: List[Dict], api_conns: List[Dict]) -> List[Dict]:
        """Compare connection lists to identify discrepancies."""
        # Create unique identifiers for connections
        def conn_id(conn):
            return (conn['protocol'], conn['local_ip'], conn['local_port'], 
                   conn['remote_ip'], conn['remote_port'], conn['pid'])
        
        netstat_set = {conn_id(conn): conn for conn in netstat_conns}
        api_set = {conn_id(conn): conn for conn in api_conns}
        
        all_conn_ids = set(netstat_set.keys()) | set(api_set.keys())
        
        result_connections = []
        
        for conn_id_tuple in all_conn_ids:
            netstat_conn = netstat_set.get(conn_id_tuple)
            api_conn = api_set.get(conn_id_tuple)
            
            if netstat_conn and api_conn:
                # Connection exists in both - use netstat data as primary
                merged_conn = netstat_conn.copy()
                merged_conn['sources'] = ['netstat', 'api']
            elif netstat_conn:
                # Only in netstat
                merged_conn = netstat_conn.copy()
                merged_conn['sources'] = ['netstat']
                merged_conn['hidden'] = True
                merged_conn['missing_from'] = ['api']
            else:
                # Only in API
                merged_conn = api_conn.copy()
                merged_conn['sources'] = ['api']
                merged_conn['hidden'] = True
                merged_conn['missing_from'] = ['netstat']
            
            # Lookup country information for external IPs
            if merged_conn['is_external'] and merged_conn['remote_ip'] != '0.0.0.0':
                country_info = self.lookup_ip_info(merged_conn['remote_ip'])
                merged_conn['country'] = country_info.get('country', 'Unknown')
            else:
                merged_conn['country'] = 'Local'
                
            result_connections.append(merged_conn)
        
        return result_connections
    
    def parse_address(self, address: str) -> tuple:
        """Parse IP:port address string."""
        try:
            if ':' in address:
                ip, port = address.rsplit(':', 1)
                return ip, int(port)
            else:
                return address, 0
        except ValueError:
            return '0.0.0.0', 0
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is in private ranges."""
        try:
            ip_int = int(socket.inet_aton(ip).hex(), 16)
            
            for start_ip, end_ip in self.private_ip_ranges:
                start_int = int(socket.inet_aton(start_ip).hex(), 16)
                end_int = int(socket.inet_aton(end_ip).hex(), 16)
                
                if start_int <= ip_int <= end_int:
                    return True
                    
        except (socket.error, ValueError):
            pass
            
        return False
    
    def is_suspicious_connection(self, remote_ip: str, remote_port: int, process_name: str) -> bool:
        """Check if a connection exhibits suspicious characteristics."""
        # Check for suspicious ports
        if remote_port in self.suspicious_ports:
            return True
        
        # Check for suspicious process names
        suspicious_processes = ['nc.exe', 'ncat.exe', 'netcat.exe', 'powershell.exe']
        if process_name.lower() in suspicious_processes:
            return True
        
        # Check for connections to suspicious countries/regions
        # This would need a more comprehensive implementation
        
        return False
    
    def lookup_ip_info(self, ip: str) -> Dict:
        """Lookup geographical and organizational information for an IP."""
        try:
            if self.is_private_ip(ip) or ip == '0.0.0.0':
                return {'country': 'Local', 'region': 'Local', 'city': 'Local'}
            
            # Using ipapi.co for IP lookup (free tier)
            response = requests.get(f'https://ipapi.co/{ip}/json/', timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country_name', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('org', 'Unknown'),
                    'org': data.get('org', 'Unknown')
                }
            else:
                return {'error': 'Lookup failed'}
                
        except requests.RequestException as e:
            return {'error': str(e)}
        except Exception as e:
            return {'error': str(e)}
    
    def get_connection_details(self, local_addr: str, remote_addr: str, protocol: str) -> Dict:
        """Get detailed information about a specific connection."""
        try:
            # Find matching connection in psutil
            for conn in psutil.net_connections(kind='inet'):
                if not conn.laddr or not conn.raddr:
                    continue
                    
                conn_local = f"{conn.laddr.ip}:{conn.laddr.port}"
                conn_remote = f"{conn.raddr.ip}:{conn.raddr.port}"
                conn_protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                
                if (conn_local == local_addr and 
                    conn_remote == remote_addr and 
                    conn_protocol == protocol):
                    
                    details = {
                        'family': conn.family,
                        'type': conn.type,
                        'status': conn.status,
                        'pid': conn.pid
                    }
                    
                    # Get process details
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            details['process'] = {
                                'name': proc.name(),
                                'exe': proc.exe(),
                                'cmdline': proc.cmdline(),
                                'create_time': proc.create_time()
                            }
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            details['process'] = {'error': 'Access denied'}
                    
                    return details
                    
        except Exception as e:
            return {'error': str(e)}
        
        return {'error': 'Connection not found'}