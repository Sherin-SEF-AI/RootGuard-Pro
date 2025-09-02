#!/usr/bin/env python3
"""
CLI test of the rootkit detection functionality
"""

import sys
import os
sys.path.append('src')

from detection.process_detector import ProcessDetector
from detection.service_detector import ServiceDetector
from detection.network_detector import NetworkDetector

def test_process_detection():
    """Test process detection capabilities."""
    print("=" * 50)
    print("TESTING PROCESS DETECTION")
    print("=" * 50)
    
    detector = ProcessDetector()
    
    print("Enumerating processes via /proc filesystem...")
    proc_fs_processes = detector.enumerate_proc_filesystem()
    print(f"Found {len(proc_fs_processes)} processes via /proc")
    
    print("\nEnumerating processes via ps command...")
    ps_processes = detector.enumerate_ps_command()
    print(f"Found {len(ps_processes)} processes via ps")
    
    print("\nComparing process lists...")
    all_processes = detector.compare_process_lists(proc_fs_processes, ps_processes, [])
    
    hidden_count = sum(1 for p in all_processes if p.get('hidden', False))
    suspicious_count = sum(1 for p in all_processes if p.get('suspicious', False))
    
    print(f"Total processes: {len(all_processes)}")
    print(f"Hidden processes: {hidden_count}")
    print(f"Suspicious processes: {suspicious_count}")
    
    if suspicious_count > 0:
        print("\nSuspicious processes found:")
        for proc in all_processes:
            if proc.get('suspicious', False):
                print(f"  - PID {proc['pid']}: {proc['name']} ({proc['cmdline'][:60]}...)")

def test_service_detection():
    """Test service detection capabilities."""
    print("\n" + "=" * 50)
    print("TESTING SERVICE DETECTION")
    print("=" * 50)
    
    detector = ServiceDetector()
    
    print("Enumerating services via systemctl...")
    systemctl_services = detector.enumerate_systemctl_services()
    print(f"Found {len(systemctl_services)} services via systemctl")
    
    print("Enumerating services via init files...")
    init_services = detector.enumerate_init_services()
    print(f"Found {len(init_services)} init services")
    
    all_services = detector.compare_service_lists(systemctl_services, init_services)
    
    hidden_count = sum(1 for s in all_services if s.get('hidden', False))
    suspicious_count = sum(1 for s in all_services if s.get('suspicious', False))
    
    print(f"Total services: {len(all_services)}")
    print(f"Hidden services: {hidden_count}")
    print(f"Suspicious services: {suspicious_count}")

def test_network_detection():
    """Test network detection capabilities."""
    print("\n" + "=" * 50)
    print("TESTING NETWORK DETECTION")
    print("=" * 50)
    
    detector = NetworkDetector()
    
    print("Enumerating connections via netstat...")
    netstat_connections = detector.enumerate_netstat()
    print(f"Found {len(netstat_connections)} connections via netstat")
    
    print("Enumerating connections via API...")
    api_connections = detector.enumerate_api_connections()
    print(f"Found {len(api_connections)} connections via API")
    
    all_connections = detector.compare_connection_lists(netstat_connections, api_connections)
    
    hidden_count = sum(1 for c in all_connections if c.get('hidden', False))
    suspicious_count = sum(1 for c in all_connections if c.get('suspicious', False))
    external_count = sum(1 for c in all_connections if c.get('is_external', False))
    
    print(f"Total connections: {len(all_connections)}")
    print(f"Hidden connections: {hidden_count}")
    print(f"Suspicious connections: {suspicious_count}")
    print(f"External connections: {external_count}")

def main():
    """Main test function."""
    print("Linux Rootkit Detection Tool - CLI Test")
    print("Testing core detection functionality...\n")
    
    try:
        test_process_detection()
        test_service_detection() 
        test_network_detection()
        
        print("\n" + "=" * 50)
        print("All tests completed successfully!")
        print("The GUI application should work with: sudo python3 main.py")
        print("=" * 50)
        
    except Exception as e:
        print(f"\nError during testing: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()