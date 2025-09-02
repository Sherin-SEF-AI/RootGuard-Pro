"""
Machine Learning Anomaly Detection
AI-powered anomaly detection for advanced rootkit identification.
"""

import os
import json
try:
    import numpy as np
except ImportError:
    print("NumPy not available - using fallback implementations")
    
    class FallbackNumPy:
        @staticmethod
        def mean(data):
            return sum(data) / len(data) if data else 0.0
        
        @staticmethod
        def std(data):
            if not data or len(data) < 2:
                return 0.0
            mean_val = sum(data) / len(data)
            variance = sum((x - mean_val) ** 2 for x in data) / (len(data) - 1)
            return variance ** 0.5
        
        @staticmethod
        def min(data):
            return min(data) if data else 0.0
        
        @staticmethod
        def max(data):
            return max(data) if data else 0.0
        
        @staticmethod
        def percentile(data, p):
            if not data:
                return 0.0
            sorted_data = sorted(data)
            k = (len(sorted_data) - 1) * p / 100
            f = int(k)
            c = k - f
            if f == len(sorted_data) - 1:
                return sorted_data[f]
            return sorted_data[f] * (1 - c) + sorted_data[f + 1] * c
        
        @staticmethod
        def var(data):
            if not data or len(data) < 2:
                return 0.0
            mean_val = sum(data) / len(data)
            return sum((x - mean_val) ** 2 for x in data) / len(data)
        
        @staticmethod
        def array(data):
            return data
        
        @staticmethod
        def log2(x):
            import math
            return math.log2(x) if x > 0 else 0
        
        class linalg:
            @staticmethod
            def norm(vector):
                return sum(x ** 2 for x in vector) ** 0.5
        
        @staticmethod
        def diff(data):
            return [data[i+1] - data[i] for i in range(len(data) - 1)]
        
        @staticmethod
        def correlate(a, b, mode='full'):
            # Simplified correlation for fallback
            return [0.0] * len(a)
        
        @staticmethod
        def clip(data, min_val, max_val):
            if isinstance(data, list):
                return [max(min_val, min(max_val, x)) for x in data]
            return max(min_val, min(max_val, data))
    
    np = FallbackNumPy()
import time
import threading
import sqlite3
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict, deque
import hashlib
import pickle

@dataclass
class SystemFeature:
    """System feature for ML analysis."""
    timestamp: float
    process_count: int
    network_connections: int
    cpu_usage: float
    memory_usage: float
    disk_io_rate: float
    network_io_rate: float
    file_operations: int
    registry_operations: int
    privilege_escalations: int
    suspicious_api_calls: int
    entropy_score: float

@dataclass
class AnomalyDetection:
    """Anomaly detection result."""
    timestamp: float
    anomaly_type: str
    confidence: float
    severity: str
    description: str
    features: Dict
    risk_score: float
    recommended_actions: List[str]

class MLAnomalyDetector:
    """Machine learning-based anomaly detection system."""
    
    def __init__(self, db_path: str = "ml_anomaly.db", model_path: str = "anomaly_model.pkl"):
        self.db_path = db_path
        self.model_path = model_path
        self.feature_buffer = deque(maxlen=1000)
        self.baseline_features = {}
        self.detection_callbacks = []
        self.monitoring_active = False
        self.monitoring_thread = None
        
        # Anomaly detection thresholds
        self.anomaly_thresholds = {
            'process_spike': 2.5,
            'network_anomaly': 3.0,
            'memory_leak': 2.0,
            'file_activity': 2.5,
            'api_anomaly': 3.5
        }
        
        # Feature weights for anomaly scoring
        self.feature_weights = {
            'process_count': 0.15,
            'network_connections': 0.20,
            'cpu_usage': 0.10,
            'memory_usage': 0.15,
            'disk_io_rate': 0.10,
            'network_io_rate': 0.15,
            'file_operations': 0.05,
            'privilege_escalations': 0.25,
            'suspicious_api_calls': 0.30,
            'entropy_score': 0.20
        }
        
        self._init_database()
        self._load_baseline_model()
    
    def _init_database(self):
        """Initialize ML anomaly detection database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS feature_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    features TEXT,
                    anomaly_score REAL,
                    is_anomaly BOOLEAN
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS anomaly_detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    anomaly_type TEXT,
                    confidence REAL,
                    severity TEXT,
                    description TEXT,
                    features TEXT,
                    risk_score REAL,
                    actions TEXT
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS baseline_models (
                    model_name TEXT PRIMARY KEY,
                    model_data BLOB,
                    training_timestamp REAL,
                    feature_stats TEXT,
                    performance_metrics TEXT
                )
            ''')
            
            conn.commit()
    
    def _load_baseline_model(self):
        """Load or create baseline anomaly detection model."""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    self.model_data = pickle.load(f)
                print("Loaded existing ML anomaly model")
            else:
                self.model_data = self._create_baseline_model()
                print("Created new ML anomaly model")
                
        except Exception as e:
            print(f"Error loading ML model: {e}")
            self.model_data = self._create_baseline_model()
    
    def _create_baseline_model(self) -> Dict:
        """Create baseline anomaly detection model."""
        return {
            'feature_means': {},
            'feature_stds': {},
            'correlation_matrix': {},
            'normal_ranges': {},
            'pattern_signatures': {},
            'training_data_size': 0,
            'last_training': time.time()
        }
    
    def collect_system_features(self) -> SystemFeature:
        """Collect current system features for analysis."""
        try:
            import psutil
            
            # Basic system metrics
            cpu_usage = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk_io = psutil.disk_io_counters()
            network_io = psutil.net_io_counters()
            
            # Process analysis
            processes = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']))
            process_count = len(processes)
            
            # Network connections
            connections = psutil.net_connections()
            network_connections = len(connections)
            
            # Calculate disk and network rates
            disk_io_rate = (disk_io.read_bytes + disk_io.write_bytes) if disk_io else 0
            network_io_rate = (network_io.bytes_sent + network_io.bytes_recv) if network_io else 0
            
            # Advanced feature extraction
            file_operations = self._count_file_operations()
            registry_operations = self._count_registry_operations()
            privilege_escalations = self._detect_privilege_escalations()
            suspicious_api_calls = self._count_suspicious_api_calls()
            entropy_score = self._calculate_system_entropy()
            
            return SystemFeature(
                timestamp=time.time(),
                process_count=process_count,
                network_connections=network_connections,
                cpu_usage=cpu_usage,
                memory_usage=memory.percent,
                disk_io_rate=disk_io_rate,
                network_io_rate=network_io_rate,
                file_operations=file_operations,
                registry_operations=registry_operations,
                privilege_escalations=privilege_escalations,
                suspicious_api_calls=suspicious_api_calls,
                entropy_score=entropy_score
            )
            
        except Exception as e:
            print(f"Error collecting system features: {e}")
            return SystemFeature(
                timestamp=time.time(),
                process_count=0, network_connections=0, cpu_usage=0.0,
                memory_usage=0.0, disk_io_rate=0.0, network_io_rate=0.0,
                file_operations=0, registry_operations=0, privilege_escalations=0,
                suspicious_api_calls=0, entropy_score=0.0
            )
    
    def _count_file_operations(self) -> int:
        """Count recent file operations."""
        try:
            # Simulate file operation counting
            # In real implementation, would monitor filesystem events
            return len(os.listdir('/tmp')) + len(os.listdir('/var/tmp'))
        except Exception:
            return 0
    
    def _count_registry_operations(self) -> int:
        """Count registry-like operations (config file changes on Linux)."""
        try:
            # Monitor config file modifications
            config_dirs = ['/etc', '/usr/local/etc']
            recent_changes = 0
            
            current_time = time.time()
            
            for config_dir in config_dirs:
                if os.path.exists(config_dir):
                    for root, dirs, files in os.walk(config_dir):
                        for file in files[:10]:  # Limit for performance
                            try:
                                file_path = os.path.join(root, file)
                                stat = os.stat(file_path)
                                if current_time - stat.st_mtime < 3600:  # Modified in last hour
                                    recent_changes += 1
                            except (OSError, PermissionError):
                                continue
                        break  # Only check top level for performance
            
            return recent_changes
        except Exception:
            return 0
    
    def _detect_privilege_escalations(self) -> int:
        """Detect recent privilege escalation attempts."""
        try:
            # Check auth logs for sudo/su usage
            auth_files = ['/var/log/auth.log', '/var/log/secure']
            escalations = 0
            
            current_time = time.time()
            
            for auth_file in auth_files:
                if os.path.exists(auth_file):
                    try:
                        with open(auth_file, 'r') as f:
                            # Read last 100 lines for performance
                            lines = f.readlines()[-100:]
                            
                        for line in lines:
                            if any(keyword in line.lower() for keyword in ['sudo', 'su:', 'elevation']):
                                escalations += 1
                                
                    except (PermissionError, OSError):
                        continue
            
            return escalations
        except Exception:
            return 0
    
    def _count_suspicious_api_calls(self) -> int:
        """Count suspicious API calls and system interactions."""
        try:
            import psutil
            
            suspicious_count = 0
            
            # Check for processes with suspicious characteristics
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                    
                    # Check for suspicious command patterns
                    suspicious_patterns = [
                        'nc -l', 'netcat', '/dev/tcp', 'bash -i', 'sh -i',
                        'python -c', 'perl -e', 'base64 -d', 'chmod +x',
                        'wget', 'curl', 'tftp', 'scp', 'rsync'
                    ]
                    
                    for pattern in suspicious_patterns:
                        if pattern in cmdline:
                            suspicious_count += 1
                            break
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return suspicious_count
        except Exception:
            return 0
    
    def _calculate_system_entropy(self) -> float:
        """Calculate system entropy for randomness detection."""
        try:
            # Calculate entropy based on process names and network activity
            entropy_sources = []
            
            import psutil
            
            # Process name entropy
            process_names = [proc.info['name'] for proc in psutil.process_iter(['name'])]
            process_entropy = self._calculate_shannon_entropy(''.join(process_names))
            entropy_sources.append(process_entropy)
            
            # Network connection entropy
            connections = psutil.net_connections()
            if connections:
                connection_data = ''.join([f"{conn.laddr.ip}{conn.laddr.port}" 
                                         for conn in connections if conn.laddr])
                network_entropy = self._calculate_shannon_entropy(connection_data)
                entropy_sources.append(network_entropy)
            
            return sum(entropy_sources) / len(entropy_sources) if entropy_sources else 0.0
            
        except Exception:
            return 0.0
    
    def _calculate_shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        # Count character frequencies
        frequencies = defaultdict(int)
        for char in data:
            frequencies[char] += 1
        
        # Calculate entropy
        length = len(data)
        entropy = 0.0
        
        for count in frequencies.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def analyze_features_for_anomalies(self, features: SystemFeature) -> List[AnomalyDetection]:
        """Analyze system features for anomalies using ML techniques."""
        anomalies = []
        
        try:
            # Update feature buffer
            self.feature_buffer.append(features)
            
            # Store features in database
            self._store_features(features)
            
            # Statistical anomaly detection
            statistical_anomalies = self._detect_statistical_anomalies(features)
            anomalies.extend(statistical_anomalies)
            
            # Pattern-based anomaly detection
            pattern_anomalies = self._detect_pattern_anomalies(features)
            anomalies.extend(pattern_anomalies)
            
            # Temporal anomaly detection
            temporal_anomalies = self._detect_temporal_anomalies(features)
            anomalies.extend(temporal_anomalies)
            
            # Behavioral anomaly detection
            behavioral_anomalies = self._detect_behavioral_anomalies(features)
            anomalies.extend(behavioral_anomalies)
            
            # Store anomalies in database
            for anomaly in anomalies:
                self._store_anomaly(anomaly)
            
        except Exception as e:
            print(f"Error analyzing features for anomalies: {e}")
        
        return anomalies
    
    def _detect_statistical_anomalies(self, features: SystemFeature) -> List[AnomalyDetection]:
        """Detect statistical anomalies using z-score analysis."""
        anomalies = []
        
        try:
            if len(self.feature_buffer) < 10:  # Need baseline data
                return anomalies
            
            # Calculate statistics for recent features
            recent_features = list(self.feature_buffer)[-50:]  # Last 50 observations
            
            feature_arrays = {
                'process_count': [f.process_count for f in recent_features],
                'network_connections': [f.network_connections for f in recent_features],
                'cpu_usage': [f.cpu_usage for f in recent_features],
                'memory_usage': [f.memory_usage for f in recent_features],
                'suspicious_api_calls': [f.suspicious_api_calls for f in recent_features]
            }
            
            # Calculate z-scores
            for feature_name, values in feature_arrays.items():
                if len(values) > 3:
                    mean_val = np.mean(values[:-1])  # Exclude current value
                    std_val = np.std(values[:-1])
                    current_val = getattr(features, feature_name)
                    
                    if std_val > 0:
                        z_score = abs((current_val - mean_val) / std_val)
                        
                        if z_score > self.anomaly_thresholds.get(feature_name.replace('_', ''), 2.5):
                            anomalies.append(AnomalyDetection(
                                timestamp=features.timestamp,
                                anomaly_type=f'statistical_{feature_name}',
                                confidence=min(z_score / 5.0, 1.0),
                                severity=self._calculate_severity(z_score),
                                description=f'Statistical anomaly in {feature_name}: z-score {z_score:.2f}',
                                features={feature_name: current_val, 'z_score': z_score},
                                risk_score=min(z_score * 0.2, 1.0),
                                recommended_actions=[
                                    f'Investigate {feature_name} spike',
                                    'Check system logs for related events',
                                    'Monitor for sustained anomalous behavior'
                                ]
                            ))
            
        except Exception as e:
            print(f"Error in statistical anomaly detection: {e}")
        
        return anomalies
    
    def _detect_pattern_anomalies(self, features: SystemFeature) -> List[AnomalyDetection]:
        """Detect pattern-based anomalies using sequence analysis."""
        anomalies = []
        
        try:
            if len(self.feature_buffer) < 20:
                return anomalies
            
            # Analyze patterns in recent feature sequences
            recent_features = list(self.feature_buffer)[-20:]
            
            # Check for unusual process creation patterns
            process_counts = [f.process_count for f in recent_features]
            if self._detect_process_pattern_anomaly(process_counts):
                anomalies.append(AnomalyDetection(
                    timestamp=features.timestamp,
                    anomaly_type='process_creation_pattern',
                    confidence=0.75,
                    severity='medium',
                    description='Unusual process creation pattern detected',
                    features={'pattern': 'process_burst'},
                    risk_score=0.6,
                    recommended_actions=[
                        'Investigate recent process creation',
                        'Check for malware spawning processes',
                        'Review system startup events'
                    ]
                ))
            
            # Check for network beaconing patterns
            network_counts = [f.network_connections for f in recent_features]
            if self._detect_beaconing_pattern(network_counts):
                anomalies.append(AnomalyDetection(
                    timestamp=features.timestamp,
                    anomaly_type='network_beaconing',
                    confidence=0.85,
                    severity='high',
                    description='Potential C&C beaconing pattern detected',
                    features={'pattern': 'network_beaconing'},
                    risk_score=0.8,
                    recommended_actions=[
                        'Analyze network traffic for C&C communication',
                        'Check for malware with periodic communication',
                        'Monitor external network connections'
                    ]
                ))
            
        except Exception as e:
            print(f"Error in pattern anomaly detection: {e}")
        
        return anomalies
    
    def _detect_temporal_anomalies(self, features: SystemFeature) -> List[AnomalyDetection]:
        """Detect temporal anomalies based on time-based patterns."""
        anomalies = []
        
        try:
            current_hour = datetime.fromtimestamp(features.timestamp).hour
            
            # Check for unusual activity during off-hours
            if current_hour < 6 or current_hour > 22:  # Night hours
                if (features.suspicious_api_calls > 5 or 
                    features.privilege_escalations > 2 or
                    features.network_connections > 50):
                    
                    anomalies.append(AnomalyDetection(
                        timestamp=features.timestamp,
                        anomaly_type='off_hours_activity',
                        confidence=0.7,
                        severity='medium',
                        description=f'Suspicious activity during off-hours ({current_hour}:00)',
                        features={
                            'hour': current_hour,
                            'suspicious_calls': features.suspicious_api_calls,
                            'escalations': features.privilege_escalations
                        },
                        risk_score=0.5,
                        recommended_actions=[
                            'Investigate off-hours system activity',
                            'Check for automated malware behavior',
                            'Review scheduled tasks and services'
                        ]
                    ))
            
            # Check for rapid changes in system state
            if len(self.feature_buffer) >= 5:
                recent_cpu = [f.cpu_usage for f in list(self.feature_buffer)[-5:]]
                recent_memory = [f.memory_usage for f in list(self.feature_buffer)[-5:]]
                
                cpu_variance = np.var(recent_cpu)
                memory_variance = np.var(recent_memory)
                
                if cpu_variance > 500 or memory_variance > 200:  # High variance
                    anomalies.append(AnomalyDetection(
                        timestamp=features.timestamp,
                        anomaly_type='rapid_state_change',
                        confidence=0.6,
                        severity='low',
                        description='Rapid changes in system resource usage',
                        features={
                            'cpu_variance': cpu_variance,
                            'memory_variance': memory_variance
                        },
                        risk_score=0.4,
                        recommended_actions=[
                            'Monitor system stability',
                            'Check for resource-intensive processes',
                            'Look for denial-of-service attacks'
                        ]
                    ))
            
        except Exception as e:
            print(f"Error in temporal anomaly detection: {e}")
        
        return anomalies
    
    def _detect_behavioral_anomalies(self, features: SystemFeature) -> List[AnomalyDetection]:
        """Detect behavioral anomalies using advanced ML techniques."""
        anomalies = []
        
        try:
            # Isolation Forest-like anomaly detection
            anomaly_score = self._calculate_isolation_score(features)
            
            if anomaly_score > 0.7:
                anomalies.append(AnomalyDetection(
                    timestamp=features.timestamp,
                    anomaly_type='behavioral_anomaly',
                    confidence=anomaly_score,
                    severity=self._calculate_severity(anomaly_score * 5),
                    description=f'Behavioral anomaly detected (score: {anomaly_score:.3f})',
                    features=asdict(features),
                    risk_score=anomaly_score,
                    recommended_actions=[
                        'Perform deep system analysis',
                        'Check for advanced persistent threats',
                        'Review system behavior patterns'
                    ]
                ))
            
            # Clustering-based anomaly detection
            cluster_anomaly = self._detect_cluster_anomaly(features)
            if cluster_anomaly:
                anomalies.append(cluster_anomaly)
            
        except Exception as e:
            print(f"Error in behavioral anomaly detection: {e}")
        
        return anomalies
    
    def _calculate_isolation_score(self, features: SystemFeature) -> float:
        """Calculate isolation-based anomaly score."""
        try:
            if len(self.feature_buffer) < 10:
                return 0.0
            
            # Create feature vector
            feature_vector = [
                features.process_count,
                features.network_connections,
                features.cpu_usage,
                features.memory_usage,
                features.suspicious_api_calls,
                features.privilege_escalations,
                features.entropy_score
            ]
            
            # Normalize features
            normalized_vector = self._normalize_features(feature_vector)
            
            # Calculate distance from normal behavior
            normal_vectors = []
            for f in list(self.feature_buffer)[-20:]:
                normal_vector = [
                    f.process_count, f.network_connections, f.cpu_usage,
                    f.memory_usage, f.suspicious_api_calls, f.privilege_escalations,
                    f.entropy_score
                ]
                normal_vectors.append(self._normalize_features(normal_vector))
            
            if normal_vectors:
                # Calculate average distance to normal samples
                distances = []
                for nv in normal_vectors:
                    # Calculate Euclidean distance
                    distance = sum((a - b) ** 2 for a, b in zip(normalized_vector, nv)) ** 0.5
                    distances.append(distance)
                
                avg_distance = sum(distances) / len(distances)
                
                # Convert distance to anomaly score (0-1)
                anomaly_score = min(avg_distance / 5.0, 1.0)
                return anomaly_score
            
        except Exception as e:
            print(f"Error calculating isolation score: {e}")
        
        return 0.0
    
    def _normalize_features(self, feature_vector):
        """Normalize feature vector using min-max scaling."""
        try:
            if len(self.feature_buffer) < 5:
                return feature_vector
            
            # Calculate min/max from recent features
            recent_features = list(self.feature_buffer)[-20:]
            feature_arrays = [
                [f.process_count, f.network_connections, f.cpu_usage,
                 f.memory_usage, f.suspicious_api_calls, f.privilege_escalations,
                 f.entropy_score] for f in recent_features
            ]
            
            if not feature_arrays:
                return feature_vector
            
            # Calculate min/max for each feature
            min_vals = []
            max_vals = []
            for i in range(len(feature_vector)):
                feature_values = [row[i] for row in feature_arrays]
                min_vals.append(min(feature_values))
                max_vals.append(max(feature_values))
            
            # Normalize features
            normalized = []
            for i, val in enumerate(feature_vector):
                range_val = max_vals[i] - min_vals[i]
                if range_val == 0:
                    range_val = 1
                norm_val = (val - min_vals[i]) / range_val
                normalized.append(max(0, min(1, norm_val)))  # Clip to 0-1
            
            return normalized
            
        except Exception:
            return feature_vector
    
    def _detect_cluster_anomaly(self, features: SystemFeature) -> Optional[AnomalyDetection]:
        """Detect anomalies using clustering-based approach."""
        try:
            if len(self.feature_buffer) < 15:
                return None
            
            # Simple k-means-like clustering
            feature_vector = [
                features.process_count, features.network_connections,
                features.cpu_usage, features.memory_usage,
                features.suspicious_api_calls
            ]
            
            # Calculate distance to cluster centers (simplified)
            recent_vectors = []
            for f in list(self.feature_buffer)[-15:]:
                vector = [f.process_count, f.network_connections, 
                         f.cpu_usage, f.memory_usage, f.suspicious_api_calls]
                recent_vectors.append(vector)
            
            if recent_vectors:
                # Calculate centroid
                centroid = []
                for i in range(len(feature_vector)):
                    feature_values = [vec[i] for vec in recent_vectors]
                    centroid.append(sum(feature_values) / len(feature_values))
                
                # Calculate distance to centroid
                distance = sum((a - b) ** 2 for a, b in zip(feature_vector, centroid)) ** 0.5
                
                # Calculate threshold based on recent distances
                recent_distances = []
                for vec in recent_vectors:
                    dist = sum((a - b) ** 2 for a, b in zip(vec, centroid)) ** 0.5
                    recent_distances.append(dist)
                
                avg_distance = sum(recent_distances) / len(recent_distances)
                distance_variance = sum((d - avg_distance) ** 2 for d in recent_distances) / len(recent_distances)
                std_distance = distance_variance ** 0.5
                threshold = avg_distance + 2 * std_distance
                
                if distance > threshold and distance > 5.0:
                    return AnomalyDetection(
                        timestamp=features.timestamp,
                        anomaly_type='cluster_outlier',
                        confidence=min(distance / threshold, 1.0),
                        severity='medium',
                        description=f'System behavior outside normal cluster (distance: {distance:.2f})',
                        features={'distance': distance, 'threshold': threshold},
                        risk_score=min(distance / 20.0, 1.0),
                        recommended_actions=[
                            'Investigate outlier system behavior',
                            'Check for malware or system compromise',
                            'Review recent system changes'
                        ]
                    )
            
        except Exception as e:
            print(f"Error in cluster anomaly detection: {e}")
        
        return None
    
    def _detect_process_pattern_anomaly(self, process_counts: List[int]) -> bool:
        """Detect anomalous process creation patterns."""
        try:
            if len(process_counts) < 10:
                return False
            
            # Check for rapid process creation bursts
            recent_counts = process_counts[-5:]
            earlier_counts = process_counts[-10:-5]
            
            recent_avg = np.mean(recent_counts)
            earlier_avg = np.mean(earlier_counts)
            
            # Burst detection: significant increase in short time
            if recent_avg > earlier_avg * 1.5 and recent_avg > 20:
                return True
            
            # Check for regular periodic spikes
            if len(process_counts) >= 20:
                differences = np.diff(process_counts)
                if np.std(differences) > 10:  # High variance
                    return True
            
        except Exception:
            pass
        
        return False
    
    def _detect_beaconing_pattern(self, network_counts: List[int]) -> bool:
        """Detect network beaconing patterns."""
        try:
            if len(network_counts) < 15:
                return False
            
            # Look for periodic patterns
            autocorr = np.correlate(network_counts, network_counts, mode='full')
            autocorr = autocorr[autocorr.size // 2:]
            
            # Check for periodic spikes
            if len(autocorr) > 5:
                peaks = []
                for i in range(2, len(autocorr) - 2):
                    if (autocorr[i] > autocorr[i-1] and autocorr[i] > autocorr[i+1] and
                        autocorr[i] > np.mean(autocorr) + np.std(autocorr)):
                        peaks.append(i)
                
                # Beaconing if regular peaks found
                if len(peaks) >= 3:
                    intervals = np.diff(peaks)
                    if np.std(intervals) < 2.0:  # Regular intervals
                        return True
            
        except Exception:
            pass
        
        return False
    
    def _calculate_severity(self, score: float) -> str:
        """Calculate severity level from anomaly score."""
        if score > 4.0:
            return 'critical'
        elif score > 3.0:
            return 'high'
        elif score > 2.0:
            return 'medium'
        else:
            return 'low'
    
    def _store_features(self, features: SystemFeature):
        """Store system features in database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO feature_history (timestamp, features, anomaly_score, is_anomaly)
                    VALUES (?, ?, ?, ?)
                ''', (
                    features.timestamp,
                    json.dumps(asdict(features)),
                    0.0,  # Will be updated after anomaly analysis
                    False
                ))
                conn.commit()
        except Exception as e:
            print(f"Error storing features: {e}")
    
    def _store_anomaly(self, anomaly: AnomalyDetection):
        """Store anomaly detection in database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO anomaly_detections 
                    (timestamp, anomaly_type, confidence, severity, description, features, risk_score, actions)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    anomaly.timestamp,
                    anomaly.anomaly_type,
                    anomaly.confidence,
                    anomaly.severity,
                    anomaly.description,
                    json.dumps(anomaly.features),
                    anomaly.risk_score,
                    json.dumps(anomaly.recommended_actions)
                ))
                conn.commit()
        except Exception as e:
            print(f"Error storing anomaly: {e}")
    
    def start_continuous_monitoring(self, interval: int = 30):
        """Start continuous ML-based anomaly monitoring."""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, args=(interval,))
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        print(f"Started ML anomaly monitoring (interval: {interval}s)")
    
    def stop_continuous_monitoring(self):
        """Stop continuous monitoring."""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        print("Stopped ML anomaly monitoring")
    
    def _monitoring_loop(self, interval: int):
        """Main monitoring loop."""
        while self.monitoring_active:
            try:
                # Collect features
                features = self.collect_system_features()
                
                # Analyze for anomalies
                anomalies = self.analyze_features_for_anomalies(features)
                
                # Notify callbacks of anomalies
                for anomaly in anomalies:
                    for callback in self.detection_callbacks:
                        callback(anomaly)
                
                time.sleep(interval)
                
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                time.sleep(interval)
    
    def train_model_on_normal_data(self, training_duration: int = 3600):
        """Train anomaly detection model on normal system behavior."""
        try:
            print(f"Training ML model for {training_duration} seconds...")
            
            training_features = []
            start_time = time.time()
            
            while time.time() - start_time < training_duration:
                features = self.collect_system_features()
                training_features.append(features)
                time.sleep(60)  # Collect every minute
            
            # Update model with training data
            self._update_model_with_training_data(training_features)
            
            # Save model
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model_data, f)
            
            print(f"Model training completed with {len(training_features)} samples")
            return True
            
        except Exception as e:
            print(f"Error training model: {e}")
            return False
    
    def _update_model_with_training_data(self, training_features: List[SystemFeature]):
        """Update model parameters with training data."""
        try:
            if not training_features:
                return
            
            # Calculate feature statistics
            feature_arrays = {
                'process_count': [f.process_count for f in training_features],
                'network_connections': [f.network_connections for f in training_features],
                'cpu_usage': [f.cpu_usage for f in training_features],
                'memory_usage': [f.memory_usage for f in training_features],
                'suspicious_api_calls': [f.suspicious_api_calls for f in training_features],
                'privilege_escalations': [f.privilege_escalations for f in training_features]
            }
            
            # Update model statistics
            for feature_name, values in feature_arrays.items():
                self.model_data['feature_means'][feature_name] = np.mean(values)
                self.model_data['feature_stds'][feature_name] = np.std(values)
                self.model_data['normal_ranges'][feature_name] = {
                    'min': np.min(values),
                    'max': np.max(values),
                    'q25': np.percentile(values, 25),
                    'q75': np.percentile(values, 75)
                }
            
            self.model_data['training_data_size'] = len(training_features)
            self.model_data['last_training'] = time.time()
            
        except Exception as e:
            print(f"Error updating model: {e}")
    
    def get_anomaly_statistics(self) -> Dict:
        """Get ML anomaly detection statistics."""
        stats = {
            'model_info': {
                'training_size': self.model_data.get('training_data_size', 0),
                'last_training': self.model_data.get('last_training', 0),
                'features_tracked': len(self.model_data.get('feature_means', {}))
            },
            'recent_anomalies': 0,
            'anomaly_types': {},
            'risk_distribution': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
            'monitoring_status': 'active' if self.monitoring_active else 'inactive'
        }
        
        try:
            # Get recent anomaly statistics
            with sqlite3.connect(self.db_path) as conn:
                # Count recent anomalies (last 24 hours)
                cursor = conn.execute('''
                    SELECT COUNT(*) FROM anomaly_detections 
                    WHERE timestamp > ?
                ''', (time.time() - 86400,))
                stats['recent_anomalies'] = cursor.fetchone()[0]
                
                # Count by type
                cursor = conn.execute('''
                    SELECT anomaly_type, COUNT(*) FROM anomaly_detections 
                    WHERE timestamp > ?
                    GROUP BY anomaly_type
                ''', (time.time() - 86400,))
                
                for anomaly_type, count in cursor.fetchall():
                    stats['anomaly_types'][anomaly_type] = count
                
                # Count by severity
                cursor = conn.execute('''
                    SELECT severity, COUNT(*) FROM anomaly_detections 
                    WHERE timestamp > ?
                    GROUP BY severity
                ''', (time.time() - 86400,))
                
                for severity, count in cursor.fetchall():
                    if severity in stats['risk_distribution']:
                        stats['risk_distribution'][severity] = count
        
        except Exception as e:
            stats['error'] = str(e)
        
        return stats
    
    def export_ml_analysis(self, output_path: str):
        """Export ML anomaly analysis report."""
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'model_statistics': self.get_anomaly_statistics(),
            'recent_features': [asdict(f) for f in list(self.feature_buffer)[-100:]],
            'model_configuration': {
                'thresholds': self.anomaly_thresholds,
                'feature_weights': self.feature_weights
            }
        }
        
        # Get recent anomalies from database
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT * FROM anomaly_detections 
                    WHERE timestamp > ?
                    ORDER BY timestamp DESC
                    LIMIT 500
                ''', (time.time() - 604800,))  # Last week
                
                anomalies = []
                for row in cursor.fetchall():
                    anomalies.append({
                        'timestamp': row[1],
                        'type': row[2],
                        'confidence': row[3],
                        'severity': row[4],
                        'description': row[5],
                        'risk_score': row[7]
                    })
                
                export_data['recent_anomalies'] = anomalies
        
        except Exception as e:
            export_data['export_error'] = str(e)
        
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
    
    def add_detection_callback(self, callback):
        """Add callback for anomaly detections."""
        self.detection_callbacks.append(callback)
    
    def get_real_time_risk_assessment(self) -> Dict:
        """Get real-time system risk assessment."""
        try:
            current_features = self.collect_system_features()
            recent_anomalies = self.analyze_features_for_anomalies(current_features)
            
            # Calculate current risk level
            if recent_anomalies:
                max_risk = max(a.risk_score for a in recent_anomalies)
                avg_confidence = np.mean([a.confidence for a in recent_anomalies])
            else:
                max_risk = 0.0
                avg_confidence = 0.0
            
            # Get historical context
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT AVG(risk_score) FROM anomaly_detections 
                    WHERE timestamp > ?
                ''', (time.time() - 3600,))  # Last hour
                
                avg_hourly_risk = cursor.fetchone()[0] or 0.0
            
            risk_level = 'low'
            if max_risk > 0.8 or avg_hourly_risk > 0.6:
                risk_level = 'critical'
            elif max_risk > 0.6 or avg_hourly_risk > 0.4:
                risk_level = 'high'
            elif max_risk > 0.4 or avg_hourly_risk > 0.2:
                risk_level = 'medium'
            
            return {
                'timestamp': time.time(),
                'current_risk_score': max_risk,
                'average_confidence': avg_confidence,
                'hourly_average_risk': avg_hourly_risk,
                'risk_level': risk_level,
                'active_anomalies': len(recent_anomalies),
                'system_features': asdict(current_features),
                'trend': 'increasing' if max_risk > avg_hourly_risk else 'stable'
            }
            
        except Exception as e:
            return {
                'timestamp': time.time(),
                'error': str(e),
                'risk_level': 'unknown'
            }