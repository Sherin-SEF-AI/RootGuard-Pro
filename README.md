# RootGuard Pro

A comprehensive, professional-grade rootkit detection and security analysis application built with PyQt6 for Linux systems.

## Overview

RootGuard Pro is an advanced security tool designed for defensive cybersecurity analysis, providing multi-layered rootkit detection capabilities through behavioral analysis, memory forensics, kernel integrity verification, and AI-powered anomaly detection.

## Features

### Core Analysis Modules
- **Process Analysis** - Advanced process behavior monitoring with anomaly detection
- **Service Analysis** - SystemD and init service integrity verification  
- **Network Analysis** - Deep packet inspection and beaconing detection
- **System Hooks** - Detection of system call hooks and API modifications
- **File Integrity Monitoring** - Real-time inotify-based file system monitoring
- **Signature Database** - Comprehensive rootkit signature matching
- **Kernel Integrity** - Kernel module verification and security analysis
- **YARA Scanner** - Malware detection using YARA rules
- **ML Anomaly Detection** - AI-powered behavioral analysis
- **Timeline Analysis** - Forensic incident reconstruction
- **Threat Intelligence** - IOC matching and intelligence feed integration

### Advanced Capabilities
- Real-time monitoring with background threads
- Machine learning anomaly detection
- Event correlation and pattern analysis
- Forensic timeline reconstruction
- Threat intelligence integration
- Comprehensive reporting and export functionality
- SQLite databases for baselines and historical data
- Dark theme professional UI

## System Requirements

- **Operating System**: Ubuntu/Debian Linux
- **Python**: 3.8+
- **Privileges**: Root access required for system-level analysis
- **Dependencies**: PyQt6, psutil, inotify_simple, requests

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Sherin-SEF-AI/RootGuard-Pro.git
cd RootGuard-Pro
```

2. Install dependencies:
```bash
# Option 1: System packages (recommended)
sudo apt update
sudo apt install python3-pyqt6 python3-psutil python3-requests
pip3 install inotify_simple --break-system-packages

# Option 2: Virtual environment
python3 -m venv rootguard-venv
source rootguard-venv/bin/activate
pip install PyQt6 psutil inotify_simple requests
```

## Usage

### Running the Application

**With system packages:**
```bash
sudo python3 main.py
```

**With virtual environment:**
```bash
source rootguard-venv/bin/activate
sudo ./rootguard-venv/bin/python main.py
```

### Application Interface

RootGuard Pro features a tabbed interface with specialized analysis modules:

1. **Process Analysis** - Monitor running processes for suspicious behavior
2. **Service Analysis** - Analyze system services and daemons
3. **Network Analysis** - Inspect network connections and traffic patterns
4. **System Hooks** - Detect API hooks and system modifications
5. **File Integrity** - Monitor file system changes in real-time
6. **Signatures** - Scan for known rootkit signatures and IOCs
7. **Kernel Integrity** - Verify kernel module integrity and security
8. **YARA Scanner** - Advanced malware detection using YARA rules
9. **ML Anomaly Detection** - AI-powered behavioral analysis
10. **Timeline Analysis** - Forensic incident reconstruction
11. **Threat Intelligence** - IOC matching and feed integration
12. **Reports** - Comprehensive analysis reporting

## Key Features

### Real-time Monitoring
- Continuous background scanning
- Automated anomaly detection
- Real-time file system monitoring
- Network traffic analysis

### Advanced Detection
- Behavioral analysis with scoring algorithms
- Memory forensics and process hollowing detection
- Kernel module integrity verification
- Machine learning anomaly detection
- YARA rule-based malware detection

### Forensic Capabilities
- Timeline event reconstruction
- Evidence collection and chain of custody
- Event correlation and pattern analysis
- Comprehensive incident reporting

### Threat Intelligence
- Multiple intelligence feed integration
- IOC matching and enrichment
- Custom indicator creation
- Automated feed updates

## Architecture

```
RootGuard-Pro/
├── main.py                 # Application entry point
├── src/
│   ├── detection/          # Core detection engines
│   │   ├── process_detector.py
│   │   ├── behavioral_analyzer.py
│   │   ├── memory_forensics.py
│   │   ├── file_integrity_monitor.py
│   │   ├── advanced_network_analyzer.py
│   │   ├── signature_database.py
│   │   ├── kernel_integrity.py
│   │   ├── yara_scanner.py
│   │   └── ml_anomaly_detector.py
│   ├── forensics/          # Forensic analysis
│   │   └── timeline_analyzer.py
│   ├── intelligence/       # Threat intelligence
│   │   └── threat_feeds.py
│   └── ui/                # User interface
│       ├── main_window.py
│       ├── styles.py
│       └── tabs/          # Analysis tab widgets
└── README.md
```

## Security Notice

RootGuard Pro is designed exclusively for **defensive security purposes**. This tool should only be used by authorized security professionals for:

- Incident response and forensic analysis
- Security monitoring and threat hunting
- System integrity verification
- Compliance and security assessments

## Contributing

This is a professional security tool. Contributions should focus on:
- Enhanced detection capabilities
- Performance improvements
- Additional threat intelligence sources
- Forensic analysis features

## License

Professional security tool for defensive cybersecurity analysis.

## Support

For issues, questions, or feature requests, please use the GitHub issue tracker.

---

**RootGuard Pro** - Professional Rootkit Detection and Security Analysis Suite