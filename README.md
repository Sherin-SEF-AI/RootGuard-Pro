# RootGuard Pro

A comprehensive, professional-grade rootkit detection and security analysis application built with PyQt6 for Linux systems.


<img width="1919" height="1012" alt="Screenshot from 2025-09-02 21-03-37" src="https://github.com/user-attachments/assets/a864cedc-39d9-4ac1-8b9b-fe4e05bf5c4d" />
<img width="1919" height="1012" alt="Screenshot from 2025-09-02 21-03-37" src="https://github.com/user-attachments/assets/f0ead394-852d-4e74-9e2d-6b05156c015f" />


## Overview

RootGuard Pro is an advanced security tool designed for defensive cybersecurity analysis, providing multi-layered rootkit detection capabilities through behavioral analysis, memory forensics, kernel integrity verification, and AI-powered anomaly detection.
<img width="1919" height="1012" alt="Screenshot from 2025-09-02 21-04-18" src="https://github.com/user-attachments/assets/f81618cb-8728-440d-92ca-21e87c868719" />
<img width="1919" height="1012" alt="Screenshot from 2025-09-02 21-04-46" src="https://github.com/user-attachments/assets/814abd75-3f25-4986-96e0-901e27b5744b" />


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
<img width="1919" height="1012" alt="Screenshot from 2025-09-02 21-04-51" src="https://github.com/user-attachments/assets/a7f09828-62aa-484b-8bd4-7f3679fec63d" />
<img width="1919" height="1012" alt="Screenshot from 2025-09-02 21-04-53" src="https://github.com/user-attachments/assets/0af78fa4-62f1-4c1d-b80e-b206735be230" />
<img width="1919" height="1012" alt="Screenshot from 2025-09-02 21-04-57" src="https://github.com/user-attachments/assets/f025f9e1-e10f-4998-b434-502227b391fe" />
<img width="1919" height="1012" alt="Screenshot from 2025-09-02 21-04-59" src="https://github.com/user-attachments/assets/92141b6e-52d6-4ca3-b99e-834c0d39a906" />


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

<img width="1919" height="1012" alt="Screenshot from 2025-09-02 21-05-01" src="https://github.com/user-attachments/assets/eaed1be6-6a43-476a-80d8-439456d69055" />

<img width="1919" height="1012" alt="Screenshot from 2025-09-02 21-05-16" src="https://github.com/user-attachments/assets/a41917f9-fc58-44c0-a7af-550d37ff83ba" />

<img width="1919" height="1012" alt="Screenshot from 2025-09-02 21-05-24" src="https://github.com/user-attachments/assets/06355294-553a-4813-89a4-f085cc30b7d1" />

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
