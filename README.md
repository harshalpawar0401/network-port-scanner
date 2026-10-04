# Python Network Port Scanner & Service Enumerator

A Python-based TCP network port scanner and basic service enumeration tool built for cybersecurity learning and authorized security testing.

## Features

- TCP port scanning
- Single-port and port-range scanning
- Multiple specific ports
- Hostname and IPv4 target resolution
- Concurrent scanning using multiple workers
- Common service identification
- Basic banner enumeration
- Configurable connection timeout
- TXT report generation
- JSON report generation
- Command-line interface
- Input validation and error handling

## Technologies

- Python 3
- TCP/IP
- Python Socket Programming
- Linux
- Git/GitHub

## Project Workflow

```text
Target
   ↓
Hostname/IP Resolution
   ↓
Port Parsing
   ↓
Concurrent TCP Scanning
   ↓
Open Port Detection
   ↓
Service Identification
   ↓
Basic Banner Enumeration
   ↓
Formatted Results
   ↓
TXT / JSON Reports
```

## Installation

Clone the repository:

```bash
git clone <your-github-repository-url>
cd network-port-scanner
```

No external Python packages are required. The project uses Python's standard library.

## Usage

### Scan a single port

```bash
python3 scanner.py 127.0.0.1 -p 8000
```

### Scan a port range

```bash
python3 scanner.py 127.0.0.1 -p 1-1000
```

### Scan multiple ports

```bash
python3 scanner.py 127.0.0.1 -p 22,80,443,8000
```

### Change timeout

```bash
python3 scanner.py 127.0.0.1 -p 1-1000 -t 2
```

### Change number of workers

```bash
python3 scanner.py 127.0.0.1 -p 1-1000 -w 100
```

### Disable banner enumeration

```bash
python3 scanner.py 127.0.0.1 -p 1-1000 --no-banner
```

### Change output filename

```bash
python3 scanner.py 127.0.0.1 -p 1-1000 --output my_scan
```

This creates:

```text
my_scan.txt
my_scan.json
```

## Example Output

```text
============================================================
       PYTHON NETWORK PORT SCANNER
============================================================
Target      : 127.0.0.1
Resolved IP : 127.0.0.1
Ports       : 1
Workers     : 50
============================================================
[+] 8000/tcp OPEN - HTTP
============================================================
SCAN COMPLETE
============================================================
Open ports : 1
Scan time  : 0.01 seconds
Text file  : scan_results.txt
JSON file  : scan_results.json
============================================================
```

## Testing

The scanner was tested against a local Python HTTP server running on:

```text
127.0.0.1:8000
```

Test cases include:

- Single-port scanning
- Port-range scanning
- Multiple-port scanning
- Hostname scanning
- Open-port detection
- Invalid port handling
- Invalid target handling
- TXT report generation
- JSON report generation
- Command-line help

## Limitations

This project is an educational TCP scanner and is not intended to replace mature tools such as Nmap.

Service names are based on common port mappings and basic banner responses where available. They should be independently verified during a real security assessment.

## Legal Notice

Use this tool only against systems you own or systems for which you have explicit authorization to perform security testing.

Unauthorized scanning may violate organizational policies or applicable laws.

## Author

Cybersecurity learning project focused on networking, Python, Linux, and security assessment fundamentals.