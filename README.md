# CodeAlpha Basic Network Sniffer

A lightweight, security-hardened Python network packet sniffer built with Scapy.
It captures network traffic, extracts IP and protocol metadata (TCP, UDP, ICMP), supports BPF filtering, and logs capture statistics.
Designed for network analysis, debugging, and educational security research with privacy-first default settings.

## Purpose & Verified Features

- **Metadata-Only Default Output:** By default, only non-sensitive packet metadata (timestamp, protocol, IP addresses, ports, total length) is printed and logged.
- **Opt-in Payload Preview (`--show-payload`):** Explicit flag to enable safe ASCII-sanitized payload previews (first 64 bytes, control characters replaced with `.`).
- **Protocol & Port Filtering:** BPF filter support for TCP, UDP, ICMP, and specific port bounds (1–65535).
- **Security & Privilege Safeguards:** Input validation, clean exit handling (code 2 for invalid args), symlink attack prevention, and strict `0o600` log file permissions.
- **Resource Cleanup:** Reliable capture finalization and summary reporting on completion or Ctrl+C interruption.

## Prerequisites & Supported Python Versions

- **Python Version:** Python 3.10, 3.11, or 3.12.
- **Dependencies:** `scapy==2.8.0`, `pytest==9.1.1`.

## Installation

1. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Linux/macOS
# or
venv\Scripts\activate     # On Windows
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

### OS Specific Setup Requirements

- **Linux / macOS:** Privileged execution (`sudo`) is required for raw network socket sniffing.
- **Windows Setup:** Npcap must be installed on Windows for packet capture. Download and install Npcap from [https://npcap.com/](https://npcap.com/). Ensure "Install Npcap in WinPcap API-compatible Mode" is selected during setup. Run Command Prompt or PowerShell as Administrator.

## Usage

### 1. List Available Network Interfaces
```bash
python3 sniffer.py --list-interfaces
```
Output:
```
eth0
lo
docker0
```

### 2. Basic Capture (Metadata-Only Default)
Capture 5 TCP packets on port 443:
```bash
sudo python3 sniffer.py -i eth0 -p tcp --port 443 -c 5
```
Output:
```
[#1] 2026-10-23 08:33:01 | TCP | 192.168.1.5:51234 -> 142.250.1.1:443 | 66 bytes
[#2] 2026-10-23 08:33:02 | TCP | 192.168.1.5:51235 -> 142.250.1.1:443 | 66 bytes
[#3] 2026-10-23 08:33:03 | TCP | 192.168.1.5:51236 -> 142.250.1.1:443 | 66 bytes
[#4] 2026-10-23 08:33:04 | TCP | 192.168.1.5:51237 -> 142.250.1.1:443 | 66 bytes
[#5] 2026-10-23 08:33:05 | TCP | 192.168.1.5:51238 -> 142.250.1.1:443 | 66 bytes
--- Capture Summary ---
Total packets: 5
TCP: 5
UDP: 0
ICMP: 0
OTHER: 0
```

### 3. Opt-in Payload Preview (`--show-payload`)
> **WARNING:** `--show-payload` prints raw packet payload previews to the console and log files. This may expose sensitive data (such as HTTP headers or credentials). Only use on authorized networks.

```bash
sudo python3 sniffer.py -i eth0 -p tcp --port 80 -c 1 --show-payload
```
Output:
```
[#1] 2026-10-23 08:33:01 | TCP | 192.168.1.5:51234 -> 142.250.1.1:80 | 66 bytes | payload: GET / HTTP
--- Capture Summary ---
Total packets: 1
TCP: 1
UDP: 0
ICMP: 0
OTHER: 0
```

### 4. Log Capture to Secure Log File
```bash
sudo python3 sniffer.py -p icmp -o capture.log
```
- Logs are created with `0o600` file permissions (owner read/write only).
- Symbolic link file paths are rejected to prevent symlink overwrite vulnerabilities.

## Automated Testing & CI

Run unit tests locally (no root privileges or live traffic required):
```bash
pytest
```

Run security static analysis:
```bash
bandit -r .
```

### CI Status
Automated continuous integration runs on GitHub Actions via `.github/workflows/ci.yml` across Python 3.10, 3.11, and 3.12 executing compilation checks, pytest suites, and bandit security scans.

## How It Works

1. **Packet Capture:** Uses Scapy's `sniff()` function to hook into OS network sockets and receive raw frames.
2. **BPF Filtering:** Constructs Berkeley Packet Filters (`tcp`, `udp`, `icmp`, `port <N>`) at the socket layer to minimize overhead.
3. **Safe Parsing:** Decodes IP headers, extracts transport ports, maps protocol numbers (including fragment fallbacks), and formats output.
4. **Sanitization & Privacy:** Sanitizes binary payloads into printable ASCII (range 32–126), masking control sequences as `.`. Payload output is omitted unless `--show-payload` is supplied.

## Privacy, Ethical Use & Legal Warning

- **Authorized Monitoring Only:** Strictly intended for educational research, network administration, and authorized security testing.
- **Privacy First:** Never capture network traffic on networks you do not own or lack explicit permission to monitor.
- **Do Not Commit Logs:** Capture log files (`*.log`, `*.pcap`) are git-ignored and must never be committed to version control.
