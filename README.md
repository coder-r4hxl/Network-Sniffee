# CodeAlpha Basic Network Sniffer
A lightweight Python network packet sniffer built with Scapy.
It captures network traffic, extracts IP/port details and payloads, and supports protocol filtering.
Designed for network analysis, debugging, and educational security research.

## Installation

1. Create and activate a virtual environment (optional but recommended):
```bash
python3 -m venv venv
source venv/bin/activate
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

> **Note for Windows Users:** Npcap must be installed on Windows for raw packet capture. Download and install it from https://npcap.com/. Ensure "Install Npcap in WinPcap API-compatible Mode" is selected during setup.

## Usage

List available network interfaces:
```bash
python3 sniffer.py --list-interfaces
```
Output:
```
eth0
lo
docker0
```

Capture 5 TCP packets on port 443:
```bash
sudo python3 sniffer.py -i eth0 -p tcp --port 443 -c 5
```
Output:
```
[#1] 2026-10-23 08:33:01 | TCP | 192.168.1.5:51234 -> 142.250.1.1:443 | 66 bytes | payload: GET / HTTP
[#2] 2026-10-23 08:33:02 | TCP | 192.168.1.5:51235 -> 142.250.1.1:443 | 66 bytes | payload: GET / HTTP
[#3] 2026-10-23 08:33:03 | TCP | 192.168.1.5:51236 -> 142.250.1.1:443 | 66 bytes | payload: GET / HTTP
[#4] 2026-10-23 08:33:04 | TCP | 192.168.1.5:51237 -> 142.250.1.1:443 | 66 bytes | payload: GET / HTTP
[#5] 2026-10-23 08:33:05 | TCP | 192.168.1.5:51238 -> 142.250.1.1:443 | 66 bytes | payload: GET / HTTP
--- Capture Summary ---
Total packets: 5
TCP: 5
UDP: 0
ICMP: 0
OTHER: 0
```

Capture ICMP traffic and output logs to file:
```bash
sudo python3 sniffer.py -p icmp -o capture.log
```
Output:
```
[#1] 2026-10-23 08:33:10 | ICMP | 192.168.1.5 -> 8.8.8.8 | 28 bytes | payload:
[#2] 2026-10-23 08:33:11 | ICMP | 8.8.8.8 -> 192.168.1.5 | 28 bytes | payload:
^C
--- Capture Summary ---
Total packets: 2
TCP: 0
UDP: 0
ICMP: 2
OTHER: 0
```

Capture 10 UDP packets on port 53:
```bash
sudo python3 sniffer.py -p udp --port 53 -c 10
```
Output:
```
[#1] 2026-10-23 08:34:00 | UDP | 192.168.1.5:54321 -> 8.8.8.8:53 | 48 bytes | payload: dns query
--- Capture Summary ---
Total packets: 1
TCP: 0
UDP: 1
ICMP: 0
OTHER: 0
```

## How It Works

Network packet sniffers listen to data transmitted across network interfaces. Packets are wrapped in multiple protocol layers (Ethernet frame, IP packet, TCP/UDP segment). Scapy captures raw network frames directly from the interface, decodes IP headers to extract source/destination addresses, identifies transport layer protocols (TCP, UDP, ICMP), parses port numbers, and formats the raw binary payload into printable ASCII strings.

## Ethical Use

This tool is strictly intended for educational, network testing, and security analysis purposes. You must only capture network traffic on networks you own or have explicit authorization to monitor. Unauthorized network packet interception may violate privacy laws and network security policies.
