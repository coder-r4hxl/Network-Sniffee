from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP, ICMP


def parse_packet(packet):
    """Parse a scapy network packet and extract relevant IP and protocol metadata.

    Args:
        packet: Scapy packet object to parse.

    Returns:
        dict or None: A dictionary containing parsed packet info if the packet
        contains an IP layer and is valid, otherwise None.
    """
    try:
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        ts_val = float(getattr(packet, "time", datetime.now().timestamp()))
        timestamp = datetime.fromtimestamp(ts_val).strftime("%Y-%m-%d %H:%M:%S")

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        length = len(packet)

        src_port = None
        dst_port = None
        payload_bytes = b""

        if packet.haslayer(TCP):
            protocol = "TCP"
            tcp_layer = packet[TCP]
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)
            payload_bytes = bytes(tcp_layer.payload)
        elif packet.haslayer(UDP):
            protocol = "UDP"
            udp_layer = packet[UDP]
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)
            payload_bytes = bytes(udp_layer.payload)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            payload_bytes = bytes(packet[ICMP].payload)
        else:
            proto_num = getattr(ip_layer, "proto", None)
            if proto_num == 6:
                protocol = "TCP"
            elif proto_num == 17:
                protocol = "UDP"
            elif proto_num == 1:
                protocol = "ICMP"
            else:
                protocol = "OTHER"

        if payload_bytes:
            truncated = payload_bytes[:64]
            payload = "".join(
                chr(b) if 32 <= b <= 126 else "." for b in truncated
            )
        else:
            payload = ""

        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "length": length,
            "payload": payload,
        }
    except Exception:
        return None


def format_packet(info, number):
    """Format parsed packet metadata into a human-readable string.

    Args:
        info (dict): Parsed packet information returned by parse_packet.
        number (int): Sequential packet number.

    Returns:
        str: Formatted one-line summary of the packet.
    """
    if info["src_port"] is not None and info["dst_port"] is not None:
        addr_str = f"{info['src_ip']}:{info['src_port']} -> {info['dst_ip']}:{info['dst_port']}"
    else:
        addr_str = f"{info['src_ip']} -> {info['dst_ip']}"

    return f"[#{number}] {info['timestamp']} | {info['protocol']} | {addr_str} | {info['length']} bytes | payload: {info['payload']}"
