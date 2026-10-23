import argparse
import sys
from datetime import datetime
from scapy.all import sniff, get_if_list
from scapy.error import Scapy_Exception
from parser import parse_packet, format_packet


def parse_args():
    """Parse command-line arguments for the network sniffer.

    Returns:
        argparse.Namespace: Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(description="CodeAlpha Basic Network Sniffer")
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        default=None,
        help="Network interface to sniff on",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited)",
    )
    parser.add_argument(
        "-p",
        "--protocol",
        choices=["tcp", "udp", "icmp", "all"],
        default="all",
        help="Protocol filter",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port filter",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Output log file path",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit",
    )
    return parser.parse_args()


def build_bpf_filter(protocol, port):
    """Build a BPF filter string based on protocol and port.

    Args:
        protocol (str): Protocol choice ("tcp", "udp", "icmp", or "all").
        port (int or None): Port number to filter on.

    Returns:
        str or None: BPF filter string or None if no filter is required.
    """
    if protocol == "icmp" and port is not None:
        print("Error: --port cannot be used with icmp")
        sys.exit(2)

    parts = []
    if protocol in ("tcp", "udp", "icmp"):
        parts.append(protocol)

    if port is not None:
        parts.append(f"port {port}")

    if not parts:
        return None

    return " and ".join(parts)


def main():
    """Main entry point for the network sniffer application."""
    args = parse_args()

    if args.list_interfaces:
        for iface in get_if_list():
            print(iface)
        sys.exit(0)

    bpf = build_bpf_filter(args.protocol, args.port)

    out_file = None
    if args.output:
        out_file = open(args.output, "a")
        start_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        out_file.write(f"# Capture started {start_ts}\n")
        out_file.flush()

    packet_count = 0
    counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}

    def packet_handler(pkt):
        nonlocal packet_count
        info = parse_packet(pkt)
        if info is None:
            return

        packet_count += 1
        proto = info["protocol"]
        if proto in counts:
            counts[proto] += 1
        else:
            counts["OTHER"] += 1

        formatted = format_packet(info, packet_count)
        print(formatted)
        if out_file:
            out_file.write(formatted + "\n")
            out_file.flush()

    try:
        sniff(
            iface=args.interface,
            filter=bpf,
            prn=packet_handler,
            count=args.count,
            store=False,
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print(
            "Error: administrator/root privileges required. Use sudo (Linux/macOS) or run as Administrator (Windows)."
        )
        if out_file:
            out_file.close()
        sys.exit(1)
    except (OSError, Scapy_Exception, ValueError):
        print(f"Error: invalid interface '{args.interface}'.")
        if out_file:
            out_file.close()
        sys.exit(1)

    summary_lines = [
        "--- Capture Summary ---",
        f"Total packets: {packet_count}",
        f"TCP: {counts['TCP']}",
        f"UDP: {counts['UDP']}",
        f"ICMP: {counts['ICMP']}",
        f"OTHER: {counts['OTHER']}",
    ]
    summary_text = "\n".join(summary_lines)
    print(summary_text)

    if out_file:
        out_file.write(summary_text + "\n")
        out_file.close()

    sys.exit(0)


if __name__ == "__main__":
    main()
