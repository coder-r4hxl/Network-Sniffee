import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Raw

from parser import parse_packet, format_packet
from sniffer import build_bpf_filter


def test_parse_packet_tcp():
    pkt = IP(src="192.168.1.5", dst="142.250.1.1") / TCP(sport=51234, dport=443) / Raw(load=b"GET / HTTP")
    parsed = parse_packet(pkt)
    assert parsed is not None
    assert parsed["src_ip"] == "192.168.1.5"
    assert parsed["dst_ip"] == "142.250.1.1"
    assert parsed["protocol"] == "TCP"
    assert parsed["src_port"] == 51234
    assert parsed["dst_port"] == 443
    assert parsed["length"] == len(pkt)
    assert parsed["payload"] == "GET / HTTP"


def test_parse_packet_udp():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1234, dport=53) / Raw(load=b"dns query")
    parsed = parse_packet(pkt)
    assert parsed is not None
    assert parsed["src_ip"] == "10.0.0.1"
    assert parsed["dst_ip"] == "10.0.0.2"
    assert parsed["protocol"] == "UDP"
    assert parsed["src_port"] == 1234
    assert parsed["dst_port"] == 53
    assert parsed["payload"] == "dns query"


def test_parse_packet_icmp():
    pkt = IP(src="192.168.1.5", dst="8.8.8.8") / ICMP()
    parsed = parse_packet(pkt)
    assert parsed is not None
    assert parsed["src_ip"] == "192.168.1.5"
    assert parsed["dst_ip"] == "8.8.8.8"
    assert parsed["protocol"] == "ICMP"
    assert parsed["src_port"] is None
    assert parsed["dst_port"] is None
    assert parsed["payload"] == ""


def test_icmp_payload():
    pkt = IP() / ICMP() / Raw(b"hello")
    parsed = parse_packet(pkt)
    assert parsed is not None
    assert parsed["protocol"] == "ICMP"
    assert parsed["payload"] == "hello"


def test_fragment_classification():
    pkt = IP(proto=6, frag=185) / Raw(b"x" * 20)
    parsed = parse_packet(pkt)
    assert parsed is not None
    assert parsed["protocol"] == "TCP"
    assert parsed["src_port"] is None
    assert parsed["dst_port"] is None
    assert parsed["payload"] == ""


def test_parse_non_ip_packet():
    pkt = Ether() / ARP()
    parsed = parse_packet(pkt)
    assert parsed is None


def test_payload_truncation_and_non_printable():
    long_raw = b"A" * 70 + b"\x00\x01\x1f" + b"B"
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=80, dport=80) / Raw(load=long_raw)
    parsed = parse_packet(pkt)
    assert parsed is not None
    assert len(parsed["payload"]) == 64
    assert parsed["payload"] == "A" * 64


def test_payload_non_printable_bytes():
    raw_data = b"Hello\x00\x07World\xff!"
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=80, dport=80) / Raw(load=raw_data)
    parsed = parse_packet(pkt)
    assert parsed is not None
    assert parsed["payload"] == "Hello..World.!"


def test_format_packet_tcp():
    info = {
        "timestamp": "2026-10-23 08:33:01",
        "protocol": "TCP",
        "src_ip": "192.168.1.5",
        "src_port": 51234,
        "dst_ip": "142.250.1.1",
        "dst_port": 443,
        "length": 66,
        "payload": "GET / HTTP",
    }
    formatted = format_packet(info, 1)
    assert formatted == "[#1] 2026-10-23 08:33:01 | TCP | 192.168.1.5:51234 -> 142.250.1.1:443 | 66 bytes | payload: GET / HTTP"


def test_format_packet_icmp():
    info = {
        "timestamp": "2026-10-23 08:33:01",
        "protocol": "ICMP",
        "src_ip": "192.168.1.5",
        "src_port": None,
        "dst_ip": "8.8.8.8",
        "dst_port": None,
        "length": 28,
        "payload": "",
    }
    formatted = format_packet(info, 2)
    assert formatted == "[#2] 2026-10-23 08:33:01 | ICMP | 192.168.1.5 -> 8.8.8.8 | 28 bytes | payload: "


def test_build_bpf_filter():
    assert build_bpf_filter("all", None) is None
    assert build_bpf_filter("tcp", None) == "tcp"
    assert build_bpf_filter("udp", 53) == "udp and port 53"
    assert build_bpf_filter("icmp", None) == "icmp"
    assert build_bpf_filter("all", 80) == "port 80"

    with pytest.raises(SystemExit) as excinfo:
        build_bpf_filter("icmp", 80)
    assert excinfo.value.code == 2
