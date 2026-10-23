import os
import sys
import pytest
from unittest.mock import patch
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from parser import parse_packet
from sniffer import parse_args, open_output_file, write_log, StopCapture


def test_parse_packet_malformed_returns_none():
    class FaultyPacket:
        def haslayer(self, layer):
            raise RuntimeError("Corrupted layer")

    parsed = parse_packet(FaultyPacket())
    assert parsed is None


def test_payload_no_control_or_escape_characters():
    all_control_bytes = bytes(range(0, 32)) + bytes([127]) + b"\x1b[31mRed\x1b[0m\r\n\t"
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=80, dport=80) / Raw(load=all_control_bytes)
    parsed = parse_packet(pkt)
    assert parsed is not None
    payload = parsed["payload"]
    for char in payload:
        assert 32 <= ord(char) <= 126, f"Character {ord(char)} outside allowed range"


def test_invalid_port_arg():
    for invalid_port in ["0", "65536"]:
        with pytest.raises(SystemExit) as excinfo:
            parse_args(["--port", invalid_port])
        assert excinfo.value.code == 2

    parsed = parse_args(["--port", "80"])
    assert parsed.port == 80


def test_invalid_count_arg():
    with pytest.raises(SystemExit) as excinfo:
        parse_args(["-c", "-5"])
    assert excinfo.value.code == 2


def test_output_file_symlink_rejection(tmp_path):
    target_file = tmp_path / "target.log"
    target_file.write_text("initial")
    symlink_file = tmp_path / "symlink.log"
    os.symlink(target_file, symlink_file)

    with pytest.raises(SystemExit) as excinfo:
        open_output_file(str(symlink_file))
    assert excinfo.value.code == 1


def test_output_file_open_errors(tmp_path, capsys):
    missing_dir_path = str(tmp_path / "non_existent_dir" / "file.log")
    with pytest.raises(SystemExit) as excinfo:
        open_output_file(missing_dir_path)
    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert "Error: cannot open output file" in captured.out

    dir_path = str(tmp_path)
    with pytest.raises(SystemExit) as excinfo:
        open_output_file(dir_path)
    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert "Error: cannot open output file" in captured.out


def test_output_file_permissions(tmp_path):
    log_file = tmp_path / "test_capture.log"
    f = open_output_file(str(log_file))
    f.write("test entry\n")
    f.close()

    if os.name == "posix":
        mode = os.stat(log_file).st_mode & 0o777
        assert mode == 0o600


def test_write_log_failure_on_closed_file(tmp_path, capsys):
    log_path = str(tmp_path / "closed.log")
    f = open(log_path, "w")
    f.close()

    with pytest.raises(StopCapture):
        write_log(f, log_path, "test line")

    captured = capsys.readouterr()
    assert f"Error: cannot write to '{log_path}'" in captured.out
    assert "invalid interface" not in captured.out
