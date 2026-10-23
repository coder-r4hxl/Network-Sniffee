# Security Policy and Audit Report

## Threat Model
The CodeAlpha Basic Network Sniffer operates as a command-line interface tool that captures and logs network packet headers and payloads.
Key threat vectors and security considerations include:
1. **Malicious or Corrupted Packets:** Malformed network packets sent across local interfaces designed to crash sniffer parsers.
2. **Command Injection / Improper Input Handling:** Unvalidated CLI arguments (such as port or count bounds) leading to unexpected runtime errors or BPF filter logic bugs.
3. **Privilege Escalation & Output File Manipulation:** High-privilege packet sniffing running under `root`/Administrator writing log outputs to arbitrary system files or symlinks.
4. **Log Injection / Terminal Escape Sequences:** Binary or ASCII control characters embedded in packet payloads causing terminal injection attacks or unreadable log outputs.
5. **Sensitive Data Exposure:** Unencrypted packet payload inspection exposing credentials, tokens, or private communications in output logs or stdout.

## Security Audit Risks and Mitigations

| Vulnerability / Risk | Severity / Impact | Handling & Mitigation Mechanism |
|---|---|---|
| **Invalid CLI Inputs (`--port`, `--count`)** | Low / Logic Error | Range checks in `parse_args()` validate `--port` (1–65535) and `--count` (>= 0). On invalid input, prints error and exits with code 2. |
| **Malformed Packet Crashes** | Medium / DoS | `parse_packet()` wraps all packet parsing in `try...except Exception:` returning `None` safely without interrupting the capture loop. |
| **Symlink Attacks / Excessive File Permissions** | High / Privilege Escalation | `open_output_file()` checks `os.path.islink()` and uses `O_NOFOLLOW` to refuse writing to symlinks. Files are created with strict `0o600` permissions (owner read/write only). |
| **Control / Escape Character Injection** | Medium / Log Injection | Payloads are sanitized strictly allowing printable ASCII characters (`32 <= ord(c) <= 126`). Non-printable, control, and escape characters are replaced with `.`. |
| **Sensitive Captured Data Exposure** | High / Data Leak | Guidance included below and in documentation advising users never to commit `.log` or `.pcap` files containing network captures. `.gitignore` ignores capture files. |

## Static Analysis & Security Tool Findings

### `bandit -r .` Analysis
- **Finding:** `B101: assert_used` detected across test files in `tests/`.
- **Rationale:** `assert` statements are standard Python test assertions evaluated by `pytest`. They are acceptable in test suites and do not impact production code execution.

### `pip-audit` Analysis
- **Finding:** `pip-audit` scanned pinned production dependencies (`scapy==2.8.0`) and reported no known vulnerabilities.

## WARNING: Sensitive Data
Captured network packets may contain sensitive information including passwords, session tokens, personally identifiable information (PII), or confidential data.
- **Do NOT** commit log files or packet capture files (`*.log`, `*.pcap`) to version control.
- Ensure capture logs are stored securely on owner-restricted storage (`0o600` permission enforced by default).
