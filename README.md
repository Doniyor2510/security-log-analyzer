# Security Log Analyzer

A Bash-based security log analysis tool that parses Linux system logs to detect brute-force attacks, privilege escalation, suspicious patterns, and anomalous activity. Includes a live monitoring mode.

## Features

| Module | What It Detects |
|--------|----------------|
| **Brute-Force Detection** | Failed SSH logins by IP and username, threshold alerts |
| **Auth Event Tracking** | Successful logins, root access, password vs pubkey |
| **Pivot Detection** | IPs with failures followed by success (brute-force win) |
| **Sudo & Privilege Escalation** | Commands run via sudo, failed sudo, dangerous commands |
| **User/Group Changes** | useradd, userdel, usermod, password changes |
| **System Anomalies** | Segfaults, OOM kills, kernel panics |
| **Firewall Analysis** | UFW/iptables blocks, top blocked IPs and ports |
| **Suspicious Patterns** | Reverse shells, encoded payloads, SUID changes |
| **Off-Hours Activity** | Authentication between 00:00-05:59 |
| **Log Integrity** | Empty logs, wrong permissions (tamper indicators) |
| **Event Timeline** | Chronological view of key security events |
| **Live Monitor** | Real-time log watching with color-coded alerts |

## Usage

```bash
chmod +x security_log_analyzer.sh

# Analyze last 24 hours (default)
sudo ./security_log_analyzer.sh

# Analyze last 72 hours
sudo ./security_log_analyzer.sh --hours 72

# Save report to file
sudo ./security_log_analyzer.sh --report incident_report.txt

# Live monitoring mode (Ctrl+C to stop)
sudo ./security_log_analyzer.sh --watch
```

## Output Severity Levels

- **[ALERT]** — Critical: active threat or confirmed attack (red)
- **[WARN]** — Needs investigation (yellow)
- **[OK]** — Check passed (green)
- **[INFO]** — Context/informational (cyan)

## Verdict Scale

| Verdict | Meaning |
|---------|---------|
| **CLEAN** | No significant threats |
| **REVIEW** | Warnings present, manual review recommended |
| **INVESTIGATE** | Active threats may be present |
| **CRITICAL** | Multiple alerts, immediate action required |

## Log Sources

The tool auto-detects available log sources:
- `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS)
- `/var/log/syslog` or `/var/log/messages`
- `journalctl` (systemd fallback)

## Example Output

```
═══════════════════════════════════════════════════════════════
  1. BRUTE-FORCE / PASSWORD ATTACK DETECTION
═══════════════════════════════════════════════════════════════

  ── Failed SSH logins by source IP ──
  COUNT   SOURCE IP
  ─────  ─────────────────
[ALERT]   Likely brute-force from 192.168.1.50 (847 failed attempts)
[WARN]    Suspicious activity from 10.0.0.15 (23 failed attempts)

═══════════════════════════════════════════════════════════════
  ANALYSIS SUMMARY
═══════════════════════════════════════════════════════════════

  Alerts (critical):  3
  Warnings:           7
  Informational:      12

  Verdict: INVESTIGATE — active threats may be present
```

## Requirements

- Linux (Debian/Ubuntu, RHEL/CentOS, Arch, etc.)
- Root privileges (`sudo`)
- Standard coreutils (grep, awk, sort, uniq)

## Author

Doniyor Sotiboldiyev
