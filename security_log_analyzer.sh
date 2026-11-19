#!/bin/bash
#
# security_log_analyzer.sh — Security Log Analysis Tool
# Analyzes auth logs, syslog, and system journals to detect
# suspicious events, brute-force attempts, privilege escalation,
# and anomalous activity.
#
# Usage: sudo ./security_log_analyzer.sh [OPTIONS]
#   --hours N        Analyze last N hours (default: 24)
#   --report FILE    Save results to FILE
#   --watch          Continuous monitoring mode (tail -f)
# Requires root for full log access.

set -euo pipefail

RED='\033[0;31m'
YEL='\033[0;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
MAG='\033[0;35m'
BLD='\033[1m'
DIM='\033[2m'
RST='\033[0m'

HOURS=24
REPORT_FILE=""
WATCH_MODE=0
ALERTS=0
WARNINGS=0
INFO_COUNT=0

log_buf=""

usage() {
    echo "Usage: sudo $0 [OPTIONS]"
    echo "  --hours N        Analyze last N hours (default: 24)"
    echo "  --report FILE    Save results to plain text file"
    echo "  --watch          Continuous monitoring mode (live tail)"
    echo "  -h, --help       Show this help"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hours) HOURS="$2"; shift 2 ;;
        --report) REPORT_FILE="$2"; shift 2 ;;
        --watch) WATCH_MODE=1; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] Run as root for full log access: sudo $0${RST}"
    exit 1
fi

out() {
    echo -e "$1"
    log_buf+="$(echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g')"$'\n'
}

alert() {
    out "${RED}[ALERT]${RST}   $1"
    ((ALERTS++)) || true
}

warn() {
    out "${YEL}[WARN]${RST}    $1"
    ((WARNINGS++)) || true
}

ok() {
    out "${GRN}[OK]${RST}      $1"
}

info() {
    out "${CYN}[INFO]${RST}    $1"
    ((INFO_COUNT++)) || true
}

section() {
    out ""
    out "${BLD}═══════════════════════════════════════════════════════════════${RST}"
    out "${BLD}  $1${RST}"
    out "${BLD}═══════════════════════════════════════════════════════════════${RST}"
}

subsection() {
    out ""
    out "  ${BLD}── $1 ──${RST}"
}

SINCE_DATE=$(date -d "$HOURS hours ago" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -v-${HOURS}H '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "")
SINCE_EPOCH=$(date -d "$HOURS hours ago" '+%s' 2>/dev/null || echo 0)

AUTH_LOG=""
for f in /var/log/auth.log /var/log/secure; do
    [[ -f "$f" ]] && AUTH_LOG="$f" && break
done

SYSLOG=""
for f in /var/log/syslog /var/log/messages; do
    [[ -f "$f" ]] && SYSLOG="$f" && break
done

has_journalctl=0
command -v journalctl &>/dev/null && has_journalctl=1

get_auth_lines() {
    if [[ -n "$AUTH_LOG" ]]; then
        cat "$AUTH_LOG"
    elif [[ $has_journalctl -eq 1 ]]; then
        journalctl -u ssh -u sshd --no-pager --since "$HOURS hours ago" 2>/dev/null
    fi
}

get_syslog_lines() {
    if [[ -n "$SYSLOG" ]]; then
        cat "$SYSLOG"
    elif [[ $has_journalctl -eq 1 ]]; then
        journalctl --no-pager --since "$HOURS hours ago" 2>/dev/null
    fi
}

# ─────────────────────────────────────────────
# WATCH MODE (live monitoring)
# ─────────────────────────────────────────────
if [[ $WATCH_MODE -eq 1 ]]; then
    echo -e "${BLD}${CYN}[*] Live Security Monitor — watching logs (Ctrl+C to stop)${RST}"
    echo -e "${DIM}    Monitoring: ${AUTH_LOG:-journalctl} ${SYSLOG:-}${RST}"
    echo ""

    patterns="Failed password|BREAK-IN|Invalid user|session opened|sudo:|account locked|authentication failure|Accepted publickey|Accepted password|segfault|OUT OF MEMORY|UFW BLOCK|iptables"

    if [[ -n "$AUTH_LOG" && -n "$SYSLOG" ]]; then
        tail -f "$AUTH_LOG" "$SYSLOG" 2>/dev/null | while IFS= read -r line; do
            if echo "$line" | grep -qiE "$patterns"; then
                ts=$(date '+%H:%M:%S')
                if echo "$line" | grep -qiE "Failed password|BREAK-IN|Invalid user|authentication failure"; then
                    echo -e "${RED}[$ts ALERT]${RST} $line"
                elif echo "$line" | grep -qiE "sudo:|session opened|Accepted"; then
                    echo -e "${YEL}[$ts AUTH]${RST}  $line"
                else
                    echo -e "${CYN}[$ts EVENT]${RST} $line"
                fi
            fi
        done
    elif [[ $has_journalctl -eq 1 ]]; then
        journalctl -f --no-pager 2>/dev/null | while IFS= read -r line; do
            if echo "$line" | grep -qiE "$patterns"; then
                ts=$(date '+%H:%M:%S')
                if echo "$line" | grep -qiE "Failed password|BREAK-IN|Invalid user|authentication failure"; then
                    echo -e "${RED}[$ts ALERT]${RST} $line"
                elif echo "$line" | grep -qiE "sudo:|session opened|Accepted"; then
                    echo -e "${YEL}[$ts AUTH]${RST}  $line"
                else
                    echo -e "${CYN}[$ts EVENT]${RST} $line"
                fi
            fi
        done
    else
        echo -e "${RED}[!] No log source available for monitoring${RST}"
        exit 1
    fi
    exit 0
fi

# ═════════════════════════════════════════════
# STATIC ANALYSIS MODE
# ═════════════════════════════════════════════

out "${BLD}${CYN}"
out "  ╔═══════════════════════════════════════════════════╗"
out "  ║       SECURITY LOG ANALYSIS REPORT                ║"
out "  ╚═══════════════════════════════════════════════════╝${RST}"
out ""
info "Analysis window: last $HOURS hours (since ${SINCE_DATE:-N/A})"
info "Hostname: $(hostname)"
info "Generated: $(date '+%Y-%m-%d %H:%M:%S %Z')"
info "Log sources: ${AUTH_LOG:-journalctl} ${SYSLOG:+| $SYSLOG}"

# ─────────────────────────────────────────────
# 1. BRUTE-FORCE DETECTION
# ─────────────────────────────────────────────
section "1. BRUTE-FORCE / PASSWORD ATTACK DETECTION"

auth_data=$(get_auth_lines 2>/dev/null || echo "")

if [[ -n "$auth_data" ]]; then
    subsection "Failed SSH logins by source IP"

    failed_ips=$(echo "$auth_data" | grep -i "Failed password" | \
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
        sort | uniq -c | sort -rn | head -20)

    if [[ -n "$failed_ips" ]]; then
        out "  ${BLD}COUNT   SOURCE IP${RST}"
        out "  ─────  ─────────────────"
        while read -r count ip; do
            if [[ $count -ge 50 ]]; then
                alert "Likely brute-force from $ip ($count failed attempts)"
            elif [[ $count -ge 10 ]]; then
                warn "Suspicious activity from $ip ($count failed attempts)"
            else
                info "$ip — $count failed attempt(s)"
            fi
        done <<< "$failed_ips"
    else
        ok "No failed SSH password attempts found"
    fi

    subsection "Failed logins by username"

    failed_users=$(echo "$auth_data" | grep -i "Failed password" | \
        grep -oP 'for (invalid user )?\K\S+' | \
        sort | uniq -c | sort -rn | head -15)

    if [[ -n "$failed_users" ]]; then
        out "  ${BLD}COUNT   USERNAME${RST}"
        out "  ─────  ─────────────────"
        while read -r count user; do
            if [[ $count -ge 20 ]]; then
                alert "Username '$user' targeted $count times"
            else
                out "  ${DIM}$count${RST}      $user"
            fi
        done <<< "$failed_users"
    fi

    subsection "Invalid/non-existent usernames attempted"

    invalid_users=$(echo "$auth_data" | grep -i "Invalid user" | \
        grep -oP 'Invalid user \K\S+' | \
        sort | uniq -c | sort -rn | head -15)

    if [[ -n "$invalid_users" ]]; then
        out "  ${BLD}COUNT   USERNAME${RST}"
        out "  ─────  ─────────────────"
        while read -r count user; do
            warn "Non-existent user attempted: '$user' ($count times)"
        done <<< "$invalid_users"
    else
        ok "No invalid username attempts"
    fi

    brute_threshold=100
    total_failed=$(echo "$auth_data" | grep -ci "Failed password" || echo 0)
    if [[ $total_failed -ge $brute_threshold ]]; then
        alert "TOTAL failed password attempts: $total_failed (threshold: $brute_threshold)"
    else
        info "Total failed password attempts: $total_failed"
    fi
else
    warn "No auth log data available"
fi

# ─────────────────────────────────────────────
# 2. SUCCESSFUL AUTHENTICATION EVENTS
# ─────────────────────────────────────────────
section "2. SUCCESSFUL AUTHENTICATION EVENTS"

if [[ -n "$auth_data" ]]; then
    subsection "Successful SSH logins"

    accepted=$(echo "$auth_data" | grep -iE "Accepted (password|publickey)" | tail -20)
    if [[ -n "$accepted" ]]; then
        out "  ${BLD}Recent successful logins:${RST}"
        echo "$accepted" | while IFS= read -r line; do
            method="password"
            echo "$line" | grep -qi "publickey" && method="pubkey"
            user=$(echo "$line" | grep -oP 'for \K\S+')
            ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
            ts=$(echo "$line" | awk '{print $1, $2, $3}')
            info "$ts — $user from $ip ($method)"
        done

        accepted_ips=$(echo "$auth_data" | grep -iE "Accepted (password|publickey)" | \
            grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)

        if [[ -n "$failed_ips" && -n "$accepted_ips" ]]; then
            subsection "IPs with both failed AND successful logins"
            while read -r ip; do
                if echo "$failed_ips" | grep -q "$ip"; then
                    fail_count=$(echo "$failed_ips" | grep "$ip" | awk '{print $1}')
                    alert "IP $ip: $fail_count failures then SUCCESS (possible brute-force win)"
                fi
            done <<< "$accepted_ips"
        fi
    else
        info "No successful SSH logins in this window"
    fi

    subsection "Root logins"
    root_logins=$(echo "$auth_data" | grep -iE "Accepted.*(password|publickey).*for root" | wc -l)
    if [[ $root_logins -gt 0 ]]; then
        warn "Direct root SSH logins detected: $root_logins"
        echo "$auth_data" | grep -iE "Accepted.*(password|publickey).*for root" | tail -5 | while IFS= read -r line; do
            out "    $line"
        done
    else
        ok "No direct root SSH logins"
    fi
fi

# ─────────────────────────────────────────────
# 3. SUDO / PRIVILEGE ESCALATION EVENTS
# ─────────────────────────────────────────────
section "3. SUDO & PRIVILEGE ESCALATION"

if [[ -n "$auth_data" ]]; then
    subsection "Sudo command executions"

    sudo_lines=$(echo "$auth_data" | grep -i "sudo:" | grep "COMMAND=" | tail -30)
    if [[ -n "$sudo_lines" ]]; then
        out "  ${BLD}Recent sudo commands:${RST}"
        echo "$sudo_lines" | while IFS= read -r line; do
            user=$(echo "$line" | grep -oP 'sudo:\s+\K\S+' || echo "?")
            cmd=$(echo "$line" | grep -oP 'COMMAND=\K.*')
            ts=$(echo "$line" | awk '{print $1, $2, $3}')

            is_dangerous=0
            for pattern in "/bin/bash" "/bin/sh" "visudo" "passwd" "useradd" "usermod" "groupmod" "chmod 777" "chown root" "/etc/shadow" "rm -rf" "dd if=" "mkfs" "fdisk" "iptables -F" "systemctl disable"; do
                if echo "$cmd" | grep -qi "$pattern"; then
                    is_dangerous=1
                    break
                fi
            done

            if [[ $is_dangerous -eq 1 ]]; then
                warn "$ts — $user: $cmd"
            else
                out "  ${DIM}$ts${RST} — $user: $cmd"
            fi
        done
    else
        info "No sudo commands recorded"
    fi

    subsection "Failed sudo attempts"

    sudo_fail=$(echo "$auth_data" | grep -iE "sudo:.*authentication failure|sudo:.*incorrect password|sudo:.*NOT in sudoers")
    if [[ -n "$sudo_fail" ]]; then
        fail_count=$(echo "$sudo_fail" | wc -l)
        alert "Failed sudo attempts: $fail_count"
        echo "$sudo_fail" | tail -10 | while IFS= read -r line; do
            out "    $line"
        done
    else
        ok "No failed sudo attempts"
    fi

    subsection "su command usage"

    su_events=$(echo "$auth_data" | grep -iE "su\[|su:" | grep -iE "session opened|Successful su|FAILED su" | tail -10)
    if [[ -n "$su_events" ]]; then
        echo "$su_events" | while IFS= read -r line; do
            if echo "$line" | grep -qi "FAILED"; then
                warn "Failed su: $line"
            else
                info "$(echo "$line" | awk '{print $1, $2, $3}') — $line"
            fi
        done
    else
        info "No su events"
    fi
fi

# ─────────────────────────────────────────────
# 4. USER/GROUP CHANGES
# ─────────────────────────────────────────────
section "4. USER & GROUP MODIFICATIONS"

if [[ -n "$auth_data" ]]; then
    account_changes=$(echo "$auth_data" | grep -iE "useradd|userdel|usermod|groupadd|groupdel|groupmod|passwd|chage" | tail -20)
    if [[ -n "$account_changes" ]]; then
        out "  ${BLD}Account management events:${RST}"
        echo "$account_changes" | while IFS= read -r line; do
            if echo "$line" | grep -qi "useradd"; then
                new_user=$(echo "$line" | grep -oP "name=\K\S+" || echo "?")
                alert "New user created: $new_user"
                out "    $line"
            elif echo "$line" | grep -qi "userdel"; then
                warn "User deleted"
                out "    $line"
            elif echo "$line" | grep -qi "usermod"; then
                warn "User modified"
                out "    $line"
            elif echo "$line" | grep -qi "passwd"; then
                info "Password changed"
                out "    $line"
            else
                out "    $line"
            fi
        done
    else
        ok "No account modifications detected"
    fi
fi

# ─────────────────────────────────────────────
# 5. SSH KEY EVENTS
# ─────────────────────────────────────────────
section "5. SSH KEY & SESSION EVENTS"

if [[ -n "$auth_data" ]]; then
    subsection "Session anomalies"

    session_open=$(echo "$auth_data" | grep -c "session opened" || echo 0)
    session_close=$(echo "$auth_data" | grep -c "session closed" || echo 0)

    info "Sessions opened: $session_open  |  Sessions closed: $session_close"

    if [[ $session_open -gt 0 ]]; then
        orphan_diff=$((session_open - session_close))
        if [[ $orphan_diff -gt 5 ]]; then
            warn "Unclosed sessions gap: $orphan_diff (opened vs closed)"
        fi
    fi

    subsection "SSH disconnection reasons"

    disconnects=$(echo "$auth_data" | grep -iE "Disconnected from|Connection closed|Connection reset" | \
        grep -oP '(Disconnected from|Connection closed by|Connection reset by) \K[^ ]+' | \
        sort | uniq -c | sort -rn | head -10)

    if [[ -n "$disconnects" ]]; then
        out "  ${BLD}COUNT   SOURCE${RST}"
        while read -r count src; do
            out "  $count      $src"
        done <<< "$disconnects"
    fi
fi

# ─────────────────────────────────────────────
# 6. SYSTEM EVENTS & ANOMALIES
# ─────────────────────────────────────────────
section "6. SYSTEM EVENTS & ANOMALIES"

syslog_data=$(get_syslog_lines 2>/dev/null || echo "")

if [[ -n "$syslog_data" ]]; then
    subsection "Kernel / hardware errors"

    segfaults=$(echo "$syslog_data" | grep -ci "segfault" || echo 0)
    oom_kills=$(echo "$syslog_data" | grep -ci "Out of memory\|oom-kill\|oom_reaper" || echo 0)
    panics=$(echo "$syslog_data" | grep -ci "kernel panic\|BUG:" || echo 0)

    if [[ $segfaults -gt 0 ]]; then
        warn "Segfaults detected: $segfaults (possible exploit or unstable software)"
        echo "$syslog_data" | grep -i "segfault" | tail -3 | while IFS= read -r line; do
            out "    ${DIM}$line${RST}"
        done
    else
        ok "No segfaults"
    fi

    if [[ $oom_kills -gt 0 ]]; then
        warn "OOM kills: $oom_kills (resource exhaustion / DoS risk)"
    else
        ok "No OOM events"
    fi

    if [[ $panics -gt 0 ]]; then
        alert "Kernel panics / BUG traces: $panics"
    fi

    subsection "Service start/stop events"

    svc_events=$(echo "$syslog_data" | grep -iE "systemd.*Started|systemd.*Stopped|systemd.*Failed" | \
        grep -oP '(Started|Stopped|Failed) \K.*' | sort | uniq -c | sort -rn | head -15)

    if [[ -n "$svc_events" ]]; then
        out "  ${BLD}COUNT   SERVICE${RST}"
        out "  ─────  ─────────────────────────────"
        echo "$svc_events" | while read -r count svc; do
            out "  $count      $svc"
        done
    fi

    subsection "Firewall events"

    fw_blocks=$(echo "$syslog_data" | grep -ciE "UFW BLOCK|iptables.*DROP|nftables.*drop|DENIED" || echo 0)
    if [[ $fw_blocks -gt 0 ]]; then
        info "Firewall blocked connections: $fw_blocks"

        fw_top_src=$(echo "$syslog_data" | grep -iE "UFW BLOCK|iptables.*DROP|nftables.*drop" | \
            grep -oP 'SRC=\K[0-9.]+' | sort | uniq -c | sort -rn | head -5)

        if [[ -n "$fw_top_src" ]]; then
            out "  ${BLD}Top blocked sources:${RST}"
            while read -r count ip; do
                if [[ $count -ge 100 ]]; then
                    warn "Heavily blocked IP: $ip ($count blocks)"
                else
                    out "    $count — $ip"
                fi
            done <<< "$fw_top_src"
        fi

        fw_top_port=$(echo "$syslog_data" | grep -iE "UFW BLOCK|iptables.*DROP|nftables.*drop" | \
            grep -oP 'DPT=\K[0-9]+' | sort | uniq -c | sort -rn | head -5)

        if [[ -n "$fw_top_port" ]]; then
            out "  ${BLD}Top targeted ports:${RST}"
            while read -r count port; do
                out "    $count — port $port"
            done <<< "$fw_top_port"
        fi
    else
        info "No firewall block events found"
    fi
else
    warn "No syslog data available"
fi

# ─────────────────────────────────────────────
# 7. SUSPICIOUS PATTERNS
# ─────────────────────────────────────────────
section "7. SUSPICIOUS PATTERN DETECTION"

if [[ -n "$auth_data" ]]; then
    subsection "Off-hours authentication (00:00-05:59)"

    offhours=$(echo "$auth_data" | grep -iE "Accepted|session opened" | \
        awk '{print $3}' | grep -E "^0[0-5]:" | wc -l)

    if [[ $offhours -gt 0 ]]; then
        warn "Off-hours (00-05) auth events: $offhours"
    else
        ok "No off-hours authentication events"
    fi

    subsection "Rapid-fire login attempts (>5 per minute from same IP)"

    rapid_fire=$(echo "$auth_data" | grep -i "Failed password" | \
        awk '{print $1, $2, $3}' | cut -d: -f1,2 | \
        sort | uniq -c | sort -rn | head -5)

    if [[ -n "$rapid_fire" ]]; then
        while read -r count ts; do
            if [[ $count -ge 5 ]]; then
                alert "Rapid-fire burst: $count attempts at $ts"
            fi
        done <<< "$rapid_fire"
    fi
fi

subsection "Suspicious commands in logs"

if [[ -n "$syslog_data" ]]; then
    for pattern in "wget.*-O /tmp" "curl.*|.*sh" "nc -e" "ncat -e" "/dev/tcp/" "python.*-c.*import.*socket" "base64.*decode" "chmod +s" "chmod 4755"; do
        hits=$(echo "$syslog_data" | grep -c "$pattern" 2>/dev/null || echo 0)
        if [[ $hits -gt 0 ]]; then
            alert "Suspicious pattern '$pattern' found $hits time(s)"
            echo "$syslog_data" | grep "$pattern" | tail -3 | while IFS= read -r line; do
                out "    ${DIM}$line${RST}"
            done
        fi
    done
fi

# ─────────────────────────────────────────────
# 8. LOG INTEGRITY
# ─────────────────────────────────────────────
section "8. LOG INTEGRITY CHECK"

for logfile in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages /var/log/kern.log /var/log/wtmp /var/log/btmp /var/log/lastlog; do
    if [[ -f "$logfile" ]]; then
        perms=$(stat -c '%a %U:%G' "$logfile" 2>/dev/null || stat -f '%Lp %Su:%Sg' "$logfile" 2>/dev/null)
        size=$(stat -c '%s' "$logfile" 2>/dev/null || stat -f '%z' "$logfile" 2>/dev/null)
        mod=$(stat -c '%y' "$logfile" 2>/dev/null | cut -d. -f1 || stat -f '%Sm' "$logfile" 2>/dev/null)

        if [[ "$size" -eq 0 ]]; then
            alert "EMPTY log file: $logfile (possible tampering)"
        fi

        owner=$(echo "$perms" | awk '{print $2}')
        mode=$(echo "$perms" | awk '{print $1}')
        if echo "$mode" | grep -qE "^..[2367]|^.....[2367]|^........[2367]"; then
            warn "World/group-writable log: $logfile ($perms)"
        fi

        out "  ${DIM}$logfile${RST}  [$perms]  ${size} bytes  mod: $mod"
    fi
done

if [[ -f /var/log/wtmp ]]; then
    out ""
    out "  ${BLD}Last 5 reboots:${RST}"
    last reboot | head -5 | while IFS= read -r line; do
        [[ -n "$line" ]] && out "    $line"
    done
fi

# ─────────────────────────────────────────────
# 9. TIMELINE (last 10 critical events)
# ─────────────────────────────────────────────
section "9. EVENT TIMELINE (key events)"

if [[ -n "$auth_data" ]]; then
    out "  ${BLD}Timestamp         Event${RST}"
    out "  ────────────────  ───────────────────────────────────────"

    {
        echo "$auth_data" | grep -iE "Failed password|Accepted (password|publickey)|sudo:.*COMMAND=|useradd|userdel|session opened.*root|NOT in sudoers" | tail -30
    } | sort | tail -15 | while IFS= read -r line; do
        ts=$(echo "$line" | awk '{print $1, $2, $3}')
        if echo "$line" | grep -qi "Failed password"; then
            out "  ${DIM}$ts${RST}  ${RED}AUTH_FAIL${RST}    $(echo "$line" | grep -oP 'for (invalid user )?\K\S+') from $(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)"
        elif echo "$line" | grep -qi "Accepted"; then
            out "  ${DIM}$ts${RST}  ${GRN}AUTH_OK${RST}      $(echo "$line" | grep -oP 'for \K\S+') from $(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)"
        elif echo "$line" | grep -qi "COMMAND="; then
            out "  ${DIM}$ts${RST}  ${YEL}SUDO${RST}         $(echo "$line" | grep -oP 'COMMAND=\K.*')"
        elif echo "$line" | grep -qi "useradd"; then
            out "  ${DIM}$ts${RST}  ${MAG}USER_ADD${RST}     $(echo "$line" | grep -oP 'name=\K\S+')"
        elif echo "$line" | grep -qi "NOT in sudoers"; then
            out "  ${DIM}$ts${RST}  ${RED}SUDO_DENY${RST}    $line"
        else
            out "  ${DIM}$ts${RST}  ${CYN}EVENT${RST}        $(echo "$line" | cut -d' ' -f6-)"
        fi
    done
fi

# ─────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────
section "ANALYSIS SUMMARY"

out ""
out "  ${RED}${BLD}Alerts (critical):  $ALERTS${RST}"
out "  ${YEL}${BLD}Warnings:           $WARNINGS${RST}"
out "  ${CYN}${BLD}Informational:      $INFO_COUNT${RST}"
out ""

if [[ $ALERTS -eq 0 && $WARNINGS -le 3 ]]; then
    out "  ${GRN}${BLD}Verdict: CLEAN — no significant threats detected${RST}"
elif [[ $ALERTS -eq 0 ]]; then
    out "  ${YEL}${BLD}Verdict: REVIEW — warnings present, manual review recommended${RST}"
elif [[ $ALERTS -le 3 ]]; then
    out "  ${RED}${BLD}Verdict: INVESTIGATE — active threats may be present${RST}"
else
    out "  ${RED}${BLD}Verdict: CRITICAL — multiple alerts, immediate action required${RST}"
fi

out ""
out "  ${BLD}Recommendations:${RST}"
if [[ $ALERTS -gt 0 ]]; then
    out "    1. Review all ALERT entries and correlate with known activity"
    out "    2. Block suspicious IPs via firewall (ufw/iptables)"
    out "    3. Rotate credentials for any compromised accounts"
    out "    4. Check for unauthorized SSH keys in ~/.ssh/authorized_keys"
fi
if [[ $WARNINGS -gt 0 ]]; then
    out "    - Investigate WARNING entries for policy violations"
    out "    - Consider enabling fail2ban for automated brute-force blocking"
fi
out "    - Schedule regular log analysis (cron + this tool)"
out "    - Ensure log rotation is configured and logs are backed up"
out ""
out "  Analysis window: $HOURS hours  |  Completed: $(date '+%Y-%m-%d %H:%M:%S %Z')"
out "  Tool: security_log_analyzer.sh v1.0"

if [[ -n "$REPORT_FILE" ]]; then
    echo "$log_buf" | sed 's/\x1b\[[0-9;]*m//g' > "$REPORT_FILE"
    echo ""
    echo -e "${GRN}[+] Report saved to: $REPORT_FILE${RST}"
fi
