#!/usr/bin/env bash
# ==============================================================================
# OpsPulse - Linux Incident Diagnostic Engine with Structured JSON & TUI Support
# Usage: ./opspulse.sh [check-all | net | sec | perf | web] [--json]
# ==============================================================================
set -euo pipefail

FORMAT="text"
if [[ "${*:-}" =~ "--json" ]]; then
    FORMAT="json"
fi

get_network_json() {
    local default_gw dns_test ip_addrs
    default_gw=$(ip route show default 2>/dev/null | awk '{print $3}' || echo "none")
    ip_addrs=$(ip -j addr show 2>/dev/null || echo "[]")
    
    if ping -c 1 -W 2 1.1.1.1 &>/dev/null; then
        gw_ping=true
    else
        gw_ping=false
    fi

    if getent hosts google.com &>/dev/null; then
        dns_ok=true
    else
        dns_ok=false
    fi

    cat <<EOF
{
  "default_gateway": "$default_gw",
  "gateway_reachable": $gw_ping,
  "dns_resolving": $dns_ok,
  "interfaces": $ip_addrs
}
EOF
}

get_security_json() {
    local ports failed_ssh
    ports=$(ss -tulpn -H 2>/dev/null | awk '{print "{\"proto\":\""$1"\",\"local_addr\":\""$5"\",\"pid_cmd\":\""$7"\"}"}' | paste -sd, - || echo "")
    failed_ssh=$(journalctl -u ssh -u sshd --no-pager -n 10 2>/dev/null | grep "Failed password" | wc -l || echo "0")
    
    cat <<EOF
{
  "failed_ssh_attempts_recent": $failed_ssh,
  "listening_sockets": [${ports}]
}
EOF
}

get_perf_json() {
    local load mem_total mem_free disk_alerts
    load=$(uptime | awk -F'load average:' '{print $2}' | xargs)
    mem_total=$(free -m | awk '/Mem:/ {print $2}')
    mem_free=$(free -m | awk '/Mem:/ {print $4}')
    disk_alerts=$(df -h | awk '$5+0 > 80 {print "{\"filesystem\":\""$1"\",\"mount\":\""$6"\",\"usage\":\""$5"\"}"}' | paste -sd, - || echo "")

    cat <<EOF
{
  "load_averages": "$load",
  "memory_total_mb": $mem_total,
  "memory_free_mb": $mem_free,
  "high_usage_disks": [${disk_alerts}]
}
EOF
}

get_web_json() {
    local nginx_status apache_status
    nginx_status=$(systemctl is-active nginx 2>/dev/null || echo "inactive")
    apache_status=$(systemctl is-active apache2 2>/dev/null || echo "inactive")

    cat <<EOF
{
  "nginx": "$nginx_status",
  "apache": "$apache_status"
}
EOF
}

run_json_suite() {
    cat <<EOF
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "hostname": "$(hostname)",
  "os": "linux",
  "network": $(get_network_json),
  "security": $(get_security_json),
  "performance": $(get_perf_json),
  "web": $(get_web_json)
}
EOF
}

run_human_suite() {
    local mode="${1:-check-all}"
    echo "====================================================="
    echo ">> OpsPulse Linux Diagnostic: Mode [$mode]"
    echo "====================================================="
    if [[ "$mode" == "check-all" || "$mode" == "net" ]]; then
        echo -e "\n[*] Network & Gateway Status:"
        ip -br addr || ifconfig -a
        ping -c 2 1.1.1.1 &>/dev/null && echo "[+] L3 Internet Gateway: REACHABLE" || echo "[-] L3 Internet Gateway: UNREACHABLE"
    fi
    if [[ "$mode" == "check-all" || "$mode" == "sec" ]]; then
        echo -e "\n[*] Active Listening Ports (ss -tulpn):"
        ss -tulpn | grep LISTEN || netstat -tulpn | grep LISTEN
    fi
    if [[ "$mode" == "check-all" || "$mode" == "perf" ]]; then
        echo -e "\n[*] Resource Consumption (RAM & High Storage):"
        free -h
        df -h | awk '$5+0 > 80 {print "ALERT Disk > 80%: " $0}'
    fi
}

if [[ "$FORMAT" == "json" ]]; then
    run_json_suite
else
    run_human_suite "${1:-check-all}"
fi
