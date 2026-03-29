#!/bin/bash
# Nemoclaw Agent-Tracker v32.0
# Location: Ubuntu Host
# Purpose: Log all sandbox "moves" and enforce Ziti-only egress.

TARGET_CONT="openshell-cluster-nemoclaw"
ZITI_DNS="100.64.0.2"
ZITI_FABRIC="100.64.0.0/10"

log_info() { echo "$(date) - [AGENT-TRACKER] $1"; }

# 1. Identify the Target IP
C_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TARGET_CONT" 2>/dev/null)

if [ -z "$C_IP" ]; then
    log_info "Error: Container $TARGET_CONT not found. Please start the onboarder."
    exit 1
fi

log_info "Tracking Agent at IP: $C_IP"

# 2. Enable Host Forwarding
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# 3. Apply Host-Side Audit Rules
# Clean existing rules for this IP to prevent duplicate logs
iptables -S FORWARD | grep "$C_IP" | sed 's/-A/iptables -D/' | bash 2>/dev/null

# STEP A: LOG and ALLOW Ziti Fabric traffic (The "Authorized Moves")
iptables -I FORWARD 1 -s "$C_IP" -d "$ZITI_FABRIC" -j LOG --log-prefix "NEMOCLAW-ZITI: "
iptables -I FORWARD 2 -s "$C_IP" -d "$ZITI_FABRIC" -j ACCEPT

# STEP B: LOG and REJECT everything else (The "Illegal Moves")
# This records every attempt the agent makes to reach the public internet.
iptables -I FORWARD 3 -s "$C_IP" -j LOG --log-prefix "NEMOCLAW-BLOCKED: "
iptables -I FORWARD 4 -s "$C_IP" -j REJECT --reject-with icmp-admin-prohibited

# 4. DNS Steering (Audit DNS Lookups)
iptables -t nat -I PREROUTING 1 -s "$C_IP" -p udp --dport 53 -j LOG --log-prefix "NEMOCLAW-DNS: "
iptables -t nat -I PREROUTING 2 -s "$C_IP" -p udp --dport 53 -j DNAT --to-destination "$ZITI_DNS":53

log_info "Jail & Tracker active. Monitor moves with: dmesg -w | grep NEMOCLAW"

