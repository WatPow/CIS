#!/bin/bash

# Section 2 - Services
log_message "=== 2 Services ==="

# Fonction de vérification des services
function check_service() {
    local service=$1
    local expected_state=$2
    
    log_message "=== Vérification du service $service ==="
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if ! command -v systemctl >/dev/null 2>&1; then
        log_message "WARN: systemctl n'est pas disponible, impossible de vérifier $service"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 0
    fi
    
    local current_state=$(systemctl is-enabled "$service" 2>/dev/null || echo "not-found")
    
    if [ "$current_state" = "not-found" ]; then
        log_message "INFO: Le service $service n'est pas installé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    fi
    
    if [ "$current_state" = "$expected_state" ]; then
        log_message "PASS: Le service $service est $expected_state"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Le service $service est $current_state (attendu: $expected_state)"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# 2.1 Services inetd
log_message "=== 2.1 Services inetd ==="

# 2.1.1 Vérification de xinetd
check_service "xinetd" "disabled"

# 2.2 Services spéciaux
log_message "=== 2.2 Services spéciaux ==="

# 2.2.1 Vérification du système X Window
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if ! rpm -qa xorg-x11* > /dev/null 2>&1; then
    log_message "PASS: Le système X Window n'est pas installé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: Le système X Window est installé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 2.2.2 Vérification du serveur Avahi
check_service "avahi-daemon" "disabled"

# 2.2.3 Vérification de CUPS
check_service "cups" "disabled"

# 2.2.4 Vérification du serveur DHCP
check_service "dhcpd" "disabled"

# 2.2.5 Vérification du serveur LDAP
check_service "slapd" "disabled"

# 2.2.6 Vérification de NFS et RPC
check_service "nfs" "disabled"
check_service "rpcbind" "disabled"

# 2.2.7 Vérification du serveur DNS
check_service "named" "disabled"

# 2.2.8 Vérification du serveur FTP
check_service "vsftpd" "disabled"

# 2.2.9 Vérification du serveur HTTP
check_service "httpd" "disabled"

# 2.2.10 Vérification du serveur IMAP et POP3
check_service "dovecot" "disabled"

# 2.2.11 Vérification du serveur Samba
check_service "smb" "disabled"

# 2.2.12 Vérification du serveur proxy HTTP
check_service "squid" "disabled"

# 2.2.13 Vérification du serveur SNMP
check_service "snmpd" "disabled"

# 2.2.14 Vérification du serveur NIS
check_service "ypserv" "disabled"

# 2.3 Services de protocole
log_message "=== 2.3 Services de protocole ==="

# Liste des protocoles à vérifier
protocols=("dccp" "sctp" "rds" "tipc")
for protocol in "${protocols[@]}"; do
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if lsmod | grep -q "^$protocol"; then
        log_message "FAIL: Le protocole $protocol est chargé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    else
        log_message "PASS: Le protocole $protocol n'est pas chargé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    fi
done 