#!/bin/bash

# Section 2 - Services
log_message "=== 2 Services ==="

# Fonction générique pour vérifier si un service est installé et actif
check_service() {
    local service=$1
    local expected_state=$2
    local cis_ref=$3
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    # Vérifie si le service est installé
    if ! systemctl list-unit-files | grep -q "^$service"; then
        log_message "PASS: [CIS $cis_ref] Le service $service n'est pas installé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
        return 0
    fi
    
    # Vérifie l'état du service
    local current_state=$(systemctl is-enabled "$service" 2>/dev/null || echo "not-found")
    if [ "$current_state" = "$expected_state" ]; then
        log_message "PASS: [CIS $cis_ref] Le service $service est $expected_state"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS $cis_ref] Le service $service est $current_state (attendu: $expected_state)"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Fonction pour vérifier si un paquet est installé
check_package() {
    local package=$1
    local cis_ref=$2
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if ! rpm -q "$package" > /dev/null 2>&1; then
        log_message "PASS: [CIS $cis_ref] Le paquet $package n'est pas installé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS $cis_ref] Le paquet $package est installé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# 2.1 Configuration de la synchronisation du temps
log_message "=== 2.1 Configuration de la synchronisation du temps ==="

# 2.1.1 Ensure time synchronization is in use
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if rpm -q chrony > /dev/null 2>&1; then
    log_message "PASS: [CIS 2.1.1] Le service de synchronisation du temps (chrony) est installé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 2.1.1] Aucun service de synchronisation du temps n'est installé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 2.1.2 Ensure chrony is configured
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ -f /etc/chrony.conf ] && grep -q "^server" /etc/chrony.conf; then
    log_message "PASS: [CIS 2.1.2] chrony est correctement configuré"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 2.1.2] chrony n'est pas correctement configuré"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 2.1.3 Ensure chrony is not run as root
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep -q "^OPTIONS=\"-u chrony\"" /etc/sysconfig/chronyd 2>/dev/null; then
    log_message "PASS: [CIS 2.1.3] chronyd ne s'exécute pas en tant que root"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 2.1.3] chronyd s'exécute en tant que root"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 2.2 Services spéciaux
log_message "=== 2.2 Services spéciaux ==="

# Vérification des services
check_service "autofs" "disabled" "2.2.1"
check_service "avahi-daemon" "disabled" "2.2.2"
check_service "dhcpd" "disabled" "2.2.3"
check_service "named" "disabled" "2.2.4"
check_service "dnsmasq" "disabled" "2.2.5"
check_service "smb" "disabled" "2.2.6"
check_service "vsftpd" "disabled" "2.2.7"
check_service "dovecot" "disabled" "2.2.8"
check_service "nfs" "disabled" "2.2.9"
check_service "ypserv" "disabled" "2.2.10"
check_service "cups" "disabled" "2.2.11"
check_service "rpcbind" "disabled" "2.2.12"
check_service "rsync" "disabled" "2.2.13"
check_service "snmpd" "disabled" "2.2.14"
check_service "telnet.socket" "disabled" "2.2.15"
check_service "tftp.socket" "disabled" "2.2.16"
check_service "squid" "disabled" "2.2.17"
check_service "httpd" "disabled" "2.2.18"
check_service "xinetd" "disabled" "2.2.19"
check_package "xorg-x11*" "2.2.20"

# 2.2.21 Ensure mail transfer agent is configured for local-only mode
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ -f /etc/postfix/main.cf ] && grep -q "^inet_interfaces = loopback-only" /etc/postfix/main.cf; then
    log_message "PASS: [CIS 2.2.21] L'agent de transfert de courrier est configuré en mode local uniquement"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 2.2.21] L'agent de transfert de courrier n'est pas configuré en mode local uniquement"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 2.2.22 Ensure only approved services are listening
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
unapproved_services=$(ss -tuln | grep LISTEN | grep -v '127.0.0.1' | grep -v '::1')
if [ -z "$unapproved_services" ]; then
    log_message "PASS: [CIS 2.2.22] Aucun service non approuvé n'écoute sur les interfaces réseau"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 2.2.22] Des services non approuvés écoutent sur les interfaces réseau"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 2.3 Configuration des clients de service
log_message "=== 2.3 Configuration des clients de service ==="

# Vérification des clients de service
check_package "ftp" "2.3.1"
check_package "openldap-clients" "2.3.2"
check_package "ypbind" "2.3.3"
check_package "telnet" "2.3.4"
check_package "tftp" "2.3.5" 