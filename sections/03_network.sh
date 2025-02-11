#!/bin/bash

# Section 3 - Configuration réseau
log_message "=== 3 Configuration réseau ==="

# Fonction de vérification des paramètres sysctl
function check_sysctl() {
    local param=$1
    local expected_value=$2
    
    log_message "=== Vérification du paramètre sysctl $param ==="
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    local current_value=$(sysctl -n "$param" 2>/dev/null)
    
    if [ -z "$current_value" ]; then
        log_message "FAIL: Le paramètre $param n'existe pas"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    fi
    
    if [ "$current_value" != "$expected_value" ]; then
        log_message "FAIL: Valeur incorrecte pour $param (actuel: $current_value, attendu: $expected_value)"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    else
        log_message "PASS: Valeur correcte pour $param"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    fi
}

# 3.1 Paramètres réseau (Host Only)
log_message "=== 3.1 Paramètres réseau (Host Only) ==="

# 3.1.1 Désactivation du forwarding IP
check_sysctl "net.ipv4.ip_forward" "0"
check_sysctl "net.ipv6.conf.all.forwarding" "0"

# 3.1.2 Désactivation des redirections de paquets
check_sysctl "net.ipv4.conf.all.send_redirects" "0"
check_sysctl "net.ipv4.conf.default.send_redirects" "0"

# 3.2 Paramètres réseau (Host and Router)
log_message "=== 3.2 Paramètres réseau (Host and Router) ==="

# 3.2.1 Désactivation de l'acceptation des paquets source routed
check_sysctl "net.ipv4.conf.all.accept_source_route" "0"
check_sysctl "net.ipv4.conf.default.accept_source_route" "0"
check_sysctl "net.ipv6.conf.all.accept_source_route" "0"
check_sysctl "net.ipv6.conf.default.accept_source_route" "0"

# 3.2.2 Désactivation de l'acceptation des redirections ICMP
check_sysctl "net.ipv4.conf.all.accept_redirects" "0"
check_sysctl "net.ipv4.conf.default.accept_redirects" "0"
check_sysctl "net.ipv6.conf.all.accept_redirects" "0"
check_sysctl "net.ipv6.conf.default.accept_redirects" "0"

# 3.2.3 Désactivation des redirections ICMP sécurisées
check_sysctl "net.ipv4.conf.all.secure_redirects" "0"
check_sysctl "net.ipv4.conf.default.secure_redirects" "0"

# 3.2.4 Journalisation des paquets suspects
check_sysctl "net.ipv4.conf.all.log_martians" "1"
check_sysctl "net.ipv4.conf.default.log_martians" "1"

# 3.2.5 Ignorer les broadcasts ICMP
check_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1"

# 3.2.6 Ignorer les réponses ICMP bogus
check_sysctl "net.ipv4.icmp_ignore_bogus_error_responses" "1"

# 3.2.7 Activation du Reverse Path Filtering
check_sysctl "net.ipv4.conf.all.rp_filter" "1"
check_sysctl "net.ipv4.conf.default.rp_filter" "1"

# 3.2.8 Activation des TCP SYN Cookies
check_sysctl "net.ipv4.tcp_syncookies" "1"

# 3.3 TCP Wrappers
log_message "=== 3.3 TCP Wrappers ==="

# 3.3.1 Vérification de l'installation de TCP Wrappers
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if rpm -q tcp_wrappers > /dev/null 2>&1; then
    log_message "PASS: TCP Wrappers est installé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: TCP Wrappers n'est pas installé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 3.3.2 Vérification de /etc/hosts.allow
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ -f "/etc/hosts.allow" ]; then
    local perms=$(stat -c %a /etc/hosts.allow)
    if [ "$perms" = "644" ]; then
        log_message "PASS: /etc/hosts.allow existe avec les bonnes permissions"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Mauvaises permissions sur /etc/hosts.allow: $perms"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
else
    log_message "FAIL: /etc/hosts.allow n'existe pas"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 3.3.3 Vérification de /etc/hosts.deny
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ -f "/etc/hosts.deny" ]; then
    local perms=$(stat -c %a /etc/hosts.deny)
    if [ "$perms" = "644" ] && grep -q "ALL: ALL" /etc/hosts.deny; then
        log_message "PASS: /etc/hosts.deny est correctement configuré"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: /etc/hosts.deny n'est pas correctement configuré"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
else
    log_message "FAIL: /etc/hosts.deny n'existe pas"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 3.4 Configuration du pare-feu
log_message "=== 3.4 Configuration du pare-feu ==="

# 3.4.1 Vérification de l'installation du pare-feu
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if rpm -q firewalld > /dev/null 2>&1 || rpm -q iptables > /dev/null 2>&1; then
    log_message "PASS: Un pare-feu est installé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: Aucun pare-feu n'est installé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 3.4.2 Vérification de l'état du service pare-feu
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if systemctl is-active firewalld > /dev/null 2>&1 || systemctl is-active iptables > /dev/null 2>&1; then
    log_message "PASS: Le service pare-feu est actif"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: Le service pare-feu n'est pas actif"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 3.5 Interfaces sans fil
log_message "=== 3.5 Interfaces sans fil ==="

# 3.5.1 Désactivation des interfaces sans fil
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if ! iwconfig 2>&1 | grep -q "no wireless extensions" && ! iwconfig 2>&1 | grep -q "No such device"; then
    log_message "FAIL: Des interfaces sans fil sont présentes"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
else
    log_message "PASS: Aucune interface sans fil n'est présente"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
fi 