#!/bin/bash

# Section 3 - Configuration réseau
log_message "=== 3 Configuration réseau ==="

# 3.1 Configuration réseau (Host Only)
log_message "=== 3.1 Configuration réseau (Host Only) ==="

# 3.1.1 Vérification du statut IPv6
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep -q "^net.ipv6.conf.all.disable_ipv6" /etc/sysctl.conf; then
    log_message "PASS: [CIS 3.1.1] Le statut IPv6 est identifié"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 3.1.1] Le statut IPv6 n'est pas identifié"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 3.1.2 Vérification des interfaces sans fil
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
wireless_interfaces=$(iwconfig 2>&1 | grep -v "no wireless" | grep "IEEE")
if [ -z "$wireless_interfaces" ]; then
    log_message "PASS: [CIS 3.1.2] Aucune interface sans fil n'est active"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 3.1.2] Des interfaces sans fil sont actives"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 3.1.3 Vérification des services Bluetooth
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if ! systemctl is-active bluetooth &>/dev/null && ! systemctl is-enabled bluetooth &>/dev/null; then
    log_message "PASS: [CIS 3.1.3] Les services Bluetooth ne sont pas utilisés"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 3.1.3] Les services Bluetooth sont actifs"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 3.2 Configuration des modules kernel réseau
log_message "=== 3.2 Configuration des modules kernel réseau ==="

check_kernel_module() {
    local module=$1
    local cis_ref=$2
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if ! modprobe -n -v "$module" 2>&1 | grep -q "install /bin/true" && \
       ! grep -q "install $module /bin/true" /etc/modprobe.d/*.conf; then
        log_message "FAIL: [CIS $cis_ref] Le module $module n'est pas désactivé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    else
        log_message "PASS: [CIS $cis_ref] Le module $module est désactivé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    fi
}

check_kernel_module "dccp" "3.2.1"
check_kernel_module "tipc" "3.2.2"
check_kernel_module "rds" "3.2.3"
check_kernel_module "sctp" "3.2.4"

# 3.3 Configuration des paramètres kernel réseau
log_message "=== 3.3 Configuration des paramètres kernel réseau ==="

check_sysctl() {
    local param=$1
    local expected=$2
    local cis_ref=$3
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    current=$(sysctl -n "$param" 2>/dev/null)
    
    if [ "$current" = "$expected" ]; then
        log_message "PASS: [CIS $cis_ref] $param est correctement configuré ($expected)"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS $cis_ref] $param est mal configuré (actuel: $current, attendu: $expected)"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Paramètres réseau IPv4
check_sysctl "net.ipv4.ip_forward" "0" "3.3.1"
check_sysctl "net.ipv4.conf.all.send_redirects" "0" "3.3.2"
check_sysctl "net.ipv4.conf.default.send_redirects" "0" "3.3.2"
check_sysctl "net.ipv4.icmp_ignore_bogus_error_responses" "1" "3.3.3"
check_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1" "3.3.4"
check_sysctl "net.ipv4.conf.all.accept_redirects" "0" "3.3.5"
check_sysctl "net.ipv4.conf.default.accept_redirects" "0" "3.3.5"
check_sysctl "net.ipv4.conf.all.secure_redirects" "0" "3.3.6"
check_sysctl "net.ipv4.conf.default.secure_redirects" "0" "3.3.6"
check_sysctl "net.ipv4.conf.all.rp_filter" "1" "3.3.7"
check_sysctl "net.ipv4.conf.default.rp_filter" "1" "3.3.7"
check_sysctl "net.ipv4.conf.all.accept_source_route" "0" "3.3.8"
check_sysctl "net.ipv4.conf.default.accept_source_route" "0" "3.3.8"
check_sysctl "net.ipv4.conf.all.log_martians" "1" "3.3.9"
check_sysctl "net.ipv4.conf.default.log_martians" "1" "3.3.9"
check_sysctl "net.ipv4.tcp_syncookies" "1" "3.3.10"

# Paramètres réseau IPv6
check_sysctl "net.ipv6.conf.all.accept_ra" "0" "3.3.11"
check_sysctl "net.ipv6.conf.default.accept_ra" "0" "3.3.11"

# 3.4 Configuration du pare-feu
log_message "=== 3.4 Configuration du pare-feu ==="

# 3.4.1 Configuration de l'utilitaire de pare-feu
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if rpm -q iptables &>/dev/null; then
    log_message "PASS: [CIS 3.4.1.1] iptables est installé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 3.4.1.1] iptables n'est pas installé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 3.4.1.2 Vérification d'un seul utilitaire de pare-feu
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
firewall_count=0
for fw in iptables firewalld nftables; do
    if systemctl is-active "$fw" &>/dev/null; then
        firewall_count=$((firewall_count + 1))
    fi
done

if [ "$firewall_count" -eq 1 ]; then
    log_message "PASS: [CIS 3.4.1.2] Un seul utilitaire de pare-feu est utilisé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 3.4.1.2] Plusieurs utilitaires de pare-feu sont actifs"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 3.4.2 Configuration de firewalld
if systemctl is-active firewalld &>/dev/null; then
    # 3.4.2.1 Installation de firewalld
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if rpm -q firewalld &>/dev/null; then
        log_message "PASS: [CIS 3.4.2.1] firewalld est installé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 3.4.2.1] firewalld n'est pas installé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 3.4.2.2 Service firewalld actif
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if systemctl is-enabled firewalld &>/dev/null; then
        log_message "PASS: [CIS 3.4.2.2] firewalld est activé et en cours d'exécution"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 3.4.2.2] firewalld n'est pas activé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 3.4.2.3 Vérification des services et ports inutiles
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if ! firewall-cmd --list-all | grep -q "services:.*\(dhcpv6-client\|ssh\)"; then
        log_message "PASS: [CIS 3.4.2.3] Pas de services inutiles dans firewalld"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 3.4.2.3] Des services inutiles sont autorisés dans firewalld"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 3.4.2.4 Vérification des zones
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if firewall-cmd --get-active-zones | grep -q "[a-zA-Z]"; then
        log_message "PASS: [CIS 3.4.2.4] Les interfaces réseau sont assignées à des zones"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 3.4.2.4] Les interfaces réseau ne sont pas assignées à des zones"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
fi

# 3.4.3 Configuration de nftables
if systemctl is-active nftables &>/dev/null; then
    # 3.4.3.1 Vérification de l'installation de nftables
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if rpm -q nftables &>/dev/null; then
        log_message "PASS: [CIS 3.4.3.1] nftables est installé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 3.4.3.1] nftables n'est pas installé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 3.4.3.2 Vérification que les tables iptables sont vidées
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if iptables -L | grep -q "^Chain" && ip6tables -L | grep -q "^Chain"; then
        log_message "FAIL: [CIS 3.4.3.2] Les tables iptables ne sont pas vidées"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    else
        log_message "PASS: [CIS 3.4.3.2] Les tables iptables sont vidées"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    fi

    # 3.4.3.3 Vérification de l'existence d'une table nftables
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if nft list tables | grep -q "table"; then
        log_message "PASS: [CIS 3.4.3.3] Une table nftables existe"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 3.4.3.3] Aucune table nftables n'existe"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 3.4.3.4 Vérification des chaînes de base
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if nft list ruleset | grep -q "type filter hook" && \
       nft list ruleset | grep -q "input" && \
       nft list ruleset | grep -q "forward" && \
       nft list ruleset | grep -q "output"; then
        log_message "PASS: [CIS 3.4.3.4] Les chaînes de base existent"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 3.4.3.4] Les chaînes de base sont manquantes"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 3.4.3.5 Vérification de la configuration du trafic loopback
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if nft list ruleset | grep -q "iif \"lo\" accept" && \
       nft list ruleset | grep -q "ip saddr 127.0.0.0/8"; then
        log_message "PASS: [CIS 3.4.3.5] Le trafic loopback est correctement configuré"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 3.4.3.5] Le trafic loopback n'est pas correctement configuré"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 3.4.3.6 Vérification des connexions sortantes et établies
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if nft list ruleset | grep -q "ct state established,related accept"; then
        log_message "PASS: [CIS 3.4.3.6] Les connexions sortantes et établies sont configurées"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 3.4.3.6] Les connexions sortantes et établies ne sont pas configurées"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 3.4.3.7 Vérification de la politique par défaut
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if nft list ruleset | grep -q "policy drop"; then
        log_message "PASS: [CIS 3.4.3.7] La politique par défaut est 'drop'"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 3.4.3.7] La politique par défaut n'est pas 'drop'"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 3.4.3.8 Vérification du service nftables
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if systemctl is-enabled nftables &>/dev/null && systemctl is-active nftables &>/dev/null; then
        log_message "PASS: [CIS 3.4.3.8] Le service nftables est activé et actif"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 3.4.3.8] Le service nftables n'est pas activé ou actif"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 3.4.3.9 Vérification de la persistance des règles
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ -f "/etc/sysconfig/nftables.conf" ] && [ -s "/etc/sysconfig/nftables.conf" ]; then
        log_message "PASS: [CIS 3.4.3.9] Les règles nftables sont persistantes"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 3.4.3.9] Les règles nftables ne sont pas persistantes"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
fi

# 3.4.4 Configuration d'iptables
if systemctl is-active iptables &>/dev/null; then
    # 3.4.4.1.1 Vérification de l'installation des paquets iptables
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if rpm -q iptables iptables-services &>/dev/null; then
        log_message "PASS: [CIS 3.4.4.1.1] Les paquets iptables sont installés"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 3.4.4.1.1] Les paquets iptables ne sont pas installés"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 3.4.4.2.1 Vérification de la configuration du trafic loopback
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if iptables -L INPUT -v -n | grep -q "ACCEPT.*lo.*" && \
       iptables -L INPUT -v -n | grep -q "DROP.*127.0.0.0/8"; then
        log_message "PASS: [CIS 3.4.4.2.1] Le trafic loopback est correctement configuré"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 3.4.4.2.1] Le trafic loopback n'est pas correctement configuré"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 3.4.4.2.2 Vérification des connexions sortantes et établies
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if iptables -L -v -n | grep -q "ACCEPT.*state ESTABLISHED,RELATED"; then
        log_message "PASS: [CIS 3.4.4.2.2] Les connexions sortantes et établies sont configurées"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 3.4.4.2.2] Les connexions sortantes et établies ne sont pas configurées"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 3.4.4.2.3 Vérification des règles pour les ports ouverts
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    open_ports=$(netstat -ln | grep "LISTEN" | awk '{print $4}' | cut -d: -f2)
    rules_missing=0
    for port in $open_ports; do
        if ! iptables -L INPUT -v -n | grep -q ".*:$port.*"; then
            rules_missing=1
            break
        fi
    done
    if [ $rules_missing -eq 0 ]; then
        log_message "PASS: [CIS 3.4.4.2.3] Des règles existent pour tous les ports ouverts"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 3.4.4.2.3] Des règles manquent pour certains ports ouverts"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 3.4.4.2.4 Vérification de la politique par défaut
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if iptables -L | grep -q "Chain .* (policy DROP)"; then
        log_message "PASS: [CIS 3.4.4.2.4] La politique par défaut est 'DROP'"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 3.4.4.2.4] La politique par défaut n'est pas 'DROP'"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 3.4.4.2.5 Vérification de la sauvegarde des règles
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ -f "/etc/sysconfig/iptables" ] && [ -s "/etc/sysconfig/iptables" ]; then
        log_message "PASS: [CIS 3.4.4.2.5] Les règles iptables sont sauvegardées"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 3.4.4.2.5] Les règles iptables ne sont pas sauvegardées"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 3.4.4.2.6 Vérification du service iptables
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if systemctl is-enabled iptables &>/dev/null && systemctl is-active iptables &>/dev/null; then
        log_message "PASS: [CIS 3.4.4.2.6] Le service iptables est activé et actif"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 3.4.4.2.6] Le service iptables n'est pas activé ou actif"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # Configuration ip6tables
    if [ -x "$(command -v ip6tables)" ]; then
        # 3.4.4.3.1 Vérification de la configuration du trafic loopback IPv6
        TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
        if ip6tables -L INPUT -v -n | grep -q "ACCEPT.*lo.*" && \
           ip6tables -L INPUT -v -n | grep -q "DROP.*::1"; then
            log_message "PASS: [CIS 3.4.4.3.1] Le trafic loopback IPv6 est correctement configuré"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        else
            log_message "FAIL: [CIS 3.4.4.3.1] Le trafic loopback IPv6 n'est pas correctement configuré"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi

        # 3.4.4.3.2 Vérification des connexions sortantes et établies IPv6
        TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
        if ip6tables -L -v -n | grep -q "ACCEPT.*state ESTABLISHED,RELATED"; then
            log_message "PASS: [CIS 3.4.4.3.2] Les connexions IPv6 sortantes et établies sont configurées"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        else
            log_message "FAIL: [CIS 3.4.4.3.2] Les connexions IPv6 sortantes et établies ne sont pas configurées"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi

        # 3.4.4.3.3 Vérification des règles pour les ports IPv6 ouverts
        TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
        open_ports_ipv6=$(netstat -ln | grep "LISTEN" | grep ":::" | awk '{print $4}' | cut -d: -f2)
        rules_missing=0
        for port in $open_ports_ipv6; do
            if ! ip6tables -L INPUT -v -n | grep -q ".*:$port.*"; then
                rules_missing=1
                break
            fi
        done
        if [ $rules_missing -eq 0 ]; then
            log_message "PASS: [CIS 3.4.4.3.3] Des règles existent pour tous les ports IPv6 ouverts"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        else
            log_message "FAIL: [CIS 3.4.4.3.3] Des règles manquent pour certains ports IPv6 ouverts"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi

        # 3.4.4.3.4 Vérification de la politique par défaut IPv6
        TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
        if ip6tables -L | grep -q "Chain .* (policy DROP)"; then
            log_message "PASS: [CIS 3.4.4.3.4] La politique IPv6 par défaut est 'DROP'"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        else
            log_message "FAIL: [CIS 3.4.4.3.4] La politique IPv6 par défaut n'est pas 'DROP'"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi

        # 3.4.4.3.5 Vérification de la sauvegarde des règles IPv6
        TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
        if [ -f "/etc/sysconfig/ip6tables" ] && [ -s "/etc/sysconfig/ip6tables" ]; then
            log_message "PASS: [CIS 3.4.4.3.5] Les règles ip6tables sont sauvegardées"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        else
            log_message "FAIL: [CIS 3.4.4.3.5] Les règles ip6tables ne sont pas sauvegardées"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi
    fi
fi 