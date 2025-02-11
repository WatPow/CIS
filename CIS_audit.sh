#!/bin/bash

# Configuration des variables globales
MODE_AUDIT=true  # Forcé en mode audit uniquement
LOG_FILE="/var/log/cis_audit.log"
REPORT_FILE="/var/log/cis_report_$(date +%Y%m%d).txt"
HTML_REPORT="./cis_report_$(date +%Y%m%d).html"
FAILED_CHECKS=0
PASSED_CHECKS=0
TOTAL_CHECKS=0
start_time=$(date +%s)
GENERATE_HTML=false

# Gestion des options
while getopts "h" opt; do
  case $opt in
    h) GENERATE_HTML=true ;;
  esac
done

# Gestion des erreurs
set -e
trap 'echo "Une erreur est survenue à la ligne $LINENO" | tee -a $LOG_FILE' ERR

# Fonction de journalisation
function log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOG_FILE
}

# Fonction de vérification des prérequis
function check_prerequisites() {
    log_message "Vérification des prérequis..."
    
    # Vérification des privilèges root
    if [ "$(id -u)" -ne 0 ]; then
        log_message "ERROR: Ce script doit être exécuté en tant que root"
        exit 1
    fi
    
    # Vérification de l'espace disque
    if ! df -h / >/dev/null 2>&1; then
        log_message "ERROR: Impossible de vérifier l'espace disque"
        exit 1
    fi
    
    SPACE=$(df -h / | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ -z "$SPACE" ]; then
        log_message "ERROR: Impossible de lire l'espace disque disponible"
        exit 1
    fi
    
    if [ "${SPACE%.*}" -lt 1 ]; then
        log_message "WARNING: Espace disque faible (< 1GB)"
    fi
    
    # Vérification des commandes requises
    local required_commands=("awk" "grep" "stat" "find" "mount" "systemctl")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_message "ERROR: Commande requise non trouvée: $cmd"
            exit 1
        fi
    done
}

# Fonction de vérification d'un paramètre
function check_setting() {
    local setting=$1
    local expected=$2
    local current=$3
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if [ "$current" = "$expected" ]; then
        log_message "PASS: $setting est correctement configuré ($current)"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: $setting n'est pas correctement configuré (attendu: $expected, actuel: $current)"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Fonction de vérification des modules du système de fichiers
function check_filesystem_modules() {
    local module=$1
    if lsmod | grep "$module" > /dev/null 2>&1; then
        log_message "FAIL: Le module $module est chargé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    else
        log_message "PASS: Le module $module n'est pas chargé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    fi
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
}

# Fonction de vérification des partitions
function check_partition() {
    local partition=$1
    local required_options=$2
    
    log_message "=== Vérification de la partition $partition ==="
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if ! mount | grep -q " $partition "; then
        log_message "FAIL: La partition $partition n'existe pas"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 0
    fi
    
    local current_options=$(mount | grep " $partition " | awk '{print $6}' | tr -d '()') || ""
    if [ -z "$current_options" ]; then
        log_message "FAIL: Impossible de lire les options de montage pour $partition"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 0
    fi
    
    local missing_options=""
    
    for option in $required_options; do
        if ! echo "$current_options" | grep -q "$option"; then
            missing_options="$missing_options $option"
        fi
    done
    
    if [ -n "$missing_options" ]; then
        log_message "FAIL: Options manquantes pour $partition :$missing_options"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    else
        log_message "PASS: Toutes les options requises sont présentes pour $partition"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    fi
    return 0
}

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
    }
    
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
    return 0
}

# Fonction de vérification des fichiers
function check_file_permissions() {
    local file=$1
    local expected_owner=$2
    local expected_group=$3
    local expected_perms=$4
    
    log_message "=== Vérification des permissions de $file ==="
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if [ ! -e "$file" ]; then
        log_message "FAIL: Le fichier $file n'existe pas"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 0
    fi
    
    if [ ! -r "$file" ]; then
        log_message "FAIL: Le fichier $file n'est pas lisible"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 0
    }
    
    local current_owner=$(stat -c %U "$file" 2>/dev/null || echo "unknown")
    local current_group=$(stat -c %G "$file" 2>/dev/null || echo "unknown")
    local current_perms=$(stat -c %a "$file" 2>/dev/null || echo "unknown")
    
    if [ "$current_owner" = "unknown" ] || [ "$current_group" = "unknown" ] || [ "$current_perms" = "unknown" ]; then
        log_message "FAIL: Impossible de lire les permissions pour $file"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 0
    }
    
    if [ "$current_owner" != "$expected_owner" ] || 
       [ "$current_group" != "$expected_group" ] || 
       [ "$current_perms" != "$expected_perms" ]; then
        log_message "FAIL: Permissions incorrectes pour $file"
        log_message "  Propriétaire actuel: $current_owner (attendu: $expected_owner)"
        log_message "  Groupe actuel: $current_group (attendu: $expected_group)"
        log_message "  Permissions actuelles: $current_perms (attendu: $expected_perms)"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    else
        log_message "PASS: Permissions correctes pour $file"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    fi
    return 0
}

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

# Fonction de vérification des utilisateurs
function check_users() {
    log_message "=== Vérification des utilisateurs système ==="
    
    # Vérification des UID en double
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local duplicate_uids=$(cut -d: -f3 /etc/passwd | sort -n | uniq -d)
    if [ -n "$duplicate_uids" ]; then
        log_message "FAIL: UIDs en double trouvés: $duplicate_uids"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    else
        log_message "PASS: Pas d'UIDs en double"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    fi
    
    # Vérification des utilisateurs sans mot de passe
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local empty_passwords=$(awk -F: '($2 == "" ) { print $1 }' /etc/shadow)
    if [ -n "$empty_passwords" ]; then
        log_message "FAIL: Utilisateurs sans mot de passe trouvés: $empty_passwords"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    else
        log_message "PASS: Pas d'utilisateurs sans mot de passe"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    fi
    
    # Vérification des entrées "+" dans /etc/passwd
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q '^+:' /etc/passwd; then
        log_message "FAIL: Entrées '+' trouvées dans /etc/passwd"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    else
        log_message "PASS: Pas d'entrées '+' dans /etc/passwd"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    fi
    
    # Vérification des utilisateurs avec UID 0
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local root_users=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd | grep -v '^root$')
    if [ -n "$root_users" ]; then
        log_message "FAIL: Utilisateurs avec UID 0 autres que root: $root_users"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    else
        log_message "PASS: Seul root a UID 0"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    fi
}

# Fonction de vérification des répertoires home
function check_home_directories() {
    log_message "=== Vérification des répertoires home ==="
    
    while IFS=: read -r user pass uid gid desc home shell; do
        if [ "$uid" -ge 1000 ] && [ "$user" != "nfsnobody" ]; then
            TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
            if [ ! -d "$home" ]; then
                log_message "FAIL: Répertoire home manquant pour $user: $home"
                FAILED_CHECKS=$((FAILED_CHECKS + 1))
            else
                local perms=$(stat -c %a "$home")
                if [ "$perms" -gt 750 ]; then
                    log_message "FAIL: Permissions trop permissives sur $home: $perms"
                    FAILED_CHECKS=$((FAILED_CHECKS + 1))
                else
                    local owner=$(stat -c %U "$home")
                    if [ "$owner" != "$user" ]; then
                        log_message "FAIL: Propriétaire incorrect pour $home: $owner (devrait être $user)"
                        FAILED_CHECKS=$((FAILED_CHECKS + 1))
                    else
                        log_message "PASS: Configuration correcte pour $home"
                        PASSED_CHECKS=$((PASSED_CHECKS + 1))
                    fi
                fi
            fi
        fi
    done < /etc/passwd
}

# Fonction de vérification de la configuration réseau
function check_network_security() {
    log_message "=== Vérification de la configuration réseau ==="
    
    # Vérification des paramètres réseau critiques
    check_sysctl "net.ipv4.ip_forward" "0"
    check_sysctl "net.ipv4.conf.all.send_redirects" "0"
    check_sysctl "net.ipv4.conf.default.send_redirects" "0"
    check_sysctl "net.ipv4.conf.all.accept_redirects" "0"
    check_sysctl "net.ipv4.conf.default.accept_redirects" "0"
    check_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1"
    check_sysctl "net.ipv4.tcp_syncookies" "1"
}

# Fonction de vérification des protocoles inutilisés
function check_unused_protocols() {
    log_message "=== Vérification des protocoles inutilisés ==="
    
    local protocols=("dccp" "sctp" "rds" "tipc")
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
}

# Fonction de vérification des services réseau
function check_network_services() {
    log_message "=== Vérification des services réseau ==="
    
    # Liste des services à vérifier
    check_service "xinetd" "disabled"
    check_service "telnet" "disabled"
    check_service "rsh" "disabled"
    check_service "rlogin" "disabled"
    check_service "rexec" "disabled"
    check_service "tftp" "disabled"
    check_service "talk" "disabled"
}

# Fonction de vérification de la configuration d'audit
function check_audit_config() {
    log_message "=== Vérification de la configuration d'audit ==="
    
    # Vérification du service auditd
    check_service "auditd" "enabled"
    
    # Vérification du fichier de configuration
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ -f "/etc/audit/auditd.conf" ]; then
        log_message "PASS: Le fichier de configuration d'audit existe"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Le fichier de configuration d'audit est manquant"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Fonction de vérification de la politique de mots de passe
function check_password_policy() {
    log_message "=== Vérification de la politique de mots de passe ==="
    
    local params=(
        "PASS_MAX_DAYS:90"
        "PASS_MIN_DAYS:7"
        "PASS_WARN_AGE:7"
    )
    
    for param in "${params[@]}"; do
        IFS=':' read -r name value <<< "$param"
        TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
        current=$(grep "^$name" /etc/login.defs | awk '{print $2}')
        
        if [ "$current" = "$value" ]; then
            log_message "PASS: $name est correctement configuré ($value)"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        else
            log_message "FAIL: $name est mal configuré (actuel: $current, attendu: $value)"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi
    done
}

# Fonction de vérification des comptes système
function check_system_accounts() {
    log_message "=== Vérification des comptes système ==="
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local system_accounts=$(awk -F: '($3 < 1000) {print $1}' /etc/passwd | grep -v "^root$")
    local invalid_shell=0
    
    for account in $system_accounts; do
        shell=$(grep "^$account:" /etc/passwd | cut -d: -f7)
        if [ "$shell" != "/sbin/nologin" ] && [ "$shell" != "/bin/false" ]; then
            log_message "FAIL: Le compte système $account a un shell invalide: $shell"
            invalid_shell=1
        fi
    done
    
    if [ $invalid_shell -eq 0 ]; then
        log_message "PASS: Tous les comptes système ont des shells appropriés"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Fonction de vérification des groupes
function check_groups() {
    log_message "=== Vérification des groupes ==="
    
    # Vérification des GID en double
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local duplicate_gids=$(cut -d: -f3 /etc/group | sort -n | uniq -d)
    if [ -n "$duplicate_gids" ]; then
        log_message "FAIL: GIDs en double trouvés: $duplicate_gids"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    else
        log_message "PASS: Pas de GIDs en double"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    fi
}

# Fonction de vérification des fichiers SUID/SGID
function check_suid_sgid() {
    log_message "=== Vérification des fichiers SUID/SGID ==="
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local suid_files=$(find / -type f -perm -4000 2>/dev/null)
    local sgid_files=$(find / -type f -perm -2000 2>/dev/null)
    
    if [ -n "$suid_files" ]; then
        log_message "INFO: Fichiers SUID trouvés:"
        echo "$suid_files" | while read -r file; do
            log_message "  $file"
        done
    fi
    
    if [ -n "$sgid_files" ]; then
        log_message "INFO: Fichiers SGID trouvés:"
        echo "$sgid_files" | while read -r file; do
            log_message "  $file"
        done
    fi
    
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
}

# Fonction de vérification des fichiers world-writable
function check_world_writable() {
    log_message "=== Vérification des fichiers world-writable ==="
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local world_writable=$(find / -type f -perm -0002 2>/dev/null)
    
    if [ -n "$world_writable" ]; then
        log_message "FAIL: Fichiers world-writable trouvés:"
        echo "$world_writable" | while read -r file; do
            log_message "  $file"
        done
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    else
        log_message "PASS: Aucun fichier world-writable trouvé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    fi
}

# Fonction de vérification des fichiers sans propriétaire
function check_unowned_files() {
    log_message "=== Vérification des fichiers sans propriétaire ==="
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local unowned=$(find / -nouser -o -nogroup 2>/dev/null)
    
    if [ -n "$unowned" ]; then
        log_message "FAIL: Fichiers sans propriétaire trouvés:"
        echo "$unowned" | while read -r file; do
            log_message "  $file"
        done
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    else
        log_message "PASS: Aucun fichier sans propriétaire trouvé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    fi
}

# Fonction de vérification du PATH root
function check_root_path() {
    log_message "=== Vérification du PATH root ==="
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local root_path=$(sudo -Hiu root env | grep '^PATH=' | cut -d= -f2)
    local invalid_path=0
    
    IFS=: read -ra paths <<< "$root_path"
    for path in "${paths[@]}"; do
        if [ -z "$path" ] || [ "$path" = "." ]; then
            log_message "FAIL: PATH contient un répertoire vide ou '.'"
            invalid_path=1
        elif [ ! -d "$path" ]; then
            log_message "FAIL: Le répertoire $path n'existe pas"
            invalid_path=1
        fi
    done
    
    if [ $invalid_path -eq 0 ]; then
        log_message "PASS: PATH root est correctement configuré"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Fonction de vérification des fichiers dot
function check_dot_files() {
    log_message "=== Vérification des fichiers dot ==="
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local dot_files_found=0
    
    while IFS=: read -r user _ uid _ _ home _; do
        if [ "$uid" -ge 1000 ] && [ -d "$home" ]; then
            for file in .forward .netrc .rhosts; do
                if [ -f "$home/$file" ]; then
                    log_message "FAIL: Fichier $file trouvé dans $home"
                    dot_files_found=1
                fi
            done
        fi
    done < /etc/passwd
    
    if [ $dot_files_found -eq 0 ]; then
        log_message "PASS: Aucun fichier dot critique trouvé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Fonction de vérification des mises à jour logicielles
function check_software_updates() {
    log_message "=== 1.2 Vérification de la configuration des mises à jour ==="
    
    # 1.2.1 Ensure GPG keys are configured (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n' | grep -q "CentOS 7"; then
        log_message "PASS: Les clés GPG de CentOS 7 sont configurées"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Les clés GPG de CentOS 7 ne sont pas configurées"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 1.2.2 Ensure package manager repositories are configured (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if yum repolist | grep -q "base/7"; then
        log_message "PASS: Les dépôts YUM sont correctement configurés"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Les dépôts YUM ne sont pas correctement configurés"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 1.2.3 Ensure gpgcheck is globally activated (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q "^gpgcheck=1" /etc/yum.conf; then
        log_message "PASS: La vérification GPG est activée globalement"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: La vérification GPG n'est pas activée globalement"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Fonction de vérification de l'intégrité du système de fichiers
function check_filesystem_integrity() {
    log_message "=== 1.3 Vérification de l'intégrité du système de fichiers ==="
    
    # 1.3.1 Ensure AIDE is installed (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if rpm -q aide > /dev/null 2>&1; then
        log_message "PASS: AIDE est installé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: AIDE n'est pas installé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 1.3.2 Ensure filesystem integrity is regularly checked (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if crontab -l 2>/dev/null | grep -q aide || ls -l /etc/cron.* | grep -q aide; then
        log_message "PASS: Une tâche CRON pour AIDE est configurée"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Aucune tâche CRON pour AIDE n'est configurée"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Fonction de vérification des paramètres de démarrage sécurisé
function check_secure_boot() {
    log_message "=== 1.4 Vérification des paramètres de démarrage ==="
    
    # 1.4.1 Ensure permissions on bootloader config are configured (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ -f /boot/grub2/grub.cfg ]; then
        local perms=$(stat -c %a /boot/grub2/grub.cfg)
        if [ "$perms" = "600" ]; then
            log_message "PASS: Les permissions sur grub.cfg sont correctes"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        else
            log_message "FAIL: Les permissions sur grub.cfg sont incorrectes (actuel: $perms, attendu: 600)"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi
    fi

    # 1.4.2 Ensure bootloader password is set (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q "^GRUB2_PASSWORD" /boot/grub2/user.cfg 2>/dev/null; then
        log_message "PASS: Le mot de passe GRUB2 est configuré"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Le mot de passe GRUB2 n'est pas configuré"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 1.4.3 Ensure authentication required for single user mode (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q "^SINGLE=/sbin/sulogin" /etc/sysconfig/init 2>/dev/null; then
        log_message "PASS: L'authentification en mode single user est requise"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: L'authentification en mode single user n'est pas requise"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Fonction de vérification du durcissement des processus
function check_process_hardening() {
    log_message "=== 1.5 Vérification du durcissement des processus ==="
    
    # 1.5.1 Ensure core dumps are restricted (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local limits_conf="/etc/security/limits.conf"
    local sysctl_core=$(sysctl -n fs.suid_dumpable 2>/dev/null)
    
    if grep -q "^\* hard core 0" "$limits_conf" && [ "$sysctl_core" = "0" ]; then
        log_message "PASS: Les core dumps sont restreints"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Les core dumps ne sont pas correctement restreints"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 1.5.2 Ensure XD/NX support is enabled (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if dmesg | grep -q "NX (Execute Disable) protection: active"; then
        log_message "PASS: La protection XD/NX est active"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: La protection XD/NX n'est pas active"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 1.5.3 Ensure address space layout randomization (ASLR) is enabled (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local aslr=$(sysctl -n kernel.randomize_va_space 2>/dev/null)
    if [ "$aslr" = "2" ]; then
        log_message "PASS: ASLR est activé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: ASLR n'est pas correctement configuré"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 1.5.4 Ensure prelink is disabled (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if ! rpm -q prelink > /dev/null 2>&1; then
        log_message "PASS: prelink n'est pas installé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: prelink est installé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Fonction de vérification du contrôle d'accès obligatoire (SELinux)
function check_mandatory_access() {
    log_message "=== 1.6 Vérification de SELinux ==="
    
    # 1.6.1.1 Ensure SELinux is installed (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if rpm -q libselinux > /dev/null 2>&1; then
        log_message "PASS: SELinux est installé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: SELinux n'est pas installé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 1.6.1.2 Ensure SELinux is not disabled in bootloader configuration (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if ! grep -q "selinux=0\|enforcing=0" /etc/default/grub; then
        log_message "PASS: SELinux n'est pas désactivé dans la configuration du bootloader"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: SELinux est désactivé dans la configuration du bootloader"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 1.6.1.3 Ensure SELinux policy is configured (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local selinux_policy=$(grep "^SELINUXTYPE=" /etc/selinux/config | cut -d= -f2)
    if [ "$selinux_policy" = "targeted" ] || [ "$selinux_policy" = "mls" ]; then
        log_message "PASS: La politique SELinux est correctement configurée ($selinux_policy)"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: La politique SELinux n'est pas correctement configurée"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 1.6.1.4 Ensure the SELinux mode is enforcing (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local selinux_mode=$(grep "^SELINUX=" /etc/selinux/config | cut -d= -f2)
    if [ "$selinux_mode" = "enforcing" ]; then
        log_message "PASS: SELinux est en mode enforcing"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: SELinux n'est pas en mode enforcing"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 1.6.1.5 Ensure no unconfined services exist (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if ! ps -eZ | grep unconfined_service_t > /dev/null 2>&1; then
        log_message "PASS: Aucun service non confiné trouvé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Des services non confinés ont été trouvés"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 1.6.1.6 Ensure SETroubleshoot is not installed (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if ! rpm -q setroubleshoot > /dev/null 2>&1; then
        log_message "PASS: SETroubleshoot n'est pas installé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: SETroubleshoot est installé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 1.6.1.7 Ensure the MCS Translation Service (mcstrans) is not installed (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if ! rpm -q mcstrans > /dev/null 2>&1; then
        log_message "PASS: mcstrans n'est pas installé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: mcstrans est installé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Fonction de vérification des bannières d'avertissement
function check_warning_banners() {
    log_message "=== 1.7 Vérification des bannières d'avertissement ==="
    
    # 1.7.1.1 Ensure message of the day is configured properly (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ -f /etc/motd ] && ! grep -E -i "(\\v|\\r|\\m|\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/motd > /dev/null; then
        log_message "PASS: Le message du jour est correctement configuré"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Le message du jour contient des informations système sensibles"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 1.7.1.2 Ensure local login warning banner is configured properly (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ -f /etc/issue ] && ! grep -E -i "(\\v|\\r|\\m|\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue > /dev/null; then
        log_message "PASS: La bannière de connexion locale est correctement configurée"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: La bannière de connexion locale contient des informations système sensibles"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 1.7.1.3 Ensure remote login warning banner is configured properly (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ -f /etc/issue.net ] && ! grep -E -i "(\\v|\\r|\\m|\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue.net > /dev/null; then
        log_message "PASS: La bannière de connexion distante est correctement configurée"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: La bannière de connexion distante contient des informations système sensibles"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 1.7.1.4 Ensure permissions on /etc/motd are configured (Scored)
    check_file_permissions "/etc/motd" "root" "root" "644"

    # 1.7.1.5 Ensure permissions on /etc/issue are configured (Scored)
    check_file_permissions "/etc/issue" "root" "root" "644"

    # 1.7.1.6 Ensure permissions on /etc/issue.net are configured (Scored)
    check_file_permissions "/etc/issue.net" "root" "root" "644"
}

# Fonction de vérification du système X Window
function check_xwindow_system() {
    log_message "=== 2.2.2 Vérification du système X Window ==="
    
    # 2.2.2 Ensure X Window System is not installed (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if ! rpm -qa xorg-x11* > /dev/null 2>&1; then
        log_message "PASS: Le système X Window n'est pas installé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Le système X Window est installé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Fonction de vérification du serveur Avahi
function check_avahi_server() {
    log_message "=== 2.2.3 Vérification du serveur Avahi ==="
    
    # 2.2.3 Ensure Avahi Server is not installed (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if ! rpm -q avahi-daemon > /dev/null 2>&1; then
        log_message "PASS: Le serveur Avahi n'est pas installé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Le serveur Avahi est installé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        
        # Vérification supplémentaire si installé
        if ! systemctl is-enabled avahi-daemon 2>/dev/null | grep -q "enabled"; then
            log_message "INFO: Le service Avahi est installé mais désactivé"
        else
            log_message "WARN: Le service Avahi est activé"
        fi
    fi
}

# Fonction de vérification de CUPS
function check_cups() {
    log_message "=== 2.2.4 Vérification de CUPS ==="
    
    # 2.2.4 Ensure CUPS is not installed (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if ! rpm -q cups > /dev/null 2>&1; then
        log_message "PASS: CUPS n'est pas installé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: CUPS est installé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        
        # Vérifications supplémentaires si installé
        if systemctl is-enabled cups 2>/dev/null | grep -q "enabled"; then
            log_message "WARN: Le service CUPS est activé"
        fi
        
        # Vérification des permissions du répertoire de configuration
        if [ -d "/etc/cups" ]; then
            local perms=$(stat -c %a /etc/cups)
            if [ "$perms" -gt 755 ]; then
                log_message "WARN: Permissions trop permissives sur /etc/cups: $perms"
            fi
        fi
    fi
}

# Fonction de vérification du serveur DHCP
function check_dhcp_server() {
    log_message "=== 2.2.5 Vérification du serveur DHCP ==="
    
    # 2.2.5 Ensure DHCP Server is not installed (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if ! rpm -q dhcp > /dev/null 2>&1; then
        log_message "PASS: Le serveur DHCP n'est pas installé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Le serveur DHCP est installé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        
        # Vérifications supplémentaires si installé
        if systemctl is-enabled dhcpd 2>/dev/null | grep -q "enabled"; then
            log_message "WARN: Le service DHCP est activé"
        fi
        
        # Vérification du fichier de configuration
        if [ -f "/etc/dhcp/dhcpd.conf" ]; then
            local perms=$(stat -c %a /etc/dhcp/dhcpd.conf)
            if [ "$perms" -gt 644 ]; then
                log_message "WARN: Permissions trop permissives sur dhcpd.conf: $perms"
            fi
        fi
    fi
}

# Fonction de vérification du serveur LDAP
function check_ldap_server() {
    log_message "=== 2.2.6 Vérification du serveur LDAP ==="
    
    # 2.2.6 Ensure LDAP server is not installed (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if ! rpm -q openldap-servers > /dev/null 2>&1; then
        log_message "PASS: Le serveur LDAP n'est pas installé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Le serveur LDAP est installé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        
        # Vérifications supplémentaires si installé
        if systemctl is-enabled slapd 2>/dev/null | grep -q "enabled"; then
            log_message "WARN: Le service LDAP est activé"
        fi
        
        # Vérification des fichiers de configuration
        if [ -d "/etc/openldap" ]; then
            local perms=$(stat -c %a /etc/openldap)
            if [ "$perms" -gt 755 ]; then
                log_message "WARN: Permissions trop permissives sur /etc/openldap: $perms"
            fi
        fi
    fi
}

# Fonction de vérification des paramètres réseau (Host Only)
function check_network_parameters() {
    log_message "=== 3.2 Vérification des paramètres réseau (Host Only) ==="
    
    # 3.2.1 Ensure IP forwarding is disabled (Scored)
    check_sysctl "net.ipv4.ip_forward" "0"
    check_sysctl "net.ipv6.conf.all.forwarding" "0"
    
    # 3.2.2 Ensure packet redirect sending is disabled (Scored)
    check_sysctl "net.ipv4.conf.all.send_redirects" "0"
    check_sysctl "net.ipv4.conf.default.send_redirects" "0"
    
    # 3.2.3 Ensure source routed packets are not accepted (Scored)
    check_sysctl "net.ipv4.conf.all.accept_source_route" "0"
    check_sysctl "net.ipv4.conf.default.accept_source_route" "0"
    check_sysctl "net.ipv6.conf.all.accept_source_route" "0"
    check_sysctl "net.ipv6.conf.default.accept_source_route" "0"
    
    # 3.2.4 Ensure ICMP redirects are not accepted (Scored)
    check_sysctl "net.ipv4.conf.all.accept_redirects" "0"
    check_sysctl "net.ipv4.conf.default.accept_redirects" "0"
    check_sysctl "net.ipv6.conf.all.accept_redirects" "0"
    check_sysctl "net.ipv6.conf.default.accept_redirects" "0"
    
    # 3.2.5 Ensure secure ICMP redirects are not accepted (Scored)
    check_sysctl "net.ipv4.conf.all.secure_redirects" "0"
    check_sysctl "net.ipv4.conf.default.secure_redirects" "0"
    
    # 3.2.6 Ensure suspicious packets are logged (Scored)
    check_sysctl "net.ipv4.conf.all.log_martians" "1"
    check_sysctl "net.ipv4.conf.default.log_martians" "1"
    
    # 3.2.7 Ensure broadcast ICMP requests are ignored (Scored)
    check_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1"
    
    # 3.2.8 Ensure bogus ICMP responses are ignored (Scored)
    check_sysctl "net.ipv4.icmp_ignore_bogus_error_responses" "1"
    
    # 3.2.9 Ensure Reverse Path Filtering is enabled (Scored)
    check_sysctl "net.ipv4.conf.all.rp_filter" "1"
    check_sysctl "net.ipv4.conf.default.rp_filter" "1"
    
    # 3.2.10 Ensure TCP SYN Cookies is enabled (Scored)
    check_sysctl "net.ipv4.tcp_syncookies" "1"
}

# Fonction de vérification de TCP Wrappers
function check_tcp_wrappers() {
    log_message "=== 3.3 Vérification de TCP Wrappers ==="
    
    # 3.3.1 Ensure TCP Wrappers is installed (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if rpm -q tcp_wrappers > /dev/null 2>&1; then
        log_message "PASS: TCP Wrappers est installé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: TCP Wrappers n'est pas installé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
    
    # 3.3.2 Ensure /etc/hosts.allow is configured (Scored)
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
    
    # 3.3.3 Ensure /etc/hosts.deny is configured (Scored)
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
}

# Fonction de vérification du pare-feu
function check_firewall_configuration() {
    log_message "=== 3.5 Vérification de la configuration du pare-feu ==="
    
    # 3.5.1 Ensure firewall package is installed (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if rpm -q firewalld > /dev/null 2>&1 || rpm -q iptables > /dev/null 2>&1; then
        log_message "PASS: Un pare-feu est installé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Aucun pare-feu n'est installé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
    
    # 3.5.2 Ensure firewall service is enabled and running (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if systemctl is-active firewalld > /dev/null 2>&1 || systemctl is-active iptables > /dev/null 2>&1; then
        log_message "PASS: Le service pare-feu est actif"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Le service pare-feu n'est pas actif"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
    
    # 3.5.3 Ensure default firewall policy is drop (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if firewall-cmd --get-default-zone 2>/dev/null | grep -q "drop"; then
        log_message "PASS: La politique par défaut du pare-feu est drop"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: La politique par défaut du pare-feu n'est pas drop"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Fonction de vérification des interfaces sans fil
function check_wireless_interfaces() {
    log_message "=== 3.6 Vérification des interfaces sans fil ==="
    
    # 3.6 Ensure wireless interfaces are disabled (Not Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if ! iwconfig 2>&1 | grep -q "no wireless extensions" && ! iwconfig 2>&1 | grep -q "No such device"; then
        log_message "FAIL: Des interfaces sans fil sont présentes"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    else
        log_message "PASS: Aucune interface sans fil n'est présente"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    fi
}

# Fonction de vérification de rsyslog
function check_rsyslog_configuration() {
    log_message "=== 4.1.2 Vérification de la configuration rsyslog ==="
    
    # 4.1.2.1 Ensure rsyslog Service is enabled (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if systemctl is-enabled rsyslog 2>/dev/null | grep -q "enabled"; then
        log_message "PASS: Le service rsyslog est activé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Le service rsyslog n'est pas activé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
    
    # 4.1.2.2 Ensure logging is configured (Not Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local log_files=("auth" "cron" "kern" "mail" "messages" "secure" "syslog")
    local missing_logs=0
    
    for log in "${log_files[@]}"; do
        if [ ! -f "/var/log/$log" ] && ! grep -q "/var/log/$log" /etc/rsyslog.conf; then
            log_message "FAIL: Configuration manquante pour /var/log/$log"
            missing_logs=1
        fi
    done
    
    if [ $missing_logs -eq 0 ]; then
        log_message "PASS: La journalisation est correctement configurée"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
    
    # 4.1.2.3 Ensure rsyslog default file permissions configured (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q "^\$FileCreateMode 0[0-6][0-4][0-4]" /etc/rsyslog.conf; then
        log_message "PASS: Les permissions par défaut de rsyslog sont correctement configurées"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Les permissions par défaut de rsyslog ne sont pas correctement configurées"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
    
    # 4.1.2.4 Ensure rsyslog is configured to send logs to a remote log host (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q "^*.*[^I][^I]*@" /etc/rsyslog.conf; then
        log_message "PASS: rsyslog est configuré pour envoyer les logs à un hôte distant"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: rsyslog n'est pas configuré pour envoyer les logs à un hôte distant"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Fonction de vérification de la configuration d'audit
function check_audit_configuration() {
    log_message "=== 4.1.3 Vérification de la configuration d'audit ==="
    
    # 4.1.3.1 Ensure audit log storage size is configured (Not Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q "^max_log_file = " /etc/audit/auditd.conf; then
        log_message "PASS: La taille de stockage des logs d'audit est configurée"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: La taille de stockage des logs d'audit n'est pas configurée"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
    
    # 4.1.3.2 Ensure audit logs are not automatically deleted (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q "^max_log_file_action = keep_logs" /etc/audit/auditd.conf; then
        log_message "PASS: Les logs d'audit ne sont pas automatiquement supprimés"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Les logs d'audit peuvent être automatiquement supprimés"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
    
    # 4.1.3.3 Ensure system is disabled when audit logs are full (Scored)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local space_left_action=$(grep "^space_left_action" /etc/audit/auditd.conf)
    local action_mail_acct=$(grep "^action_mail_acct" /etc/audit/auditd.conf)
    local admin_space_left_action=$(grep "^admin_space_left_action" /etc/audit/auditd.conf)
    
    if [[ "$space_left_action" == *"email"* ]] && \
       [[ "$action_mail_acct" == *"root"* ]] && \
       [[ "$admin_space_left_action" == *"halt"* ]]; then
        log_message "PASS: Le système est configuré pour s'arrêter quand les logs d'audit sont pleins"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Le système n'est pas configuré pour s'arrêter quand les logs d'audit sont pleins"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Fonction de vérification des règles d'audit
function check_audit_rules() {
    log_message "=== 4.1.4-17 Vérification des règles d'audit ==="
    
    local audit_rules=(
        "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change"
        "-a always,exit -F arch=b32 -S stime -S settimeofday -S adjtimex -k time-change"
        "-w /etc/localtime -p wa -k time-change"
        "-w /etc/group -p wa -k identity"
        "-w /etc/passwd -p wa -k identity"
        "-w /etc/gshadow -p wa -k identity"
        "-w /etc/shadow -p wa -k identity"
        "-w /etc/security/opasswd -p wa -k identity"
        "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale"
        "-w /etc/issue -p wa -k system-locale"
        "-w /etc/issue.net -p wa -k system-locale"
        "-w /etc/hosts -p wa -k system-locale"
        "-w /etc/sysconfig/network -p wa -k system-locale"
        "-w /etc/selinux/ -p wa -k MAC-policy"
        "-w /var/log/lastlog -p wa -k logins"
        "-w /var/run/faillock/ -p wa -k logins"
        "-w /var/run/utmp -p wa -k session"
        "-w /var/log/wtmp -p wa -k logins"
        "-w /var/log/btmp -p wa -k logins"
        "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod"
        "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod"
        "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod"
        "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod"
        "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
        "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
    )
    
    for rule in "${audit_rules[@]}"; do
        TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
        if auditctl -l | grep -q -- "$rule"; then
            log_message "PASS: Règle d'audit présente: $rule"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        else
            log_message "FAIL: Règle d'audit manquante: $rule"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi
    done
}

# Fonction de vérification de la configuration SSH
function check_ssh_configuration() {
    log_message "=== 5.2 Vérification de la configuration SSH ==="
    
    # 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured (Scored)
    check_file_permissions "/etc/ssh/sshd_config" "root" "root" "600"
    
    # Vérification des paramètres SSH
    local ssh_params=(
        "Protocol 2"
        "LogLevel INFO"
        "X11Forwarding no"
        "MaxAuthTries 4"
        "IgnoreRhosts yes"
        "HostbasedAuthentication no"
        "PermitRootLogin no"
        "PermitEmptyPasswords no"
        "PermitUserEnvironment no"
        "Ciphers aes256-ctr,aes192-ctr,aes128-ctr"
        "ClientAliveInterval 300"
        "ClientAliveCountMax 0"
        "LoginGraceTime 60"
        "Banner /etc/issue.net"
        "UsePAM yes"
        "MaxStartups 10:30:60"
        "MaxSessions 4"
    )
    
    for param in "${ssh_params[@]}"; do
        TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
        local param_name=$(echo "$param" | cut -d' ' -f1)
        local param_value=$(echo "$param" | cut -d' ' -f2-)
        if grep -q "^${param_name} ${param_value}" /etc/ssh/sshd_config; then
            log_message "PASS: Configuration SSH - $param_name est correctement configuré"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        else
            log_message "FAIL: Configuration SSH - $param_name n'est pas correctement configuré"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi
    done
    
    # 5.2.15 Ensure only approved MAC algorithms are used
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local approved_macs="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
    if grep -q "^MACs $approved_macs" /etc/ssh/sshd_config; then
        log_message "PASS: Algorithmes MAC SSH approuvés configurés"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Algorithmes MAC SSH non configurés correctement"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Fonction de vérification de la configuration PAM
function check_pam_configuration() {
    log_message "=== 5.3 Vérification de la configuration PAM ==="
    
    # 5.3.1 Ensure password creation requirements are configured
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q "pam_pwquality.so" /etc/pam.d/password-auth && \
       grep -q "pam_pwquality.so" /etc/pam.d/system-auth; then
        log_message "PASS: Les exigences de création de mot de passe sont configurées"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Les exigences de création de mot de passe ne sont pas configurées"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
    
    # 5.3.2 Ensure lockout for failed password attempts is configured
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q "pam_faillock.so" /etc/pam.d/password-auth && \
       grep -q "pam_faillock.so" /etc/pam.d/system-auth; then
        log_message "PASS: Le verrouillage après échecs d'authentification est configuré"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Le verrouillage après échecs d'authentification n'est pas configuré"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
    
    # 5.3.3 Ensure password reuse is limited
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q "remember=" /etc/pam.d/system-auth; then
        log_message "PASS: La réutilisation des mots de passe est limitée"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: La réutilisation des mots de passe n'est pas limitée"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
    
    # 5.3.4 Ensure password hashing algorithm is SHA-512
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q "sha512" /etc/pam.d/system-auth && \
       grep -q "sha512" /etc/pam.d/password-auth; then
        log_message "PASS: L'algorithme de hachage SHA-512 est utilisé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: L'algorithme de hachage SHA-512 n'est pas utilisé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Fonction de vérification des contrôles de connexion root
function check_root_login_controls() {
    log_message "=== 5.5 Vérification des contrôles de connexion root ==="
    
    # 5.5.1 Ensure root login is restricted to system console
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ -f "/etc/securetty" ]; then
        local console_only=$(wc -l < /etc/securetty)
        if [ "$console_only" -lt 10 ]; then
            log_message "PASS: La connexion root est restreinte à la console système"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        else
            log_message "FAIL: La connexion root n'est pas suffisamment restreinte"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi
    else
        log_message "FAIL: /etc/securetty n'existe pas"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
    
    # 5.5.2 Ensure access to the su command is restricted
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q "pam_wheel.so use_uid" /etc/pam.d/su && \
       grep -q "wheel" /etc/group; then
        log_message "PASS: L'accès à la commande su est restreint"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: L'accès à la commande su n'est pas restreint"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Fonction de rapport final
function print_summary() {
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo "
=== Rapport d'audit CIS $(date) ===
Durée de l'audit: $((duration / 60)) minutes et $((duration % 60)) secondes

Résumé des vérifications:
------------------------
Total des contrôles: $TOTAL_CHECKS
Contrôles réussis: $PASSED_CHECKS
Contrôles échoués: $FAILED_CHECKS
Taux de conformité: $(( (PASSED_CHECKS * 100) / TOTAL_CHECKS ))%

Détails par section:
-------------------
1. Configuration système initiale
2. Services
3. Configuration réseau
4. Journalisation et audit
5. Accès, authentification et autorisation
6. Maintenance système

Fichiers générés:
----------------
- Journal détaillé: $LOG_FILE
- Rapport complet: $REPORT_FILE" | tee -a $REPORT_FILE

    if [ "$GENERATE_HTML" = true ]; then
        generate_html_report
    fi
}

# Exécution des vérifications
log_message "=== Début de l'audit CIS ==="
check_prerequisites

# 1 Initial Setup
log_message "=== 1 Initial Setup ==="

# 1.1 Filesystem Configuration
log_message "=== 1.1 Filesystem Configuration ==="

# Ajout des nouvelles vérifications
check_software_updates
check_filesystem_integrity
check_secure_boot
check_process_hardening
check_mandatory_access
check_warning_banners

# 1.1.1 Disable unused filesystems
log_message "=== 1.1.1 Disable unused filesystems ==="

# 1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Scored)
log_message "=== 1.1.1.1 Vérification du module cramfs ==="
check_filesystem_modules "cramfs"

# 1.1.1.2 Ensure mounting of freevxfs filesystems is disabled (Scored)
log_message "=== 1.1.1.2 Vérification du module freevxfs ==="
check_filesystem_modules "freevxfs"

# 1.1.1.3 Ensure mounting of jffs2 filesystems is disabled (Scored)
log_message "=== 1.1.1.3 Vérification du module jffs2 ==="
check_filesystem_modules "jffs2"

# 1.1.1.4 Ensure mounting of hfs filesystems is disabled (Scored)
log_message "=== 1.1.1.4 Vérification du module hfs ==="
check_filesystem_modules "hfs"

# 1.1.1.5 Ensure mounting of hfsplus filesystems is disabled (Scored)
log_message "=== 1.1.1.5 Vérification du module hfsplus ==="
check_filesystem_modules "hfsplus"

# 1.1.1.6 Ensure mounting of squashfs filesystems is disabled (Scored)
log_message "=== 1.1.1.6 Vérification du module squashfs ==="
check_filesystem_modules "squashfs"

# 1.1.1.7 Ensure mounting of udf filesystems is disabled (Scored)
log_message "=== 1.1.1.7 Vérification du module udf ==="
check_filesystem_modules "udf"

# 1.1.1.8 Ensure mounting of FAT filesystems is disabled (Scored)
log_message "=== 1.1.1.8 Vérification du module vfat ==="
check_filesystem_modules "vfat"

# 1.1.2 Ensure /tmp is configured (Scored)
log_message "=== 1.1.2 Vérification de la configuration de /tmp ==="
check_partition "/tmp" "nodev,nosuid,noexec"

# 1.1.3 Ensure nodev option set on /tmp partition (Scored)
# 1.1.4 Ensure nosuid option set on /tmp partition (Scored)
# 1.1.5 Ensure noexec option set on /tmp partition (Scored)
# (Déjà vérifié dans 1.1.2)

# 1.1.6 Ensure separate partition exists for /var (Scored)
log_message "=== 1.1.6 Vérification de la partition /var ==="
check_partition "/var" "nodev"

# 1.1.7 Ensure separate partition exists for /var/tmp (Scored)
# 1.1.8 Ensure nodev option set on /var/tmp partition (Scored)
# 1.1.9 Ensure nosuid option set on /var/tmp partition (Scored)
log_message "=== 1.1.7-10 Vérification de la partition /var/tmp ==="
check_partition "/var/tmp" "nodev,nosuid,noexec"

# 1.1.11 Ensure separate partition exists for /var/log (Scored)
log_message "=== 1.1.11 Vérification de la partition /var/log ==="
check_partition "/var/log" ""

# 1.1.12 Ensure separate partition exists for /var/log/audit (Scored)
log_message "=== 1.1.12 Vérification de la partition /var/log/audit ==="
check_partition "/var/log/audit" ""

# 1.1.13 Ensure separate partition exists for /home (Scored)
# 1.1.14 Ensure nodev option set on /home partition (Scored)
log_message "=== 1.1.13-14 Vérification de la partition /home ==="
check_partition "/home" "nodev"

# 1.1.15 Ensure nodev option set on /dev/shm partition (Scored)
# 1.1.16 Ensure nosuid option set on /dev/shm partition (Scored)
# 1.1.17 Ensure noexec option set on /dev/shm partition (Scored)
log_message "=== 1.1.15-17 Vérification de la partition /dev/shm ==="
check_partition "/dev/shm" "nodev,nosuid,noexec"

# Section 2 - Services
log_message "=== Section 2: Services ==="
check_xwindow_system
check_avahi_server
check_cups
check_dhcp_server
check_ldap_server
check_service "xinetd" "disabled"
check_service "avahi-daemon" "disabled"
check_service "cups" "disabled"
check_service "dhcpd" "disabled"
check_service "slapd" "disabled"
check_service "nfs" "disabled"
check_service "rpcbind" "disabled"
check_service "named" "disabled"
check_service "vsftpd" "disabled"
check_service "httpd" "disabled"
check_service "dovecot" "disabled"
check_service "smb" "disabled"
check_service "squid" "disabled"
check_service "snmpd" "disabled"
check_service "ypserv" "disabled"

# Section 3 - Configuration réseau
log_message "=== Section 3: Configuration réseau ==="
check_network_parameters
check_tcp_wrappers
check_unused_protocols
check_network_services
check_firewall_configuration
check_wireless_interfaces

# Section 4 - Journalisation et audit
log_message "=== Section 4: Journalisation et audit ==="
check_rsyslog_configuration
check_audit_configuration
check_audit_rules

# Section 5 - Accès et authentification
log_message "=== Section 5: Accès et authentification ==="
check_ssh_configuration
check_pam_configuration
check_password_policy
check_system_accounts
check_root_login_controls
check_groups

# Section 6 - Maintenance système
log_message "=== Section 6: Maintenance système ==="
check_system_file_permissions
check_user_group_settings
check_suid_sgid
check_world_writable
check_unowned_files
check_root_path
check_dot_files

# Génération du rapport final
print_summary

log_message "=== Fin de l'audit CIS ==="