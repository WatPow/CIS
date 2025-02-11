#!/bin/bash

# Configuration des variables globales
BACKUP_DIR="/root/cis_backup_$(date +%Y%m%d)"
LOG_FILE="/var/log/cis_apply.log"
REPORT_FILE="/var/log/cis_apply_report_$(date +%Y%m%d).txt"
start_time=$(date +%s)

# Gestion des erreurs
set -e
trap 'echo "Une erreur est survenue à la ligne $LINENO" | tee -a $LOG_FILE' ERR

# Fonction de journalisation
function log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOG_FILE
}

# Fonction de sauvegarde
function backup_file() {
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
        log_message "Création du répertoire de sauvegarde: $BACKUP_DIR"
    fi
    if [ -f "$1" ]; then
        cp -p "$1" "$BACKUP_DIR/" && log_message "Sauvegarde de $1 effectuée"
    fi
}

# Fonction de vérification des prérequis
function check_prerequisites() {
    log_message "Vérification des prérequis..."
    if [ "$(id -u)" -ne 0 ]; then
        log_message "ERROR: Ce script doit être exécuté en tant que root"
        exit 1
    fi
    
    # Vérification de l'espace disque
    SPACE=$(df -h / | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "${SPACE%.*}" -lt 1 ]; then
        log_message "WARNING: Espace disque faible (< 1GB)"
    fi
}

# Fonction d'application des corrections pour les modules du système de fichiers
function apply_filesystem_modules() {
    local module=$1
    if lsmod | grep "$module" > /dev/null 2>&1; then
        log_message "Application: Désactivation du module $module"
        echo "install $module /bin/true" >> /etc/modprobe.d/CIS.conf
        rmmod "$module" 2>/dev/null || true
    fi
}

# Fonction d'application des corrections pour les partitions
function apply_partition() {
    local partition=$1
    local required_options=$2
    
    if mount | grep -q " $partition "; then
        backup_file "/etc/fstab"
        log_message "Application: Ajout des options $required_options à $partition"
        sed -i "\\| $partition |s|defaults|defaults,$required_options|g" /etc/fstab
        mount -o remount "$partition"
    fi
}

# Fonction d'application des corrections pour les services
function apply_service() {
    local service=$1
    local target_state=$2
    
    if [ "$target_state" = "enabled" ]; then
        log_message "Application: Activation du service $service"
        systemctl enable "$service"
        systemctl start "$service"
    else
        log_message "Application: Désactivation du service $service"
        systemctl disable "$service"
        systemctl stop "$service"
    fi
}

# Fonction d'application des corrections pour les permissions de fichiers
function apply_file_permissions() {
    local file=$1
    local owner=$2
    local group=$3
    local perms=$4
    
    if [ -f "$file" ]; then
        backup_file "$file"
        log_message "Application: Correction des permissions pour $file"
        chown "$owner:$group" "$file"
        chmod "$perms" "$file"
    fi
}

# Fonction d'application des corrections pour les paramètres sysctl
function apply_sysctl() {
    local param=$1
    local value=$2
    
    backup_file "/etc/sysctl.conf"
    log_message "Application: Configuration de $param à $value"
    sed -i "\\|^$param|d" /etc/sysctl.conf
    echo "$param = $value" >> /etc/sysctl.conf
    sysctl -w "$param=$value"
}

# Fonction de vérification d'un paramètre
function check_setting() {
    local setting=$1
    local expected=$2
    local current=$3
    
    if [ "$current" = "$expected" ]; then
        log_message "PASS: $setting est correctement configuré ($current)"
        return 0
    else
        log_message "FAIL: $setting n'est pas correctement configuré (attendu: $expected, actuel: $current)"
        return 1
    fi
}

# Fonction de vérification des modules du système de fichiers
function check_filesystem_modules() {
    local module=$1
    if lsmod | grep "$module" > /dev/null 2>&1; then
        log_message "FAIL: Le module $module est chargé"
        return 1
    else
        log_message "PASS: Le module $module n'est pas chargé"
        return 0
    fi
}

# Fonction de vérification des partitions
function check_partition() {
    local partition=$1
    local required_options=$2
    
    log_message "=== Vérification de la partition $partition ==="
    
    if ! mount | grep -q " $partition "; then
        log_message "FAIL: La partition $partition n'existe pas"
        return 1
    fi
    
    local current_options=$(mount | grep " $partition " | awk '{print $6}' | tr -d '()')
    local missing_options=""
    
    for option in $required_options; do
        if ! echo "$current_options" | grep -q "$option"; then
            missing_options="$missing_options $option"
        fi
    done
    
    if [ -n "$missing_options" ]; then
        log_message "FAIL: Options manquantes pour $partition :$missing_options"
        return 1
    else
        log_message "PASS: Toutes les options requises sont présentes pour $partition"
        return 0
    fi
}

# Fonction de vérification des services
function check_service() {
    local service=$1
    local expected_state=$2  # enabled ou disabled
    
    log_message "=== Vérification du service $service ==="
    
    local current_state=$(systemctl is-enabled "$service" 2>/dev/null || echo "not-found")
    
    if [ "$current_state" = "not-found" ]; then
        log_message "INFO: Le service $service n'est pas installé"
        return 0
    fi
    
    if [ "$current_state" = "$expected_state" ]; then
        log_message "PASS: Le service $service est $expected_state"
        return 0
    else
        log_message "FAIL: Le service $service est $current_state (attendu: $expected_state)"
        return 1
    fi
}

# Fonction de vérification des fichiers
function check_file_permissions() {
    local file=$1
    local expected_owner=$2
    local expected_group=$3
    local expected_perms=$4
    
    log_message "=== Vérification des permissions de $file ==="
    
    if [ ! -f "$file" ]; then
        log_message "FAIL: Le fichier $file n'existe pas"
        return 1
    fi
    
    local current_owner=$(stat -c %U "$file")
    local current_group=$(stat -c %G "$file")
    local current_perms=$(stat -c %a "$file")
    
    if [ "$current_owner" != "$expected_owner" ] || 
       [ "$current_group" != "$expected_group" ] || 
       [ "$current_perms" != "$expected_perms" ]; then
        log_message "FAIL: Permissions incorrectes pour $file"
        log_message "  Propriétaire actuel: $current_owner (attendu: $expected_owner)"
        log_message "  Groupe actuel: $current_group (attendu: $expected_group)"
        log_message "  Permissions actuelles: $current_perms (attendu: $expected_perms)"
        return 1
    else
        log_message "PASS: Permissions correctes pour $file"
        return 0
    fi
}

# Fonction de vérification des paramètres sysctl
function check_sysctl() {
    local param=$1
    local expected_value=$2
    
    log_message "=== Vérification du paramètre sysctl $param ==="
    
    local current_value=$(sysctl -n "$param" 2>/dev/null)
    
    if [ -z "$current_value" ]; then
        log_message "FAIL: Le paramètre $param n'existe pas"
        return 1
    fi
    
    if [ "$current_value" != "$expected_value" ]; then
        log_message "FAIL: Valeur incorrecte pour $param (actuel: $current_value, attendu: $expected_value)"
        return 1
    else
        log_message "PASS: Valeur correcte pour $param"
        return 0
    fi
}

# Fonction de vérification des utilisateurs
function check_users() {
    log_message "=== Vérification des utilisateurs système ==="
    
    # Vérification des UID en double
    local duplicate_uids=$(cut -d: -f3 /etc/passwd | sort -n | uniq -d)
    if [ -n "$duplicate_uids" ]; then
        log_message "FAIL: UIDs en double trouvés: $duplicate_uids"
        return 1
    fi
    
    # Vérification des utilisateurs sans mot de passe
    local empty_passwords=$(awk -F: '($2 == "" ) { print $1 }' /etc/shadow)
    if [ -n "$empty_passwords" ]; then
        log_message "FAIL: Utilisateurs sans mot de passe trouvés: $empty_passwords"
        return 1
    fi
    
    # Vérification des entrées "+" dans /etc/passwd
    if grep -q '^+:' /etc/passwd; then
        log_message "FAIL: Entrées '+' trouvées dans /etc/passwd"
        return 1
    fi
    
    # Vérification des utilisateurs avec UID 0
    local root_users=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd | grep -v '^root$')
    if [ -n "$root_users" ]; then
        log_message "FAIL: Utilisateurs avec UID 0 autres que root: $root_users"
        return 1
    fi
}

# Fonction de vérification des répertoires home
function check_home_directories() {
    log_message "=== Vérification des répertoires home ==="
    
    while IFS=: read -r user pass uid gid desc home shell; do
        if [ "$uid" -ge 1000 ] && [ "$user" != "nfsnobody" ]; then
            if [ ! -d "$home" ]; then
                log_message "FAIL: Répertoire home manquant pour $user: $home"
                return 1
            else
                local perms=$(stat -c %a "$home")
                if [ "$perms" -gt 750 ]; then
                    log_message "FAIL: Permissions trop permissives sur $home: $perms"
                    return 1
                else
                    local owner=$(stat -c %U "$home")
                    if [ "$owner" != "$user" ]; then
                        log_message "FAIL: Propriétaire incorrect pour $home: $owner (devrait être $user)"
                        return 1
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
        if lsmod | grep -q "^$protocol"; then
            log_message "FAIL: Le protocole $protocol est chargé"
            return 1
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
    if [ -f "/etc/audit/auditd.conf" ]; then
        log_message "PASS: Le fichier de configuration d'audit existe"
        return 0
    else
        log_message "FAIL: Le fichier de configuration d'audit est manquant"
        return 1
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
        current=$(grep "^$name" /etc/login.defs | awk '{print $2}')
        
        if [ "$current" = "$value" ]; then
            log_message "PASS: $name est correctement configuré ($value)"
            return 0
        else
            log_message "FAIL: $name est mal configuré (actuel: $current, attendu: $value)"
            return 1
        fi
    done
}

# Fonction de vérification des comptes système
function check_system_accounts() {
    log_message "=== Vérification des comptes système ==="
    
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
        return 0
    else
        return 1
    fi
}

# Fonction de vérification des groupes
function check_groups() {
    log_message "=== Vérification des groupes ==="
    
    # Vérification des GID en double
    local duplicate_gids=$(cut -d: -f3 /etc/group | sort -n | uniq -d)
    if [ -n "$duplicate_gids" ]; then
        log_message "FAIL: GIDs en double trouvés: $duplicate_gids"
        return 1
    fi
}

# Fonction de vérification des fichiers SUID/SGID
function check_suid_sgid() {
    log_message "=== Vérification des fichiers SUID/SGID ==="
    
    local suid_files=$(find / -type f -perm -4000 2>/dev/null)
    local sgid_files=$(find / -type f -perm -2000 2>/dev/null)
    
    if [ -n "$suid_files" ]; then
        log_message "INFO: Fichiers SUID trouvés:"
        echo "$suid_files" | while read -r file; do
            log_message "  $file"
        done
        return 1
    fi
    
    if [ -n "$sgid_files" ]; then
        log_message "INFO: Fichiers SGID trouvés:"
        echo "$sgid_files" | while read -r file; do
            log_message "  $file"
        done
        return 1
    fi
    
    return 0
}

# Fonction de vérification des fichiers world-writable
function check_world_writable() {
    log_message "=== Vérification des fichiers world-writable ==="
    
    local world_writable=$(find / -type f -perm -0002 2>/dev/null)
    
    if [ -n "$world_writable" ]; then
        log_message "FAIL: Fichiers world-writable trouvés:"
        echo "$world_writable" | while read -r file; do
            log_message "  $file"
        done
        return 1
    else
        log_message "PASS: Aucun fichier world-writable trouvé"
        return 0
    fi
}

# Fonction de vérification des fichiers sans propriétaire
function check_unowned_files() {
    log_message "=== Vérification des fichiers sans propriétaire ==="
    
    local unowned=$(find / -nouser -o -nogroup 2>/dev/null)
    
    if [ -n "$unowned" ]; then
        log_message "FAIL: Fichiers sans propriétaire trouvés:"
        echo "$unowned" | while read -r file; do
            log_message "  $file"
        done
        return 1
    else
        log_message "PASS: Aucun fichier sans propriétaire trouvé"
        return 0
    fi
}

# Fonction de vérification du PATH root
function check_root_path() {
    log_message "=== Vérification du PATH root ==="
    
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
        return 0
    else
        return 1
    fi
}

# Fonction de vérification des fichiers dot
function check_dot_files() {
    log_message "=== Vérification des fichiers dot ==="
    
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
        return 0
    else
        return 1
    fi
}

# Fonction de rapport final
function print_summary() {
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo "
=== Rapport d'application CIS $(date) ===
Durée de l'application: $((duration / 60)) minutes et $((duration % 60)) secondes

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
}

# Fonction d'application des corrections pour les utilisateurs
function apply_user_corrections() {
    log_message "=== Application des corrections pour les utilisateurs ==="
    
    # Correction des utilisateurs sans mot de passe
    local empty_passwords=$(awk -F: '($2 == "" ) { print $1 }' /etc/shadow)
    if [ -n "$empty_passwords" ]; then
        log_message "Application: Verrouillage des comptes sans mot de passe"
        for user in $empty_passwords; do
            passwd -l "$user"
        done
    fi
    
    # Correction des utilisateurs avec UID 0
    local root_users=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd | grep -v '^root$')
    if [ -n "$root_users" ]; then
        log_message "Application: Modification des UID 0 non-root"
        for user in $root_users; do
            usermod -u $((RANDOM + 1000)) "$user"
        done
    fi
}

# Fonction d'application des corrections pour les répertoires home
function apply_home_directory_corrections() {
    log_message "=== Application des corrections pour les répertoires home ==="
    
    while IFS=: read -r user pass uid gid desc home shell; do
        if [ "$uid" -ge 1000 ] && [ "$user" != "nfsnobody" ]; then
            if [ ! -d "$home" ]; then
                log_message "Application: Création du répertoire home pour $user"
                mkdir -p "$home"
                chown "$user:$gid" "$home"
                chmod 750 "$home"
            else
                local perms=$(stat -c %a "$home")
                if [ "$perms" -gt 750 ]; then
                    log_message "Application: Correction des permissions pour $home"
                    chmod 750 "$home"
                fi
                
                local owner=$(stat -c %U "$home")
                if [ "$owner" != "$user" ]; then
                    log_message "Application: Correction du propriétaire pour $home"
                    chown "$user" "$home"
                fi
            fi
        fi
    done < /etc/passwd
}

# Fonction d'application des corrections pour les fichiers dot
function apply_dot_file_corrections() {
    log_message "=== Application des corrections pour les fichiers dot ==="
    
    while IFS=: read -r user _ uid _ _ home _; do
        if [ "$uid" -ge 1000 ] && [ -d "$home" ]; then
            for file in .forward .netrc .rhosts; do
                if [ -f "$home/$file" ]; then
                    log_message "Application: Suppression du fichier $file de $home"
                    backup_file "$home/$file"
                    rm -f "$home/$file"
                fi
            done
        fi
    done < /etc/passwd
}

# Fonction d'application des corrections pour les fichiers world-writable
function apply_world_writable_corrections() {
    log_message "=== Application des corrections pour les fichiers world-writable ==="
    
    local world_writable=$(find / -type f -perm -0002 2>/dev/null)
    if [ -n "$world_writable" ]; then
        log_message "Application: Correction des permissions world-writable"
        echo "$world_writable" | while read -r file; do
            backup_file "$file"
            chmod o-w "$file"
        done
    fi
}

# Fonction d'application des corrections pour les fichiers sans propriétaire
function apply_unowned_file_corrections() {
    log_message "=== Application des corrections pour les fichiers sans propriétaire ==="
    
    local unowned=$(find / -nouser -o -nogroup 2>/dev/null)
    if [ -n "$unowned" ]; then
        log_message "Application: Attribution des fichiers sans propriétaire à root"
        echo "$unowned" | while read -r file; do
            backup_file "$file"
            chown root:root "$file"
        done
    fi
}

# Fonction d'application des corrections pour le PATH root
function apply_root_path_corrections() {
    log_message "=== Application des corrections pour le PATH root ==="
    
    backup_file "/root/.bashrc"
    echo 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' >> /root/.bashrc
    source /root/.bashrc
}

# Exécution des corrections
log_message "=== Début de l'application des corrections CIS ==="
check_prerequisites

# Section 1 - Configuration système initiale
log_message "=== Section 1: Configuration système initiale ==="
apply_filesystem_modules "cramfs"
apply_filesystem_modules "freevxfs"
apply_filesystem_modules "jffs2"
apply_filesystem_modules "hfs"
apply_filesystem_modules "hfsplus"
apply_filesystem_modules "squashfs"
apply_filesystem_modules "udf"
apply_filesystem_modules "vfat"

apply_partition "/tmp" "nodev,nosuid,noexec"
apply_partition "/var" "nodev"
apply_partition "/var/tmp" "nodev,nosuid,noexec"
apply_partition "/home" "nodev"
apply_partition "/dev/shm" "nodev,nosuid,noexec"

# Section 2 - Services
log_message "=== Section 2: Services ==="
apply_service "xinetd" "disabled"
apply_service "avahi-daemon" "disabled"
apply_service "cups" "disabled"
apply_service "dhcpd" "disabled"
apply_service "slapd" "disabled"
apply_service "nfs" "disabled"
apply_service "rpcbind" "disabled"
apply_service "named" "disabled"
apply_service "vsftpd" "disabled"
apply_service "httpd" "disabled"
apply_service "dovecot" "disabled"
apply_service "smb" "disabled"
apply_service "squid" "disabled"
apply_service "snmpd" "disabled"
apply_service "ypserv" "disabled"

# Section 3 - Configuration réseau
log_message "=== Section 3: Configuration réseau ==="
apply_sysctl "net.ipv4.ip_forward" "0"
apply_sysctl "net.ipv4.conf.all.send_redirects" "0"
apply_sysctl "net.ipv4.conf.default.send_redirects" "0"
apply_sysctl "net.ipv4.conf.all.accept_redirects" "0"
apply_sysctl "net.ipv4.conf.default.accept_redirects" "0"
apply_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1"
apply_sysctl "net.ipv4.tcp_syncookies" "1"

# Section 4 - Journalisation et audit
log_message "=== Section 4: Journalisation et audit ==="
apply_service "auditd" "enabled"

# Section 5 - Accès et authentification
log_message "=== Section 5: Accès et authentification ==="
apply_user_corrections
apply_home_directory_corrections

# Section 6 - Maintenance système
log_message "=== Section 6: Maintenance système ==="
apply_file_permissions "/etc/passwd" "root" "root" "644"
apply_file_permissions "/etc/shadow" "root" "root" "000"
apply_file_permissions "/etc/group" "root" "root" "644"
apply_file_permissions "/etc/gshadow" "root" "root" "000"
apply_file_permissions "/etc/ssh/sshd_config" "root" "root" "600"

apply_world_writable_corrections
apply_unowned_file_corrections
apply_root_path_corrections
apply_dot_file_corrections

# Génération du rapport final
print_summary

log_message "=== Fin de l'application des corrections CIS ==="