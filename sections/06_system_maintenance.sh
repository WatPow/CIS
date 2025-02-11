#!/bin/bash

# Section 6 - Maintenance du système
log_message "=== 6 Maintenance du système ==="

# 6.1 Configuration du système de fichiers
log_message "=== 6.1 Configuration du système de fichiers ==="

# 6.1.1 Vérification des partitions avec des options restrictives
check_mount_options() {
    local mount_point=$1
    local expected_options=$2
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if mount | grep -q " $mount_point "; then
        current_options=$(mount | grep " $mount_point " | awk '{print $6}' | tr -d '()')
        if echo "$current_options" | grep -q "$expected_options"; then
            log_message "PASS: $mount_point a les options requises"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        else
            log_message "FAIL: $mount_point n'a pas les options requises (actuel: $current_options, attendu: $expected_options)"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi
    else
        log_message "FAIL: $mount_point n'est pas monté"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Vérification des points de montage critiques
check_mount_options "/tmp" "nosuid,nodev,noexec"
check_mount_options "/var" "nosuid"
check_mount_options "/var/tmp" "nosuid,nodev,noexec"
check_mount_options "/var/log" "nosuid,nodev,noexec"
check_mount_options "/var/log/audit" "nosuid,nodev,noexec"
check_mount_options "/home" "nosuid,nodev"
check_mount_options "/dev/shm" "nosuid,nodev,noexec"

# 6.2 Vérification des fichiers utilisateur
log_message "=== 6.2 Vérification des fichiers utilisateur ==="

# 6.2.1 Vérification des permissions des fichiers de configuration utilisateur
check_user_files() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    local file_type=$1
    local max_perm=$2
    
    find /home -name "$file_type" -type f -perm /g+w,o+w 2>/dev/null | while read -r file; do
        log_message "FAIL: $file a des permissions trop permissives"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    done || return
    
    log_message "PASS: Tous les fichiers $file_type ont des permissions correctes"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
}

check_user_files ".bashrc" "644"
check_user_files ".bash_profile" "644"
check_user_files ".bash_logout" "644"

# 6.3 Vérification des fichiers système
log_message "=== 6.3 Vérification des fichiers système ==="

# 6.3.1 Vérification des permissions des fichiers système critiques
system_files=(
    "/etc/passwd:644"
    "/etc/shadow:000"
    "/etc/group:644"
    "/etc/gshadow:000"
    "/etc/passwd-:644"
    "/etc/shadow-:000"
    "/etc/group-:644"
    "/etc/gshadow-:000"
)

for entry in "${system_files[@]}"; do
    file=$(echo "$entry" | cut -d: -f1)
    expected_perm=$(echo "$entry" | cut -d: -f2)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if [ -f "$file" ]; then
        current_perm=$(stat -c %a "$file")
        if [ "$current_perm" = "$expected_perm" ]; then
            log_message "PASS: $file a les permissions correctes ($expected_perm)"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        else
            log_message "FAIL: $file a des permissions incorrectes (actuel: $current_perm, attendu: $expected_perm)"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi
    else
        log_message "FAIL: $file n'existe pas"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
done

# 6.4 Vérification des processus système
log_message "=== 6.4 Vérification des processus système ==="

# 6.4.1 Vérification des processus sans propriétaire
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
unowned_procs=$(ps -ef | awk '$1=="UNKNOWN" {print $2}')
if [ -z "$unowned_procs" ]; then
    log_message "PASS: Aucun processus sans propriétaire trouvé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: Processus sans propriétaire trouvés: $unowned_procs"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 6.5 Vérification des tâches planifiées
log_message "=== 6.5 Vérification des tâches planifiées ==="

# 6.5.1 Vérification des tâches cron de root
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ -f /var/spool/cron/root ]; then
    perms=$(stat -c %a /var/spool/cron/root)
    if [ "$perms" = "600" ]; then
        log_message "PASS: Les tâches cron de root ont les bonnes permissions"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Les tâches cron de root ont des permissions incorrectes: $perms"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
else
    log_message "INFO: Pas de tâches cron pour root"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
fi

# 6.6 Vérification de la configuration réseau
log_message "=== 6.6 Vérification de la configuration réseau ==="

# 6.6.1 Vérification des interfaces en mode promiscuous
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
promisc_interfaces=$(ip link | grep PROMISC)
if [ -z "$promisc_interfaces" ]; then
    log_message "PASS: Aucune interface en mode promiscuous"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: Interfaces en mode promiscuous trouvées: $promisc_interfaces"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 6.7 Vérification des services inutiles
log_message "=== 6.7 Vérification des services inutiles ==="

# Liste des services considérés comme inutiles ou dangereux
unnecessary_services=(
    "telnet"
    "rsh"
    "rlogin"
    "rexec"
    "tftp"
    "talk"
    "xinetd"
)

for service in "${unnecessary_services[@]}"; do
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if systemctl is-active "$service" &>/dev/null; then
        log_message "FAIL: Le service $service est actif"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    else
        log_message "PASS: Le service $service est inactif ou non installé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    fi
done 