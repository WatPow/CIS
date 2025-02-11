#!/bin/bash

# Section 1 - Configuration système initiale
log_message "=== 1 Configuration système initiale ==="

# Fonction de vérification des modules du système de fichiers
check_filesystem_modules() {
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
check_partition() {
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
}

# 1.1 Configuration du système de fichiers
log_message "=== 1.1 Configuration du système de fichiers ==="

# 1.1.1 Désactivation des systèmes de fichiers inutilisés
log_message "=== 1.1.1 Désactivation des systèmes de fichiers inutilisés ==="
check_filesystem_modules "cramfs"
check_filesystem_modules "freevxfs"
check_filesystem_modules "jffs2"
check_filesystem_modules "hfs"
check_filesystem_modules "hfsplus"
check_filesystem_modules "squashfs"
check_filesystem_modules "udf"
check_filesystem_modules "vfat"

# 1.1.2-17 Vérification des partitions
log_message "=== 1.1.2-17 Vérification des partitions ==="
check_partition "/tmp" "nodev,nosuid,noexec"
check_partition "/var" "nodev"
check_partition "/var/tmp" "nodev,nosuid,noexec"
check_partition "/home" "nodev"
check_partition "/dev/shm" "nodev,nosuid,noexec"

# 1.2 Configuration des mises à jour logicielles
log_message "=== 1.2 Configuration des mises à jour ==="

# 1.2.1 Vérification des clés GPG
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n' | grep -q "CentOS 7"; then
    log_message "PASS: Les clés GPG de CentOS 7 sont configurées"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: Les clés GPG de CentOS 7 ne sont pas configurées"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.2.2 Vérification des dépôts
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if yum repolist | grep -q "base/7"; then
    log_message "PASS: Les dépôts YUM sont correctement configurés"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: Les dépôts YUM ne sont pas correctement configurés"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.3 Vérification de l'intégrité AIDE
log_message "=== 1.3 Vérification de l'intégrité AIDE ==="

# 1.3.1 Installation d'AIDE
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if rpm -q aide > /dev/null 2>&1; then
    log_message "PASS: AIDE est installé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: AIDE n'est pas installé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.3.2 Vérification de la planification AIDE
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if crontab -l 2>/dev/null | grep -q aide || ls -l /etc/cron.* | grep -q aide; then
    log_message "PASS: Une tâche CRON pour AIDE est configurée"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: Aucune tâche CRON pour AIDE n'est configurée"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.4 Configuration du démarrage sécurisé
log_message "=== 1.4 Configuration du démarrage ==="

# 1.4.1 Vérification des permissions du bootloader
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

# 1.5 Processus de durcissement
log_message "=== 1.5 Processus de durcissement ==="

# 1.5.1 Vérification des core dumps
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep -q "^\* hard core 0" /etc/security/limits.conf && [ "$(sysctl -n fs.suid_dumpable)" = "0" ]; then
    log_message "PASS: Les core dumps sont restreints"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: Les core dumps ne sont pas correctement restreints"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.6 Configuration SELinux
log_message "=== 1.6 Configuration SELinux ==="

# 1.6.1 Vérification de l'état SELinux
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ "$(getenforce)" = "Enforcing" ]; then
    log_message "PASS: SELinux est en mode Enforcing"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: SELinux n'est pas en mode Enforcing"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.7 Bannières d'avertissement
log_message "=== 1.7 Bannières d'avertissement ==="

# 1.7.1 Vérification des fichiers de bannière
for file in /etc/motd /etc/issue /etc/issue.net; do
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ -f "$file" ] && ! grep -E -i "(\\v|\\r|\\m|\\s)" "$file" > /dev/null; then
        log_message "PASS: Le fichier $file est correctement configuré"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Le fichier $file contient des informations système sensibles ou n'existe pas"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
done 