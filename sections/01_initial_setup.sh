#!/bin/bash

# Section 1 - Configuration système initiale
log_message "=== 1 Configuration système initiale ==="

# 1.1 Filesystem Configuration
log_message "=== 1.1 Configuration du système de fichiers ==="

# 1.1.1 Disable unused filesystems
log_message "=== 1.1.1 Désactivation des systèmes de fichiers inutilisés ==="

check_filesystem_module() {
    local module=$1
    local cis_ref=$2
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    # Vérifie si le module est chargé
    if lsmod | grep "$module" > /dev/null 2>&1; then
        log_message "FAIL: [CIS $cis_ref] Le module $module est chargé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    fi
    
    # Vérifie si le module peut être chargé
    if modprobe -n -v "$module" 2>&1 | grep -q "^install /bin/true"; then
        log_message "PASS: [CIS $cis_ref] Le module $module est désactivé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS $cis_ref] Le module $module n'est pas correctement désactivé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Vérification des modules du système de fichiers
check_filesystem_module "cramfs" "1.1.1.1"
check_filesystem_module "freevxfs" "1.1.1.2"
check_filesystem_module "hfs" "1.1.1.3"
check_filesystem_module "hfsplus" "1.1.1.4"
check_filesystem_module "jffs2" "1.1.1.5"
check_filesystem_module "squashfs" "1.1.1.6"
check_filesystem_module "udf" "1.1.1.7"
check_filesystem_module "usb-storage" "1.1.1.8"

# 1.1.2 Configure /tmp
check_partition_mount() {
    local partition=$1
    local options=$2
    local cis_ref=$3
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    # Vérifie si la partition est montée
    if ! mount | grep -E "\\s${partition}\\s" > /dev/null; then
        log_message "FAIL: [CIS $cis_ref] $partition n'est pas une partition séparée"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        return 1
    fi
    
    # Vérifie les options de montage
    local current_options=$(mount | grep "\\s${partition}\\s" | awk '{print $6}' | tr -d '()')
    local missing_options=""
    
    for option in $options; do
        if ! echo "$current_options" | grep -q "$option"; then
            missing_options="$missing_options $option"
        fi
    done
    
    if [ -z "$missing_options" ]; then
        log_message "PASS: [CIS $cis_ref] $partition est monté avec les bonnes options"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS $cis_ref] $partition manque les options:$missing_options"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Vérification des partitions
check_partition_mount "/tmp" "nodev,nosuid,noexec" "1.1.2.1"
check_partition_mount "/dev/shm" "nodev,nosuid,noexec" "1.1.2.2"
check_partition_mount "/home" "nodev" "1.1.2.3"
check_partition_mount "/var" "nodev" "1.1.2.4"
check_partition_mount "/var/tmp" "nodev,nosuid,noexec" "1.1.2.5"
check_partition_mount "/var/log" "nodev,nosuid,noexec" "1.1.2.6"
check_partition_mount "/var/log/audit" "nodev,nosuid,noexec" "1.1.2.7"

# 1.2 Configure Software Updates
log_message "=== 1.2 Configuration des mises à jour logicielles ==="

# 1.2.1 Ensure GPG keys are configured
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if rpm -q gpg-pubkey > /dev/null 2>&1; then
    log_message "PASS: [CIS 1.2.1] Les clés GPG sont configurées"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 1.2.1] Les clés GPG ne sont pas configurées"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.2.2 Verify gpgcheck Enabled
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep -q "^gpgcheck=1" /etc/yum.conf && ! grep -q "^gpgcheck=0" /etc/yum.repos.d/*; then
    log_message "PASS: [CIS 1.2.2] gpgcheck est activé globalement"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 1.2.2] gpgcheck n'est pas activé globalement"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.2.3 Verify repo_gpgcheck Enabled
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep -q "^repo_gpgcheck=1" /etc/yum.conf && ! grep -q "^repo_gpgcheck=0" /etc/yum.repos.d/*; then
    log_message "PASS: [CIS 1.2.3] repo_gpgcheck est activé globalement"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 1.2.3] repo_gpgcheck n'est pas activé globalement"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.2.4 Ensure package manager repositories are configured
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if yum repolist | grep -q "base/7" && yum repolist | grep -q "updates/7"; then
    log_message "PASS: [CIS 1.2.4] Les dépôts sont correctement configurés"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 1.2.4] Les dépôts ne sont pas correctement configurés"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.2.5 Check for updates
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if yum check-update --security > /dev/null 2>&1; then
    log_message "PASS: [CIS 1.2.5] Pas de mises à jour de sécurité en attente"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 1.2.5] Des mises à jour de sécurité sont disponibles"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.3 Configure Boot Settings
log_message "=== 1.3 Configuration du démarrage ==="

# 1.3.1 Ensure bootloader password is set
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep -q "^GRUB2_PASSWORD=" /boot/grub2/user.cfg 2>/dev/null; then
    log_message "PASS: [CIS 1.3.1] Le mot de passe du bootloader est configuré"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 1.3.1] Le mot de passe du bootloader n'est pas configuré"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.3.2 Ensure bootloader config is secured
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ -f /boot/grub2/grub.cfg ] && [ "$(stat -L -c "%a" /boot/grub2/grub.cfg)" -eq 400 ]; then
    log_message "PASS: [CIS 1.3.2] La configuration du bootloader est sécurisée"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 1.3.2] La configuration du bootloader n'est pas sécurisée"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.3.3 Ensure authentication required for single user mode
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep -q "^ExecStart=-/bin/sh -c '/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default'" /usr/lib/systemd/system/rescue.service && \
   grep -q "^ExecStart=-/bin/sh -c '/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default'" /usr/lib/systemd/system/emergency.service; then
    log_message "PASS: [CIS 1.3.3] L'authentification est requise pour le mode single user"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 1.3.3] L'authentification n'est pas requise pour le mode single user"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.4 Additional Process Hardening
log_message "=== 1.4 Durcissement supplémentaire des processus ==="

# 1.4.1 Ensure ASLR is enabled
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ "$(sysctl -n kernel.randomize_va_space)" -eq 2 ]; then
    log_message "PASS: [CIS 1.4.1] ASLR est activé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 1.4.1] ASLR n'est pas activé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.4.2 Ensure ptrace scope is restricted
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ "$(sysctl -n kernel.yama.ptrace_scope)" -eq 1 ]; then
    log_message "PASS: [CIS 1.4.2] ptrace est restreint"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 1.4.2] ptrace n'est pas restreint"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.4.3 Ensure core dump backtraces are disabled
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if ! grep -q "ProcessSizeMax=0" /etc/systemd/coredump.conf && ! grep -q "Storage=none" /etc/systemd/coredump.conf; then
    log_message "PASS: [CIS 1.4.3] Les core dumps sont désactivés"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 1.4.3] Les core dumps ne sont pas désactivés"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.4.4 Ensure core dump storage is disabled
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ "$(sysctl -n fs.suid_dumpable)" -eq 0 ] && grep -q "hard core 0" /etc/security/limits.conf; then
    log_message "PASS: [CIS 1.4.4] Le stockage des core dumps est désactivé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 1.4.4] Le stockage des core dumps n'est pas désactivé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.5 Mandatory Access Control
log_message "=== 1.5 Contrôle d'accès obligatoire ==="

# 1.5.1 Configure SELinux
# 1.5.1.1 Ensure SELinux is installed
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if rpm -q libselinux > /dev/null 2>&1; then
    log_message "PASS: [CIS 1.5.1.1] SELinux est installé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 1.5.1.1] SELinux n'est pas installé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.5.1.2 Ensure SELinux is not disabled in bootloader
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if ! grep -E "selinux=0|enforcing=0" /boot/grub2/grub.cfg > /dev/null 2>&1; then
    log_message "PASS: [CIS 1.5.1.2] SELinux n'est pas désactivé dans le bootloader"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 1.5.1.2] SELinux est désactivé dans le bootloader"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.5.1.3 Ensure SELinux policy is configured
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep -E "^SELINUXTYPE=(targeted|mls)" /etc/selinux/config > /dev/null 2>&1; then
    log_message "PASS: [CIS 1.5.1.3] La politique SELinux est configurée"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 1.5.1.3] La politique SELinux n'est pas configurée"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.5.1.4 Ensure the SELinux mode is not disabled
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep -E "^SELINUX=enforcing|^SELINUX=permissive" /etc/selinux/config > /dev/null 2>&1; then
    log_message "PASS: [CIS 1.5.1.4] Le mode SELinux n'est pas désactivé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 1.5.1.4] Le mode SELinux est désactivé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.5.1.5 Ensure the SELinux mode is enforcing
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ "$(getenforce)" = "Enforcing" ]; then
    log_message "PASS: [CIS 1.5.1.5] SELinux est en mode enforcing"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 1.5.1.5] SELinux n'est pas en mode enforcing"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.5.1.6 Ensure no unconfined services exist
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if ! ps -eZ | grep unconfined_service_t > /dev/null 2>&1; then
    log_message "PASS: [CIS 1.5.1.6] Pas de services non confinés"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 1.5.1.6] Des services non confinés existent"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.5.1.7 Ensure MCS Translation Service is not installed
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if ! rpm -q mcstrans > /dev/null 2>&1; then
    log_message "PASS: [CIS 1.5.1.7] mcstrans n'est pas installé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 1.5.1.7] mcstrans est installé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 1.6 Command Line Warning Banners
log_message "=== 1.6 Bannières d'avertissement ==="

check_banner_file() {
    local file=$1
    local cis_ref=$2
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if [ -f "$file" ]; then
        if ! grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" "$file" > /dev/null; then
            if [ "$(stat -L -c "%a" "$file")" = "644" ]; then
                log_message "PASS: [CIS $cis_ref] $file est correctement configuré"
                PASSED_CHECKS=$((PASSED_CHECKS + 1))
                return 0
            fi
        fi
    fi
    log_message "FAIL: [CIS $cis_ref] $file n'est pas correctement configuré"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
}

check_banner_file "/etc/motd" "1.6.1"
check_banner_file "/etc/issue" "1.6.2"
check_banner_file "/etc/issue.net" "1.6.3"

# 1.7 GNOME Display Manager
log_message "=== 1.7 Gestionnaire d'affichage GNOME ==="

# 1.7.1 Ensure GNOME Display Manager is removed
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if ! rpm -q gdm > /dev/null 2>&1; then
    log_message "PASS: [CIS 1.7.1] GNOME Display Manager n'est pas installé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    # Si GDM est installé, vérifions sa configuration
    log_message "INFO: [CIS 1.7.1] GNOME Display Manager est installé, vérification de la configuration"
    
    # 1.7.2 Ensure GDM login banner is configured
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ -f "/etc/dconf/profile/gdm" ] && [ -f "/etc/dconf/db/gdm.d/01-banner-message" ]; then
        log_message "PASS: [CIS 1.7.2] La bannière de connexion GDM est configurée"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 1.7.2] La bannière de connexion GDM n'est pas configurée"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
    
    # Vérifications supplémentaires pour GDM (1.7.3 à 1.7.10)
    check_gdm_setting() {
        local setting=$1
        local expected=$2
        local cis_ref=$3
        
        TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
        if [ -f "/etc/dconf/db/gdm.d/00-security-settings" ] && \
           grep -q "^$setting=$expected$" /etc/dconf/db/gdm.d/00-security-settings; then
            log_message "PASS: [CIS $cis_ref] Le paramètre GDM $setting est correctement configuré"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        else
            log_message "FAIL: [CIS $cis_ref] Le paramètre GDM $setting n'est pas correctement configuré"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi
    }
    
    check_gdm_setting "disable-user-list" "true" "1.7.3"
    check_gdm_setting "idle-delay" "900" "1.7.4"
    check_gdm_setting "lock-delay" "0" "1.7.5"
    check_gdm_setting "automount" "false" "1.7.6"
    check_gdm_setting "automount-open" "false" "1.7.7"
    check_gdm_setting "autorun-never" "true" "1.7.8"
    check_gdm_setting "autorun-never" "true" "1.7.9"
    
    # 1.7.10 Ensure XDMCP is not enabled
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if ! grep -q "Enable=true" /etc/gdm/custom.conf 2>/dev/null; then
        log_message "PASS: [CIS 1.7.10] XDMCP n'est pas activé"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 1.7.10] XDMCP est activé"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
fi 