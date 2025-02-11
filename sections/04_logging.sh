#!/bin/bash

# Section 4 - Configuration des planificateurs de tâches et accès
log_message "=== 4 Configuration des planificateurs de tâches et accès ==="

# 4.1 Configuration des planificateurs de tâches
log_message "=== 4.1 Configuration des planificateurs de tâches ==="

# 4.1.1 Configuration de cron
# 4.1.1.1 Vérification de l'activation du démon cron
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if systemctl is-enabled crond &>/dev/null && systemctl is-active crond &>/dev/null; then
    log_message "PASS: [CIS 4.1.1.1] Le service cron est activé et actif"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 4.1.1.1] Le service cron n'est pas activé ou actif"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# Fonction pour vérifier les permissions des fichiers cron
check_cron_permissions() {
    local file=$1
    local expected_perms=$2
    local cis_ref=$3
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ -f "$file" ]; then
        perms=$(stat -c %a "$file")
        owner=$(stat -c %U "$file")
        group=$(stat -c %G "$file")
        
        if [ "$perms" = "$expected_perms" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
            log_message "PASS: [CIS $cis_ref] Les permissions de $file sont correctes"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        else
            log_message "FAIL: [CIS $cis_ref] Les permissions de $file sont incorrectes (perms: $perms, owner: $owner, group: $group)"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi
    else
        log_message "FAIL: [CIS $cis_ref] Le fichier $file n'existe pas"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Vérification des permissions des fichiers cron
check_cron_permissions "/etc/crontab" "600" "4.1.1.2"
check_cron_permissions "/etc/cron.hourly" "700" "4.1.1.3"
check_cron_permissions "/etc/cron.daily" "700" "4.1.1.4"
check_cron_permissions "/etc/cron.weekly" "700" "4.1.1.5"
check_cron_permissions "/etc/cron.monthly" "700" "4.1.1.6"
check_cron_permissions "/etc/cron.d" "700" "4.1.1.7"

# 4.1.1.8 Vérification de la restriction de crontab
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ ! -f "/etc/cron.deny" ] && [ -f "/etc/cron.allow" ]; then
    if [ "$(stat -c %a /etc/cron.allow)" = "640" ]; then
        log_message "PASS: [CIS 4.1.1.8] L'accès à crontab est correctement restreint"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 4.1.1.8] Les permissions de /etc/cron.allow sont incorrectes"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
else
    log_message "FAIL: [CIS 4.1.1.8] La configuration de restriction crontab est incorrecte"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 4.1.2 Configuration de at
# 4.1.2.1 Vérification de la restriction de at
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ ! -f "/etc/at.deny" ] && [ -f "/etc/at.allow" ]; then
    if [ "$(stat -c %a /etc/at.allow)" = "640" ]; then
        log_message "PASS: [CIS 4.1.2.1] L'accès à at est correctement restreint"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 4.1.2.1] Les permissions de /etc/at.allow sont incorrectes"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
else
    log_message "FAIL: [CIS 4.1.2.1] La configuration de restriction at est incorrecte"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 4.2 Configuration du serveur SSH
log_message "=== 4.2 Configuration du serveur SSH ==="

# Fonction pour vérifier les paramètres SSH
check_sshd_config() {
    local param=$1
    local expected=$2
    local cis_ref=$3
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -Ei "^${param}\s+${expected}" /etc/ssh/sshd_config &>/dev/null; then
        log_message "PASS: [CIS $cis_ref] Le paramètre SSH $param est correctement configuré"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS $cis_ref] Le paramètre SSH $param n'est pas correctement configuré"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# 4.2.1 Vérification des permissions de sshd_config
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ -f "/etc/ssh/sshd_config" ]; then
    perms=$(stat -c %a /etc/ssh/sshd_config)
    if [ "$perms" = "600" ]; then
        log_message "PASS: [CIS 4.2.1] Les permissions de sshd_config sont correctes"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 4.2.1] Les permissions de sshd_config sont incorrectes"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
fi

# 4.2.2 Vérification des permissions des clés privées SSH
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
private_keys=$(find /etc/ssh -xdev -type f -name 'ssh_host_*_key')
incorrect_perms=0
for key in $private_keys; do
    if [ "$(stat -c %a "$key")" != "600" ]; then
        incorrect_perms=1
        break
    fi
done
if [ $incorrect_perms -eq 0 ]; then
    log_message "PASS: [CIS 4.2.2] Les permissions des clés privées SSH sont correctes"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 4.2.2] Certaines clés privées SSH ont des permissions incorrectes"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# Vérification des paramètres SSH
check_sshd_config "Banner" "/etc/issue.net" "4.2.5"
check_sshd_config "Ciphers" "aes256-ctr,aes192-ctr,aes128-ctr" "4.2.6"
check_sshd_config "ClientAliveInterval" "300" "4.2.7"
check_sshd_config "ClientAliveCountMax" "0" "4.2.7"
check_sshd_config "DisableForwarding" "yes" "4.2.8"
check_sshd_config "GSSAPIAuthentication" "no" "4.2.9"
check_sshd_config "HostbasedAuthentication" "no" "4.2.10"
check_sshd_config "IgnoreRhosts" "yes" "4.2.11"
check_sshd_config "KexAlgorithms" "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256" "4.2.12"
check_sshd_config "LoginGraceTime" "60" "4.2.13"
check_sshd_config "LogLevel" "INFO" "4.2.14"
check_sshd_config "MACs" "hmac-sha2-512,hmac-sha2-256" "4.2.15"
check_sshd_config "MaxAuthTries" "4" "4.2.16"
check_sshd_config "MaxSessions" "4" "4.2.17"
check_sshd_config "MaxStartups" "10:30:60" "4.2.18"
check_sshd_config "PermitEmptyPasswords" "no" "4.2.19"
check_sshd_config "PermitRootLogin" "no" "4.2.20"
check_sshd_config "PermitUserEnvironment" "no" "4.2.21"
check_sshd_config "UsePAM" "yes" "4.2.22"

# 4.3 Configuration de l'escalade de privilèges
log_message "=== 4.3 Configuration de l'escalade de privilèges ==="

# 4.3.1 Vérification de l'installation de sudo
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if rpm -q sudo &>/dev/null; then
    log_message "PASS: [CIS 4.3.1] sudo est installé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 4.3.1] sudo n'est pas installé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# Fonction pour vérifier les paramètres sudo
check_sudo_config() {
    local param=$1
    local expected=$2
    local cis_ref=$3
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -Ei "^Defaults\s+$param\s*=\s*$expected" /etc/sudoers &>/dev/null; then
        log_message "PASS: [CIS $cis_ref] Le paramètre sudo $param est correctement configuré"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS $cis_ref] Le paramètre sudo $param n'est pas correctement configuré"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

check_sudo_config "use_pty" "yes" "4.3.2"
check_sudo_config "logfile" "/var/log/sudo.log" "4.3.3"
check_sudo_config "authenticate" "yes" "4.3.4"
check_sudo_config "!authenticate" "no" "4.3.5"
check_sudo_config "timestamp_timeout" "15" "4.3.6"

# 4.3.7 Vérification de la restriction de su
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep -q "auth required pam_wheel.so use_uid" /etc/pam.d/su && \
   grep -q "^wheel:" /etc/group; then
    log_message "PASS: [CIS 4.3.7] L'accès à su est correctement restreint"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 4.3.7] L'accès à su n'est pas correctement restreint"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 4.4 Configuration des modules PAM
log_message "=== 4.4 Configuration des modules PAM ==="

# 4.4.1 Vérification des paquets PAM
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if rpm -q pam libpwquality &>/dev/null; then
    log_message "PASS: [CIS 4.4.1] Les paquets PAM sont installés"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 4.4.1] Certains paquets PAM sont manquants"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# Fonction pour vérifier la configuration PAM
check_pam_config() {
    local file=$1
    local pattern=$2
    local cis_ref=$3
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q "$pattern" "$file" &>/dev/null; then
        log_message "PASS: [CIS $cis_ref] La configuration PAM est correcte pour $pattern"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS $cis_ref] La configuration PAM est incorrecte pour $pattern"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Vérification des configurations PAM
for auth_file in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    check_pam_config "$auth_file" "pam_faillock.so" "4.4.2.1.1"
    check_pam_config "$auth_file" "deny=5" "4.4.2.1.2"
    check_pam_config "$auth_file" "unlock_time=900" "4.4.2.1.3"
    check_pam_config "$auth_file" "pam_pwquality.so" "4.4.2.2.1"
    check_pam_config "$auth_file" "minlen=14" "4.4.2.2.3"
    check_pam_config "$auth_file" "dcredit=-1" "4.4.2.2.4"
    check_pam_config "$auth_file" "maxrepeat=3" "4.4.2.2.5"
    check_pam_config "$auth_file" "maxsequence=3" "4.4.2.2.6"
    check_pam_config "$auth_file" "dictcheck=1" "4.4.2.2.7"
    check_pam_config "$auth_file" "remember=5" "4.4.2.3.2"
    check_pam_config "$auth_file" "use_authtok" "4.4.2.3.4"
    check_pam_config "$auth_file" "sha512" "4.4.2.4.3"
done

# 4.5 Configuration des comptes utilisateurs et de l'environnement
log_message "=== 4.5 Configuration des comptes utilisateurs et de l'environnement ==="

# 4.5.1 Vérification des paramètres de mot de passe
check_password_param() {
    local param=$1
    local expected=$2
    local cis_ref=$3
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    current=$(grep "^$param" /etc/login.defs | awk '{print $2}')
    if [ "$current" = "$expected" ]; then
        log_message "PASS: [CIS $cis_ref] $param est correctement configuré"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS $cis_ref] $param n'est pas correctement configuré"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

check_password_param "PASS_MAX_DAYS" "365" "4.5.1.2"
check_password_param "PASS_WARN_AGE" "7" "4.5.1.3"
check_password_param "INACTIVE" "30" "4.5.1.4"

# 4.5.2 Vérification des comptes root et système
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ "$(grep "^root:" /etc/passwd | cut -f4 -d:)" = "0" ]; then
    log_message "PASS: [CIS 4.5.2.1] Le GID par défaut pour root est 0"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 4.5.2.1] Le GID par défaut pour root n'est pas 0"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 4.5.3 Configuration de l'environnement utilisateur par défaut
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if ! grep -q "^/sbin/nologin$" /etc/shells; then
    log_message "PASS: [CIS 4.5.3.1] nologin n'est pas listé dans /etc/shells"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 4.5.3.1] nologin est listé dans /etc/shells"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# Vérification du timeout par défaut
check_timeout_files() {
    local file=$1
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q "^TMOUT=900" "$file" 2>/dev/null; then
        log_message "PASS: [CIS 4.5.3.2] Le timeout est configuré dans $file"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS 4.5.3.2] Le timeout n'est pas configuré dans $file"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

for profile_file in /etc/profile /etc/bashrc; do
    check_timeout_files "$profile_file"
done 