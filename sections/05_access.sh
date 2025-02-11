#!/bin/bash

# Section 5 - Accès et authentification
log_message "=== 5 Accès et authentification ==="

# 5.1 Configuration de cron et at
log_message "=== 5.1 Configuration de cron et at ==="

# 5.1.1 Vérification des permissions des fichiers cron
for file in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ -e "$file" ]; then
        perms=$(stat -c %a "$file")
        owner=$(stat -c %U "$file")
        if [ "$perms" = "600" ] || [ "$perms" = "700" ] && [ "$owner" = "root" ]; then
            log_message "PASS: Permissions correctes sur $file"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        else
            log_message "FAIL: Permissions incorrectes sur $file (perms: $perms, owner: $owner)"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi
    else
        log_message "FAIL: $file n'existe pas"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
done

# 5.1.2 Vérification des fichiers de restriction cron
for file in /etc/cron.deny /etc/at.deny; do
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ ! -f "$file" ]; then
        log_message "PASS: $file n'existe pas (recommandé)"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: $file existe (non recommandé)"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
done

# 5.2 Configuration SSH
log_message "=== 5.2 Configuration SSH ==="

# 5.2.1 Vérification des permissions du fichier sshd_config
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ -f "/etc/ssh/sshd_config" ]; then
    perms=$(stat -c %a /etc/ssh/sshd_config)
    if [ "$perms" = "600" ]; then
        log_message "PASS: Permissions correctes sur sshd_config"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Permissions incorrectes sur sshd_config: $perms"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
fi

# 5.2.2 Vérification des paramètres SSH
ssh_params=(
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
    param_name=$(echo "$param" | cut -d' ' -f1)
    param_value=$(echo "$param" | cut -d' ' -f2-)
    if grep -q "^${param_name} ${param_value}" /etc/ssh/sshd_config; then
        log_message "PASS: Configuration SSH - $param_name est correctement configuré"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Configuration SSH - $param_name n'est pas correctement configuré"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
done

# 5.3 Configuration PAM
log_message "=== 5.3 Configuration PAM ==="

# 5.3.1 Vérification des exigences de mot de passe
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep -q "pam_pwquality.so" /etc/pam.d/password-auth && \
   grep -q "pam_pwquality.so" /etc/pam.d/system-auth; then
    log_message "PASS: Les exigences de mot de passe sont configurées"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: Les exigences de mot de passe ne sont pas configurées"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 5.3.2 Vérification du verrouillage après échecs
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep -q "pam_faillock.so" /etc/pam.d/password-auth && \
   grep -q "pam_faillock.so" /etc/pam.d/system-auth; then
    log_message "PASS: Le verrouillage après échecs est configuré"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: Le verrouillage après échecs n'est pas configuré"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 5.4 Politique de mots de passe
log_message "=== 5.4 Politique de mots de passe ==="

# Vérification des paramètres dans /etc/login.defs
password_params=(
    "PASS_MAX_DAYS 90"
    "PASS_MIN_DAYS 7"
    "PASS_WARN_AGE 7"
)

for param in "${password_params[@]}"; do
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    param_name=$(echo "$param" | cut -d' ' -f1)
    param_value=$(echo "$param" | cut -d' ' -f2)
    current=$(grep "^$param_name" /etc/login.defs | awk '{print $2}')
    
    if [ "$current" = "$param_value" ]; then
        log_message "PASS: $param_name est correctement configuré ($param_value)"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: $param_name est mal configuré (actuel: $current, attendu: $param_value)"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
done

# 5.5 Contrôles de connexion root
log_message "=== 5.5 Contrôles de connexion root ==="

# 5.5.1 Vérification des restrictions de connexion root
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ -f "/etc/securetty" ]; then
    console_only=$(wc -l < /etc/securetty)
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

# 5.5.2 Vérification de l'accès su
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep -q "pam_wheel.so use_uid" /etc/pam.d/su && \
   grep -q "wheel" /etc/group; then
    log_message "PASS: L'accès à la commande su est restreint"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: L'accès à la commande su n'est pas restreint"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi 