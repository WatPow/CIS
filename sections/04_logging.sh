#!/bin/bash

# Section 4 - Journalisation et audit
log_message "=== 4 Journalisation et audit ==="

# 4.1 Configuration de rsyslog
log_message "=== 4.1 Configuration de rsyslog ==="

# 4.1.1 Vérification de l'installation de rsyslog
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if rpm -q rsyslog > /dev/null 2>&1; then
    log_message "PASS: rsyslog est installé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: rsyslog n'est pas installé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 4.1.2 Vérification de l'activation du service rsyslog
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if systemctl is-enabled rsyslog 2>/dev/null | grep -q "enabled"; then
    log_message "PASS: Le service rsyslog est activé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: Le service rsyslog n'est pas activé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 4.1.3 Vérification de la configuration des fichiers de log
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

# 4.1.4 Vérification des permissions des fichiers de log
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep -q "^\$FileCreateMode 0[0-6][0-4][0-4]" /etc/rsyslog.conf; then
    log_message "PASS: Les permissions par défaut de rsyslog sont correctement configurées"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: Les permissions par défaut de rsyslog ne sont pas correctement configurées"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 4.2 Configuration d'auditd
log_message "=== 4.2 Configuration d'auditd ==="

# 4.2.1 Vérification de l'installation d'auditd
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if rpm -q audit > /dev/null 2>&1; then
    log_message "PASS: audit est installé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: audit n'est pas installé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 4.2.2 Vérification de l'activation du service auditd
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if systemctl is-enabled auditd 2>/dev/null | grep -q "enabled"; then
    log_message "PASS: Le service auditd est activé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: Le service auditd n'est pas activé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 4.2.3 Vérification de la configuration d'audit
if [ -f "/etc/audit/auditd.conf" ]; then
    # 4.2.3.1 Vérification de la taille des logs
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q "^max_log_file = " /etc/audit/auditd.conf; then
        log_message "PASS: La taille des logs d'audit est configurée"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: La taille des logs d'audit n'est pas configurée"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 4.2.3.2 Vérification de la conservation des logs
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q "^max_log_file_action = keep_logs" /etc/audit/auditd.conf; then
        log_message "PASS: Les logs d'audit sont conservés"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Les logs d'audit peuvent être supprimés"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # 4.2.3.3 Vérification de l'action en cas de logs pleins
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q "^space_left_action = email" /etc/audit/auditd.conf && \
       grep -q "^action_mail_acct = root" /etc/audit/auditd.conf && \
       grep -q "^admin_space_left_action = halt" /etc/audit/auditd.conf; then
        log_message "PASS: Les actions en cas de logs pleins sont correctement configurées"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: Les actions en cas de logs pleins ne sont pas correctement configurées"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
fi

# 4.2.4 Vérification des règles d'audit
log_message "=== 4.2.4 Vérification des règles d'audit ==="

# Liste des règles d'audit à vérifier
audit_rules=(
    "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change"
    "-a always,exit -F arch=b32 -S stime -S settimeofday -S adjtimex -k time-change"
    "-w /etc/localtime -p wa -k time-change"
    "-w /etc/group -p wa -k identity"
    "-w /etc/passwd -p wa -k identity"
    "-w /etc/gshadow -p wa -k identity"
    "-w /etc/shadow -p wa -k identity"
    "-w /etc/security/opasswd -p wa -k identity"
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