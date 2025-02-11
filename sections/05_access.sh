#!/bin/bash

# Section 5 - Journalisation et audit
log_message "=== 5 Journalisation et audit ==="

# 5.1 Configuration de la journalisation
log_message "=== 5.1 Configuration de la journalisation ==="

# 5.1.1 Configuration de rsyslog
# 5.1.1.1 Vérification de l'installation de rsyslog
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if rpm -q rsyslog &>/dev/null; then
    log_message "PASS: [CIS 5.1.1.1] rsyslog est installé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 5.1.1.1] rsyslog n'est pas installé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 5.1.1.2 Vérification de l'activation du service rsyslog
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if systemctl is-enabled rsyslog &>/dev/null; then
    log_message "PASS: [CIS 5.1.1.2] Le service rsyslog est activé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 5.1.1.2] Le service rsyslog n'est pas activé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 5.1.1.3 Vérification de la configuration de journald pour envoyer les logs à rsyslog
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep -q "^ForwardToSyslog=yes" /etc/systemd/journald.conf; then
    log_message "PASS: [CIS 5.1.1.3] journald est configuré pour envoyer les logs à rsyslog"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 5.1.1.3] journald n'est pas configuré pour envoyer les logs à rsyslog"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 5.1.1.4 Vérification des permissions par défaut de rsyslog
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep -q "^\$FileCreateMode 0640" /etc/rsyslog.conf; then
    log_message "PASS: [CIS 5.1.1.4] Les permissions par défaut de rsyslog sont correctement configurées"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 5.1.1.4] Les permissions par défaut de rsyslog ne sont pas correctement configurées"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 5.1.1.5 Vérification de la configuration de la journalisation
check_syslog_rules() {
    local rule=$1
    local cis_ref=$2
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q "^$rule" /etc/rsyslog.conf || grep -q "^$rule" /etc/rsyslog.d/*.conf 2>/dev/null; then
        log_message "PASS: [CIS $cis_ref] La règle de journalisation est configurée: $rule"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS $cis_ref] La règle de journalisation n'est pas configurée: $rule"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

check_syslog_rules "*.emerg                                  :omusrmsg:*" "5.1.1.5"
check_syslog_rules "auth,authpriv.*                         /var/log/secure" "5.1.1.5"
check_syslog_rules "mail.*                                  /var/log/maillog" "5.1.1.5"
check_syslog_rules "cron.*                                  /var/log/cron" "5.1.1.5"

# 5.1.2 Configuration de journald
# 5.1.2.1 Configuration de l'envoi des logs à un hôte distant
# 5.1.2.1.1 Vérification de l'installation de systemd-journal-remote
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if rpm -q systemd-journal-remote &>/dev/null; then
    log_message "PASS: [CIS 5.1.2.1.1] systemd-journal-remote est installé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 5.1.2.1.1] systemd-journal-remote n'est pas installé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 5.1.2.2 Vérification de l'activation du service journald
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if systemctl is-enabled systemd-journald &>/dev/null; then
    log_message "PASS: [CIS 5.1.2.2] Le service journald est activé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 5.1.2.2] Le service journald n'est pas activé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 5.1.2.3 Vérification de la compression des fichiers journaux
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep -q "^Compress=yes" /etc/systemd/journald.conf; then
    log_message "PASS: [CIS 5.1.2.3] La compression des journaux est activée"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 5.1.2.3] La compression des journaux n'est pas activée"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 5.1.2.4 Vérification de la persistance des journaux
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep -q "^Storage=persistent" /etc/systemd/journald.conf; then
    log_message "PASS: [CIS 5.1.2.4] Les journaux sont configurés pour être persistants"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 5.1.2.4] Les journaux ne sont pas configurés pour être persistants"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 5.1.4 Vérification des permissions des fichiers journaux
check_log_permissions() {
    local log_file=$1
    local expected_perms=$2
    local cis_ref=$3
    
    if [ -f "$log_file" ]; then
        perms=$(stat -c %a "$log_file")
        if [ "$perms" -le "$expected_perms" ]; then
            log_message "PASS: [CIS $cis_ref] Les permissions de $log_file sont correctes"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        else
            log_message "FAIL: [CIS $cis_ref] Les permissions de $log_file sont trop permissives"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi
    fi
}

# Vérification des permissions des fichiers de log
for log_file in $(find /var/log -type f); do
    check_log_permissions "$log_file" 640 "5.1.4"
done

# 5.2 Configuration de l'audit système (auditd)
log_message "=== 5.2 Configuration de l'audit système ==="

# 5.2.1 Activation de l'audit
# 5.2.1.1 Vérification de l'installation d'audit
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if rpm -q audit &>/dev/null; then
    log_message "PASS: [CIS 5.2.1.1] audit est installé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 5.2.1.1] audit n'est pas installé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 5.2.1.2 Vérification de l'audit des processus avant auditd
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep "^GRUB_CMDLINE_LINUX.*audit=1" /etc/default/grub &>/dev/null; then
    log_message "PASS: [CIS 5.2.1.2] L'audit des processus avant auditd est activé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 5.2.1.2] L'audit des processus avant auditd n'est pas activé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 5.2.2 Configuration de la rétention des données
check_audit_config() {
    local param=$1
    local expected=$2
    local cis_ref=$3
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if grep -q "^$param = $expected" /etc/audit/auditd.conf; then
        log_message "PASS: [CIS $cis_ref] $param est correctement configuré"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS $cis_ref] $param n'est pas correctement configuré"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

check_audit_config "max_log_file" "8" "5.2.2.1"
check_audit_config "max_log_file_action" "keep_logs" "5.2.2.2"
check_audit_config "space_left_action" "email" "5.2.2.3"
check_audit_config "action_mail_acct" "root" "5.2.2.4"

# 5.2.3 Configuration des règles d'audit
check_audit_rule() {
    local rule=$1
    local cis_ref=$2
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if auditctl -l | grep -q -- "$rule"; then
        log_message "PASS: [CIS $cis_ref] La règle d'audit est configurée"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        log_message "FAIL: [CIS $cis_ref] La règle d'audit n'est pas configurée"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Vérification des règles d'audit importantes
check_audit_rule "-w /etc/sudoers -p wa -k scope" "5.2.3.1"
check_audit_rule "-w /etc/sudoers.d/ -p wa -k scope" "5.2.3.1"
check_audit_rule "-w /var/log/sudo.log -p wa -k actions" "5.2.3.3"
check_audit_rule "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" "5.2.3.4"
check_audit_rule "-w /etc/sysconfig/network -p wa -k system-locale" "5.2.3.5"
check_audit_rule "-w /etc/selinux/ -p wa -k MAC-policy" "5.2.3.14"

# 5.2.4 Configuration des accès aux fichiers d'audit
check_audit_file_permissions() {
    local file=$1
    local expected_perms=$2
    local cis_ref=$3
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [ -f "$file" ]; then
        perms=$(stat -c %a "$file")
        if [ "$perms" -le "$expected_perms" ]; then
            log_message "PASS: [CIS $cis_ref] Les permissions de $file sont correctes"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        else
            log_message "FAIL: [CIS $cis_ref] Les permissions de $file sont trop permissives"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi
    fi
}

check_audit_file_permissions "/var/log/audit/" 750 "5.2.4.1"
check_audit_file_permissions "/etc/audit/auditd.conf" 640 "5.2.4.5"
check_audit_file_permissions "/etc/audit/audit.rules" 640 "5.2.4.5"

# 5.3 Configuration de la vérification d'intégrité
log_message "=== 5.3 Configuration de la vérification d'intégrité ==="

# 5.3.1 Vérification de l'installation d'AIDE
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if rpm -q aide &>/dev/null; then
    log_message "PASS: [CIS 5.3.1] AIDE est installé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 5.3.1] AIDE n'est pas installé"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 5.3.2 Vérification de la planification des contrôles d'intégrité
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if grep -r "aide --check" /etc/cron.* /etc/crontab &>/dev/null; then
    log_message "PASS: [CIS 5.3.2] Les contrôles d'intégrité sont planifiés"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 5.3.2] Les contrôles d'intégrité ne sont pas planifiés"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi 