#!/bin/bash

# Section 6 - Maintenance du système
log_message "=== 6 Maintenance du système ==="

# 6.1 Permissions des fichiers système
log_message "=== 6.1 Permissions des fichiers système ==="

# Fonction pour vérifier les permissions des fichiers système
check_file_permissions() {
    local file=$1
    local expected_perms=$2
    local expected_owner=$3
    local expected_group=$4
    local cis_ref=$5
    
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if [ -f "$file" ]; then
        local perms=$(stat -c %a "$file")
        local owner=$(stat -c %U "$file")
        local group=$(stat -c %G "$file")
        
        if [ "$perms" = "$expected_perms" ] && [ "$owner" = "$expected_owner" ] && [ "$group" = "$expected_group" ]; then
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

# Vérification des permissions des fichiers système critiques
check_file_permissions "/etc/passwd" "644" "root" "root" "6.1.1"
check_file_permissions "/etc/passwd-" "644" "root" "root" "6.1.2"
check_file_permissions "/etc/group" "644" "root" "root" "6.1.3"
check_file_permissions "/etc/group-" "644" "root" "root" "6.1.4"
check_file_permissions "/etc/shadow" "000" "root" "root" "6.1.5"
check_file_permissions "/etc/shadow-" "000" "root" "root" "6.1.6"
check_file_permissions "/etc/gshadow" "000" "root" "root" "6.1.7"
check_file_permissions "/etc/gshadow-" "000" "root" "root" "6.1.8"
check_file_permissions "/etc/shells" "644" "root" "root" "6.1.9"
check_file_permissions "/etc/security/opasswd" "600" "root" "root" "6.1.10"

# 6.1.11 Vérification des fichiers world-writable
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
world_writable_files=$(find / -xdev -type f -perm -0002 -print 2>/dev/null)
if [ -z "$world_writable_files" ]; then
    log_message "PASS: [CIS 6.1.11] Aucun fichier world-writable trouvé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 6.1.11] Fichiers world-writable trouvés"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 6.1.12 Vérification des fichiers sans propriétaire
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
unowned_files=$(find / -xdev -nouser -o -nogroup -print 2>/dev/null)
if [ -z "$unowned_files" ]; then
    log_message "PASS: [CIS 6.1.12] Aucun fichier sans propriétaire trouvé"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 6.1.12] Fichiers sans propriétaire trouvés"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 6.1.13 Vérification des fichiers SUID/SGID
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
suid_sgid_files=$(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null)
log_message "INFO: [CIS 6.1.13] Liste des fichiers SUID/SGID à examiner manuellement:"
echo "$suid_sgid_files" >> "$LOG_FILE"

# 6.1.14 Audit des permissions des fichiers système
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
log_message "INFO: [CIS 6.1.14] Un audit manuel des permissions des fichiers système est recommandé"

# 6.2 Paramètres des utilisateurs et groupes locaux
log_message "=== 6.2 Paramètres des utilisateurs et groupes locaux ==="

# 6.2.1 Vérification de l'utilisation des mots de passe shadow
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if ! grep -q '^[^:]*:[^:]*:' /etc/passwd; then
    log_message "PASS: [CIS 6.2.1] Tous les comptes utilisent des mots de passe shadow"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 6.2.1] Certains comptes n'utilisent pas de mots de passe shadow"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 6.2.2 Vérification des champs de mot de passe vides
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if ! awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow | grep -q .; then
    log_message "PASS: [CIS 6.2.2] Aucun compte n'a de mot de passe vide"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 6.2.2] Des comptes ont des mots de passe vides"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 6.2.3 Vérification de la correspondance des groupes
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
for gid in $(cut -d: -f4 /etc/passwd | sort -u); do
    if ! grep -q "^[^:]*:[^:]*:$gid:" /etc/group; then
        log_message "FAIL: [CIS 6.2.3] Le GID $gid de /etc/passwd n'existe pas dans /etc/group"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
        break
    fi
done
if [ $? -eq 0 ]; then
    log_message "PASS: [CIS 6.2.3] Tous les groupes dans /etc/passwd existent dans /etc/group"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
fi

# 6.2.4 Vérification des UID dupliqués
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if ! cut -d: -f3 /etc/passwd | sort | uniq -d | grep -q .; then
    log_message "PASS: [CIS 6.2.4] Aucun UID dupliqué"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 6.2.4] Des UID dupliqués ont été trouvés"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 6.2.5 Vérification des GID dupliqués
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if ! cut -d: -f3 /etc/group | sort | uniq -d | grep -q .; then
    log_message "PASS: [CIS 6.2.5] Aucun GID dupliqué"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 6.2.5] Des GID dupliqués ont été trouvés"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 6.2.6 Vérification des noms d'utilisateur dupliqués
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if ! cut -d: -f1 /etc/passwd | sort | uniq -d | grep -q .; then
    log_message "PASS: [CIS 6.2.6] Aucun nom d'utilisateur dupliqué"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 6.2.6] Des noms d'utilisateur dupliqués ont été trouvés"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 6.2.7 Vérification des noms de groupe dupliqués
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if ! cut -d: -f1 /etc/group | sort | uniq -d | grep -q .; then
    log_message "PASS: [CIS 6.2.7] Aucun nom de groupe dupliqué"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 6.2.7] Des noms de groupe dupliqués ont été trouvés"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# 6.2.8 Vérification de l'intégrité du PATH de root
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ "$(echo $PATH | grep ::)" != "" ] || [ "$(echo $PATH | grep :$)" != "" ]; then
    log_message "FAIL: [CIS 6.2.8] Le PATH de root contient :: ou se termine par :"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
else
    log_message "PASS: [CIS 6.2.8] Le PATH de root est correctement configuré"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
fi

# 6.2.9 Vérification que root est le seul UID 0
TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
if [ $(awk -F: '($3 == 0) { print $1 }' /etc/passwd | wc -l) -eq 1 ] && [ $(awk -F: '($3 == 0) { print $1 }' /etc/passwd) = "root" ]; then
    log_message "PASS: [CIS 6.2.9] root est le seul compte avec UID 0"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
else
    log_message "FAIL: [CIS 6.2.9] D'autres comptes ont un UID 0"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
fi

# Vérification des répertoires home
check_home_directories() {
    local user_home
    while IFS=: read -r username _ uid _ _ home_dir _; do
        if [ "$uid" -ge 1000 ] && [ "$uid" -ne 65534 ]; then
            if [ -d "$home_dir" ]; then
                perms=$(stat -L -c "%a" "$home_dir")
                if [ "$perms" -gt 750 ]; then
                    log_message "FAIL: [CIS 6.2.10] Les permissions du répertoire home $home_dir sont trop permissives"
                    FAILED_CHECKS=$((FAILED_CHECKS + 1))
                else
                    log_message "PASS: [CIS 6.2.10] Les permissions du répertoire home $home_dir sont correctes"
                    PASSED_CHECKS=$((PASSED_CHECKS + 1))
                fi
            fi
        fi
    done < /etc/passwd
}

# Vérification des fichiers dot
check_dot_files() {
    local user_home
    while IFS=: read -r username _ uid _ _ home_dir _; do
        if [ "$uid" -ge 1000 ] && [ -d "$home_dir" ]; then
            for dot_file in "$home_dir"/.*; do
                if [ -f "$dot_file" ]; then
                    perms=$(stat -L -c "%a" "$dot_file")
                    if [ "$perms" -gt 750 ]; then
                        log_message "FAIL: [CIS 6.2.11] Les permissions du fichier $dot_file sont trop permissives"
                        FAILED_CHECKS=$((FAILED_CHECKS + 1))
                        break
                    fi
                fi
            done
        fi
    done < /etc/passwd
} 