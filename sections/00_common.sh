#!/bin/bash

# Variables globales
MODE_AUDIT=true
LOG_FILE="/var/log/cis_audit.log"
REPORT_FILE="/var/log/cis_report_$(date +%Y%m%d).txt"
HTML_REPORT="./cis_report_$(date +%Y%m%d).html"
FAILED_CHECKS=0
PASSED_CHECKS=0
TOTAL_CHECKS=0
start_time=$(date +%s)
GENERATE_HTML=false

# Fonction de journalisation
function log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOG_FILE
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