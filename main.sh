#!/bin/bash

# Variables globales
export MODE_AUDIT=1
export LOG_FILE="/var/log/cis_audit.log"
export REPORT_FILE="/var/log/cis_audit_report.txt"
export HTML_REPORT="/var/log/cis_audit_report.html"
export FAILED_CHECKS=0
export PASSED_CHECKS=0
export TOTAL_CHECKS=0
export GENERATE_HTML=1
export start_time=$(date +%s)

# Création des fichiers temporaires
TEMP_FAILS=$(mktemp)
trap 'rm -f "$TEMP_FAILS"' EXIT

# Fonction de journalisation
log_message() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Extraction du type de message (PASS/FAIL/INFO) et de la référence CIS
    local msg_type=$(echo "$message" | grep -o '^[A-Z]\+:')
    local cis_ref=$(echo "$message" | grep -o '\[CIS [0-9]\.[0-9]\.[0-9]*\.*[0-9]*\]')
    local content=$(echo "$message" | sed -E 's/^[A-Z]+: \[CIS [0-9]+\.[0-9]+\.[0-9]+\.*[0-9]*\] //')
    
    # Formatage du message pour le fichier de log
    echo "[$timestamp] $message" >> "$LOG_FILE"
    
    # Stockage des échecs pour le rapport HTML
    if [[ "$message" == FAIL:* ]]; then
        echo "<div class='failure-item'>" >> "$TEMP_FAILS"
        echo "<div class='failure-header'><span class='cis-ref'>$cis_ref</span></div>" >> "$TEMP_FAILS"
        echo "<div class='failure-message'>$content</div>" >> "$TEMP_FAILS"
        echo "</div>" >> "$TEMP_FAILS"
    fi
}
export -f log_message

# Vérification des prérequis
check_prerequisites() {
    # Vérification de l'exécution en tant que root
    if [ "$(id -u)" -ne 0 ]; then
        echo "Ce script doit être exécuté en tant que root"
        exit 1
    fi

    # Vérification de l'espace disque
    local min_space=1048576  # 1GB en KB
    local available_space=$(df -k /var/log | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt "$min_space" ]; then
        echo "Espace disque insuffisant dans /var/log"
        exit 1
    fi

    # Création des fichiers de log s'ils n'existent pas
    touch "$LOG_FILE" "$REPORT_FILE"
    chmod 600 "$LOG_FILE" "$REPORT_FILE"

    # Vérification des commandes requises
    local required_commands=(
        "awk" "grep" "stat" "find" "systemctl" "ip"
        "mount" "df" "ps" "cut" "tr" "sort" "uniq"
    )

    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "Commande requise non trouvée: $cmd"
            exit 1
        fi
    done
}

# Fonction pour générer le rapport HTML
generate_html_report() {
    local start_time=$1
    local end_time=$2
    local duration=$3
    local compliance_rate=$4
    
    cat > "$HTML_REPORT" << EOF
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Rapport d'audit CIS</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .failure-item {
            margin: 15px 0;
            padding: 15px;
            background-color: #fff;
            border-left: 4px solid #dc3545;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }
        .failure-header {
            margin-bottom: 8px;
        }
        .cis-ref {
            font-weight: bold;
            color: #2c3e50;
            background-color: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.9em;
        }
        .failure-message {
            margin-top: 5px;
            color: #666;
            font-size: 0.95em;
            line-height: 1.4;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Rapport d'audit CIS</h1>
        
        <div class="summary">
            <h2>Résumé</h2>
            <p>Total des vérifications: <strong>$TOTAL_CHECKS</strong></p>
            <p>Vérifications réussies: <strong>$PASSED_CHECKS</strong></p>
            <p>Vérifications échouées: <strong>$FAILED_CHECKS</strong></p>
            <p>Taux de conformité: <strong>${compliance_rate}%</strong></p>
        </div>

        <div class="failures">
            <h2>Points de contrôle échoués</h2>
            $(cat "$TEMP_FAILS")
        </div>
    </div>
</body>
</html>
EOF
}

# Fonction principale
main() {
    # Vérification des prérequis
    check_prerequisites

    # Nettoyage des fichiers de log existants
    echo "" > "$LOG_FILE"
    echo "" > "$REPORT_FILE"

    log_message "Début de l'audit CIS"
    log_message "===================="

    # Export des variables pour les sous-scripts
    export FAILED_CHECKS
    export PASSED_CHECKS
    export TOTAL_CHECKS

    # Exécution des sections dans l'ordre
    local sections=(
        "01_initial_setup.sh"
        "02_services.sh"
        "03_network.sh"
        "04_logging.sh"
        "05_access.sh"
        "06_system_maintenance.sh"
    )

    for section in "${sections[@]}"; do
        if [ -f "sections/$section" ]; then
            log_message "Exécution de la section: $section"
            # Exécution dans le même environnement shell
            . "sections/$section"
            if [ $? -ne 0 ]; then
                log_message "ERREUR: Échec de l'exécution de $section"
            fi
        else
            log_message "ERREUR: Section non trouvée: $section"
        fi
    done

    # Génération du rapport final
    log_message "===================="
    log_message "Fin de l'audit CIS"
    log_message "Total des vérifications: $TOTAL_CHECKS"
    log_message "Vérifications réussies: $PASSED_CHECKS"
    log_message "Vérifications échouées: $FAILED_CHECKS"
    
    if [ "$GENERATE_HTML" -eq 1 ]; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        local compliance_rate=0
        
        if [ "$TOTAL_CHECKS" -gt 0 ]; then
            compliance_rate=$(( (PASSED_CHECKS * 100) / TOTAL_CHECKS ))
        fi
        generate_html_report "$start_time" "$end_time" "$duration" "$compliance_rate"
    fi
}

# Exécution du script principal
main 