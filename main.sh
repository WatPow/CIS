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

# Fonction de journalisation
log_message() {
    local message="$1"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $message" | tee -a "$LOG_FILE"
    echo "$message" >> "$REPORT_FILE"
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
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local compliance_rate=0
    
    if [ "$TOTAL_CHECKS" -gt 0 ]; then
        compliance_rate=$(( (PASSED_CHECKS * 100) / TOTAL_CHECKS ))
    fi

    # Création d'un fichier temporaire pour stocker les échecs
    local temp_fails=$(mktemp)
    grep "FAIL:" "$REPORT_FILE" > "$temp_fails"
    
    cat > "$HTML_REPORT" << EOF
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport d'audit CIS</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        h1 {
            text-align: center;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
            margin: 20px 0;
        }
        .stat-box {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }
        .progress-bar {
            width: 100%;
            background-color: #e9ecef;
            border-radius: 5px;
            margin: 10px 0;
        }
        .progress {
            width: ${compliance_rate}%;
            height: 20px;
            background-color: #4CAF50;
            border-radius: 5px;
            transition: width 0.5s ease-in-out;
        }
        .failed {
            color: #dc3545;
        }
        .passed {
            color: #28a745;
        }
        .section {
            margin: 20px 0;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 5px;
        }
        .failure-item {
            margin: 10px 0;
            padding: 10px;
            background-color: #fff;
            border-left: 4px solid #dc3545;
        }
        .cis-ref {
            font-weight: bold;
            color: #2c3e50;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Rapport d'audit CIS</h1>
        
        <div class="summary">
            <div class="stat-box">
                <h3>Résumé des vérifications</h3>
                <p>Total des vérifications: $TOTAL_CHECKS</p>
                <p class="passed">Vérifications réussies: $PASSED_CHECKS</p>
                <p class="failed">Vérifications échouées: $FAILED_CHECKS</p>
            </div>
            <div class="stat-box">
                <h3>Taux de conformité</h3>
                <div class="progress-bar">
                    <div class="progress"></div>
                </div>
                <p>${compliance_rate}% conforme</p>
            </div>
        </div>

        <div class="details">
            <h3>Détails de l'exécution</h3>
            <p>Début de l'audit: $(date -d @$start_time)</p>
            <p>Fin de l'audit: $(date -d @$end_time)</p>
            <p>Durée: ${duration} secondes</p>
        </div>

        <div class="failures">
            <h2>Points de contrôle échoués</h2>

            <div class="section">
                <h3>1. Configuration système initiale</h3>
                $(grep "FAIL: \[CIS 1" "$temp_fails" | while read -r line; do
                    echo "<div class='failure-item'>"
                    echo "<span class='cis-ref'>$(echo "$line" | grep -o '\[CIS [0-9]\.[0-9]\.[0-9]\.[0-9]\]')</span>"
                    echo "<p>$line</p>"
                    echo "</div>"
                done)
            </div>

            <div class="section">
                <h3>2. Services</h3>
                $(grep "FAIL: \[CIS 2" "$temp_fails" | while read -r line; do
                    echo "<div class='failure-item'>"
                    echo "<span class='cis-ref'>$(echo "$line" | grep -o '\[CIS [0-9]\.[0-9]\.[0-9]\.[0-9]\]')</span>"
                    echo "<p>$line</p>"
                    echo "</div>"
                done)
            </div>

            <div class="section">
                <h3>3. Configuration réseau</h3>
                $(grep "FAIL: \[CIS 3" "$temp_fails" | while read -r line; do
                    echo "<div class='failure-item'>"
                    echo "<span class='cis-ref'>$(echo "$line" | grep -o '\[CIS [0-9]\.[0-9]\.[0-9]\.[0-9]\]')</span>"
                    echo "<p>$line</p>"
                    echo "</div>"
                done)
            </div>

            <div class="section">
                <h3>4. Journalisation et audit</h3>
                $(grep "FAIL: \[CIS 4" "$temp_fails" | while read -r line; do
                    echo "<div class='failure-item'>"
                    echo "<span class='cis-ref'>$(echo "$line" | grep -o '\[CIS [0-9]\.[0-9]\.[0-9]\.[0-9]\]')</span>"
                    echo "<p>$line</p>"
                    echo "</div>"
                done)
            </div>

            <div class="section">
                <h3>5. Accès et authentification</h3>
                $(grep "FAIL: \[CIS 5" "$temp_fails" | while read -r line; do
                    echo "<div class='failure-item'>"
                    echo "<span class='cis-ref'>$(echo "$line" | grep -o '\[CIS [0-9]\.[0-9]\.[0-9]\.[0-9]\]')</span>"
                    echo "<p>$line</p>"
                    echo "</div>"
                done)
            </div>

            <div class="section">
                <h3>6. Maintenance système</h3>
                $(grep "FAIL: \[CIS 6" "$temp_fails" | while read -r line; do
                    echo "<div class='failure-item'>"
                    echo "<span class='cis-ref'>$(echo "$line" | grep -o '\[CIS [0-9]\.[0-9]\.[0-9]\.[0-9]\]')</span>"
                    echo "<p>$line</p>"
                    echo "</div>"
                done)
            </div>
        </div>
    </div>
</body>
</html>
EOF

    # Nettoyage
    rm -f "$temp_fails"

    chmod 644 "$HTML_REPORT"
    log_message "Rapport HTML généré: $HTML_REPORT"
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
        generate_html_report
    fi
}

# Exécution du script principal
main 