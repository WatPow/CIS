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
    
    # Affichage en console et dans le fichier de log
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
    echo "$message" >> "$REPORT_FILE"
    
    # Comptage des tests uniquement pour les messages PASS/FAIL avec référence CIS
    if [[ -n "$cis_ref" ]]; then
        if [[ "$message" == PASS:* ]]; then
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
            TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
        elif [[ "$message" == FAIL:* ]]; then
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
            TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
        fi
    fi
    
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
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'audit CIS</title>
    <style>
        :root {
            --primary-color: #2c3e50;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --background-color: #f5f7fa;
            --card-background: #ffffff;
            --text-color: #2c3e50;
            --border-radius: 8px;
            --shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            background-color: var(--background-color);
            color: var(--text-color);
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            background-color: var(--card-background);
            padding: 30px;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            margin-bottom: 30px;
            text-align: center;
        }

        .header h1 {
            color: var(--primary-color);
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .header p {
            color: #666;
            font-size: 1.1em;
        }

        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background-color: var(--card-background);
            padding: 20px;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            text-align: center;
        }

        .stat-card h3 {
            font-size: 1.1em;
            color: #666;
            margin-bottom: 10px;
        }

        .stat-card .value {
            font-size: 2em;
            font-weight: bold;
            color: var(--primary-color);
        }

        .progress-container {
            background-color: var(--card-background);
            padding: 30px;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            margin-bottom: 30px;
        }

        .progress-bar {
            height: 25px;
            background-color: #ecf0f1;
            border-radius: 12.5px;
            overflow: hidden;
            margin: 20px 0;
        }

        .progress-fill {
            height: 100%;
            width: ${compliance_rate}%;
            background-color: var(--success-color);
            transition: width 1s ease-in-out;
        }

        .failures-section {
            background-color: var(--card-background);
            padding: 30px;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
        }

        .failures-section h2 {
            color: var(--primary-color);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }

        .failure-item {
            background-color: #fff;
            border-left: 4px solid var(--danger-color);
            margin: 15px 0;
            padding: 20px;
            border-radius: 0 var(--border-radius) var(--border-radius) 0;
            box-shadow: var(--shadow);
        }

        .failure-header {
            display: flex;
            align-items: center;
            margin-bottom: 10px;
        }

        .cis-ref {
            background-color: #f8f9fa;
            color: var(--primary-color);
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.9em;
            margin-right: 10px;
        }

        .failure-message {
            color: #555;
            font-size: 1em;
            line-height: 1.5;
        }

        .section-title {
            color: var(--primary-color);
            font-size: 1.5em;
            margin: 30px 0 20px 0;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }

        .execution-details {
            background-color: var(--card-background);
            padding: 20px;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            margin: 20px 0;
        }

        .execution-details h3 {
            color: var(--primary-color);
            margin-bottom: 15px;
        }

        .execution-details p {
            margin: 10px 0;
            color: #666;
        }

        .execution-details strong {
            color: var(--primary-color);
        }

        @media (max-width: 768px) {
            .dashboard {
                grid-template-columns: 1fr;
            }
            
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2em;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Rapport d'audit CIS</h1>
            <p>Généré le $(date -d @$end_time '+%d/%m/%Y à %H:%M:%S')</p>
        </div>

        <div class="dashboard">
            <div class="stat-card">
                <h3>Total des vérifications</h3>
                <div class="value">$TOTAL_CHECKS</div>
            </div>
            <div class="stat-card">
                <h3>Vérifications réussies</h3>
                <div class="value" style="color: var(--success-color)">$PASSED_CHECKS</div>
            </div>
            <div class="stat-card">
                <h3>Vérifications échouées</h3>
                <div class="value" style="color: var(--danger-color)">$FAILED_CHECKS</div>
            </div>
        </div>

        <div class="progress-container">
            <h2>Taux de conformité</h2>
            <div class="progress-bar">
                <div class="progress-fill"></div>
            </div>
            <p style="text-align: center; font-size: 1.2em;">
                <strong>${compliance_rate}%</strong> de conformité
            </p>
        </div>

        <div class="execution-details">
            <h3>Détails de l'exécution</h3>
            <p><strong>Début de l'audit:</strong> $(date -d @$start_time '+%d/%m/%Y %H:%M:%S')</p>
            <p><strong>Fin de l'audit:</strong> $(date -d @$end_time '+%d/%m/%Y %H:%M:%S')</p>
            <p><strong>Durée:</strong> ${duration} secondes</p>
        </div>

        <div class="failures-section">
            <h2>Points de contrôle échoués</h2>
            <div class="failures-content">
                $(if [ -s "$TEMP_FAILS" ]; then
                    cat "$TEMP_FAILS"
                else
                    echo "<p style='text-align: center; color: var(--success-color); padding: 20px;'>Aucun échec détecté</p>"
                fi)
            </div>
        </div>
    </div>
</body>
</html>
EOF

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

    # Réinitialisation des compteurs
    FAILED_CHECKS=0
    PASSED_CHECKS=0
    TOTAL_CHECKS=0

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
            
            # Sauvegarde des compteurs avant l'exécution de la section
            local prev_total=$TOTAL_CHECKS
            local prev_passed=$PASSED_CHECKS
            local prev_failed=$FAILED_CHECKS
            
            # Exécution dans le même environnement shell
            . "sections/$section"
            
            # Vérification de la cohérence après l'exécution
            local new_checks=$((TOTAL_CHECKS - prev_total))
            local new_passed=$((PASSED_CHECKS - prev_passed))
            local new_failed=$((FAILED_CHECKS - prev_failed))
            
            if [ $new_checks -ne $((new_passed + new_failed)) ]; then
                log_message "ERREUR: Incohérence dans le comptage pour la section $section"
                log_message "Nouveaux tests: $new_checks"
                log_message "Nouveaux succès: $new_passed"
                log_message "Nouveaux échecs: $new_failed"
            fi
            
            if [ $? -ne 0 ]; then
                log_message "ERREUR: Échec de l'exécution de $section"
            fi
        else
            log_message "ERREUR: Section non trouvée: $section"
        fi
    done

    # Vérification finale de la cohérence
    if [ $TOTAL_CHECKS -ne $((PASSED_CHECKS + FAILED_CHECKS)) ]; then
        log_message "ERREUR: Incohérence dans le comptage final"
        log_message "Total des vérifications: $TOTAL_CHECKS"
        log_message "Total succès + échecs: $((PASSED_CHECKS + FAILED_CHECKS))"
    fi

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