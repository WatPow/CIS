#!/bin/bash

# Fonction de rapport final
function print_summary() {
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo "
=== Rapport d'audit CIS $(date) ===
Durée de l'audit: $((duration / 60)) minutes et $((duration % 60)) secondes

Résumé des vérifications:
------------------------
Total des contrôles: $TOTAL_CHECKS
Contrôles réussis: $PASSED_CHECKS
Contrôles échoués: $FAILED_CHECKS
Taux de conformité: $(( (PASSED_CHECKS * 100) / TOTAL_CHECKS ))%

Détails par section:
-------------------
1. Configuration système initiale
2. Services
3. Configuration réseau
4. Journalisation et audit
5. Accès, authentification et autorisation
6. Maintenance système

Fichiers générés:
----------------
- Journal détaillé: $LOG_FILE
- Rapport complet: $REPORT_FILE" | tee -a $REPORT_FILE

    if [ "$GENERATE_HTML" = true ]; then
        generate_html_report
    fi
}

# Fonction de génération du rapport HTML
function generate_html_report() {
    log_message "Génération du rapport HTML..."
    
    cat > "$HTML_REPORT" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Rapport d'audit CIS $(date)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .section { margin: 20px 0; }
        .pass { color: green; }
        .fail { color: red; }
        .summary { background-color: #f0f0f0; padding: 10px; }
    </style>
</head>
<body>
    <h1>Rapport d'audit CIS $(date)</h1>
    <div class="summary">
        <h2>Résumé</h2>
        <p>Total des contrôles: $TOTAL_CHECKS</p>
        <p>Contrôles réussis: $PASSED_CHECKS</p>
        <p>Contrôles échoués: $FAILED_CHECKS</p>
        <p>Taux de conformité: $(( (PASSED_CHECKS * 100) / TOTAL_CHECKS ))%</p>
    </div>
    <div class="section">
        <h2>Détails</h2>
        <pre>$(cat $LOG_FILE)</pre>
    </div>
</body>
</html>
EOF
    
    log_message "Rapport HTML généré: $HTML_REPORT"
}

# Génération du rapport
print_summary 