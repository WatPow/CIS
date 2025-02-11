# Script d'audit CIS pour CentOS 7

Ce script permet d'effectuer un audit de sécurité basé sur les recommandations CIS (Center for Internet Security) pour CentOS 7.

## Prérequis

- CentOS 7
- Droits root
- Au moins 1 Go d'espace disque disponible dans /var/log
- Les commandes suivantes doivent être installées :
  - awk
  - grep
  - stat
  - find
  - systemctl
  - ip
  - mount
  - df
  - ps
  - cut
  - tr
  - sort
  - uniq

## Structure du projet

```
.
├── main.sh                 # Script principal
├── sections/              # Dossier contenant les sections d'audit
│   ├── 01_initial_setup.sh    # Configuration initiale
│   ├── 02_services.sh         # Services
│   ├── 03_network.sh          # Configuration réseau
│   ├── 04_logging.sh          # Journalisation et audit
│   ├── 05_access.sh           # Accès et authentification
│   └── 06_system_maintenance.sh # Maintenance système
└── README.md              # Ce fichier
```

## Installation

1. Clonez ce dépôt :
```bash
git clone https://github.com/votre-repo/cis-audit.git
cd cis-audit
```

2. Rendez les scripts exécutables :
```bash
chmod +x main.sh
chmod +x sections/*.sh
```

## Utilisation

1. Exécutez le script en tant que root :
```bash
sudo ./main.sh
```

## Fichiers de sortie

Le script génère trois types de fichiers de sortie :

1. Journal détaillé (`/var/log/cis_audit.log`)
   - Contient tous les messages de log avec horodatage
   - Format : `[YYYY-MM-DD HH:MM:SS] Message`

2. Rapport texte (`/var/log/cis_audit_report.txt`)
   - Contient un résumé des vérifications effectuées
   - Liste les succès et échecs

3. Rapport HTML (`/var/log/cis_audit_report.html`)
   - Version formatée et interactive du rapport
   - Inclut des statistiques et graphiques
   - Facilement partageable

## Sections auditées

1. Configuration initiale
   - Système de fichiers
   - Partitions
   - AIDE
   - Boot sécurisé
   - Processus core dump
   - SELinux
   - Bannières d'avertissement

2. Services
   - Services inutiles
   - Services réseau
   - Protocoles spéciaux
   - Service X Window

3. Configuration réseau
   - Paramètres réseau
   - Pare-feu
   - TCP Wrappers
   - Protocoles IPv6
   - Interfaces sans fil

4. Journalisation et audit
   - Configuration rsyslog
   - Configuration auditd
   - Rotation des logs
   - Journaux d'authentification

5. Accès et authentification
   - Configuration cron et at
   - Configuration SSH
   - Configuration PAM
   - Politique de mots de passe
   - Contrôles de connexion root

6. Maintenance système
   - Permissions des fichiers
   - Fichiers utilisateur
   - Processus système
   - Tâches planifiées
   - Services inutiles

## Exemples d'utilisation

### Cas d'utilisation typiques

1. Audit initial d'un nouveau serveur :
```bash
sudo ./main.sh
```
Examinez le rapport HTML généré pour avoir une vue d'ensemble de la sécurité du serveur.

2. Audit périodique (via cron) :
```bash
# Ajoutez dans crontab :
0 2 * * 1 /chemin/vers/main.sh >/dev/null 2>&1
```

3. Audit avant une mise en production :
```bash
# Sauvegardez les logs actuels
sudo mv /var/log/cis_audit* /var/log/backup/
# Lancez l'audit
sudo ./main.sh
# Comparez avec les benchmarks requis
```

### Interprétation des résultats

Le script génère trois types de messages :
- `PASS` : Le contrôle est conforme aux recommandations CIS
- `FAIL` : Le contrôle n'est pas conforme et nécessite une correction
- `INFO` : Information générale ne nécessitant pas d'action

Exemple de sortie :
```
[2024-03-21 14:30:45] PASS: SELinux est en mode Enforcing
[2024-03-21 14:30:46] FAIL: Les permissions sur /etc/shadow sont incorrectes (actuel: 644, attendu: 000)
[2024-03-21 14:30:47] INFO: Pas de tâches cron pour root
```

### Résolution des problèmes courants

1. **Erreur "Permission denied"** :
   ```bash
   sudo chmod +x main.sh sections/*.sh
   sudo ./main.sh
   ```

2. **Logs manquants** :
   ```bash
   sudo mkdir -p /var/log
   sudo chmod 755 /var/log
   ```

3. **Commandes manquantes** :
   ```bash
   sudo yum install -y audit rsyslog
   ```

## Personnalisation

Vous pouvez personnaliser le script en modifiant les variables globales dans `main.sh` :

```bash
export MODE_AUDIT=1           # Mode d'audit (1) ou de correction (0)
export LOG_FILE="..."         # Chemin du fichier de log
export REPORT_FILE="..."      # Chemin du rapport texte
export HTML_REPORT="..."      # Chemin du rapport HTML
export GENERATE_HTML=1        # Générer (1) ou non (0) le rapport HTML
```

## Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :

1. Fork le projet
2. Créer une branche pour votre fonctionnalité
3. Commiter vos changements
4. Pousser vers la branche
5. Créer une Pull Request

## Licence

Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.

## Support

Pour toute question ou problème, veuillez :

1. Consulter les issues existantes
2. Créer une nouvelle issue si nécessaire
3. Fournir les logs et les détails de votre environnement 