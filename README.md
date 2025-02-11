# Documentation CIS_audit.sh

## Description
Script d'audit et de durcissement de sécurité basé sur les recommandations CIS (Center for Internet Security) pour CentOS/RHEL 7.

## Fonctionnalités principales

### 1. Modes d'exécution
- **Mode Audit** (`-a`) : Vérifie la configuration sans faire de modifications
- **Mode Normal** : Vérifie et applique les corrections
- **Mode HTML** (`-h`) : Génère un rapport au format HTML

### 2. Catégories de contrôles
1. Configuration système initiale
   - Systèmes de fichiers
   - Mises à jour logicielles
   - Vérification d'intégrité
   - Configuration du démarrage

2. Services
   - Services inetd
   - Services spéciaux
   - Clients de service

3. Configuration réseau
   - Paramètres réseau
   - Pare-feu
   - Configuration TCP Wrappers

4. Journalisation et audit
   - Configuration auditd
   - Configuration rsyslog
   - Rotation des logs

5. Accès et authentification
   - Configuration cron
   - Configuration SSH
   - Configuration PAM
   - Comptes utilisateurs

6. Maintenance système
   - Permissions des fichiers
   - Paramètres utilisateurs et groupes

## Utilisation

### Installation
```bash
git clone [repository]
cd [directory]
chmod +x CIS_audit.sh
```

### Commandes principales
```bash
# Audit simple
sudo ./CIS_audit.sh -a

# Audit avec rapport HTML
sudo ./CIS_audit.sh -a -h

# Application des corrections
sudo ./CIS_audit.sh
```

### Fichiers générés
- Journal détaillé : `/var/log/cis_audit.log`
- Rapport d'audit : `/var/log/cis_report_[DATE].txt`
- Sauvegardes : `/root/cis_backup_[DATE]/`

## Fonctions principales

### check_filesystem_modules
Vérifie et désactive les systèmes de fichiers non nécessaires :
- cramfs
- freevxfs
- jffs2
- hfs
- hfsplus
- squashfs
- udf
- vfat

### check_partition
Vérifie les options de montage des partitions critiques :
- /tmp (nodev,nosuid,noexec)
- /var/tmp (nodev,nosuid,noexec)
- /home (nodev)
- /dev/shm (nodev,nosuid,noexec)

### check_service
Vérifie l'état des services critiques :
- Services à désactiver (xinetd, avahi, cups, etc.)
- Services à activer (auditd, crond, firewalld)

### check_file_permissions
Vérifie les permissions des fichiers sensibles :
- /etc/passwd (644)
- /etc/shadow (000)
- /etc/group (644)
- /etc/gshadow (000)
- /etc/ssh/sshd_config (600)

### check_sysctl
Vérifie les paramètres réseau sécurisés :
- Désactivation du forwarding IP
- Configuration des redirections ICMP
- Protection contre les attaques

### check_users
Vérifie la sécurité des comptes :
- UIDs dupliqués
- Mots de passe vides
- Entrées legacy
- UID 0 multiple

## Sécurité

### Sauvegardes
- Sauvegarde automatique des fichiers avant modification
- Horodatage des sauvegardes
- Conservation des sauvegardes pendant 30 jours

### Journalisation
- Journalisation détaillée des actions
- Horodatage des événements
- Statistiques de conformité

## Recommandations

1. Exécuter d'abord en mode audit (`-a`)
2. Examiner le rapport généré
3. Sauvegarder les configurations critiques
4. Appliquer les corrections progressivement
5. Vérifier le fonctionnement après modifications

## Notes importantes

- Nécessite les privilèges root
- Certaines modifications peuvent impacter les services
- Adapter les paramètres SSH selon vos besoins
- Configurer le serveur NTP approprié
- Personnaliser les règles du pare-feu

## Prérequis système

- CentOS/RHEL 7.x
- Accès root
- Espace disque minimum : 1 GB
- Paquets requis :
  - aide
  - tcp_wrappers
  - rsyslog
  - auditd
  - firewalld
  - libselinux

## Structure des rapports

### Format JSON
```json
{
  "hostname": "server_name",
  "date": "YYYY-MM-DD",
  "audit_results": {
    "total_checks": X,
    "passed": Y,
    "failed": Z,
    "compliance_rate": "XX%"
  },
  "sections": {
    "filesystem": [...],
    "services": [...],
    "network": [...],
    "audit": [...],
    "access": [...],
    "system": [...]
  }
}
```

### Format HTML
- Vue d'ensemble
- Résultats par section
- Graphiques de conformité
- Détails des échecs
- Recommandations de correction

## Dépannage

### Problèmes courants
1. **Erreur de permissions** : Vérifier l'exécution en tant que root
2. **Services non trouvés** : Installer les paquets manquants
3. **Échec de montage** : Vérifier les points de montage dans /etc/fstab
4. **Erreurs SELinux** : Vérifier le mode SELinux

### Commandes de diagnostic
```bash
# Vérifier les logs
tail -f /var/log/cis_audit.log

# État des services
systemctl status auditd firewalld

# Vérifier SELinux
sestatus
```

## Personnalisation

### Fichier de configuration
Créer `/etc/cis_audit.conf` pour personnaliser :
```ini
# Exemple de configuration
BACKUP_RETENTION=30
LOG_LEVEL=verbose
EXCLUDED_CHECKS=1.1.1.1,2.2.1.2
MAIL_ALERTS=admin@domain.com
```

### Exclusions
Pour exclure des contrôles spécifiques :
```bash
sudo ./CIS_audit.sh -a -e "1.1.1.1,2.2.1.2,3.1.1"
```

## Intégration

### Automatisation
Exemple de crontab pour des audits réguliers :
```bash
# Audit hebdomadaire
0 2 * * 0 /path/to/CIS_audit.sh -a -h > /dev/null 2>&1
```

### Surveillance
Compatible avec :
- Nagios
- Zabbix
- Prometheus
- ELK Stack

## Support

### Mise à jour
- Vérifier régulièrement les nouvelles versions CIS
- Mettre à jour le script selon les nouvelles recommandations
- Tester les modifications dans un environnement de test

### Ressources
- Documentation CIS : [lien]
- Forum de support : [lien]
- Base de connaissances : [lien] 