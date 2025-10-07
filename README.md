# VPN Logger v2.2.0

Système de monitoring et de logging des connexions VPN UniFi avec interface web multi-tenant.

## 🚀 Fonctionnalités

### Multi-tenant
- **Gestion de sociétés** : Support multi-tenant avec isolation complète des données
- **Routeurs par société** : Association des routeurs UniFi aux sociétés
- **Réseaux locaux configurables** : Détection automatique Local vs Remote par société
- **Gestion utilisateurs** : Attribution des utilisateurs à une ou plusieurs sociétés

### Authentification
- **Authentification locale** : Comptes utilisateurs avec mots de passe hashés (SHA256)
- **LDAP/Active Directory** : Authentification automatique via LDAP
  - Auto-provisioning des utilisateurs
  - Restriction par groupe (Domain Admins)
  - Configuration LDAP par société
  - Support SSL/TLS

### Rôles utilisateurs
- **super_admin** : Accès total multi-tenant
- **admin** : Gestion de sa/ses société(s)
- **viewer** : Lecture seule de sa/ses société(s)
- **demo** : Accès anonymisé pour démonstration

### Interface web
- **Dashboard temps réel** : Logs VPN en temps réel avec auto-refresh
- **Calendrier interactif** : Vue mensuelle et timeline journalière 24h
- **Page Statistiques** : Graphiques interactifs avec Chart.js (v2.2.0)
  - Graphiques de connexions par jour
  - Top utilisateurs et statistiques par société
  - Distribution des durées de session
  - Filtres par période (7j, 30j, 90j, personnalisée)
- **Filtrage avancé** : Par société, utilisateur, type d'événement
- **Export CSV** : Export des logs

### Administration
- **Gestion utilisateurs** : CRUD complet, attribution rôles et sociétés
- **Gestion sociétés** : CRUD avec configuration réseaux locaux et LDAP
- **Gestion routeurs** : Association routeurs UniFi aux sociétés

## 📋 Prérequis

- Python 3.7+
- Flask
- SQLite3
- python3-ldap (pour authentification LDAP)
- UniFi Controller/Dream Machine avec webhooks

## 🔧 Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/jckubiaczyk/vpn-logger.git
cd vpn-logger
```

### 2. Installer les dépendances

```bash
sudo apt update
sudo apt install -y python3-flask python3-ldap sqlite3
```

### 3. Initialiser la base de données

```bash
python3 init_db.py
python3 add_routers_table.py  # Si migration depuis v1.0
```

### 4. Configurer le service systemd

```bash
sudo cp vpn-logger.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable vpn-logger.service
sudo systemctl start vpn-logger.service
```

### 5. Configurer UniFi Webhooks

Dans votre UniFi Controller/Dream Machine :
1. Aller dans Settings → System → Advanced
2. Activer Webhooks
3. Ajouter l'URL : `http://votre-serveur/webhook/unifi`

## 🔐 Configuration LDAP

Pour activer l'authentification LDAP/Active Directory :

1. Connectez-vous avec un compte super_admin
2. Allez dans Admin → Sociétés
3. Éditez votre société
4. Configurez les paramètres LDAP :
   - Serveur LDAP
   - Port (389 ou 636 pour SSL)
   - Base DN
   - Template DN utilisateur
   - Groupe Admin (seuls les membres peuvent se connecter)

## 📊 Structure de la base de données

- **users** : Utilisateurs (local et LDAP)
- **companies** : Sociétés/tenants
- **user_companies** : Association many-to-many
- **router_devices** : Routeurs UniFi par société
- **vpn_events** : Événements VPN

## 🔒 Sécurité

- Authentification obligatoire pour toutes les pages
- Sessions Flask sécurisées
- Isolation multi-tenant stricte
- Validation des permissions par rôle
- Support LDAP/AD avec restriction par groupe

## 📝 Comptes par défaut

**Super Admin** : `admin` / `admin123`
**Demo** : `demo` / `demo`

⚠️ **Important** : Changez le mot de passe admin après la première connexion !

## 🗺️ Roadmap

### v2.2.0 ✅ (Complété - 2025-10-07)
- [x] Graphiques statistiques
  - Graphiques de connexions par jour/semaine/mois
  - Statistiques par utilisateur
  - Statistiques par société
  - Durées moyennes de session

### v2.2.1
- [ ] Dark mode
  - Thème sombre pour toutes les pages
  - Switch automatique ou manuel
  - Préférences utilisateur sauvegardées

### v2.2.2
- [ ] Export PDF rapports
  - Export des logs en PDF
  - Rapports statistiques PDF
  - Mise en page personnalisée

### v2.2.3
- [ ] Logs d'audit complets
  - Traçabilité des actions admin
  - Historique des modifications
  - Export des logs d'audit

### v2.2.4.1
- [ ] HTTPS/SSL - Configuration certificats
  - Support Let's Encrypt
  - Certificats auto-signés
  - Configuration Apache/Nginx

### v2.2.4.2
- [ ] HTTPS/SSL - Redirection et sécurité
  - Redirection HTTP → HTTPS
  - Configuration Flask SSL

### v2.2.4.3
- [ ] HTTPS/SSL - Durcissement
  - HSTS (HTTP Strict Transport Security)
  - Configuration headers sécurité
  - Tests SSL/TLS

### v2.3.0
- [ ] API REST complète (OpenAPI)
- [ ] Bcrypt pour mots de passe
- [ ] 2FA (TOTP)
- [ ] Notifications email/Slack

### v2.4.0
- [ ] Compatibilité mobile améliorée
  - Optimisation responsive de l'interface
  - Design mobile-first pour les graphiques
  - Adaptation des tableaux pour petits écrans
  - Menu hamburger pour la navigation
- [ ] Application mobile native
  - Étude de faisabilité (React Native / Flutter)
  - Prototype application iOS/Android
  - Notifications push pour alertes
  - Mode hors-ligne avec synchronisation

## 📄 License

Ce projet est sous licence propriétaire sys2lan.

## 👤 Auteur

**sys2lan**
- Développé par: Jean-Christophe KUBIACZYK
- GitHub: [@jckubiaczyk](https://github.com/jckubiaczyk)
- Email: jckubiaczyk@nidaplast.com

## 🏢 Société

**sys2lan** - Solutions informatiques et développement sur mesure
- Client: NIDAPLAST

## 🤝 Contribution

Projet développé par sys2lan pour NIDAPLAST. Pour toute question ou suggestion, contactez l'équipe de développement.
