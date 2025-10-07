# Changelog VPN Logger

Tous les changements notables de ce projet seront documentés dans ce fichier.

## [2.2.0] - 2025-10-07

### 📊 Graphiques et Statistiques

#### Nouvelle page Statistiques
- **Page dédiée** : Nouvelle page `/statistics` avec interface graphique complète
- **Navigation** : Lien "📊 Statistiques" ajouté dans toutes les pages
- **Design cohérent** : Style unifié avec le reste de l'application

#### Cartes de statistiques
- **Total Connexions** : Nombre total de connexions sur la période
- **Utilisateurs Actifs** : Nombre d'utilisateurs différents
- **Durée Moyenne** : Durée moyenne des sessions
- **Sessions Actives** : Nombre de sessions en cours actuellement

#### Graphiques interactifs
- **📈 Connexions par jour** : Graphique en ligne montrant l'évolution des connexions
- **👥 Top 10 Utilisateurs** : Graphique en barres horizontales des utilisateurs les plus actifs
- **🏢 Connexions par Société** : Graphique en donut de répartition par société
- **⏱️ Durées de Session** : Graphique en barres des tranches de durée (0-1h, 1-2h, 2-4h, 4-8h, 8h+)
- **🌍 Type de Connexion** : Graphique en camembert Local vs Remote
- **📊 Connexions par Type VPN** : Graphique en barres par type VPN

#### Filtres avancés
- **Périodes prédéfinies** : 7, 30 ou 90 derniers jours
- **Période personnalisée** : Sélection de dates de début et fin
- **Filtre société** : Super_admin peut filtrer par société (dropdown dynamique)
- **Bouton actualiser** : Rechargement manuel des données

#### API Statistics
- **Endpoint** : `/api/statistics` avec support de paramètres
  - `period` : Nombre de jours (7, 30, 90)
  - `start_date` et `end_date` : Période personnalisée (format YYYY-MM-DD)
  - `company_id` : Filtrage par société (super_admin uniquement)
- **Permissions** : Respect des rôles (super_admin voit tout, autres rôles limités à leurs sociétés)
- **Mode démo** : Anonymisation automatique des noms d'utilisateur

#### Technologies
- **Chart.js 4.4.1** : Bibliothèque de graphiques via CDN
- **Graphiques responsive** : Adaptation automatique à la taille d'écran
- **Couleurs cohérentes** : Palette en accord avec la charte graphique (#667eea, #764ba2...)

---

## [2.1.0] - 2025-10-07

### 🔐 Authentification LDAP/Active Directory

#### Configuration LDAP par société
- **Interface admin** : Configuration LDAP dans les paramètres de société
  - Serveur LDAP (hostname/IP)
  - Port (389 par défaut, 636 pour SSL/TLS)
  - SSL/TLS activable
  - Base DN (ex: DC=nidaplast,DC=local)
  - Template DN utilisateur avec placeholder {username}
  - Groupe Admin (DN complet du groupe Domain Admins)
  - Bind DN et mot de passe optionnels pour service account

#### Authentification automatique
- **Auto-provisioning** : Création automatique des utilisateurs à la première connexion
- **Restriction** : Seuls les membres du groupe Domain Admins peuvent se connecter
- **Vérification groupes** : Recherche LDAP par sAMAccountName et userPrincipalName
- **Récupération email** : Email récupéré depuis attributs mail ou userPrincipalName
- **Support multi-sociétés** : Chaque société peut avoir sa propre config LDAP

#### Type d'authentification
- **Champ auth_type** : Distinction utilisateurs 'local' vs 'ldap'
- **Interface admin** :
  - Affichage "LDAP/Active Directory" pour les utilisateurs LDAP
  - Champ mot de passe masqué pour les utilisateurs LDAP
  - Type d'authentification non modifiable
- **Mise à jour email** : Email synchronisé depuis LDAP à chaque connexion

#### Flux d'authentification
1. Recherche utilisateur en base locale
2. Si utilisateur local : vérification password hash
3. Si utilisateur LDAP existant : authentification via LDAP de sa société
4. Si utilisateur inexistant : tentative LDAP sur toutes sociétés avec LDAP activé
5. Si authentification LDAP réussie et utilisateur est Domain Admin : création compte

#### Sécurité
- **Validation groupes** : Vérification membership dans groupe admin configuré
- **Session persistante** : Utilisateur reste associé à sa société
- **Gestion erreurs** : Logs d'erreurs LDAP sans exposer de détails sensibles

### 🔧 Améliorations techniques
- **Dépendance** : python3-ldap (version 3.4.3) installé via apt
- **Colonnes BDD** : 9 nouveaux champs LDAP dans table companies
- **API endpoints** : GET/POST/PUT /api/admin/companies supportent config LDAP

---

## [2.0.0] - 2025-10-07

### 🎉 Ajout majeur - Multi-tenant

#### Nouvelles tables
- **`companies`** : Gestion des sociétés/tenants
  - Nom, description, réseaux locaux (JSON)
- **`user_companies`** : Association utilisateurs ↔ sociétés (many-to-many)
- **`router_devices`** : Gestion des routeurs UniFi par société

#### Nouveaux rôles utilisateurs
- **super_admin** : Accès total multi-tenant
- **admin** : Gestion de sa/ses société(s)
- **viewer** : Lecture seule de sa/ses société(s)
- **demo** : Accès anonymisé pour démonstration

#### Fonctionnalités multi-tenant
- **Isolation des données** par société
- **Filtrage automatique** selon droits utilisateur
- **Sélecteur de société** dans interface (si plusieurs sociétés)
- **Assignation automatique** des événements VPN via routeur
- **Réseaux locaux par société** (détection 🏠 Local vs 🌍 Remote)

### ✨ Nouvelles fonctionnalités

#### Interface d'administration
- **Gestion utilisateurs**
  - CRUD complet (Créer, Lire, Modifier, Supprimer)
  - Attribution rôles
  - Assignation sociétés multiples (checkboxes)
  - Changement mot de passe
  - Activation/désactivation compte

- **Gestion sociétés**
  - CRUD complet
  - Configuration réseaux locaux (notation CIDR)
  - Statistiques : nombre utilisateurs, nombre événements

- **Gestion routeurs**
  - CRUD complet
  - Assignation société
  - Auto-création lors de nouveau `UNIFIhost` détecté
  - Réassignation automatique des événements lors du changement de société
  - Statistiques par routeur

#### Authentification
- **Page de connexion** avec design moderne
- **Sessions Flask** sécurisées
- **Hash SHA256** des mots de passe
- **Décorateurs** : `@login_required`, `@role_required`
- **Module auth.py** dédié

#### Filtrage et sélection
- **Sélecteur de société** intelligent :
  - Masqué pour demo et utilisateurs mono-société
  - Visible pour utilisateurs multi-sociétés
  - Filtrage temps réel dans calendrier
  - Rechargement page dans logs

#### Mode demo
- **Anonymisation automatique** :
  - Noms d'utilisateurs : `Leopold RICHE` → `L************`
  - Adresses IP : `192.168.30.100` → `192.168.xxx.xxx`
- **Accès lecture seule**
- **Affichage badge "demo"**

### 🔧 Améliorations

#### Détection Local/Remote
- **Par société** au lieu de global
- **Configuration CIDR** dans l'interface admin
- **Affichage icônes** : 🏠 Local, 🌍 Remote
- **Prise en compte company_id** dans `is_local_ip()`

#### API
- **Paramètre company_id** optionnel pour filtrage :
  - `/api/calendar/month?company_id=2`
  - `/api/calendar/day?company_id=2`
  - `/?company_id=2` (logs)
- **Validation des accès** : vérification des droits avant filtrage
- **Statistiques filtrées** : `/api/stats` respecte les droits

#### Interface
- **Info utilisateur** en header (nom + rôle)
- **Menu adaptatif** selon rôle
- **Bouton déconnexion** visible
- **Design cohérent** sur toutes les pages
- **Badges rôles** colorés
- **Messages flash** pour feedback utilisateur

### 🐛 Corrections

#### Variables conflictuelles
- **Ligne 489, 501, 517** : Conflit variable `session` (Flask vs VPN session)
  - Renommé en `user_session` pour éviter UnboundLocalError

#### Onglet Networks
- Supprimé l'onglet "Réseaux" obsolète (configuration globale)
- Bug du hardcode `192.168.0.0/24` dans `addNetwork()`
- Réseaux maintenant gérés par société

#### Sélecteur de société
- **Visibilité** : Condition corrigée pour affichage uniquement si > 1 société
- **Fonctionnalité** : Passage du `company_id` aux API
- **Initialisation** : Auto-sélection si 1 seule société

#### Réseaux locaux
- `is_local_ip()` ne recevait jamais le `company_id`
- SELECT SQL manquait le champ `company_id`
- Maintenant détection correcte par société

### 📊 Base de données

#### Migrations
- **Script** : `add_routers_table.py`
- **Nouvelles colonnes** :
  - `vpn_events.company_id` (défaut: 1)
  - `companies.local_networks` (JSON)
- **Clés étrangères** avec CASCADE

#### Données initiales
- **Utilisateur admin** (super_admin)
- **Société NIDAPLAST** (ID: 1, défaut)
- **Routeur UDM Pro SE** assigné à NIDAPLAST

### 🔐 Sécurité

#### Permissions
- **Filtrage systématique** des données selon société
- **Validation accès** : impossible d'accéder aux données d'autres sociétés
- **Protection suppression** :
  - User ID 1 (admin)
  - Company ID 1 (défaut)
- **Hash mots de passe** : SHA256 (à améliorer avec bcrypt)

#### Sessions
- **Secret key aléatoire** : 32 bytes hex
- **Cookies httponly**
- **Déconnexion automatique** en cas de session invalide

### 📝 Documentation

- **DOCUMENTATION.md** : Documentation complète du système
- **CHANGELOG.md** : Historique des versions (ce fichier)
- **Commentaires code** améliorés
- **Docstrings** sur fonctions principales

---

## [1.0.0] - 2025-10-05

### 🎉 Version initiale

#### Fonctionnalités de base
- **Réception webhooks UniFi** (CEF format)
- **Enregistrement événements** VPN (connect/disconnect)
- **Calcul durée sessions**
- **Dashboard logs** :
  - Liste des 100 derniers événements
  - Auto-refresh 10s
  - Export CSV
  - Recherche utilisateur
- **Calendrier** :
  - Vue mensuelle avec activité
  - Timeline journalière 24h
  - Sessions par utilisateur
  - Barres colorées local/remote

#### Base de données
- **Table vpn_events** : Stockage événements
- **SQLite** : Base de données simple

#### Configuration
- **config.json** : Réseaux locaux globaux
- **Service systemd** : Démarrage automatique

---

## Notes de migration

### De v1.0.0 à v2.0.0

**⚠️ Breaking changes**

1. **Nouvelles tables requises** :
   ```bash
   python3 add_routers_table.py
   ```

2. **Anciens événements** :
   - Assignés automatiquement à société ID 1
   - Si plusieurs sociétés, réassigner manuellement via admin

3. **Utilisateurs existants** :
   - Rôle `admin` → Nouveau rôle (super_admin, admin, viewer, demo)
   - Assigner sociétés via interface admin

4. **Configuration réseaux** :
   - Migration manuelle : `config.json` → Admin > Sociétés > Réseaux

5. **Webhook UniFi** :
   - Aucun changement nécessaire
   - Auto-création routeurs

---

---

## [2.2.2] - 2025-10-07

### 📄 Export PDF des Rapports

#### Rapports PDF générés
- **Rapport Utilisateur** (format portrait A4)
  - Statistiques de la période (connexions remote/local, durées)
  - Timeline graphique 24h avec marqueurs horaires
  - Détail par jour avec vue graphique
  - Logo de société inclus (si configuré)

- **Rapport Société** (format paysage A4)
  - Vue consolidée de tous les utilisateurs
  - Statistiques globales par société
  - Timelines individuelles par utilisateur et par jour
  - Format optimisé pour impression paysage

#### Fonctionnalités des rapports
- **Timeline graphique 24h** :
  - Marqueurs horaires : 00:00, 04:00, 08:00, 12:00, 16:00, 20:00, 24:00
  - Alignement précis avec grille CSS (grid-template-columns)
  - Barres de session positionnées selon l'heure exacte
  - Distinction visuelle : 🟢 Local (vert) / 🟠 Remote (orange)

- **Périodes supportées** :
  - Semaine (ISO 8601)
  - Mois
  - Trimestre
  - Année

- **Statistiques incluses** :
  - Nombre de connexions (remote/local séparées)
  - Durée totale et moyenne des sessions
  - Détail quotidien avec compteurs

#### Gestion des logos
- **Upload de logos** via interface d'administration
  - Formats : PNG, JPG, JPEG, GIF
  - Taille max : 2 MB
  - Stockage : `/static/logos/`

- **Affichage dans PDF** :
  - Logo centré en en-tête
  - Protocole `file://` pour WeasyPrint
  - Dimensions max : 200x80px (user) / 200x60px (company)

#### Routes API ajoutées
- `GET /api/reports/user/pdf` : Génère PDF rapport utilisateur
  - Paramètres : username, period_type, year, week, month, quarter, company_id

- `GET /api/reports/company/pdf` : Génère PDF rapport société
  - Paramètres : company_id, period_type, year, week, month, quarter

- `POST /api/admin/companies/<id>/logo` : Upload logo société
  - Validation format et taille
  - Suppression ancien logo si existant

- `DELETE /api/admin/companies/<id>/logo` : Suppression logo

#### Améliorations techniques
- **WeasyPrint 60.0+** : Génération PDF depuis HTML/CSS
- **Calcul positions timeline** :
  - start_percent = (heure_début / 24) × 100
  - duration_percent = (durée_heures / 24) × 100

- **Appels API internes** :
  - Utilisation de `requests` pour appeler `/api/reports/user` et `/api/reports/company`
  - Propagation des cookies de session pour authentification

- **Gestion robuste des données** :
  - `.get()` pour éviter KeyError sur clés optionnelles
  - Calcul des totaux depuis données quotidiennes
  - Support des sessions actives (end=None)

#### Corrections apportées
- **Alignement timeline** : Grid CSS au lieu de flexbox space-between
- **Structure données** : Adaptation aux différences API user vs company
  - User : remote_connections, local_connections, remote_duration, local_duration
  - Company : uniquement remote_connections et remote_duration
- **Chemins fichiers** : Préfixe `file://` pour images locales dans WeasyPrint
- **Calcul sessions** : Parser timestamps, calculer durée end-start ou utiliser champ duration

#### Dépendances système requises
```bash
apt-get install python3-cffi python3-brotli libpango-1.0-0 libpangoft2-1.0-0
pip3 install --break-system-packages weasyprint requests
```

#### Fichiers ajoutés
- `/templates/pdf/user_report.html` : Template rapport utilisateur
- `/templates/pdf/company_report.html` : Template rapport société
- `/static/logos/` : Répertoire stockage logos

---

## Roadmap

### v2.2.3 (Prochaine)
- [ ] **Logs d'audit complets**
  - Traçabilité des actions admin
  - Historique des modifications
  - Export des logs d'audit

### v2.2.4.1 (HTTPS/SSL - Configuration)
- [ ] **Configuration certificats**
  - Support Let's Encrypt
  - Certificats auto-signés
  - Configuration Apache/Nginx

### v2.2.4.2 (HTTPS/SSL - Redirection)
- [ ] **Redirection et sécurité**
  - Redirection HTTP → HTTPS
  - Configuration Flask SSL

### v2.2.4.3 (HTTPS/SSL - Durcissement)
- [ ] **Durcissement sécurité**
  - HSTS (HTTP Strict Transport Security)
  - Configuration headers sécurité
  - Tests SSL/TLS

### v2.3.0 (Futur)
- [ ] **API REST complète (OpenAPI)**
  - Documentation Swagger/OpenAPI
  - Endpoints standardisés REST
- [ ] **Bcrypt pour mots de passe**
  - Migration vers bcrypt
  - Politique de mot de passe renforcée
- [ ] **2FA (TOTP)**
  - Authentification à deux facteurs
  - Support Google Authenticator/Authy
- [ ] **Notifications email/Slack**
  - Alertes configurable
  - Webhooks personnalisés

### v2.4.0 (Vision Mobile)
- [ ] **Compatibilité mobile améliorée**
  - Optimisation responsive de l'interface
  - Design mobile-first pour les graphiques
  - Adaptation des tableaux pour petits écrans
  - Menu hamburger pour la navigation
- [ ] **Application mobile native**
  - Étude de faisabilité (React Native / Flutter)
  - Prototype application iOS/Android
  - Notifications push pour alertes
  - Mode hors-ligne avec synchronisation

### v3.0.0 (Vision Enterprise)
- [ ] PostgreSQL support
- [ ] Clustering/HA
- [ ] SSO (SAML, OAuth2)
- [ ] AI anomaly detection

---

*Dernière mise à jour : 2025-10-07*
