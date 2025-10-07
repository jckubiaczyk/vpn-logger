# Documentation VPN Logger - Multi-tenant

## Vue d'ensemble

VPN Logger est une application web Flask pour la surveillance et le logging des connexions VPN UniFi avec support multi-tenant complet.

## Table des matières

1. [Architecture](#architecture)
2. [Base de données](#base-de-données)
3. [Authentification et rôles](#authentification-et-rôles)
4. [Multi-tenant](#multi-tenant)
5. [Fonctionnalités](#fonctionnalités)
6. [API Endpoints](#api-endpoints)
7. [Configuration](#configuration)
8. [Déploiement](#déploiement)

---

## Architecture

### Stack technique
- **Backend**: Python 3 + Flask
- **Base de données**: SQLite
- **Frontend**: HTML/CSS/JavaScript (Vanilla)
- **Serveur**: Gunicorn (production) ou Flask dev server

### Structure des fichiers
```
/var/www/html/vpn-logger/
├── app.py                 # Application principale Flask
├── auth.py                # Module d'authentification
├── config.json            # Configuration réseau (legacy)
├── vpn_logs.db           # Base de données SQLite
├── vpn_events.log        # Logs bruts des webhooks
├── templates/
│   ├── login.html        # Page de connexion
│   ├── index.html        # Dashboard principal (logs)
│   ├── calendar.html     # Vue calendrier
│   └── admin.html        # Interface d'administration
└── add_routers_table.py  # Script de migration DB
```

---

## Base de données

### Schéma

#### Table `users`
Gestion des utilisateurs du système.

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT,
    role TEXT NOT NULL,           -- super_admin, admin, viewer, demo
    active INTEGER DEFAULT 1,
    auth_type TEXT DEFAULT 'local', -- local ou ldap (futur)
    last_login TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
)
```

**Rôles disponibles:**
- `super_admin`: Accès total, gestion multi-tenant
- `admin`: Gestion de sa/ses société(s)
- `viewer`: Lecture seule de sa/ses société(s)
- `demo`: Accès lecture avec données anonymisées

#### Table `companies`
Gestion des sociétés (tenants).

```sql
CREATE TABLE companies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    local_networks TEXT DEFAULT '[]',  -- JSON: ["192.168.1.0/24"]
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
)
```

**Champ `local_networks`:**
- Format JSON: `["192.168.30.0/24", "192.168.10.0/24"]`
- Détermine quelles IPs sont considérées comme "locales" pour cette société
- Utilisé pour l'icône 🏠 Local vs 🌍 Remote

#### Table `user_companies`
Association many-to-many entre utilisateurs et sociétés.

```sql
CREATE TABLE user_companies (
    user_id INTEGER,
    company_id INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, company_id)
)
```

#### Table `router_devices`
Routeurs UniFi configurés.

```sql
CREATE TABLE router_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    unifi_host TEXT UNIQUE,        -- Valeur UNIFIhost du webhook
    alarm_id TEXT,
    company_id INTEGER NOT NULL,
    description TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
)
```

**Auto-détection:**
- Lorsqu'un webhook arrive avec un nouveau `UNIFIhost`, un routeur est créé automatiquement
- Assigné par défaut à la société ID 1 (NIDAPLAST)
- Peut être réassigné manuellement via l'interface admin

#### Table `vpn_events`
Événements VPN (connexions/déconnexions).

```sql
CREATE TABLE vpn_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    event_type TEXT,               -- vpn_connect, vpn_disconnect
    user TEXT,
    ip_address TEXT,
    vpn_type TEXT,                 -- WireGuard, L2TP, OpenVPN, etc.
    duration INTEGER,              -- Durée en secondes (pour disconnect)
    raw_data TEXT,                 -- JSON brut du webhook
    session_closed INTEGER DEFAULT 0,
    company_id INTEGER DEFAULT 1,
    FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
)
```

---

## Authentification et rôles

### Module `auth.py`

#### Fonctions principales

**`authenticate_user(username, password)`**
- Authentifie un utilisateur
- Vérifie le hash SHA256 du mot de passe
- Retourne les infos utilisateur + sociétés accessibles
- Met à jour `last_login`

**`get_user_by_id(user_id)`**
- Récupère un utilisateur par ID
- Inclut les sociétés accessibles selon le rôle:
  - `super_admin`: Toutes les sociétés
  - `demo`: Société avec le plus de logs (anonymisée)
  - Autres: Sociétés assignées via `user_companies`

**`get_user_companies()`**
- Retourne la liste des IDs de sociétés accessibles pour l'utilisateur en session
- Basé sur `session['user_id']`

**`is_demo_mode()`**
- Vérifie si l'utilisateur connecté est en mode demo
- Utilisé pour anonymiser les données

**`anonymize_username(username)`**
- Masque un nom d'utilisateur: `"John"` → `"J***"`

**`anonymize_ip(ip)`**
- Masque une IP: `"192.168.30.100"` → `"192.168.xxx.xxx"`

#### Décorateurs

**`@login_required`**
```python
@app.route('/dashboard')
@login_required
def dashboard():
    # Accessible uniquement si connecté
```

**`@role_required('super_admin', 'admin')`**
```python
@app.route('/admin')
@role_required('super_admin', 'admin')
def admin():
    # Accessible uniquement pour super_admin et admin
```

### Hiérarchie des rôles

```
super_admin (Accès total)
    ├── Gestion utilisateurs
    ├── Gestion sociétés
    ├── Gestion routeurs
    ├── Accès à toutes les données
    └── Configuration système

admin (Gestion limitée)
    ├── Gestion utilisateurs de ses sociétés
    ├── Consultation de ses sociétés
    ├── Accès aux données de ses sociétés
    └── Vue calendrier/logs

viewer (Lecture seule)
    ├── Consultation des données de ses sociétés
    ├── Vue calendrier/logs
    └── Export CSV

demo (Démo anonymisée)
    ├── Consultation données anonymisées
    ├── Pas d'accès admin
    └── Données en lecture seule
```

---

## Multi-tenant

### Principe

Chaque événement VPN est associé à une **société** (company) via le champ `company_id`.

### Assignation automatique

1. **Webhook reçu** → Extraction de `UNIFIhost`
2. **Recherche du routeur** dans `router_devices`
3. **Récupération du `company_id`** du routeur
4. **Enregistrement de l'événement** avec ce `company_id`

```python
# Extrait de app.py - webhook handler
unifi_host = params.get('UNIFIhost', 'unknown')
c.execute('SELECT company_id FROM router_devices WHERE unifi_host = ?', (unifi_host,))
router = c.fetchone()
company_id = router[0] if router else 1  # Défaut: société 1
```

### Filtrage des données

Tous les endpoints filtrent automatiquement selon les droits:

```python
user = get_user_by_id(session['user_id'])
company_ids = get_user_companies()

if user['role'] == 'super_admin':
    # Voir toutes les sociétés
    c.execute('SELECT * FROM vpn_events')
elif company_ids:
    # Voir uniquement les sociétés autorisées
    placeholders = ','.join('?' * len(company_ids))
    c.execute(f'SELECT * FROM vpn_events WHERE company_id IN ({placeholders})', company_ids)
else:
    # Aucune société = aucune donnée
    return []
```

### Sélecteur de société

**Affichage:**
- Masqué pour: `demo` ou utilisateurs avec 1 seule société
- Visible pour: Utilisateurs avec plusieurs sociétés

**Comportement:**
- `super_admin` / `admin`: "Toutes les sociétés" par défaut
- `viewer`: Première société présélectionnée
- Changement → Recharge les données filtrées

**Implémentation:**
```html
<select id="company-filter"
        style="{% if user.role == 'demo' or user.companies|length <= 1 %}display:none;{% endif %}"
        onchange="filterByCompany()">
    <option value="">Toutes les sociétés</option>
    {% for company in user.companies %}
    <option value="{{ company.id }}">{{ company.name }}</option>
    {% endfor %}
</select>
```

---

## Fonctionnalités

### 1. Webhook UniFi

**Endpoint:** `POST /webhook/unifi`

Reçoit les notifications CEF (Common Event Format) d'UniFi.

**Événements supportés:**
- `VPN Client Connected`
- `VPN Client Disconnected`

**Paramètres extraits:**
```json
{
  "app": "network",
  "name": "VPN Client Connected",
  "parameters": {
    "suser": "VPN - User Name",
    "src": "91.171.100.26",          // IP externe
    "UNIFIclientIp": "192.168.6.2",  // IP interne VPN
    "UNIFIvpnType": "wireguard-server",
    "UNIFIhost": "UDM Pro SE - Fresnes"
  }
}
```

**Traitement:**
1. Extraction des données
2. Identification du routeur (UNIFIhost)
3. Assignation société via routeur
4. Enregistrement dans `vpn_events`
5. Calcul durée pour déconnexions
6. Log brut dans `vpn_events.log`

### 2. Dashboard Logs

**Route:** `GET /`

**Fonctionnalités:**
- Liste des 100 derniers événements
- Filtrage par société (si plusieurs)
- Statistiques temps réel
- Auto-refresh 10s
- Export CSV
- Recherche utilisateur
- Filtre type événement

**Colonnes affichées:**
- Horodatage
- Type (CONNECT/DISCONNECT)
- Utilisateur
- IP
- Origine (Local 🏠 / Remote 🌍)
- VPN Type
- Durée

### 3. Calendrier

**Route:** `GET /calendar`

**Vue mensuelle:**
- Calendrier avec indicateur d'activité
- Nombre de connexions/jour
- Nombre d'utilisateurs uniques/jour
- Durée totale/jour
- Code couleur selon activité

**Vue journalière:**
- Timeline 24h
- Sessions par utilisateur
- Barres colorées:
  - Bleu: Local 🏠
  - Orange: Remote 🌍
  - Vert clignotant: En cours
- Durée totale par utilisateur
- Détails au survol

### 4. Administration

**Route:** `GET /admin`

**Accès:** `super_admin`, `admin`

**Onglets:**

#### Utilisateurs
- Création/modification/suppression
- Gestion mot de passe (SHA256)
- Attribution rôles
- Assignation sociétés (checkboxes)
- Activation/désactivation
- Affichage dernière connexion

**Règles:**
- Super admin: Gère tous les utilisateurs
- Admin: Gère les utilisateurs de ses sociétés
- Impossible de supprimer l'utilisateur ID 1 (admin)

#### Sociétés
- Création/modification/suppression
- Gestion réseaux locaux (CIDR)
- Compteur utilisateurs
- Compteur événements
- Description

**Réseaux locaux:**
- Format CIDR: `192.168.30.0/24`
- Validation côté client (regex)
- Ajout/suppression dynamique
- Stockage JSON dans DB

**Règles:**
- Impossible de supprimer la société ID 1 (défaut)
- Suppression en cascade des événements

#### Routeurs
- Liste des routeurs UniFi
- Assignation société
- Champs:
  - Nom (descriptif)
  - UniFi Host (identifiant unique)
  - Alarm ID (optionnel)
  - Société (dropdown)
  - Description
- Compteur événements par routeur
- Réassignation → Mise à jour automatique des événements

**Auto-création:**
- Nouveau `UNIFIhost` détecté → Routeur créé automatiquement
- Assigné à société ID 1 par défaut
- Peut être modifié ensuite

---

## API Endpoints

### Authentification

#### `POST /login`
Connexion utilisateur.

**Body:**
```json
{
  "username": "admin",
  "password": "password"
}
```

**Response:**
- 200: Redirection vers `/`
- 401: Identifiants invalides

#### `GET /logout`
Déconnexion et suppression session.

### Événements

#### `GET /api/events`
Liste des événements VPN.

**Paramètres:**
- `limit` (int, défaut: 100): Nombre max d'événements
- `type` (string): Filtre type (`connect`, `disconnect`)
- `company_id` (int): Filtre société (optionnel)

**Response:**
```json
[
  {
    "id": 1,
    "timestamp": "2025-10-06T13:07:45.513414",
    "event_type": "vpn_connect",
    "user": "Leopold RICHE",
    "ip_address": "91.171.100.26",
    "vpn_type": "WireGuard",
    "duration": null,
    "is_local": false
  }
]
```

**Filtrage automatique:**
- Demo: Données anonymisées
- Utilisateurs: Sociétés accessibles uniquement

#### `GET /api/stats`
Statistiques globales.

**Response:**
```json
{
  "total_events": 33,
  "events_by_type": {
    "vpn_connect": 17,
    "vpn_disconnect": 16
  },
  "last_connection": [
    "2025-10-06T17:20:32.227337",
    "Test User",
    "192.168.7.100"
  ]
}
```

### Calendrier

#### `GET /api/calendar/month`
Données mensuelles agrégées.

**Paramètres:**
- `year` (int): Année
- `month` (int): Mois (1-12)
- `company_id` (int): Filtre société (optionnel)

**Response:**
```json
{
  "2025-10-06": {
    "total_duration": 7854,
    "users": ["Leopold RICHE", "Maxime DURA"],
    "user_count": 2,
    "connections": 12,
    "disconnections": 12
  }
}
```

#### `GET /api/calendar/day`
Timeline journalière détaillée.

**Paramètres:**
- `date` (string): Date ISO (YYYY-MM-DD)
- `company_id` (int): Filtre société (optionnel)

**Response:**
```json
{
  "Leopold RICHE": [
    {
      "start": "2025-10-06T13:07:45.513414",
      "end": "2025-10-06T13:18:16.193220",
      "duration": 630,
      "ip": "91.171.100.26",
      "vpn_type": "WireGuard",
      "is_local": false
    }
  ]
}
```

### Administration

#### `GET /api/admin/users`
Liste utilisateurs avec sociétés.

**Accès:** `super_admin`, `admin`

**Response:**
```json
[
  {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "role": "super_admin",
    "active": 1,
    "auth_type": "local",
    "last_login": "2025-10-07T10:00:00",
    "companies": [
      {"id": 1, "name": "NIDAPLAST"}
    ]
  }
]
```

#### `POST /api/admin/users`
Créer un utilisateur.

**Body:**
```json
{
  "username": "newuser",
  "password": "secret",
  "email": "user@example.com",
  "role": "viewer",
  "auth_type": "local",
  "active": 1,
  "company_ids": [1, 2]
}
```

#### `PUT /api/admin/users/<id>`
Modifier un utilisateur.

**Body:** Idem POST (password optionnel)

#### `DELETE /api/admin/users/<id>`
Supprimer un utilisateur.

**Protection:** Impossible de supprimer user ID 1

---

#### `GET /api/admin/companies`
Liste sociétés avec stats.

**Response:**
```json
[
  {
    "id": 1,
    "name": "NIDAPLAST",
    "description": "Société principale",
    "local_networks": "[\"192.168.30.0/24\"]",
    "user_count": 2,
    "event_count": 31
  }
]
```

#### `POST /api/admin/companies`
Créer une société.

**Body:**
```json
{
  "name": "Nouvelle Société",
  "description": "Description",
  "local_networks": "[\"192.168.50.0/24\"]"
}
```

#### `PUT /api/admin/companies/<id>`
Modifier une société.

#### `DELETE /api/admin/companies/<id>`
Supprimer une société.

**Protection:** Impossible de supprimer société ID 1

---

#### `GET /api/admin/routers`
Liste routeurs avec stats.

**Response:**
```json
[
  {
    "id": 1,
    "name": "UDM Pro SE - Fresnes",
    "unifi_host": "UDM Pro SE - Fresnes",
    "alarm_id": "0199b8f8-31d0-7a22-bd3f-fa94e3ede1d7",
    "company_id": 1,
    "company_name": "NIDAPLAST",
    "description": "Routeur principal",
    "event_count": 31
  }
]
```

#### `POST /api/admin/routers`
Créer un routeur.

**Body:**
```json
{
  "name": "UDM Pro - Site 2",
  "unifi_host": "UDM Pro - Site 2",
  "alarm_id": "xxx-yyy-zzz",
  "company_id": 2,
  "description": "Routeur site 2"
}
```

#### `PUT /api/admin/routers/<id>`
Modifier un routeur.

**Particularité:** Si `company_id` change, tous les événements du routeur sont réassignés automatiquement.

```python
# Réassigner tous les événements
c.execute('UPDATE vpn_events SET company_id = ? WHERE company_id = (SELECT company_id FROM router_devices WHERE id = ?)',
          (new_company_id, router_id))
```

#### `DELETE /api/admin/routers/<id>`
Supprimer un routeur.

---

## Configuration

### Réseaux locaux

**Ancienne méthode (legacy):**
Fichier `config.json`:
```json
{
  "local_networks": [
    "192.168.30.0/24",
    "192.168.10.0/24"
  ]
}
```

**Nouvelle méthode (multi-tenant):**
Stocké dans `companies.local_networks` (JSON).

**Fonction `is_local_ip(ip, company_id)`:**
1. Si `company_id` fourni → Vérifier réseaux de la société
2. Sinon → Fallback sur config.json (compatibilité)

```python
def is_local_ip(ip_str, company_id=None):
    ip = ipaddress.ip_address(ip_str)

    if company_id:
        # Vérifier réseaux de la société
        networks = json.loads(get_company_networks(company_id))
        for network_str in networks:
            if ip in ipaddress.ip_network(network_str):
                return True

    # Fallback config globale
    config = load_config()
    for network_str in config['local_networks']:
        if ip in ipaddress.ip_network(network_str):
            return True

    return False
```

### Variables d'environnement

```bash
# Chemin base de données
DB_PATH=/var/www/html/vpn-logger/vpn_logs.db

# Port Flask
FLASK_PORT=80

# Secret key (auto-généré)
SECRET_KEY=auto
```

---

## Déploiement

### Service systemd

**Fichier:** `/etc/systemd/system/vpn-logger.service`

```ini
[Unit]
Description=VPN Logger Web Application
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/html/vpn-logger
ExecStart=/usr/bin/python3 /var/www/html/vpn-logger/app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

**Commandes:**
```bash
# Démarrer
sudo systemctl start vpn-logger

# Arrêter
sudo systemctl stop vpn-logger

# Redémarrer
sudo systemctl restart vpn-logger

# Statut
sudo systemctl status vpn-logger

# Logs
sudo journalctl -u vpn-logger -f
```

### Configuration UniFi

**Notifications → Webhooks:**
1. URL: `http://IP_SERVER/webhook/unifi`
2. Événements:
   - VPN Client Connected
   - VPN Client Disconnected
3. Format: CEF

### Permissions

```bash
# Propriétaire fichiers
sudo chown -R www-data:www-data /var/www/html/vpn-logger

# Permissions
sudo chmod 755 /var/www/html/vpn-logger
sudo chmod 644 /var/www/html/vpn-logger/*.py
sudo chmod 666 /var/www/html/vpn-logger/vpn_logs.db
```

### Backup

**Base de données:**
```bash
# Backup
sqlite3 vpn_logs.db .dump > backup_$(date +%Y%m%d).sql

# Restore
sqlite3 vpn_logs_new.db < backup_20251007.sql
```

---

## Sécurité

### Mots de passe

- Hashing: **SHA256** (basique, à améliorer avec bcrypt)
- Stockage: `users.password_hash`
- Aucun mot de passe en clair

### Sessions

- Flask session sécurisée
- Secret key aléatoire (32 bytes hex)
- Cookie httponly

### Permissions

- Tous les endpoints protégés par `@login_required`
- Endpoints admin: `@role_required`
- Filtrage automatique des données selon société

### Logs

- Webhooks bruts: `vpn_events.log`
- Erreurs: `journalctl -u vpn-logger`

---

## Évolutions futures

### Planifié
- [ ] LDAP/Active Directory
- [ ] Logs d'audit (qui a modifié quoi)
- [ ] Statistiques avancées par utilisateur
- [ ] Notifications email/Slack
- [ ] Export PDF rapports
- [ ] API REST complète (OpenAPI)
- [ ] Bcrypt pour mots de passe
- [ ] 2FA (TOTP)

### En considération
- [ ] Dark mode
- [ ] Graphiques (Chart.js)
- [ ] Recherche avancée
- [ ] Gestion quotas VPN
- [ ] Alertes déconnexions anormales
- [ ] Mobile app

---

## Support

**Fichiers de log:**
- Application: `journalctl -u vpn-logger`
- Webhooks: `/var/www/html/vpn-logger/vpn_events.log`

**Debug mode:**
```python
# Dans app.py
app.run(host='0.0.0.0', port=80, debug=True)
```

**Utilisateur par défaut:**
- Username: `admin`
- Password: `admin`
- Rôle: `super_admin`

---

*Documentation générée le 2025-10-07*
