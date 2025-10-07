# Guide d'Implémentation - Système d'Authentification Multi-Société

**Date**: 2025-10-06
**Version**: 1.0
**Statut**: En cours d'implémentation

---

## 📋 Table des matières

1. [Vue d'ensemble](#vue-densemble)
2. [Architecture de la base de données](#architecture-de-la-base-de-données)
3. [Rôles et permissions](#rôles-et-permissions)
4. [Flux d'authentification](#flux-dauthentification)
5. [Étapes d'implémentation](#étapes-dimplémentation)
6. [API Endpoints](#api-endpoints)
7. [Interfaces utilisateur](#interfaces-utilisateur)
8. [Tests et validation](#tests-et-validation)

---

## 🎯 Vue d'ensemble

### Objectifs
- ✅ Authentification locale (base de données)
- 🔜 Authentification LDAP (phase 2)
- ✅ Gestion multi-société
- ✅ 4 niveaux de rôles utilisateurs
- ✅ Mode démo avec données anonymisées

### Technologies
- **Backend**: Flask (Python)
- **Base de données**: SQLite
- **Sessions**: Flask-Session (cookies sécurisés)
- **Hash mot de passe**: SHA256 (phase 1) → bcrypt (phase 2)
- **Frontend**: HTML/CSS/JavaScript (vanilla)

---

## 🗄️ Architecture de la base de données

### Schéma actuel (✅ Migré)

```sql
-- Table des sociétés
CREATE TABLE companies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Table des utilisateurs
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT,
    role TEXT NOT NULL CHECK(role IN ('super_admin', 'admin', 'viewer', 'demo')),
    active INTEGER DEFAULT 1,
    auth_type TEXT DEFAULT 'local' CHECK(auth_type IN ('local', 'ldap')),
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_login TEXT
);

-- Table d'association utilisateur ↔ société (many-to-many)
CREATE TABLE user_companies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    company_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE,
    UNIQUE(user_id, company_id)
);

-- Ajout à la table existante vpn_events
ALTER TABLE vpn_events ADD COLUMN company_id INTEGER DEFAULT 1;
```

### Relations
```
users (1) ←→ (N) user_companies (N) ←→ (1) companies
                                              ↓
                                        vpn_events (N)
```

---

## 👥 Rôles et permissions

### 1. Super Admin
**Accès**: Toutes les sociétés
**Permissions**:
- ✅ Voir tous les événements VPN de toutes les sociétés
- ✅ Créer/modifier/supprimer des sociétés
- ✅ Créer/modifier/supprimer des utilisateurs
- ✅ Assigner des sociétés aux utilisateurs
- ✅ Modifier la configuration système
- ✅ Accès à `/admin` et `/admin/users`

### 2. Admin
**Accès**: Une ou plusieurs sociétés assignées
**Permissions**:
- ✅ Voir les événements VPN de ses sociétés assignées
- ✅ Créer/modifier des utilisateurs Viewer pour ses sociétés
- ✅ Modifier la configuration de ses sociétés
- ✅ Accès à `/admin` (limité à ses sociétés)
- ❌ Ne peut pas créer de sociétés
- ❌ Ne peut pas créer d'Admin ou Super Admin

### 3. Viewer
**Accès**: Une ou plusieurs sociétés assignées (lecture seule)
**Permissions**:
- ✅ Voir les événements VPN de ses sociétés assignées
- ✅ Exporter les données (CSV)
- ✅ Accès au calendrier
- ❌ Aucune modification
- ❌ Pas d'accès à `/admin`

### 4. Demo
**Accès**: Société avec le plus d'événements (automatique)
**Permissions**:
- ✅ Voir les événements VPN (données anonymisées)
- ✅ Accès au calendrier (données anonymisées)
- ❌ Aucune donnée personnelle visible (noms, IPs partiellement masquées)
- ❌ Pas d'export
- ❌ Pas d'accès à `/admin`

**Anonymisation**:
- Noms d'utilisateurs → `User_XXX` (hash consistant)
- IPs → `xxx.xxx.xxx.***` (dernier octet masqué)
- Durées et types VPN → conservés

---

## 🔐 Flux d'authentification

### 1. Login - Authentification locale

```
┌─────────────┐
│ GET /login  │
└──────┬──────┘
       │
       ▼
┌──────────────────────────┐
│ Formulaire login/password│
└──────┬───────────────────┘
       │
       ▼ POST /login
┌──────────────────────────┐
│ Validation credentials   │
│ - Hash password          │
│ - Vérifier en DB         │
│ - Vérifier active=1      │
└──────┬───────────────────┘
       │
       ├─ ✅ Valide
       │   └─> Créer session
       │       - session['user_id']
       │       - session['username']
       │       - session['role']
       │       - session['company_ids']
       │       └─> Redirect /
       │
       └─ ❌ Invalide
           └─> Retour login + erreur
```

### 2. Login - Authentification LDAP (Phase 2)

```
┌─────────────┐
│ GET /login  │
└──────┬──────┘
       │
       ▼
┌──────────────────────────┐
│ Formulaire login/password│
└──────┬───────────────────┘
       │
       ▼ POST /login
┌──────────────────────────┐
│ Détection auth_type      │
│ - Vérifier user en DB    │
└──────┬───────────────────┘
       │
       ├─ auth_type=local
       │   └─> Hash + DB check
       │
       └─ auth_type=ldap
           └─> LDAP bind
               - ldap://server:389
               - bind DN: cn={user},ou=users,dc=company,dc=com
               └─> Success? → Créer session
```

### 3. Protection des routes

```python
from functools import wraps

def login_required(f):
    """Décorateur : utilisateur doit être connecté"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    """Décorateur : utilisateur doit avoir un rôle spécifique"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in roles:
                abort(403)  # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Utilisation
@app.route('/admin')
@login_required
@role_required('super_admin', 'admin')
def admin():
    ...
```

---

## 🚀 Étapes d'implémentation

### ✅ Phase 0 : Migration DB (TERMINÉE)
- [x] Créer tables companies, users, user_companies
- [x] Ajouter company_id à vpn_events
- [x] Créer société par défaut "NIDAPLAST"
- [x] Créer users admin et demo

### 🔄 Phase 1 : Authentification de base (EN COURS)

#### Étape 1.1 : Créer le module auth.py
**Fichier**: `/var/www/html/vpn-logger/auth.py`

```python
import hashlib
import sqlite3
from datetime import datetime
from functools import wraps
from flask import session, redirect, url_for, abort

DB_PATH = '/var/www/html/vpn-logger/vpn_logs.db'

def hash_password(password):
    """Hash un mot de passe avec SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, password_hash):
    """Vérifie un mot de passe"""
    return hash_password(password) == password_hash

def authenticate_user(username, password):
    """Authentifie un utilisateur (local)"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''SELECT id, username, password_hash, role, active, auth_type
                 FROM users WHERE username = ?''', (username,))
    user = c.fetchone()
    conn.close()

    if not user:
        return None

    user_id, username, password_hash, role, active, auth_type = user

    # Vérifier si actif
    if not active:
        return None

    # Vérifier mot de passe (auth locale uniquement)
    if auth_type == 'local' and not verify_password(password, password_hash):
        return None

    # Récupérer les sociétés de l'utilisateur
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT company_id FROM user_companies WHERE user_id = ?''', (user_id,))
    company_ids = [row[0] for row in c.fetchall()]

    # Mettre à jour last_login
    c.execute('UPDATE users SET last_login = ? WHERE id = ?',
              (datetime.now().isoformat(), user_id))
    conn.commit()
    conn.close()

    return {
        'id': user_id,
        'username': username,
        'role': role,
        'company_ids': company_ids
    }

def login_required(f):
    """Décorateur : utilisateur doit être connecté"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    """Décorateur : utilisateur doit avoir un rôle spécifique"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_user_companies(user_id=None, role=None):
    """Retourne les IDs des sociétés accessibles à l'utilisateur"""
    if user_id is None:
        user_id = session.get('user_id')
        role = session.get('role')

    # Super admin voit tout
    if role == 'super_admin':
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id FROM companies')
        company_ids = [row[0] for row in c.fetchall()]
        conn.close()
        return company_ids

    # Demo voit la société avec le plus de logs
    if role == 'demo':
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''SELECT company_id, COUNT(*) as cnt
                     FROM vpn_events
                     GROUP BY company_id
                     ORDER BY cnt DESC
                     LIMIT 1''')
        result = c.fetchone()
        conn.close()
        return [result[0]] if result else []

    # Admin/Viewer voient leurs sociétés assignées
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT company_id FROM user_companies WHERE user_id = ?', (user_id,))
    company_ids = [row[0] for row in c.fetchall()]
    conn.close()
    return company_ids
```

#### Étape 1.2 : Ajouter les routes d'authentification dans app.py

```python
# Import au début de app.py
from flask import session, redirect, url_for
from auth import (authenticate_user, login_required, role_required,
                  get_user_companies, hash_password)
import secrets

# Configuration Flask
app.secret_key = secrets.token_hex(32)  # Clé secrète pour sessions

# Route de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = authenticate_user(username, password)

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['company_ids'] = user['company_ids']
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Identifiants incorrects')

    return render_template('login.html')

# Route de logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Protéger les routes existantes
@app.route('/')
@login_required
def index():
    # Filtrer par sociétés de l'utilisateur
    company_ids = get_user_companies()
    ...
```

#### Étape 1.3 : Créer la page de login
**Fichier**: `/var/www/html/vpn-logger/templates/login.html`

---

### 📋 Phase 2 : Filtrage par société

#### Étape 2.1 : Modifier les requêtes SQL

**Avant**:
```sql
SELECT * FROM vpn_events ORDER BY timestamp DESC LIMIT 100
```

**Après**:
```sql
SELECT * FROM vpn_events
WHERE company_id IN (?, ?, ...)  -- IDs des sociétés de l'utilisateur
ORDER BY timestamp DESC LIMIT 100
```

#### Étape 2.2 : Anonymisation pour mode demo

```python
def anonymize_event(event, role):
    """Anonymise un événement pour le mode demo"""
    if role != 'demo':
        return event

    # Anonymiser le nom d'utilisateur
    user_hash = hashlib.md5(event['user'].encode()).hexdigest()[:6]
    event['user'] = f'User_{user_hash}'

    # Masquer le dernier octet de l'IP
    if event['ip_address'] != 'unknown':
        parts = event['ip_address'].split('.')
        if len(parts) == 4:
            event['ip_address'] = f"{parts[0]}.{parts[1]}.{parts[2]}.***"

    return event
```

---

### 📋 Phase 3 : Interface admin

#### Pages à créer:
1. **`/admin/users`** - Gestion des utilisateurs (Super Admin seulement)
2. **`/admin/companies`** - Gestion des sociétés (Super Admin seulement)
3. **`/admin/assign`** - Attribution société ↔ utilisateur

#### Fonctionnalités:
- Liste des utilisateurs avec filtres
- Création/modification/suppression utilisateur
- Changement de mot de passe
- Activation/désactivation compte
- Attribution des sociétés

---

### 📋 Phase 4 : LDAP (Optionnel - Phase 2)

```python
import ldap

def authenticate_ldap(username, password, ldap_config):
    """Authentification LDAP"""
    try:
        server = ldap_config['server']
        base_dn = ldap_config['base_dn']

        ldap_conn = ldap.initialize(f'ldap://{server}')
        user_dn = f"cn={username},{base_dn}"

        ldap_conn.simple_bind_s(user_dn, password)
        return True
    except ldap.INVALID_CREDENTIALS:
        return False
    except Exception as e:
        print(f"LDAP error: {e}")
        return False
```

---

## 🔌 API Endpoints

### Authentification
- `GET /login` - Page de connexion
- `POST /login` - Authentification
- `GET /logout` - Déconnexion

### Utilisateurs (Super Admin uniquement)
- `GET /api/users` - Liste des utilisateurs
- `POST /api/users` - Créer un utilisateur
- `PUT /api/users/{id}` - Modifier un utilisateur
- `DELETE /api/users/{id}` - Supprimer un utilisateur

### Sociétés (Super Admin uniquement)
- `GET /api/companies` - Liste des sociétés
- `POST /api/companies` - Créer une société
- `PUT /api/companies/{id}` - Modifier une société
- `DELETE /api/companies/{id}` - Supprimer une société

### Événements VPN (Tous, filtré par rôle)
- `GET /api/events` - Liste des événements (filtrés par company_ids)
- `GET /api/stats` - Statistiques (filtrées par company_ids)

---

## 🎨 Interfaces utilisateur

### 1. Page de login (`login.html`)
- Formulaire username/password
- Message d'erreur
- Lien "Mot de passe oublié?" (Phase 2)
- Design cohérent avec l'application

### 2. Barre de navigation (mise à jour)
```html
<nav>
  <a href="/">Logs</a>
  <a href="/calendar">Calendrier</a>

  <!-- Visible seulement Admin/Super Admin -->
  {% if session.role in ['admin', 'super_admin'] %}
    <a href="/admin">Admin</a>
  {% endif %}

  <!-- Info utilisateur -->
  <div class="user-info">
    <span>{{ session.username }}</span>
    <span class="role-badge">{{ session.role }}</span>
    <a href="/logout">Déconnexion</a>
  </div>
</nav>
```

### 3. Sélecteur de société (Admin/Viewer multi-société)
```html
<!-- Si l'utilisateur a accès à plusieurs sociétés -->
{% if session.company_ids|length > 1 %}
<select id="company-filter" onchange="filterByCompany()">
  <option value="all">Toutes mes sociétés</option>
  {% for company in companies %}
    <option value="{{ company.id }}">{{ company.name }}</option>
  {% endfor %}
</select>
{% endif %}
```

---

## ✅ Tests et validation

### Tests manuels à effectuer

#### Test 1 : Authentification
- [ ] Login avec admin/admin123 → succès
- [ ] Login avec mauvais mot de passe → erreur
- [ ] Login avec utilisateur inexistant → erreur
- [ ] Login avec compte désactivé → erreur
- [ ] Logout → redirection vers login

#### Test 2 : Rôles
- [ ] Super Admin voit toutes les sociétés
- [ ] Admin voit uniquement ses sociétés
- [ ] Viewer peut voir mais pas modifier
- [ ] Demo voit données anonymisées

#### Test 3 : Filtrage
- [ ] Événements filtrés par company_id
- [ ] Stats filtrées par company_id
- [ ] Calendrier filtré par company_id

#### Test 4 : Sécurité
- [ ] Accès à /admin sans login → redirect login
- [ ] Accès à /admin en tant que Viewer → 403 Forbidden
- [ ] Session expire après X minutes
- [ ] Protection CSRF sur les formulaires

---

## 📊 Métriques de succès

- ✅ Migration DB sans perte de données
- ✅ Login fonctionnel pour tous les rôles
- ✅ Filtrage correct par société
- ✅ Anonymisation fonctionnelle en mode demo
- ✅ Interface admin opérationnelle
- ✅ Aucune régression sur fonctionnalités existantes

---

## 🔜 Prochaines étapes

1. **Immédiat** :
   - Créer auth.py
   - Créer login.html
   - Modifier app.py pour ajouter routes auth
   - Tester login/logout

2. **Court terme** :
   - Ajouter filtrage par société
   - Créer interface admin de base
   - Implémenter anonymisation demo

3. **Moyen terme** :
   - Interface admin complète
   - Changement de mot de passe
   - LDAP (si besoin)

---

## 📝 Notes importantes

- **Sécurité** : Changer immédiatement le mot de passe admin par défaut
- **Backup** : Faire une sauvegarde de vpn_logs.db avant toute modification
- **Testing** : Tester chaque fonctionnalité en environnement de dev avant production
- **Performance** : Les requêtes avec filtrage par company_id doivent rester rapides (index si besoin)

---

**Document créé le** : 2025-10-06
**Dernière mise à jour** : 2025-10-06
**Par** : Claude Code
