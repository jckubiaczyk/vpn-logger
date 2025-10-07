#!/usr/bin/env python3
"""
Site Web de Logs VPN UniFi
Reçoit les webhooks UniFi pour les connexions/déconnexions VPN
"""

from flask import Flask, request, render_template, jsonify, redirect, url_for, session, flash
from datetime import datetime
import json
import sqlite3
import os
import ipaddress
import secrets

# Import auth module
from auth import (
    authenticate_user, get_user_by_id, login_required, role_required,
    get_user_companies, is_demo_mode, anonymize_username, anonymize_ip
)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Clé secrète pour les sessions

# Configuration
APP_VERSION = '2.1.0'
DB_PATH = '/var/www/html/vpn-logger/vpn_logs.db'
LOG_FILE = '/var/www/html/vpn-logger/vpn_events.log'
CONFIG_FILE = '/var/www/html/vpn-logger/config.json'

# Rendre la version disponible dans tous les templates
@app.context_processor
def inject_version():
    return {'app_version': APP_VERSION}

# Charger la configuration
def load_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except:
        return {'local_networks': ['192.168.30.0/24', '192.168.10.0/24']}

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def is_local_ip(ip_str, company_id=None):
    """Vérifie si une IP est dans un réseau local configuré pour une société"""
    try:
        ip = ipaddress.ip_address(ip_str)

        if company_id:
            # Vérifier les réseaux spécifiques à la société
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('SELECT local_networks FROM companies WHERE id = ?', (company_id,))
            result = c.fetchone()
            conn.close()

            if result and result[0]:
                networks = json.loads(result[0])
                for network_str in networks:
                    network = ipaddress.ip_network(network_str, strict=False)
                    if ip in network:
                        return True

        # Fallback sur la config globale (pour compatibilité)
        config = load_config()
        for network_str in config.get('local_networks', []):
            network = ipaddress.ip_network(network_str, strict=False)
            if ip in network:
                return True
        return False
    except:
        return False

# Initialiser la base de données
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS vpn_events
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  event_type TEXT,
                  user TEXT,
                  ip_address TEXT,
                  vpn_type TEXT,
                  duration INTEGER,
                  raw_data TEXT,
                  session_closed INTEGER DEFAULT 0)''')
    conn.commit()
    conn.close()

# Routes d'authentification
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Si déjà connecté, rediriger vers l'accueil
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Veuillez renseigner tous les champs', 'error')
            return render_template('login.html')

        user = authenticate_user(username, password)

        if user:
            # Créer la session
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f'Bienvenue {user["username"]} !', 'success')
            return redirect(url_for('index'))
        else:
            flash('Nom d\'utilisateur ou mot de passe incorrect', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Vous avez été déconnecté', 'success')
    return redirect(url_for('login'))

# Webhook endpoint pour UniFi (pas d'authentification nécessaire)
@app.route('/webhook/unifi', methods=['POST'])
def unifi_webhook():
    try:
        data = request.get_json()

        # Log brut
        with open(LOG_FILE, 'a') as f:
            f.write(f"{datetime.now().isoformat()} - {json.dumps(data)}\n")

        # Parser les données UniFi (format CEF)
        params = data.get('parameters', {})

        # Event type
        event_name = data.get('name', 'unknown')
        if 'Connected' in event_name:
            event_type = 'vpn_connect'
        elif 'Disconnected' in event_name:
            event_type = 'vpn_disconnect'
        else:
            event_type = data.get('event', event_name)

        # User
        user = params.get('suser', data.get('user', 'unknown'))
        if 'VPN - ' in user:
            user = user.replace('VPN - ', '')

        # IP Address
        ip_address = params.get('src', params.get('UNIFIclientIp', data.get('ip', 'unknown')))

        # VPN Type
        vpn_type = params.get('UNIFIvpnType', data.get('vpn_type', 'unknown'))
        if vpn_type == 'wireguard-server':
            vpn_type = 'WireGuard'
        elif vpn_type == 'l2tp-server':
            vpn_type = 'L2TP'
        elif vpn_type == 'openvpn-server':
            vpn_type = 'OpenVPN'

        # Router/Device identification
        unifi_host = params.get('UNIFIhost', 'unknown')
        alarm_id = data.get('alarm_id', None)

        # Déterminer la société basée sur le routeur
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        company_id = 1  # Par défaut: NIDAPLAST

        # Chercher le routeur dans la base
        if unifi_host != 'unknown':
            c.execute('SELECT company_id FROM router_devices WHERE unifi_host = ?', (unifi_host,))
            router = c.fetchone()
            if router:
                company_id = router[0]
            else:
                # Créer automatiquement le routeur avec société par défaut
                try:
                    c.execute('''INSERT INTO router_devices (name, unifi_host, alarm_id, company_id, description)
                                 VALUES (?, ?, ?, ?, ?)''',
                              (unifi_host, unifi_host, alarm_id, 1, 'Auto-créé lors de la réception du webhook'))
                    conn.commit()
                    app.logger.info(f"Nouveau routeur créé: {unifi_host}")
                except:
                    pass  # Si erreur (doublon), on continue avec company_id = 1

        # Traiter selon le type d'événement
        if event_type == 'vpn_connect':
            # Connexion : insérer directement
            c.execute('''INSERT INTO vpn_events
                         (timestamp, event_type, user, ip_address, vpn_type, duration, raw_data, session_closed, company_id)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (datetime.now().isoformat(), event_type, user, ip_address,
                       vpn_type, None, json.dumps(data), 0, company_id))

        elif event_type == 'vpn_disconnect':
            # Chercher la dernière connexion ACTIVE (non fermée) de cet utilisateur
            c.execute('''SELECT id, timestamp, ip_address FROM vpn_events
                         WHERE user = ? AND event_type = 'vpn_connect' AND session_closed = 0
                         ORDER BY timestamp DESC LIMIT 1''', (user,))
            last_connect = c.fetchone()

            duration = None
            if last_connect:
                connect_id = last_connect[0]
                connect_time = datetime.fromisoformat(last_connect[1])
                disconnect_time = datetime.now()
                duration = int((disconnect_time - connect_time).total_seconds())

                # Si pas d'IP dans la déconnexion, utiliser celle de la connexion
                if ip_address == 'unknown':
                    ip_address = last_connect[2]

                # Marquer la connexion comme fermée
                c.execute('''UPDATE vpn_events SET session_closed = 1 WHERE id = ?''', (connect_id,))

            # Insérer l'événement de déconnexion
            c.execute('''INSERT INTO vpn_events
                         (timestamp, event_type, user, ip_address, vpn_type, duration, raw_data, session_closed, company_id)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (datetime.now().isoformat(), event_type, user, ip_address,
                       vpn_type, duration, json.dumps(data), 1, company_id))

        conn.commit()
        conn.close()

        return jsonify({'status': 'success'}), 200

    except Exception as e:
        app.logger.error(f"Error processing webhook: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Page d'accueil - Affichage des logs
@app.route('/')
@login_required
def index():
    filter_company_id = request.args.get('company_id', type=int)  # Filtrage optionnel

    user = get_user_by_id(session['user_id'])
    company_ids = get_user_companies()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Si un filtre de société est demandé, vérifier que l'utilisateur y a accès
    if filter_company_id:
        if user['role'] == 'super_admin' or filter_company_id in company_ids:
            # Filtrer uniquement cette société
            c.execute('''SELECT * FROM vpn_events
                         WHERE company_id = ?
                         ORDER BY timestamp DESC LIMIT 100''', (filter_company_id,))
        else:
            # Pas d'accès à cette société
            events = []
            conn.close()
            return render_template('index.html', events=events, user=user)
    else:
        # Pas de filtre : afficher selon les droits
        if user['role'] == 'super_admin':
            # Super admin voit tout
            c.execute('''SELECT * FROM vpn_events
                         ORDER BY timestamp DESC LIMIT 100''')
        elif company_ids:
            # Admin/Viewer/Demo : filtrer par sociétés accessibles
            placeholders = ','.join('?' * len(company_ids))
            c.execute(f'''SELECT * FROM vpn_events
                          WHERE company_id IN ({placeholders})
                          ORDER BY timestamp DESC LIMIT 100''', company_ids)
        else:
            # Aucune société accessible
            events = []
            conn.close()
            return render_template('index.html', events=events, user=user)

    events = c.fetchall()

    # Récupérer les sociétés pour le sélecteur
    # Super admin voit toutes les sociétés, autres voient leurs sociétés assignées
    user['companies'] = get_user_by_id(user['id'])['companies']

    conn.close()

    return render_template('index.html', events=events, user=user)

# Page calendrier
@app.route('/calendar')
@login_required
def calendar():
    user = get_user_by_id(session['user_id'])
    # Récupérer les sociétés pour le sélecteur
    # Super admin voit toutes les sociétés, autres voient leurs sociétés assignées
    user['companies'] = get_user_by_id(user['id'])['companies']
    return render_template('calendar.html', user=user)

# API pour récupérer les logs en JSON
@app.route('/api/events')
@login_required
def get_events():
    limit = request.args.get('limit', 100, type=int)
    event_type = request.args.get('type', None)

    user = get_user_by_id(session['user_id'])
    company_ids = get_user_companies()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Construire la requête avec filtrage par société
    if user['role'] == 'super_admin':
        # Super admin voit tout
        if event_type:
            c.execute('''SELECT * FROM vpn_events
                         WHERE event_type = ?
                         ORDER BY timestamp DESC LIMIT ?''', (event_type, limit))
        else:
            c.execute('''SELECT * FROM vpn_events
                         ORDER BY timestamp DESC LIMIT ?''', (limit,))
    elif company_ids:
        # Admin/Viewer/Demo : filtrer par sociétés accessibles
        placeholders = ','.join('?' * len(company_ids))
        if event_type:
            query = f'''SELECT * FROM vpn_events
                        WHERE event_type = ? AND company_id IN ({placeholders})
                        ORDER BY timestamp DESC LIMIT ?'''
            c.execute(query, [event_type] + company_ids + [limit])
        else:
            query = f'''SELECT * FROM vpn_events
                        WHERE company_id IN ({placeholders})
                        ORDER BY timestamp DESC LIMIT ?'''
            c.execute(query, company_ids + [limit])
    else:
        # Aucune société accessible
        conn.close()
        return jsonify([])

    events = c.fetchall()
    conn.close()

    # Convertir en JSON
    demo_mode = is_demo_mode()
    result = []
    for event in events:
        ip_address = event[4]
        username = event[3]
        company_id = event[9] if len(event) > 9 else None

        # Anonymiser si mode demo
        if demo_mode:
            username = anonymize_username(username)
            if ip_address != 'unknown':
                ip_address = anonymize_ip(ip_address)

        result.append({
            'id': event[0],
            'timestamp': event[1],
            'event_type': event[2],
            'user': username,
            'ip_address': ip_address,
            'vpn_type': event[5],
            'duration': event[6],
            'is_local': is_local_ip(event[4], company_id) if event[4] != 'unknown' else False
        })

    return jsonify(result)

# API pour données calendrier (stats mensuelles)
@app.route('/api/calendar/month')
@login_required
def get_calendar_month():
    year = request.args.get('year', datetime.now().year, type=int)
    month = request.args.get('month', datetime.now().month, type=int)
    filter_company_id = request.args.get('company_id', type=int)  # Filtrage optionnel

    user = get_user_by_id(session['user_id'])
    company_ids = get_user_companies()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Événements du mois
    start_date = f"{year}-{month:02d}-01"
    if month == 12:
        end_date = f"{year+1}-01-01"
    else:
        end_date = f"{year}-{month+1:02d}-01"

    # Si un filtre de société est demandé, vérifier que l'utilisateur y a accès
    if filter_company_id:
        if user['role'] == 'super_admin' or filter_company_id in company_ids:
            # Filtrer uniquement cette société
            c.execute('''SELECT timestamp, event_type, user, duration
                         FROM vpn_events
                         WHERE timestamp >= ? AND timestamp < ? AND company_id = ?
                         ORDER BY timestamp''', (start_date, end_date, filter_company_id))
        else:
            # Pas d'accès à cette société
            conn.close()
            return jsonify({})
    else:
        # Pas de filtre : afficher selon les droits
        if user['role'] == 'super_admin':
            # Super admin voit tout
            c.execute('''SELECT timestamp, event_type, user, duration
                         FROM vpn_events
                         WHERE timestamp >= ? AND timestamp < ?
                         ORDER BY timestamp''', (start_date, end_date))
        elif company_ids:
            # Admin/Viewer/Demo : filtrer par sociétés accessibles
            placeholders = ','.join('?' * len(company_ids))
            query = f'''SELECT timestamp, event_type, user, duration
                        FROM vpn_events
                        WHERE timestamp >= ? AND timestamp < ? AND company_id IN ({placeholders})
                        ORDER BY timestamp'''
            c.execute(query, [start_date, end_date] + company_ids)
        else:
            # Aucune société accessible
            conn.close()
            return jsonify({})

    events = c.fetchall()
    conn.close()

    # Agréger par jour
    demo_mode = is_demo_mode()
    daily_stats = {}
    for event in events:
        timestamp = event[0]
        event_type = event[1]
        user = event[2]
        duration = event[3] or 0

        # Anonymiser si mode demo
        if demo_mode:
            user = anonymize_username(user)

        day = timestamp.split('T')[0]

        if day not in daily_stats:
            daily_stats[day] = {
                'total_duration': 0,
                'users': set(),
                'connections': 0,
                'disconnections': 0
            }

        if event_type == 'vpn_disconnect':
            daily_stats[day]['total_duration'] += duration
            daily_stats[day]['disconnections'] += 1
        elif event_type == 'vpn_connect':
            daily_stats[day]['connections'] += 1

        daily_stats[day]['users'].add(user)

    # Convertir sets en listes
    result = {}
    for day, stats in daily_stats.items():
        result[day] = {
            'total_duration': stats['total_duration'],
            'users': list(stats['users']),
            'user_count': len(stats['users']),
            'connections': stats['connections'],
            'disconnections': stats['disconnections']
        }

    return jsonify(result)

# API pour timeline journalière (24h)
@app.route('/api/calendar/day')
@login_required
def get_calendar_day():
    date = request.args.get('date', datetime.now().strftime('%Y-%m-%d'))
    filter_company_id = request.args.get('company_id', type=int)  # Filtrage optionnel

    user = get_user_by_id(session['user_id'])
    company_ids = get_user_companies()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Si un filtre de société est demandé, vérifier que l'utilisateur y a accès
    if filter_company_id:
        if user['role'] == 'super_admin' or filter_company_id in company_ids:
            # Filtrer uniquement cette société
            c.execute('''SELECT timestamp, event_type, user, ip_address, vpn_type, duration, company_id
                         FROM vpn_events
                         WHERE timestamp >= ? AND timestamp < date(?, '+1 day') AND company_id = ?
                         ORDER BY timestamp''', (date, date, filter_company_id))
        else:
            # Pas d'accès à cette société
            conn.close()
            return jsonify({})
    else:
        # Pas de filtre : afficher selon les droits
        if user['role'] == 'super_admin':
            # Super admin voit tout
            c.execute('''SELECT timestamp, event_type, user, ip_address, vpn_type, duration, company_id
                         FROM vpn_events
                         WHERE timestamp >= ? AND timestamp < date(?, '+1 day')
                         ORDER BY timestamp''', (date, date))
        elif company_ids:
            # Admin/Viewer/Demo : filtrer par sociétés accessibles
            placeholders = ','.join('?' * len(company_ids))
            query = f'''SELECT timestamp, event_type, user, ip_address, vpn_type, duration, company_id
                        FROM vpn_events
                        WHERE company_id IN ({placeholders})
                          AND timestamp >= ? AND timestamp < date(?, '+1 day')
                        ORDER BY timestamp'''
            c.execute(query, company_ids + [date, date])
        else:
            # Aucune société accessible
            events = []
            conn.close()
            return jsonify({})

    events = c.fetchall()
    conn.close()

    # Organiser par utilisateur avec périodes de connexion
    demo_mode = is_demo_mode()
    user_sessions = {}
    active_connections = {}  # Suivi des connexions actives

    for event in events:
        timestamp = event[0]
        event_type = event[1]
        user = event[2]
        ip_address = event[3]
        vpn_type = event[4]
        duration = event[5]
        company_id = event[6] if len(event) > 6 else None

        if user not in user_sessions:
            user_sessions[user] = []

        if event_type == 'vpn_connect':
            # Début d'une session
            active_connections[user] = {
                'start': timestamp,
                'ip': ip_address,
                'vpn_type': vpn_type,
                'is_local': is_local_ip(ip_address, company_id) if ip_address != 'unknown' else False
            }
        elif event_type == 'vpn_disconnect' and user in active_connections:
            # Fin d'une session
            user_session = active_connections[user]
            user_sessions[user].append({
                'start': user_session['start'],
                'end': timestamp,
                'duration': duration,
                'ip': user_session['ip'],
                'vpn_type': user_session['vpn_type'],
                'is_local': user_session['is_local']
            })
            del active_connections[user]

    # Ajouter les sessions encore actives
    for user, user_session in active_connections.items():
        user_sessions[user].append({
            'start': user_session['start'],
            'end': None,  # Encore connecté
            'duration': None,
            'ip': user_session['ip'],
            'vpn_type': user_session['vpn_type'],
            'is_local': user_session['is_local']
        })

    # Anonymiser les données si mode demo
    if demo_mode:
        anonymized_sessions = {}
        for user, sessions in user_sessions.items():
            anonymized_user = anonymize_username(user)
            anonymized_sessions[anonymized_user] = []
            for user_session in sessions:
                anonymized_session = user_session.copy()
                if user_session['ip'] != 'unknown':
                    anonymized_session['ip'] = anonymize_ip(user_session['ip'])
                anonymized_sessions[anonymized_user].append(anonymized_session)
        return jsonify(anonymized_sessions)

    return jsonify(user_sessions)

# Statistiques
@app.route('/api/stats')
@login_required
def get_stats():
    user = get_user_by_id(session['user_id'])
    company_ids = get_user_companies()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Filtrage par société
    if user['role'] == 'super_admin':
        # Super admin voit tout
        # Total d'événements
        c.execute('SELECT COUNT(*) FROM vpn_events')
        total = c.fetchone()[0]

        # Par type
        c.execute('''SELECT event_type, COUNT(*)
                     FROM vpn_events
                     GROUP BY event_type''')
        by_type = dict(c.fetchall())

        # Dernière connexion
        c.execute('''SELECT timestamp, user, ip_address
                     FROM vpn_events
                     WHERE event_type LIKE '%connect%'
                     ORDER BY timestamp DESC LIMIT 1''')
        last_connection = c.fetchone()
    elif company_ids:
        # Admin/Viewer/Demo : filtrer par sociétés accessibles
        placeholders = ','.join('?' * len(company_ids))

        # Total d'événements
        c.execute(f'SELECT COUNT(*) FROM vpn_events WHERE company_id IN ({placeholders})', company_ids)
        total = c.fetchone()[0]

        # Par type
        c.execute(f'''SELECT event_type, COUNT(*)
                      FROM vpn_events
                      WHERE company_id IN ({placeholders})
                      GROUP BY event_type''', company_ids)
        by_type = dict(c.fetchall())

        # Dernière connexion
        c.execute(f'''SELECT timestamp, user, ip_address
                      FROM vpn_events
                      WHERE company_id IN ({placeholders}) AND event_type LIKE '%connect%'
                      ORDER BY timestamp DESC LIMIT 1''', company_ids)
        last_connection = c.fetchone()
    else:
        # Aucune société accessible
        conn.close()
        return jsonify({
            'total_events': 0,
            'events_by_type': {},
            'last_connection': None
        })

    conn.close()

    return jsonify({
        'total_events': total,
        'events_by_type': by_type,
        'last_connection': last_connection
    })

# Test endpoint
@app.route('/test')
def test():
    # Simuler un événement VPN
    test_data = {
        'event': 'vpn_connect',
        'user': 'test_user',
        'ip': '192.168.10.100',
        'vpn_type': 'L2TP',
        'timestamp': datetime.now().isoformat()
    }

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO vpn_events
                 (timestamp, event_type, user, ip_address, vpn_type, raw_data)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (datetime.now().isoformat(), 'vpn_connect', 'test_user',
               '192.168.10.100', 'L2TP', json.dumps(test_data)))
    conn.commit()
    conn.close()

    return jsonify({'status': 'Test event created', 'data': test_data})

# Page d'administration
@app.route('/admin')
@login_required
@role_required('super_admin', 'admin')
def admin():
    user = get_user_by_id(session['user_id'])
    config = load_config()
    return render_template('admin.html', config=config, user=user)

# API pour récupérer la configuration
@app.route('/api/config', methods=['GET'])
@login_required
def get_config():
    return jsonify(load_config())

# API pour sauvegarder la configuration
@app.route('/api/config', methods=['POST'])
@login_required
@role_required('super_admin', 'admin')
def update_config():
    try:
        new_config = request.get_json()
        # Valider les réseaux
        for network_str in new_config.get('local_networks', []):
            try:
                ipaddress.ip_network(network_str, strict=False)
            except:
                return jsonify({'status': 'error', 'message': f'Invalid network: {network_str}'}), 400

        save_config(new_config)
        return jsonify({'status': 'success', 'message': 'Configuration saved'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ==================== ADMIN API - USERS ====================

@app.route('/api/admin/users', methods=['GET'])
@login_required
@role_required('super_admin', 'admin')
def admin_get_users():
    """Liste tous les utilisateurs avec leurs sociétés"""
    from auth import hash_password

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''SELECT id, username, email, role, active, auth_type, created_at, last_login
                 FROM users
                 ORDER BY created_at DESC''')
    users = c.fetchall()

    result = []
    for user in users:
        user_id = user[0]

        # Récupérer les sociétés associées
        c.execute('''SELECT c.id, c.name
                     FROM companies c
                     JOIN user_companies uc ON c.id = uc.company_id
                     WHERE uc.user_id = ?''', (user_id,))
        companies = [{'id': row[0], 'name': row[1]} for row in c.fetchall()]

        result.append({
            'id': user_id,
            'username': user[1],
            'email': user[2],
            'role': user[3],
            'active': user[4],
            'auth_type': user[5],
            'created_at': user[6],
            'last_login': user[7],
            'companies': companies
        })

    conn.close()
    return jsonify(result)

@app.route('/api/admin/users', methods=['POST'])
@login_required
@role_required('super_admin', 'admin')
def admin_create_user():
    """Créer un nouvel utilisateur"""
    from auth import hash_password

    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
        auth_type = data.get('auth_type', 'local')
        active = data.get('active', 1)
        company_ids = data.get('company_ids', [])

        if not username or not password or not role:
            return jsonify({'status': 'error', 'message': 'Champs requis manquants'}), 400

        if len(password) < 6:
            return jsonify({'status': 'error', 'message': 'Le mot de passe doit contenir au moins 6 caractères'}), 400

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Vérifier si l'utilisateur existe déjà
        c.execute('SELECT id FROM users WHERE username = ?', (username,))
        if c.fetchone():
            conn.close()
            return jsonify({'status': 'error', 'message': 'Cet utilisateur existe déjà'}), 400

        # Créer l'utilisateur
        password_hash = hash_password(password)
        c.execute('''INSERT INTO users (username, password_hash, email, role, active, auth_type)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (username, password_hash, email, role, active, auth_type))
        user_id = c.lastrowid

        # Associer aux sociétés (sauf pour super_admin et demo)
        if role not in ['super_admin', 'demo']:
            for company_id in company_ids:
                c.execute('''INSERT INTO user_companies (user_id, company_id)
                             VALUES (?, ?)''', (user_id, company_id))

        conn.commit()
        conn.close()

        return jsonify({'status': 'success', 'message': 'Utilisateur créé', 'id': user_id})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@login_required
@role_required('super_admin', 'admin')
def admin_update_user(user_id):
    """Modifier un utilisateur"""
    from auth import hash_password

    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
        auth_type = data.get('auth_type')
        active = data.get('active')
        company_ids = data.get('company_ids', [])

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Vérifier que l'utilisateur existe
        c.execute('SELECT id FROM users WHERE id = ?', (user_id,))
        if not c.fetchone():
            conn.close()
            return jsonify({'status': 'error', 'message': 'Utilisateur introuvable'}), 404

        # Mettre à jour les informations de base
        if password:
            if len(password) < 6:
                conn.close()
                return jsonify({'status': 'error', 'message': 'Le mot de passe doit contenir au moins 6 caractères'}), 400
            password_hash = hash_password(password)
            c.execute('''UPDATE users
                         SET username = ?, email = ?, password_hash = ?, role = ?, auth_type = ?, active = ?
                         WHERE id = ?''',
                      (username, email, password_hash, role, auth_type, active, user_id))
        else:
            c.execute('''UPDATE users
                         SET username = ?, email = ?, role = ?, auth_type = ?, active = ?
                         WHERE id = ?''',
                      (username, email, role, auth_type, active, user_id))

        # Mettre à jour les associations de sociétés
        c.execute('DELETE FROM user_companies WHERE user_id = ?', (user_id,))

        if role not in ['super_admin', 'demo']:
            for company_id in company_ids:
                c.execute('''INSERT INTO user_companies (user_id, company_id)
                             VALUES (?, ?)''', (user_id, company_id))

        conn.commit()
        conn.close()

        return jsonify({'status': 'success', 'message': 'Utilisateur modifié'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
@role_required('super_admin', 'admin')
def admin_delete_user(user_id):
    """Supprimer un utilisateur"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Vérifier que l'utilisateur existe
        c.execute('SELECT username FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        if not user:
            conn.close()
            return jsonify({'status': 'error', 'message': 'Utilisateur introuvable'}), 404

        # Ne pas permettre la suppression du compte admin principal
        if user[0] == 'admin' and user_id == 1:
            conn.close()
            return jsonify({'status': 'error', 'message': 'Impossible de supprimer le compte admin principal'}), 400

        # Supprimer l'utilisateur (les associations seront supprimées en cascade)
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))

        conn.commit()
        conn.close()

        return jsonify({'status': 'success', 'message': 'Utilisateur supprimé'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ==================== ADMIN API - COMPANIES ====================

@app.route('/api/admin/companies', methods=['GET'])
@login_required
@role_required('super_admin', 'admin')
def admin_get_companies():
    """Liste toutes les sociétés avec statistiques"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''SELECT id, name, description, created_at, local_networks,
                        ldap_enabled, ldap_server, ldap_port, ldap_use_ssl, ldap_base_dn,
                        ldap_user_dn_template, ldap_bind_dn, ldap_bind_password, ldap_admin_group
                 FROM companies ORDER BY name''')
    companies = c.fetchall()

    result = []
    for company in companies:
        company_id = company[0]

        # Compter les utilisateurs
        c.execute('SELECT COUNT(*) FROM user_companies WHERE company_id = ?', (company_id,))
        user_count = c.fetchone()[0]

        # Compter les événements
        c.execute('SELECT COUNT(*) FROM vpn_events WHERE company_id = ?', (company_id,))
        event_count = c.fetchone()[0]

        result.append({
            'id': company_id,
            'name': company[1],
            'description': company[2],
            'created_at': company[3],
            'local_networks': company[4],
            'user_count': user_count,
            'event_count': event_count,
            'ldap_enabled': company[5],
            'ldap_server': company[6],
            'ldap_port': company[7],
            'ldap_use_ssl': company[8],
            'ldap_base_dn': company[9],
            'ldap_user_dn_template': company[10],
            'ldap_bind_dn': company[11],
            'ldap_bind_password': company[12],
            'ldap_admin_group': company[13]
        })

    conn.close()
    return jsonify(result)

@app.route('/api/admin/companies', methods=['POST'])
@login_required
@role_required('super_admin', 'admin')
def admin_create_company():
    """Créer une nouvelle société"""
    try:
        data = request.get_json()
        name = data.get('name')
        description = data.get('description', '')
        local_networks = data.get('local_networks', '[]')
        ldap_enabled = data.get('ldap_enabled', 0)
        ldap_server = data.get('ldap_server', '')
        ldap_port = data.get('ldap_port', 389)
        ldap_use_ssl = data.get('ldap_use_ssl', 0)
        ldap_base_dn = data.get('ldap_base_dn', '')
        ldap_user_dn_template = data.get('ldap_user_dn_template', '')
        ldap_bind_dn = data.get('ldap_bind_dn', '')
        ldap_bind_password = data.get('ldap_bind_password', '')
        ldap_admin_group = data.get('ldap_admin_group', '')

        if not name:
            return jsonify({'status': 'error', 'message': 'Le nom est requis'}), 400

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Vérifier si la société existe déjà
        c.execute('SELECT id FROM companies WHERE name = ?', (name,))
        if c.fetchone():
            conn.close()
            return jsonify({'status': 'error', 'message': 'Cette société existe déjà'}), 400

        # Créer la société
        c.execute('''INSERT INTO companies (name, description, local_networks,
                                           ldap_enabled, ldap_server, ldap_port, ldap_use_ssl,
                                           ldap_base_dn, ldap_user_dn_template, ldap_bind_dn,
                                           ldap_bind_password, ldap_admin_group)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (name, description, local_networks,
                   ldap_enabled, ldap_server, ldap_port, ldap_use_ssl,
                   ldap_base_dn, ldap_user_dn_template, ldap_bind_dn,
                   ldap_bind_password, ldap_admin_group))
        company_id = c.lastrowid

        conn.commit()
        conn.close()

        return jsonify({'status': 'success', 'message': 'Société créée', 'id': company_id})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/admin/companies/<int:company_id>', methods=['PUT'])
@login_required
@role_required('super_admin', 'admin')
def admin_update_company(company_id):
    """Modifier une société"""
    try:
        data = request.get_json()
        name = data.get('name')
        description = data.get('description', '')
        local_networks = data.get('local_networks', '[]')
        ldap_enabled = data.get('ldap_enabled', 0)
        ldap_server = data.get('ldap_server', '')
        ldap_port = data.get('ldap_port', 389)
        ldap_use_ssl = data.get('ldap_use_ssl', 0)
        ldap_base_dn = data.get('ldap_base_dn', '')
        ldap_user_dn_template = data.get('ldap_user_dn_template', '')
        ldap_bind_dn = data.get('ldap_bind_dn', '')
        ldap_bind_password = data.get('ldap_bind_password', '')
        ldap_admin_group = data.get('ldap_admin_group', '')

        if not name:
            return jsonify({'status': 'error', 'message': 'Le nom est requis'}), 400

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Vérifier que la société existe
        c.execute('SELECT id FROM companies WHERE id = ?', (company_id,))
        if not c.fetchone():
            conn.close()
            return jsonify({'status': 'error', 'message': 'Société introuvable'}), 404

        # Mettre à jour
        c.execute('''UPDATE companies SET name = ?, description = ?, local_networks = ?,
                                         ldap_enabled = ?, ldap_server = ?, ldap_port = ?, ldap_use_ssl = ?,
                                         ldap_base_dn = ?, ldap_user_dn_template = ?, ldap_bind_dn = ?,
                                         ldap_bind_password = ?, ldap_admin_group = ?
                     WHERE id = ?''',
                  (name, description, local_networks,
                   ldap_enabled, ldap_server, ldap_port, ldap_use_ssl,
                   ldap_base_dn, ldap_user_dn_template, ldap_bind_dn,
                   ldap_bind_password, ldap_admin_group, company_id))

        conn.commit()
        conn.close()

        return jsonify({'status': 'success', 'message': 'Société modifiée'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/admin/companies/<int:company_id>', methods=['DELETE'])
@login_required
@role_required('super_admin', 'admin')
def admin_delete_company(company_id):
    """Supprimer une société"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Vérifier que la société existe
        c.execute('SELECT name FROM companies WHERE id = ?', (company_id,))
        company = c.fetchone()
        if not company:
            conn.close()
            return jsonify({'status': 'error', 'message': 'Société introuvable'}), 404

        # Ne pas permettre la suppression de la société par défaut
        if company_id == 1:
            conn.close()
            return jsonify({'status': 'error', 'message': 'Impossible de supprimer la société par défaut'}), 400

        # Supprimer la société (les associations et événements seront supprimés en cascade)
        c.execute('DELETE FROM companies WHERE id = ?', (company_id,))

        conn.commit()
        conn.close()

        return jsonify({'status': 'success', 'message': 'Société supprimée'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ==================== ADMIN API - ROUTERS ====================

@app.route('/api/admin/routers', methods=['GET'])
@login_required
@role_required('super_admin', 'admin')
def admin_get_routers():
    """Liste tous les routeurs avec leurs statistiques"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''SELECT r.id, r.name, r.unifi_host, r.alarm_id, r.company_id, r.description, r.created_at, c.name
                 FROM router_devices r
                 LEFT JOIN companies c ON r.company_id = c.id
                 ORDER BY r.name''')
    routers = c.fetchall()

    result = []
    for router in routers:
        router_id = router[0]

        # Compter les événements
        c.execute('SELECT COUNT(*) FROM vpn_events WHERE company_id = ?', (router[4],))
        event_count = c.fetchone()[0]

        result.append({
            'id': router_id,
            'name': router[1],
            'unifi_host': router[2],
            'alarm_id': router[3],
            'company_id': router[4],
            'company_name': router[7],
            'description': router[5],
            'created_at': router[6],
            'event_count': event_count
        })

    conn.close()
    return jsonify(result)

@app.route('/api/admin/routers', methods=['POST'])
@login_required
@role_required('super_admin', 'admin')
def admin_create_router():
    """Créer un nouveau routeur"""
    try:
        data = request.get_json()
        name = data.get('name')
        unifi_host = data.get('unifi_host')
        alarm_id = data.get('alarm_id', '')
        company_id = data.get('company_id')
        description = data.get('description', '')

        if not name or not company_id:
            return jsonify({'status': 'error', 'message': 'Le nom et la société sont requis'}), 400

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Vérifier si le routeur existe déjà
        if unifi_host:
            c.execute('SELECT id FROM router_devices WHERE unifi_host = ?', (unifi_host,))
            if c.fetchone():
                conn.close()
                return jsonify({'status': 'error', 'message': 'Ce routeur (UNIFIhost) existe déjà'}), 400

        # Créer le routeur
        c.execute('''INSERT INTO router_devices (name, unifi_host, alarm_id, company_id, description)
                     VALUES (?, ?, ?, ?, ?)''',
                  (name, unifi_host, alarm_id, company_id, description))
        router_id = c.lastrowid

        conn.commit()
        conn.close()

        return jsonify({'status': 'success', 'message': 'Routeur créé', 'id': router_id})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/admin/routers/<int:router_id>', methods=['PUT'])
@login_required
@role_required('super_admin', 'admin')
def admin_update_router(router_id):
    """Modifier un routeur"""
    try:
        data = request.get_json()
        name = data.get('name')
        unifi_host = data.get('unifi_host')
        alarm_id = data.get('alarm_id', '')
        company_id = data.get('company_id')
        description = data.get('description', '')

        if not name or not company_id:
            return jsonify({'status': 'error', 'message': 'Le nom et la société sont requis'}), 400

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Vérifier que le routeur existe
        c.execute('SELECT id FROM router_devices WHERE id = ?', (router_id,))
        if not c.fetchone():
            conn.close()
            return jsonify({'status': 'error', 'message': 'Routeur introuvable'}), 404

        # Mettre à jour
        c.execute('''UPDATE router_devices
                     SET name = ?, unifi_host = ?, alarm_id = ?, company_id = ?, description = ?
                     WHERE id = ?''',
                  (name, unifi_host, alarm_id, company_id, description, router_id))

        # Mettre à jour les événements existants de ce routeur
        if unifi_host:
            c.execute('''UPDATE vpn_events
                         SET company_id = ?
                         WHERE raw_data LIKE ?''',
                      (company_id, f'%"UNIFIhost": "{unifi_host}"%'))

        conn.commit()
        conn.close()

        return jsonify({'status': 'success', 'message': 'Routeur modifié'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/admin/routers/<int:router_id>', methods=['DELETE'])
@login_required
@role_required('super_admin', 'admin')
def admin_delete_router(router_id):
    """Supprimer un routeur"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Vérifier que le routeur existe
        c.execute('SELECT name FROM router_devices WHERE id = ?', (router_id,))
        router = c.fetchone()
        if not router:
            conn.close()
            return jsonify({'status': 'error', 'message': 'Routeur introuvable'}), 404

        # Supprimer le routeur (les événements restent mais perdent leur association)
        c.execute('DELETE FROM router_devices WHERE id = ?', (router_id,))

        conn.commit()
        conn.close()

        return jsonify({'status': 'success', 'message': 'Routeur supprimé'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    # Créer le répertoire si nécessaire
    os.makedirs('/var/www/html/vpn-logger', exist_ok=True)

    # Initialiser la DB
    init_db()

    # Démarrer le serveur
    app.run(host='0.0.0.0', port=80, debug=False)
