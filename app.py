#!/usr/bin/env python3
"""
Site Web de Logs VPN UniFi
Reçoit les webhooks UniFi pour les connexions/déconnexions VPN
"""

from flask import Flask, request, render_template, jsonify, redirect, url_for, session, flash, send_from_directory, make_response
from datetime import datetime
from werkzeug.utils import secure_filename
from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration
import json
import sqlite3
import os
import ipaddress
import secrets
import logging
import sys
import uuid
import io

# Import auth module
from auth import (
    authenticate_user, get_user_by_id, login_required, role_required,
    get_user_companies, is_demo_mode, anonymize_username, anonymize_ip
)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Clé secrète pour les sessions

# Configure logging
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
app.logger.setLevel(logging.INFO)

# Configuration
APP_VERSION = '2.3.0'
DB_PATH = '/var/www/html/vpn-logger/vpn_logs.db'
LOG_FILE = '/var/www/html/vpn-logger/vpn_events.log'
CONFIG_FILE = '/var/www/html/vpn-logger/config.json'
LOGOS_FOLDER = '/var/www/html/vpn-logger/static/logos'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB

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

def allowed_file(filename):
    """Vérifie si l'extension du fichier est autorisée"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_logo(file):
    """Sauvegarde un logo et retourne le nom du fichier"""
    if file and allowed_file(file.filename):
        # Générer un nom de fichier unique
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"{uuid.uuid4().hex}.{ext}"
        filepath = os.path.join(LOGOS_FOLDER, filename)

        # Créer le dossier s'il n'existe pas
        os.makedirs(LOGOS_FOLDER, exist_ok=True)

        # Sauvegarder le fichier
        file.save(filepath)
        return filename
    return None

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
                        ldap_user_dn_template, ldap_bind_dn, ldap_bind_password, ldap_admin_group, logo
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
            'ldap_admin_group': company[13],
            'logo': company[14]
        })

    conn.close()
    return jsonify(result)

@app.route('/api/admin/companies', methods=['POST'])
@login_required
@role_required('super_admin', 'admin')
def admin_create_company():
    """Créer une nouvelle société"""
    try:
        # Récupérer les données du formulaire (FormData)
        name = request.form.get('name')
        description = request.form.get('description', '')
        local_networks = request.form.get('local_networks', '[]')
        ldap_enabled = int(request.form.get('ldap_enabled', 0))
        ldap_server = request.form.get('ldap_server', '')
        ldap_port = int(request.form.get('ldap_port', 389))
        ldap_use_ssl = int(request.form.get('ldap_use_ssl', 0))
        ldap_base_dn = request.form.get('ldap_base_dn', '')
        ldap_user_dn_template = request.form.get('ldap_user_dn_template', '')
        ldap_bind_dn = request.form.get('ldap_bind_dn', '')
        ldap_bind_password = request.form.get('ldap_bind_password', '')
        ldap_admin_group = request.form.get('ldap_admin_group', '')

        # Gérer le logo
        logo_filename = None
        if 'logo' in request.files:
            logo_file = request.files['logo']
            if logo_file.filename:
                logo_filename = save_logo(logo_file)

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
                                           ldap_bind_password, ldap_admin_group, logo)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (name, description, local_networks,
                   ldap_enabled, ldap_server, ldap_port, ldap_use_ssl,
                   ldap_base_dn, ldap_user_dn_template, ldap_bind_dn,
                   ldap_bind_password, ldap_admin_group, logo_filename))
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
        # Récupérer les données du formulaire (FormData)
        name = request.form.get('name')
        description = request.form.get('description', '')
        local_networks = request.form.get('local_networks', '[]')
        ldap_enabled = int(request.form.get('ldap_enabled', 0))
        ldap_server = request.form.get('ldap_server', '')
        ldap_port = int(request.form.get('ldap_port', 389))
        ldap_use_ssl = int(request.form.get('ldap_use_ssl', 0))
        ldap_base_dn = request.form.get('ldap_base_dn', '')
        ldap_user_dn_template = request.form.get('ldap_user_dn_template', '')
        ldap_bind_dn = request.form.get('ldap_bind_dn', '')
        ldap_bind_password = request.form.get('ldap_bind_password', '')
        ldap_admin_group = request.form.get('ldap_admin_group', '')

        if not name:
            return jsonify({'status': 'error', 'message': 'Le nom est requis'}), 400

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Vérifier que la société existe et récupérer le logo actuel
        c.execute('SELECT id, logo FROM companies WHERE id = ?', (company_id,))
        company = c.fetchone()
        if not company:
            conn.close()
            return jsonify({'status': 'error', 'message': 'Société introuvable'}), 404

        current_logo = company[1]

        # Gérer le logo
        logo_filename = current_logo  # Garder l'ancien logo par défaut
        if 'logo' in request.files:
            logo_file = request.files['logo']
            if logo_file.filename:
                new_logo = save_logo(logo_file)
                if new_logo:
                    logo_filename = new_logo
                    # Supprimer l'ancien logo si existe
                    if current_logo:
                        old_logo_path = os.path.join(LOGOS_FOLDER, current_logo)
                        if os.path.exists(old_logo_path):
                            os.remove(old_logo_path)

        # Mettre à jour
        c.execute('''UPDATE companies SET name = ?, description = ?, local_networks = ?,
                                         ldap_enabled = ?, ldap_server = ?, ldap_port = ?, ldap_use_ssl = ?,
                                         ldap_base_dn = ?, ldap_user_dn_template = ?, ldap_bind_dn = ?,
                                         ldap_bind_password = ?, ldap_admin_group = ?, logo = ?
                     WHERE id = ?''',
                  (name, description, local_networks,
                   ldap_enabled, ldap_server, ldap_port, ldap_use_ssl,
                   ldap_base_dn, ldap_user_dn_template, ldap_bind_dn,
                   ldap_bind_password, ldap_admin_group, logo_filename, company_id))

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

# Route page statistiques
@app.route('/statistics')
@login_required
def statistics():
    """Page des statistiques"""
    user = get_user_by_id(session['user_id'])
    return render_template('statistics.html',
                         username=user['username'],
                         role=user['role'])

@app.route('/reports')
@login_required
def reports():
    """Page des rapports détaillés"""
    user = get_user_by_id(session['user_id'])
    # Récupérer les sociétés complètes pour le sélecteur
    user['companies'] = get_user_by_id(user['id'])['companies']
    import time
    cache_bust = int(time.time())
    return render_template('reports.html', user=user, cache_bust=cache_bust)

# API Statistiques
@app.route('/api/statistics')
@login_required
def api_statistics():
    """API pour récupérer les statistiques selon les filtres"""
    try:
        from datetime import datetime, timedelta

        # Récupérer les paramètres
        period = request.args.get('period', '30')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        company_id = request.args.get('company_id')

        # Calculer les dates
        if start_date and end_date:
            start_dt = datetime.strptime(start_date, '%Y-%m-%d')
            end_dt = datetime.strptime(end_date, '%Y-%m-%d')
        else:
            days = int(period)
            end_dt = datetime.now()
            start_dt = end_dt - timedelta(days=days)

        # Récupérer l'utilisateur et ses sociétés
        user = get_user_by_id(session['user_id'])
        user_companies = get_user_companies()

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Construire la clause WHERE selon les permissions
        where_clauses = []
        params = []

        # Filtre date
        where_clauses.append("datetime(timestamp) >= datetime(?)")
        where_clauses.append("datetime(timestamp) <= datetime(?)")
        params.extend([start_dt.strftime('%Y-%m-%d 00:00:00'), end_dt.strftime('%Y-%m-%d 23:59:59')])

        # Filtre société selon rôle
        if user['role'] == 'super_admin':
            if company_id:
                where_clauses.append("company_id = ?")
                params.append(company_id)
        else:
            # Limiter aux sociétés de l'utilisateur
            if user_companies:
                placeholders = ','.join('?' * len(user_companies))
                where_clauses.append(f"company_id IN ({placeholders})")
                params.extend(user_companies)

        where_sql = ' AND '.join(where_clauses)

        # 1. Résumé général
        c.execute(f'''
            SELECT
                COUNT(*) as total_connections,
                COUNT(DISTINCT user) as active_users,
                AVG(CASE WHEN duration > 0 THEN duration ELSE NULL END) as avg_duration,
                COUNT(CASE WHEN session_closed = 0 THEN 1 END) as active_sessions
            FROM vpn_events
            WHERE {where_sql}
        ''', params)

        summary = c.fetchone()
        summary_data = {
            'total_connections': summary[0] if summary[0] else 0,
            'active_users': summary[1] if summary[1] else 0,
            'avg_duration': int(summary[2]) if summary[2] else 0,
            'active_sessions': summary[3] if summary[3] else 0
        }

        # 2. Connexions par jour
        c.execute(f'''
            SELECT
                date(timestamp) as date,
                COUNT(*) as count
            FROM vpn_events
            WHERE {where_sql}
            GROUP BY date(timestamp)
            ORDER BY date
        ''', params)

        connections_by_day = []
        for row in c.fetchall():
            connections_by_day.append({
                'date': row[0],
                'count': row[1]
            })

        # 3. Top 10 utilisateurs (par temps de session remote uniquement)
        # Récupérer toutes les sessions avec IP et durée
        c.execute(f'''
            SELECT
                user,
                ip_address,
                company_id,
                duration
            FROM vpn_events v
            WHERE {where_sql} AND duration > 0
        ''', params)

        # Calculer le temps total remote par utilisateur
        user_remote_time = {}
        for row in c.fetchall():
            username = row[0]
            ip_address = row[1]
            comp_id = row[2]
            duration = row[3]

            # Vérifier si l'IP est remote (pas locale)
            if ip_address and not is_local_ip(ip_address, comp_id):
                if username not in user_remote_time:
                    user_remote_time[username] = 0
                user_remote_time[username] += duration

        # Trier et prendre le top 10
        sorted_users = sorted(user_remote_time.items(), key=lambda x: x[1], reverse=True)[:10]

        top_users = []
        for username, total_seconds in sorted_users:
            hours = total_seconds / 3600
            top_users.append({
                'user': anonymize_username(username) if is_demo_mode() else username,
                'hours': round(hours, 1)
            })

        # 4. Par société
        c.execute(f'''
            SELECT
                c.name,
                COUNT(*) as count
            FROM vpn_events v
            LEFT JOIN companies c ON v.company_id = c.id
            WHERE {where_sql}
            GROUP BY v.company_id
            ORDER BY count DESC
        ''', params)

        by_company = []
        for row in c.fetchall():
            by_company.append({
                'company': row[0] if row[0] else 'Non assigné',
                'count': row[1]
            })

        # 5. Distribution des durées (en tranches d'heures)
        c.execute(f'''
            SELECT
                duration
            FROM vpn_events
            WHERE {where_sql} AND duration > 0 AND session_closed = 1
        ''', params)

        durations = [row[0] for row in c.fetchall()]
        duration_ranges = {
            '0-1h': 0,
            '1-2h': 0,
            '2-4h': 0,
            '4-8h': 0,
            '8h+': 0
        }

        for duration in durations:
            hours = duration / 3600
            if hours < 1:
                duration_ranges['0-1h'] += 1
            elif hours < 2:
                duration_ranges['1-2h'] += 1
            elif hours < 4:
                duration_ranges['2-4h'] += 1
            elif hours < 8:
                duration_ranges['4-8h'] += 1
            else:
                duration_ranges['8h+'] += 1

        duration_distribution = [
            {'range': k, 'count': v} for k, v in duration_ranges.items()
        ]

        # 6. Par localisation (Local vs Remote)
        c.execute(f'''
            SELECT
                CASE
                    WHEN ip_address = '' OR ip_address IS NULL THEN 'Inconnu'
                    ELSE 'Détecté'
                END as location,
                COUNT(*) as count
            FROM vpn_events
            WHERE {where_sql}
            GROUP BY location
        ''', params)

        # Vérifier quelles IPs sont locales
        c.execute(f'''
            SELECT ip_address, company_id
            FROM vpn_events
            WHERE {where_sql} AND ip_address != '' AND ip_address IS NOT NULL
        ''', params)

        local_count = 0
        remote_count = 0
        unknown_count = 0

        for row in c.fetchall():
            ip = row[0]
            comp_id = row[1]
            if ip:
                if is_local_ip(ip, comp_id):
                    local_count += 1
                else:
                    remote_count += 1
            else:
                unknown_count += 1

        by_location = []
        if local_count > 0:
            by_location.append({'location': 'Local', 'count': local_count})
        if remote_count > 0:
            by_location.append({'location': 'Remote', 'count': remote_count})
        if unknown_count > 0:
            by_location.append({'location': 'Inconnu', 'count': unknown_count})

        # 7. Par type VPN
        c.execute(f'''
            SELECT
                CASE
                    WHEN vpn_type = '' OR vpn_type IS NULL THEN 'Non spécifié'
                    ELSE vpn_type
                END as vpn_type,
                COUNT(*) as count
            FROM vpn_events
            WHERE {where_sql}
            GROUP BY vpn_type
            ORDER BY count DESC
        ''', params)

        by_vpn_type = []
        for row in c.fetchall():
            by_vpn_type.append({
                'vpn_type': row[0],
                'count': row[1]
            })

        conn.close()

        return jsonify({
            'summary': summary_data,
            'connections_by_day': connections_by_day,
            'top_users': top_users,
            'by_company': by_company,
            'duration_distribution': duration_distribution,
            'by_location': by_location,
            'by_vpn_type': by_vpn_type
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# API Rapports - Statistiques par utilisateur
@app.route('/api/reports/user')
@login_required
def api_reports_user():
    """Statistiques détaillées par utilisateur (connexions REMOTE uniquement)"""
    try:
        from datetime import datetime, timedelta
        import calendar

        # Paramètres
        username = request.args.get('username')
        period_type = request.args.get('period_type', 'week')  # week, month, quarter
        year = request.args.get('year')
        week_number = request.args.get('week')
        month_number = request.args.get('month')
        quarter_number = request.args.get('quarter')
        company_id = request.args.get('company_id')

        if not username:
            return jsonify({'status': 'error', 'message': 'Username requis'}), 400

        # Calculer les dates selon le type de période
        now = datetime.now()
        current_year = int(year) if year else now.year

        if period_type == 'week':
            # Semaine ISO 8601 (France) : lundi -> dimanche
            # Semaine 1 = première semaine avec au moins 4 jours (ou contenant le 1er jeudi)
            week = int(week_number) if week_number else now.isocalendar()[1]

            # Utiliser isocalendar pour obtenir le bon lundi de la semaine ISO
            # On cherche un jour de cette semaine, puis on trouve son lundi
            jan_4 = datetime(current_year, 1, 4)  # Le 4 janvier est toujours dans la semaine 1
            week_1_monday = jan_4 - timedelta(days=jan_4.weekday())  # Lundi de la semaine 1

            # Calculer le lundi de la semaine demandée
            start = week_1_monday + timedelta(weeks=week - 1)
            end = start + timedelta(days=6)  # Dimanche

        elif period_type == 'month':
            # Mois complet : 1er -> dernier jour
            month = int(month_number) if month_number else now.month
            start = datetime(current_year, month, 1)
            last_day = calendar.monthrange(current_year, month)[1]
            end = datetime(current_year, month, last_day)

        elif period_type == 'quarter':
            # Trimestre : Q1 (jan-mar), Q2 (avr-jun), Q3 (jul-sep), Q4 (oct-dec)
            quarter = int(quarter_number) if quarter_number else ((now.month - 1) // 3 + 1)
            start_month = (quarter - 1) * 3 + 1
            end_month = start_month + 2
            start = datetime(current_year, start_month, 1)
            last_day = calendar.monthrange(current_year, end_month)[1]
            end = datetime(current_year, end_month, last_day)

        else:
            return jsonify({'status': 'error', 'message': 'Type de période invalide'}), 400

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Filtrage par permissions
        user_companies = get_user_companies()
        where_clauses = ["user = ?", "timestamp >= ?", "timestamp <= ?"]
        params = [username, start.strftime('%Y-%m-%d'), end.strftime('%Y-%m-%d 23:59:59')]

        if user_companies:
            placeholders = ','.join('?' * len(user_companies))
            where_clauses.append(f"company_id IN ({placeholders})")
            params.extend(user_companies)

        if company_id:
            where_clauses.append("company_id = ?")
            params.append(company_id)

        where_sql = ' AND '.join(where_clauses)

        # Récupérer tous les événements avec IP et durée
        c.execute(f'''
            SELECT DATE(timestamp) as date, ip_address, company_id, duration, event_type
            FROM vpn_events
            WHERE {where_sql}
            ORDER BY date
        ''', params)

        events = c.fetchall()

        # Calculer les stats par jour (REMOTE uniquement)
        daily_stats = {}
        current_date = start.date()
        end_date_obj = end.date()

        # Initialiser tous les jours de la période avec 0
        while current_date <= end_date_obj:
            date_str = current_date.strftime('%Y-%m-%d')
            daily_stats[date_str] = {
                'date': date_str,
                'remote_connections': 0,
                'remote_duration': 0,
                'local_connections': 0,
                'local_duration': 0
            }
            current_date += timedelta(days=1)

        # Remplir avec les données réelles
        for row in events:
            date, ip_address, comp_id, duration, event_type = row

            if date not in daily_stats:
                continue

            # Vérifier si c'est remote ou local
            if ip_address and not is_local_ip(ip_address, comp_id):
                # Remote
                if event_type == 'vpn_connect':
                    daily_stats[date]['remote_connections'] += 1
                if duration:
                    daily_stats[date]['remote_duration'] += duration
            else:
                # Local
                if event_type == 'vpn_connect':
                    daily_stats[date]['local_connections'] += 1
                if duration:
                    daily_stats[date]['local_duration'] += duration

        # Récupérer les sessions individuelles pour les timelines
        c.execute(f'''
            SELECT timestamp, ip_address, company_id, duration, event_type, vpn_type
            FROM vpn_events
            WHERE {where_sql}
            ORDER BY timestamp
        ''', params)

        all_events = c.fetchall()

        # Organiser les sessions par jour pour les timelines
        sessions_by_day = {}
        active_connections = {}  # Suivi des connexions actives

        app.logger.info(f"[DEBUG] Processing {len(all_events)} events for sessions")

        for row in all_events:
            timestamp_str, ip_address, comp_id, duration, event_type, vpn_type = row

            # Parser le timestamp (support ISO format et format standard)
            try:
                # Essayer ISO format avec T et microsecondes
                event_time = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%f')
            except:
                try:
                    # Essayer ISO format avec T sans microsecondes
                    event_time = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S')
                except:
                    try:
                        # Essayer format standard avec espace
                        event_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                    except:
                        try:
                            # Essayer format standard avec espace et microsecondes
                            event_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
                        except:
                            app.logger.warning(f"[DEBUG] Could not parse timestamp: {timestamp_str}")
                            continue

            date_str = event_time.strftime('%Y-%m-%d')

            if date_str not in sessions_by_day:
                sessions_by_day[date_str] = []

            # Déterminer si local ou remote
            is_local = is_local_ip(ip_address, comp_id) if ip_address else True

            app.logger.info(f"[DEBUG] Event: {event_type}, IP: {ip_address}, Date: {date_str}")

            if event_type == 'vpn_connect':
                # Début d'une session - la stocker comme active
                active_connections[ip_address] = {
                    'start': event_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'date': date_str,
                    'is_local': is_local,
                    'vpn_type': vpn_type if vpn_type else 'N/A'
                }
                app.logger.info(f"[DEBUG] Stored connect for {ip_address}")
            elif event_type == 'vpn_disconnect':
                app.logger.info(f"[DEBUG] Disconnect for {ip_address}, in active_connections: {ip_address in active_connections}")
                if ip_address in active_connections:
                    # Fin d'une session
                    active_conn = active_connections[ip_address]
                    sessions_by_day[active_conn['date']].append({
                        'start': active_conn['start'],
                        'end': event_time.strftime('%Y-%m-%d %H:%M:%S'),
                        'duration': duration if duration else 0,
                        'is_local': active_conn['is_local'],
                        'ip': ip_address if ip_address else 'N/A',
                        'vpn_type': active_conn['vpn_type']
                    })
                    app.logger.info(f"[DEBUG] Created session for {ip_address}")
                    del active_connections[ip_address]

        # Ajouter les connexions toujours actives
        for ip, active_conn in active_connections.items():
            sessions_by_day[active_conn['date']].append({
                'start': active_conn['start'],
                'end': None,  # Toujours connecté
                'duration': 0,
                'is_local': active_conn['is_local'],
                'ip': ip if ip else 'N/A',
                'vpn_type': active_conn['vpn_type']
            })

        app.logger.info(f"[DEBUG] Created sessions for {len(sessions_by_day)} days")
        app.logger.info(f"[DEBUG] Sessions by day: {sessions_by_day}")

        # Convertir en liste triée
        daily_list = sorted(daily_stats.values(), key=lambda x: x['date'])

        # Ajouter les sessions à chaque jour
        for day in daily_list:
            day['sessions'] = sessions_by_day.get(day['date'], [])

        # Calculer les totaux
        total_remote_connections = sum(d['remote_connections'] for d in daily_list)
        total_remote_duration = sum(d['remote_duration'] for d in daily_list)
        total_local_connections = sum(d['local_connections'] for d in daily_list)
        total_local_duration = sum(d['local_duration'] for d in daily_list)

        conn.close()

        # Anonymiser si mode demo
        display_username = anonymize_username(username) if is_demo_mode() else username

        return jsonify({
            'status': 'success',
            'username': display_username,
            'period': {
                'start': start.strftime('%Y-%m-%d'),
                'end': end.strftime('%Y-%m-%d')
            },
            'daily': daily_list,
            'totals': {
                'remote_connections': total_remote_connections,
                'remote_duration': total_remote_duration,
                'remote_hours': round(total_remote_duration / 3600, 2),
                'local_connections': total_local_connections,
                'local_duration': total_local_duration,
                'local_hours': round(total_local_duration / 3600, 2)
            }
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# API Rapports PDF - Rapport utilisateur
@app.route('/api/reports/user/pdf')
@login_required
def api_reports_user_pdf():
    """Génère un PDF du rapport utilisateur"""
    try:
        from datetime import datetime, timedelta
        import calendar

        # Récupérer les mêmes paramètres que la route JSON
        username = request.args.get('username')
        period_type = request.args.get('period_type', 'week')
        year = request.args.get('year')
        week_number = request.args.get('week')
        month_number = request.args.get('month')
        quarter_number = request.args.get('quarter')
        company_id = request.args.get('company_id')

        if not username:
            return jsonify({'status': 'error', 'message': 'Username requis'}), 400

        # Faire un appel HTTP interne à la route JSON pour récupérer les données
        import requests
        url = f'http://127.0.0.1/api/reports/user?username={username}&period_type={period_type}'
        if year:
            url += f'&year={year}'
        if week_number:
            url += f'&week={week_number}'
        if month_number:
            url += f'&month={month_number}'
        if quarter_number:
            url += f'&quarter={quarter_number}'
        if company_id:
            url += f'&company_id={company_id}'

        # Copier les cookies de session
        cookies = request.cookies
        response = requests.get(url, cookies=cookies)

        if response.status_code != 200:
            return jsonify({'status': 'error', 'message': 'Erreur lors de la récupération des données'}), 500

        data = response.json()

        # Récupérer les informations de la société pour le logo
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Trouver la société de l'utilisateur (prendre la première)
        c.execute('''SELECT c.id, c.name, c.logo
                     FROM companies c
                     WHERE c.id IN (SELECT company_id FROM user_companies uc
                                   JOIN users u ON u.id = uc.user_id
                                   WHERE u.username = ?)
                     LIMIT 1''', (username,))
        company = c.fetchone()

        if not company:
            # Fallback: prendre la première société
            c.execute('SELECT id, name, logo FROM companies LIMIT 1')
            company = c.fetchone()

        conn.close()

        company_name = company[1] if company else "VPN Logger"
        company_logo_path = None
        if company and company[2]:
            # Utiliser file:// pour que WeasyPrint puisse charger l'image
            company_logo_path = f"file://{os.path.join(LOGOS_FOLDER, company[2])}"

        # Préparer le label de période
        now = datetime.now()
        current_year = int(year) if year else now.year

        if period_type == 'week':
            week = int(week_number) if week_number else now.isocalendar()[1]
            period_label = f"Semaine {week}, {current_year}"
        elif period_type == 'month':
            month = int(month_number) if month_number else now.month
            month_names = ['Janvier', 'Février', 'Mars', 'Avril', 'Mai', 'Juin',
                          'Juillet', 'Août', 'Septembre', 'Octobre', 'Novembre', 'Décembre']
            period_label = f"{month_names[month-1]} {current_year}"
        elif period_type == 'quarter':
            quarter = int(quarter_number) if quarter_number else ((now.month - 1) // 3 + 1)
            period_label = f"Trimestre {quarter}, {current_year}"

        # Formater les données pour le template
        def format_duration(seconds):
            if not seconds:
                return "0h 00m"
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes:02d}m"

        summary = {
            'remote_connections': data['totals']['remote_connections'],
            'local_connections': data['totals']['local_connections'],
            'total_duration': format_duration(data['totals']['remote_duration'] + data['totals']['local_duration']),
            'avg_duration': format_duration((data['totals']['remote_duration'] + data['totals']['local_duration']) / max(data['totals']['remote_connections'] + data['totals']['local_connections'], 1))
        }

        # Filtrer les jours vides et formater les données
        daily_data = []
        for day in data['daily']:
            if day['remote_connections'] == 0 and day['local_connections'] == 0:
                continue

            # Formater la date
            date_obj = datetime.strptime(day['date'], '%Y-%m-%d')
            day_formatted = {
                'date': date_obj.strftime('%d/%m/%Y'),
                'remote_connections': day['remote_connections'],
                'local_connections': day['local_connections'],
                'sessions': []
            }

            # Ajouter les sessions pour la timeline (si disponibles)
            for session in day.get('sessions', []):
                try:
                    # Calculer les pourcentages pour la timeline 24h
                    if session.get('start'):
                        start_time = datetime.strptime(session['start'], '%Y-%m-%d %H:%M:%S')
                        start_hour = start_time.hour + start_time.minute / 60 + start_time.second / 3600
                        start_percent = (start_hour / 24) * 100

                        # Calculer la durée en heures
                        if session.get('end'):
                            end_time = datetime.strptime(session['end'], '%Y-%m-%d %H:%M:%S')
                            duration_seconds = (end_time - start_time).total_seconds()
                        elif session.get('duration'):
                            duration_seconds = session['duration']
                        else:
                            duration_seconds = 0

                        duration_hours = duration_seconds / 3600
                        duration_percent = (duration_hours / 24) * 100

                        day_formatted['sessions'].append({
                            'is_local': session.get('is_local', False),
                            'start_percent': round(start_percent, 4),
                            'duration_percent': round(duration_percent, 4)
                        })
                except (KeyError, TypeError, ValueError) as e:
                    # Ignorer les sessions sans les données nécessaires
                    app.logger.warning(f"Erreur calcul session timeline: {e}")
                    pass

            daily_data.append(day_formatted)

        # Rendre le template HTML
        html_content = render_template('pdf/user_report.html',
            username=data['username'],
            period_label=period_label,
            generation_date=datetime.now().strftime('%d/%m/%Y %H:%M'),
            summary=summary,
            daily_data=daily_data,
            company_name=company_name,
            company_logo=company_logo_path,
            app_version=APP_VERSION
        )

        # Générer le PDF
        pdf_file = HTML(string=html_content, base_url=request.host_url).write_pdf()

        # Créer la réponse
        response = make_response(pdf_file)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="rapport_utilisateur_{username}_{period_type}_{current_year}.pdf"'

        return response

    except Exception as e:
        app.logger.error(f"Erreur génération PDF utilisateur: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# API Rapports - Statistiques par société
@app.route('/api/reports/company')
@login_required
def api_reports_company():
    """Statistiques détaillées par société (tous utilisateurs, REMOTE uniquement)"""
    try:
        from datetime import datetime, timedelta
        import calendar

        # Paramètres
        company_id = request.args.get('company_id')
        period_type = request.args.get('period_type', 'week')
        year = request.args.get('year')
        week_number = request.args.get('week')
        month_number = request.args.get('month')
        quarter_number = request.args.get('quarter')

        if not company_id:
            return jsonify({'status': 'error', 'message': 'Company ID requis'}), 400

        # Vérifier les permissions
        user_companies = get_user_companies()
        if user_companies and int(company_id) not in user_companies:
            return jsonify({'status': 'error', 'message': 'Accès refusé'}), 403

        # Calculer les dates selon le type de période
        now = datetime.now()
        current_year = int(year) if year else now.year

        if period_type == 'week':
            # Semaine ISO 8601 (France)
            week = int(week_number) if week_number else now.isocalendar()[1]
            jan_4 = datetime(current_year, 1, 4)
            week_1_monday = jan_4 - timedelta(days=jan_4.weekday())
            start = week_1_monday + timedelta(weeks=week - 1)
            end = start + timedelta(days=6)

        elif period_type == 'month':
            month = int(month_number) if month_number else now.month
            start = datetime(current_year, month, 1)
            last_day = calendar.monthrange(current_year, month)[1]
            end = datetime(current_year, month, last_day)

        elif period_type == 'quarter':
            quarter = int(quarter_number) if quarter_number else ((now.month - 1) // 3 + 1)
            start_month = (quarter - 1) * 3 + 1
            end_month = start_month + 2
            start = datetime(current_year, start_month, 1)
            last_day = calendar.monthrange(current_year, end_month)[1]
            end = datetime(current_year, end_month, last_day)

        else:
            return jsonify({'status': 'error', 'message': 'Type de période invalide'}), 400

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Récupérer tous les événements de la société
        c.execute('''
            SELECT DATE(timestamp) as date, user, ip_address, duration, event_type
            FROM vpn_events
            WHERE company_id = ? AND timestamp >= ? AND timestamp <= ?
            ORDER BY date, user
        ''', (company_id, start.strftime('%Y-%m-%d'), end.strftime('%Y-%m-%d 23:59:59')))

        events = c.fetchall()

        # Stats par utilisateur et par jour
        user_daily_stats = {}

        # Initialiser la structure
        current_date = start.date()
        end_date_obj = end.date()

        for row in events:
            date, username, ip_address, duration, event_type = row

            if username not in user_daily_stats:
                user_daily_stats[username] = {}
                # Initialiser tous les jours pour cet utilisateur
                temp_date = start.date()
                while temp_date <= end_date_obj:
                    date_str = temp_date.strftime('%Y-%m-%d')
                    user_daily_stats[username][date_str] = {
                        'date': date_str,
                        'remote_connections': 0,
                        'remote_duration': 0
                    }
                    temp_date += timedelta(days=1)

            if date not in user_daily_stats[username]:
                continue

            # Compter uniquement les REMOTE
            if ip_address and not is_local_ip(ip_address, int(company_id)):
                if event_type == 'vpn_connect':
                    user_daily_stats[username][date]['remote_connections'] += 1
                if duration:
                    user_daily_stats[username][date]['remote_duration'] += duration

        # Récupérer les sessions individuelles pour les timelines
        c.execute('''
            SELECT timestamp, user, ip_address, duration, event_type, vpn_type
            FROM vpn_events
            WHERE company_id = ? AND timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp
        ''', (company_id, start.strftime('%Y-%m-%d'), end.strftime('%Y-%m-%d 23:59:59')))

        all_events = c.fetchall()

        # Organiser les sessions par utilisateur et par jour
        sessions_by_user_day = {}
        active_connections_by_user = {}  # Suivi des connexions actives par utilisateur

        for row in all_events:
            timestamp_str, username, ip_address, duration, event_type, vpn_type = row

            # Parser le timestamp (support ISO format et format standard)
            try:
                # Essayer ISO format avec T et microsecondes
                event_time = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%f')
            except:
                try:
                    # Essayer ISO format avec T sans microsecondes
                    event_time = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S')
                except:
                    try:
                        # Essayer format standard avec espace
                        event_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                    except:
                        try:
                            # Essayer format standard avec espace et microsecondes
                            event_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
                        except:
                            app.logger.warning(f"[DEBUG] Could not parse timestamp: {timestamp_str}")
                            continue

            date_str = event_time.strftime('%Y-%m-%d')

            if username not in sessions_by_user_day:
                sessions_by_user_day[username] = {}

            if date_str not in sessions_by_user_day[username]:
                sessions_by_user_day[username][date_str] = []

            if username not in active_connections_by_user:
                active_connections_by_user[username] = {}

            # Déterminer si local ou remote
            is_local = is_local_ip(ip_address, int(company_id)) if ip_address else True

            if event_type == 'vpn_connect':
                # Début d'une session
                active_connections_by_user[username][ip_address] = {
                    'start': event_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'date': date_str,
                    'is_local': is_local,
                    'vpn_type': vpn_type if vpn_type else 'N/A'
                }
            elif event_type == 'vpn_disconnect' and ip_address in active_connections_by_user.get(username, {}):
                # Fin d'une session
                active_conn = active_connections_by_user[username][ip_address]
                sessions_by_user_day[username][active_conn['date']].append({
                    'start': active_conn['start'],
                    'end': event_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'duration': duration if duration else 0,
                    'is_local': active_conn['is_local'],
                    'ip': ip_address if ip_address else 'N/A',
                    'vpn_type': active_conn['vpn_type']
                })
                del active_connections_by_user[username][ip_address]

        # Ajouter les connexions toujours actives
        for username, connections in active_connections_by_user.items():
            for ip, active_conn in connections.items():
                if username not in sessions_by_user_day:
                    sessions_by_user_day[username] = {}
                if active_conn['date'] not in sessions_by_user_day[username]:
                    sessions_by_user_day[username][active_conn['date']] = []
                sessions_by_user_day[username][active_conn['date']].append({
                    'start': active_conn['start'],
                    'end': None,
                    'duration': 0,
                    'is_local': active_conn['is_local'],
                    'ip': ip if ip else 'N/A',
                    'vpn_type': active_conn['vpn_type']
                })

        # Formater les résultats
        users_data = []
        for username, daily_data in user_daily_stats.items():
            daily_list = sorted(daily_data.values(), key=lambda x: x['date'])

            # Ajouter les sessions à chaque jour
            for day in daily_list:
                if username in sessions_by_user_day and day['date'] in sessions_by_user_day[username]:
                    day['sessions'] = sessions_by_user_day[username][day['date']]
                else:
                    day['sessions'] = []

            total_remote = sum(d['remote_duration'] for d in daily_list)
            total_connections = sum(d['remote_connections'] for d in daily_list)

            display_username = anonymize_username(username) if is_demo_mode() else username

            users_data.append({
                'username': display_username,
                'daily': daily_list,
                'totals': {
                    'connections': total_connections,
                    'duration': total_remote,
                    'hours': round(total_remote / 3600, 2)
                }
            })

        # Trier par temps total décroissant
        users_data.sort(key=lambda x: x['totals']['duration'], reverse=True)

        conn.close()

        return jsonify({
            'status': 'success',
            'company_id': int(company_id),
            'period': {
                'start': start.strftime('%Y-%m-%d'),
                'end': end.strftime('%Y-%m-%d')
            },
            'users': users_data
        })

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# API Rapports PDF - Rapport société
@app.route('/api/reports/company/pdf')
@login_required
def api_reports_company_pdf():
    """Génère un PDF du rapport société"""
    try:
        from datetime import datetime, timedelta
        import calendar

        # Récupérer les mêmes paramètres que la route JSON
        company_id = request.args.get('company_id')
        period_type = request.args.get('period_type', 'week')
        year = request.args.get('year')
        week_number = request.args.get('week')
        month_number = request.args.get('month')
        quarter_number = request.args.get('quarter')

        if not company_id:
            return jsonify({'status': 'error', 'message': 'Company ID requis'}), 400

        # Faire un appel HTTP interne à la route JSON pour récupérer les données
        import requests
        url = f'http://127.0.0.1/api/reports/company?company_id={company_id}&period_type={period_type}'
        if year:
            url += f'&year={year}'
        if week_number:
            url += f'&week={week_number}'
        if month_number:
            url += f'&month={month_number}'
        if quarter_number:
            url += f'&quarter={quarter_number}'

        # Copier les cookies de session
        cookies = request.cookies
        response = requests.get(url, cookies=cookies)

        if response.status_code != 200:
            return jsonify({'status': 'error', 'message': 'Erreur lors de la récupération des données'}), 500

        data = response.json()

        # Récupérer les informations de la société pour le logo
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT name, logo FROM companies WHERE id = ?', (company_id,))
        company = c.fetchone()
        conn.close()

        if not company:
            return jsonify({'status': 'error', 'message': 'Société introuvable'}), 404

        company_name = company[0]
        company_logo_path = None
        if company[1]:
            # Utiliser file:// pour que WeasyPrint puisse charger l'image
            company_logo_path = f"file://{os.path.join(LOGOS_FOLDER, company[1])}"

        # Préparer le label de période
        now = datetime.now()
        current_year = int(year) if year else now.year

        if period_type == 'week':
            week = int(week_number) if week_number else now.isocalendar()[1]
            period_label = f"Semaine {week}, {current_year}"
        elif period_type == 'month':
            month = int(month_number) if month_number else now.month
            month_names = ['Janvier', 'Février', 'Mars', 'Avril', 'Mai', 'Juin',
                          'Juillet', 'Août', 'Septembre', 'Octobre', 'Novembre', 'Décembre']
            period_label = f"{month_names[month-1]} {current_year}"
        elif period_type == 'quarter':
            quarter = int(quarter_number) if quarter_number else ((now.month - 1) // 3 + 1)
            period_label = f"Trimestre {quarter}, {current_year}"

        # Formater les données
        def format_duration(seconds):
            if not seconds:
                return "0h 00m"
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes:02d}m"

        # Calculer les totaux depuis les données quotidiennes
        total_remote = 0
        total_local = 0
        total_duration_seconds = 0

        for user in data['users']:
            for day in user['daily']:
                total_remote += day.get('remote_connections', 0)
                total_local += day.get('local_connections', 0)
            total_duration_seconds += user.get('totals', {}).get('duration', 0)

        summary = {
            'total_remote_connections': total_remote,
            'total_local_connections': total_local,
            'total_duration': format_duration(total_duration_seconds)
        }

        # Formater les utilisateurs
        users_formatted = []
        for user in data['users']:
            # Calculer les totaux depuis les données quotidiennes
            remote_connections = sum(day.get('remote_connections', 0) for day in user['daily'])
            local_connections = sum(day.get('local_connections', 0) for day in user['daily'])
            total_duration_seconds = user.get('totals', {}).get('duration', 0)

            user_formatted = {
                'username': user['username'],
                'remote_connections': remote_connections,
                'local_connections': local_connections,
                'total_duration': format_duration(total_duration_seconds),
                'daily_data': []
            }

            # Filtrer et formater les jours
            for day in user['daily']:
                if day.get('remote_connections', 0) == 0:
                    continue

                date_obj = datetime.strptime(day['date'], '%Y-%m-%d')
                day_formatted = {
                    'date': date_obj.strftime('%d/%m/%Y'),
                    'remote_connections': day.get('remote_connections', 0),
                    'local_connections': day.get('local_connections', 0),
                    'sessions': []
                }

                # Ajouter les sessions pour la timeline (si disponibles)
                for session in day.get('sessions', []):
                    try:
                        # Calculer les pourcentages pour la timeline 24h
                        if session.get('start'):
                            start_time = datetime.strptime(session['start'], '%Y-%m-%d %H:%M:%S')
                            start_hour = start_time.hour + start_time.minute / 60 + start_time.second / 3600
                            start_percent = (start_hour / 24) * 100

                            # Calculer la durée en heures
                            if session.get('end'):
                                end_time = datetime.strptime(session['end'], '%Y-%m-%d %H:%M:%S')
                                duration_seconds = (end_time - start_time).total_seconds()
                            elif session.get('duration'):
                                duration_seconds = session['duration']
                            else:
                                duration_seconds = 0

                            duration_hours = duration_seconds / 3600
                            duration_percent = (duration_hours / 24) * 100

                            day_formatted['sessions'].append({
                                'is_local': session.get('is_local', False),
                                'start_percent': round(start_percent, 4),
                                'duration_percent': round(duration_percent, 4)
                            })
                    except (KeyError, TypeError, ValueError) as e:
                        # Ignorer les sessions sans les données nécessaires
                        app.logger.warning(f"Erreur calcul session timeline (company): {e}")
                        pass

                user_formatted['daily_data'].append(day_formatted)

            users_formatted.append(user_formatted)

        # Rendre le template HTML
        html_content = render_template('pdf/company_report.html',
            company_name=company_name,
            period_label=period_label,
            generation_date=datetime.now().strftime('%d/%m/%Y %H:%M'),
            summary=summary,
            users=users_formatted,
            company_logo=company_logo_path,
            app_version=APP_VERSION
        )

        # Générer le PDF
        pdf_file = HTML(string=html_content, base_url=request.host_url).write_pdf()

        # Créer la réponse
        response = make_response(pdf_file)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="rapport_societe_{company_name}_{period_type}_{current_year}.pdf"'

        return response

    except Exception as e:
        app.logger.error(f"Erreur génération PDF société: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    # Créer le répertoire si nécessaire
    os.makedirs('/var/www/html/vpn-logger', exist_ok=True)

    # Initialiser la DB
    init_db()

    # Démarrer le serveur
    app.run(host='0.0.0.0', port=80, debug=False)
