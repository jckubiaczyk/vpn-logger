#!/usr/bin/env python3
"""
Module d'authentification pour VPN Logger
Gestion des utilisateurs, sessions et permissions
Support authentification locale et LDAP
"""

import sqlite3
import hashlib
import ldap
from datetime import datetime
from functools import wraps
from flask import session, redirect, url_for, flash

DB_PATH = '/var/www/html/vpn-logger/vpn_logs.db'

def hash_password(password):
    """Hash un mot de passe avec SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, password_hash):
    """Vérifie un mot de passe contre son hash"""
    return hash_password(password) == password_hash

def authenticate_ldap(username, password, company_id):
    """
    Authentifie un utilisateur via LDAP pour une société donnée
    Retourne (success, is_admin, user_info) ou (False, False, None)
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Récupérer config LDAP de la société
    c.execute('''SELECT ldap_enabled, ldap_server, ldap_port, ldap_use_ssl, ldap_base_dn,
                        ldap_user_dn_template, ldap_bind_dn, ldap_bind_password, ldap_admin_group
                 FROM companies WHERE id = ?''', (company_id,))
    ldap_config = c.fetchone()
    conn.close()

    if not ldap_config or not ldap_config[0]:  # LDAP non activé
        return (False, False, None)

    (enabled, server, port, use_ssl, base_dn, user_dn_template,
     bind_dn, bind_password, admin_group) = ldap_config

    try:
        # Connexion LDAP
        ldap_url = f"ldaps://{server}:{port}" if use_ssl else f"ldap://{server}:{port}"
        conn_ldap = ldap.initialize(ldap_url)
        conn_ldap.set_option(ldap.OPT_REFERRALS, 0)

        # Construction du DN utilisateur
        if user_dn_template:
            user_dn = user_dn_template.replace('{username}', username)
        else:
            user_dn = f"cn={username},{base_dn}"

        # Tentative de bind avec les credentials utilisateur
        conn_ldap.simple_bind_s(user_dn, password)

        # Vérifier si l'utilisateur est dans le groupe admin
        is_admin = False
        user_email = None

        if admin_group:
            # Rechercher les groupes de l'utilisateur
            # Chercher par sAMAccountName (Active Directory) ou userPrincipalName
            search_filter = f"(|(sAMAccountName={username})(userPrincipalName={user_dn}))"

            try:
                result = conn_ldap.search_s(base_dn, ldap.SCOPE_SUBTREE, search_filter, ['memberOf', 'mail', 'userPrincipalName'])

                if result and len(result) > 0:
                    # result est une liste de tuples: [(dn, {attributs})]
                    for entry in result:
                        if len(entry) >= 2 and entry[0]:  # Ignorer les références
                            dn, attributes = entry[0], entry[1]

                            if isinstance(attributes, dict):
                                # Récupérer l'email
                                if 'mail' in attributes:
                                    user_email = attributes['mail'][0]
                                    if isinstance(user_email, bytes):
                                        user_email = user_email.decode('utf-8')
                                elif 'userPrincipalName' in attributes:
                                    user_email = attributes['userPrincipalName'][0]
                                    if isinstance(user_email, bytes):
                                        user_email = user_email.decode('utf-8')

                                # Vérifier les groupes
                                if 'memberOf' in attributes:
                                    member_of = attributes['memberOf']
                                    for group in member_of:
                                        if isinstance(group, bytes):
                                            group = group.decode('utf-8')
                                        if admin_group in group:
                                            is_admin = True
                                            break

                            if is_admin:
                                break
            except Exception as e:
                print(f"LDAP Error: Failed to search groups - {e}")

        conn_ldap.unbind_s()

        # Utiliser l'email récupéré ou défaut
        if not user_email:
            user_email = f"{username}@{base_dn.replace('DC=', '').replace(',', '.')}"

        return (True, is_admin, {'username': username, 'email': user_email})

    except ldap.INVALID_CREDENTIALS:
        return (False, False, None)
    except Exception as e:
        print(f"LDAP Error: {type(e).__name__}: {e}")
        return (False, False, None)


def authenticate_user(username, password):
    """
    Authentifie un utilisateur avec username/password
    Supporte authentification locale ET LDAP
    Retourne les informations utilisateur si succès, None sinon
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # 1. Chercher d'abord un utilisateur local existant
    c.execute('''SELECT id, username, password_hash, email, role, active, auth_type
                 FROM users
                 WHERE username = ?''', (username,))
    user = c.fetchone()

    if user:
        user_id, username_db, password_hash, email, role, active, auth_type = user

        # Vérifier si actif
        if not active:
            conn.close()
            return None

        # Auth locale : vérifier password hash
        if auth_type == 'local':
            if not verify_password(password, password_hash):
                conn.close()
                return None
        elif auth_type == 'ldap':
            # Utilisateur LDAP existant : authentifier via LDAP
            # Récupérer la société de l'utilisateur
            c.execute('''SELECT company_id FROM user_companies WHERE user_id = ? LIMIT 1''', (user_id,))
            company_row = c.fetchone()

            if not company_row:
                conn.close()
                return None

            company_id = company_row[0]

            # Authentifier via LDAP
            success, is_admin, ldap_info = authenticate_ldap(username, password, company_id)

            if not success or not is_admin:
                conn.close()
                return None

            # Mettre à jour l'email si disponible
            if ldap_info and ldap_info.get('email'):
                c.execute('UPDATE users SET email = ? WHERE id = ?', (ldap_info['email'], user_id))
                email = ldap_info['email']
                conn.commit()
        else:
            conn.close()
            return None

    else:
        # 2. Pas d'utilisateur local → Tenter LDAP sur toutes les sociétés avec LDAP activé
        c.execute('SELECT id, name FROM companies WHERE ldap_enabled = 1')
        ldap_companies = c.fetchall()

        authenticated = False
        is_admin = False
        ldap_info = None
        company_id = None

        for comp_id, comp_name in ldap_companies:
            success, admin_status, info = authenticate_ldap(username, password, comp_id)
            if success:
                authenticated = True
                is_admin = admin_status
                ldap_info = info
                company_id = comp_id
                break

        if not authenticated:
            conn.close()
            return None

        # Créer automatiquement l'utilisateur LDAP
        # Seuls les admins du domaine peuvent se connecter
        if not is_admin:
            conn.close()
            return None

        role = 'admin'  # Admin de domaine → admin de sa société
        email = ldap_info['email']

        c.execute('''INSERT INTO users (username, password_hash, email, role, active, auth_type)
                     VALUES (?, ?, ?, ?, 1, 'ldap')''',
                  (username, '', email, role))
        user_id = c.lastrowid

        # Assigner à la société
        c.execute('INSERT INTO user_companies (user_id, company_id) VALUES (?, ?)',
                  (user_id, company_id))

        conn.commit()

    # Récupérer les sociétés associées
    companies = []
    if role not in ['super_admin', 'demo']:
        c.execute('''SELECT c.id, c.name
                     FROM companies c
                     JOIN user_companies uc ON c.id = uc.company_id
                     WHERE uc.user_id = ?''', (user_id,))
        companies = [{'id': row[0], 'name': row[1]} for row in c.fetchall()]
    elif role == 'super_admin':
        c.execute('SELECT id, name FROM companies')
        companies = [{'id': row[0], 'name': row[1]} for row in c.fetchall()]
    elif role == 'demo':
        c.execute('''SELECT company_id, COUNT(*) as count
                     FROM vpn_events
                     WHERE company_id IS NOT NULL
                     GROUP BY company_id
                     ORDER BY count DESC
                     LIMIT 1''')
        demo_company = c.fetchone()
        if demo_company:
            c.execute('SELECT id, name FROM companies WHERE id = ?', (demo_company[0],))
            company = c.fetchone()
            if company:
                companies = [{'id': company[0], 'name': 'Société Demo'}]

    # Mettre à jour la dernière connexion
    c.execute('UPDATE users SET last_login = ? WHERE id = ?',
              (datetime.now().isoformat(), user_id))
    conn.commit()
    conn.close()

    return {
        'id': user_id,
        'username': username,
        'email': email,
        'role': role,
        'companies': companies,
        'auth_type': auth_type if user else 'ldap'
    }

def get_user_by_id(user_id):
    """Récupère les informations d'un utilisateur par son ID"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''SELECT id, username, email, role, active, auth_type
                 FROM users
                 WHERE id = ?''', (user_id,))
    user = c.fetchone()

    if not user:
        conn.close()
        return None

    user_id, username, email, role, active, auth_type = user

    if not active:
        conn.close()
        return None

    # Récupérer les sociétés
    companies = []
    if role not in ['super_admin', 'demo']:
        c.execute('''SELECT c.id, c.name
                     FROM companies c
                     JOIN user_companies uc ON c.id = uc.company_id
                     WHERE uc.user_id = ?''', (user_id,))
        companies = [{'id': row[0], 'name': row[1]} for row in c.fetchall()]
    elif role == 'super_admin':
        c.execute('SELECT id, name FROM companies')
        companies = [{'id': row[0], 'name': row[1]} for row in c.fetchall()]
    elif role == 'demo':
        c.execute('''SELECT company_id, COUNT(*) as count
                     FROM vpn_events
                     WHERE company_id IS NOT NULL
                     GROUP BY company_id
                     ORDER BY count DESC
                     LIMIT 1''')
        demo_company = c.fetchone()
        if demo_company:
            c.execute('SELECT id, name FROM companies WHERE id = ?', (demo_company[0],))
            company = c.fetchone()
            if company:
                companies = [{'id': company[0], 'name': 'Société Demo'}]

    conn.close()

    return {
        'id': user_id,
        'username': username,
        'email': email,
        'role': role,
        'companies': companies,
        'auth_type': auth_type
    }

def login_required(f):
    """Décorateur pour protéger les routes nécessitant une authentification"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Veuillez vous connecter pour accéder à cette page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    """Décorateur pour vérifier le rôle de l'utilisateur"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Veuillez vous connecter', 'warning')
                return redirect(url_for('login'))

            user = get_user_by_id(session['user_id'])
            if not user or user['role'] not in roles:
                flash('Accès refusé : permissions insuffisantes', 'error')
                return redirect(url_for('index'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_user_companies():
    """Retourne la liste des IDs de sociétés accessibles par l'utilisateur connecté"""
    if 'user_id' not in session:
        return []

    user = get_user_by_id(session['user_id'])
    if not user:
        return []

    return [c['id'] for c in user['companies']]

def can_access_company(company_id):
    """Vérifie si l'utilisateur connecté peut accéder à une société donnée"""
    if 'user_id' not in session:
        return False

    user = get_user_by_id(session['user_id'])
    if not user:
        return False

    # Super admin a accès à tout
    if user['role'] == 'super_admin':
        return True

    # Vérifier si la société est dans la liste
    return company_id in [c['id'] for c in user['companies']]

def anonymize_username(username):
    """Anonymise un nom d'utilisateur pour le mode demo"""
    # Garder la première lettre et remplacer le reste par des *
    if len(username) <= 1:
        return username
    return username[0] + '*' * (len(username) - 1)

def anonymize_ip(ip):
    """Anonymise une adresse IP pour le mode demo"""
    parts = ip.split('.')
    if len(parts) == 4:
        # Garder les 2 premiers octets
        return f"{parts[0]}.{parts[1]}.xxx.xxx"
    return "xxx.xxx.xxx.xxx"

def is_demo_mode():
    """Vérifie si l'utilisateur connecté est en mode demo"""
    if 'user_id' not in session:
        return False

    user = get_user_by_id(session['user_id'])
    return user and user['role'] == 'demo'
