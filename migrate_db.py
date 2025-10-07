#!/usr/bin/env python3
"""
Script de migration de la base de données pour ajouter le support multi-société
"""

import sqlite3
import hashlib
from datetime import datetime

DB_PATH = '/var/www/html/vpn-logger/vpn_logs.db'

def hash_password(password):
    """Hash un mot de passe avec SHA256 (simple pour commencer)"""
    return hashlib.sha256(password.encode()).hexdigest()

def migrate():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    print("🔄 Début de la migration de la base de données...")

    # 1. Créer la table companies
    print("📊 Création de la table 'companies'...")
    c.execute('''CREATE TABLE IF NOT EXISTS companies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        description TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')

    # 2. Créer la table users
    print("👥 Création de la table 'users'...")
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT,
        role TEXT NOT NULL CHECK(role IN ('super_admin', 'admin', 'viewer', 'demo')),
        active INTEGER DEFAULT 1,
        auth_type TEXT DEFAULT 'local' CHECK(auth_type IN ('local', 'ldap')),
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_login TEXT
    )''')

    # 3. Créer la table user_companies (association many-to-many)
    print("🔗 Création de la table 'user_companies'...")
    c.execute('''CREATE TABLE IF NOT EXISTS user_companies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        company_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE,
        UNIQUE(user_id, company_id)
    )''')

    # 4. Ajouter company_id à vpn_events si elle n'existe pas
    print("🔧 Ajout de la colonne 'company_id' à 'vpn_events'...")
    try:
        c.execute('ALTER TABLE vpn_events ADD COLUMN company_id INTEGER DEFAULT 1')
    except sqlite3.OperationalError:
        print("   ⚠️  Colonne 'company_id' existe déjà")

    # 5. Créer une société par défaut (NIDAPLAST basé sur les logs)
    print("🏢 Création de la société par défaut...")
    try:
        c.execute('''INSERT INTO companies (name, description)
                     VALUES (?, ?)''',
                  ('NIDAPLAST', 'Société par défaut - migration automatique'))
        company_id = c.lastrowid
        print(f"   ✅ Société 'NIDAPLAST' créée avec ID: {company_id}")
    except sqlite3.IntegrityError:
        c.execute('SELECT id FROM companies WHERE name = ?', ('NIDAPLAST',))
        company_id = c.fetchone()[0]
        print(f"   ⚠️  Société 'NIDAPLAST' existe déjà (ID: {company_id})")

    # 6. Mettre à jour tous les événements existants avec company_id = 1
    print("📝 Association des événements existants à la société par défaut...")
    c.execute('UPDATE vpn_events SET company_id = ? WHERE company_id IS NULL', (company_id,))
    updated = c.rowcount
    print(f"   ✅ {updated} événements mis à jour")

    # 7. Créer un super admin par défaut
    print("👤 Création du super administrateur...")
    default_password = 'admin123'  # À changer lors de la première connexion
    try:
        c.execute('''INSERT INTO users (username, password_hash, email, role, auth_type)
                     VALUES (?, ?, ?, ?, ?)''',
                  ('admin', hash_password(default_password), 'admin@example.com', 'super_admin', 'local'))
        print(f"   ✅ Super admin créé")
        print(f"   📌 Username: admin")
        print(f"   📌 Password: {default_password}")
        print(f"   ⚠️  CHANGEZ CE MOT DE PASSE IMMÉDIATEMENT!")
    except sqlite3.IntegrityError:
        print("   ⚠️  L'utilisateur 'admin' existe déjà")

    # 8. Créer un utilisateur demo
    print("🎭 Création de l'utilisateur demo...")
    try:
        c.execute('''INSERT INTO users (username, password_hash, email, role, auth_type)
                     VALUES (?, ?, ?, ?, ?)''',
                  ('demo', hash_password('demo'), 'demo@example.com', 'demo', 'local'))
        print("   ✅ Utilisateur demo créé (username: demo, password: demo)")
    except sqlite3.IntegrityError:
        print("   ⚠️  L'utilisateur 'demo' existe déjà")

    conn.commit()
    conn.close()

    print("\n✅ Migration terminée avec succès!")
    print("\n📋 Prochaines étapes:")
    print("   1. Connectez-vous avec admin/admin123")
    print("   2. Changez le mot de passe admin")
    print("   3. Créez vos sociétés et utilisateurs")
    print("   4. Redémarrez le service: systemctl restart vpn-logger")

if __name__ == '__main__':
    migrate()
