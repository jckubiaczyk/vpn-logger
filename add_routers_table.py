#!/usr/bin/env python3
"""
Script pour ajouter la table router_devices à la base de données
"""

import sqlite3

DB_PATH = '/var/www/html/vpn-logger/vpn_logs.db'

def add_routers_table():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    print("🔄 Ajout de la table router_devices...")

    # Créer la table router_devices
    c.execute('''CREATE TABLE IF NOT EXISTS router_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        unifi_host TEXT UNIQUE,
        alarm_id TEXT,
        company_id INTEGER NOT NULL,
        description TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
    )''')

    print("✅ Table 'router_devices' créée")

    # Ajouter le routeur par défaut "UDM Pro SE - Fresnes sur Escaut" → NIDAPLAST
    try:
        c.execute('''INSERT INTO router_devices (name, unifi_host, alarm_id, company_id, description)
                     VALUES (?, ?, ?, ?, ?)''',
                  ('UDM Pro SE - Fresnes sur Escaut',
                   'UDM Pro SE - Fresnes sur Escaut',
                   '0199b8f8-31d0-7a22-bd3f-fa94e3ede1d7',
                   1,
                   'Routeur principal NIDAPLAST'))
        print("✅ Routeur par défaut ajouté (UDM Pro SE → NIDAPLAST)")
    except sqlite3.IntegrityError:
        print("⚠️  Routeur par défaut existe déjà")

    conn.commit()
    conn.close()

    print("\n✅ Migration terminée avec succès!")
    print("\n📋 Prochaines étapes:")
    print("   1. Les événements seront automatiquement assignés à la bonne société")
    print("   2. Gérez les routeurs depuis l'interface admin")
    print("   3. Redémarrez le service: systemctl restart vpn-logger")

if __name__ == '__main__':
    add_routers_table()
