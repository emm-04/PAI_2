import sqlite3
import datetime
from pathlib import Path
import sys
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))
import security


DB_FILE = BASE_DIR / "DB/vpn_usecure.db"


def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Tabla de Usuarios y Roles Corporativos
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    userID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    role TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    cert_cn TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                 )''')


    # Tabla de Registro de Auditoría de Red
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
                    auditID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    username TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    details TEXT NOT NULL
                 )''')


    #Tabla de nonces
    c.execute('''CREATE TABLE IF NOT EXISTS nonces(
                    nonce TEXT NOT NULL primary key,
                    timestamp INTEGER NOT NULL,
                    UNIQUE(nonce, timestamp)
                )''')

    conn.commit()
    conn.close()

def get_connection():
     return sqlite3.connect(DB_FILE)

def add_user(username: str, role: str, password: str, cert_cn: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    salt, pwd_hash = security.hash_password(password)
    c.execute("INSERT OR REPLACE INTO users (username, role, salt, password_hash, cert_cn) VALUES (?, ?, ?, ?, ?)",
              (username, role, salt, pwd_hash, cert_cn))
    conn.commit()
    conn.close()

def log_audit_event(event_type: str, username: str, client_ip: str, details: str):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    c.execute("INSERT INTO audit_logs (timestamp, event_type, username, client_ip, details) VALUES (?, ?, ?, ?, ?)",
              (timestamp, event_type, username, client_ip, details))
    conn.commit()
    conn.close()
