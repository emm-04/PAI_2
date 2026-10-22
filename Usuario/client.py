import hashlib
import hmac
import json
import secrets
import time
import requests
import os
import subprocess
from pathlib import Path
import sys
BASE_DIR = Path(__file__).resolve().parent
sys.path.append(str(BASE_DIR))


BASE_URL = "https://localhost:8443/api/v1"
CERT_DIR = BASE_DIR / "client_certs"  # Carpeta donde el usuario almacena su certificado personal


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    print("=" * 65)
    print("        🛡️  U-SECURE VPN GATEWAY - PORTAL BYOD SEGURO  🛡️")
    print("        [ Cifrado TLS 1.3 | mTLS | HMAC-SHA256 | Nonce ]")
    print("=" * 65)

def register_flow():
    clear_screen()
    print_banner()
    print("\n" + "=" * 65)
    print("          📝 REGISTRO DE NUEVO USUARIO CORPORATIVO")
    print("=" * 65)
    username = input("  👤 Usuario corporativo (ej: pdi_alice): ").strip()
    password = input("  🔒 Contraseña (Mín. 8 chars, Mayús, minús, num, símbolo): ").strip()
    role = input("  🎓 Rol institucional (PDI / PAS / Investigador): ").strip()
    
    if not username or not password or not role:
        print("\n  [✖] Error: Todos los campos son obligatorios.")
        input("\n  [⏎] Pulsa ENTER para volver al menú principal...")
        return

    user_key_path = os.path.join(CERT_DIR, f"{username}.key")
    user_csr_path = os.path.join(CERT_DIR, f"{username}.csr")
    
    print("\n  [⏳] Generando clave privada y solicitud CSR localmente...")
    try:
        subprocess.run([
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", user_key_path, "-out", user_csr_path,
            "-subj", f"/C=ES/ST=Sevilla/O=U-Secure/OU=BYOD/CN={username}"
        ], check=True, capture_output=True)
        
        with open(user_csr_path, "r") as f:
            csr_content = f.read()
        if os.path.exists(user_csr_path):
            os.remove(user_csr_path)
            
        print(f"  [✔] Clave privada almacenada de forma segura en: {user_key_path}")
        
    except Exception as e:
        print(f"  [✖] Error crítico generando credenciales locales con OpenSSL: {e}")
        input("\n  [⏎] Pulsa ENTER para volver al menú principal...")
        return
    
    print("  [⏳] Conectando con el Gateway de U-Secure para registrar y firmar...")
    try:
        payload = {"username": username, "password": password, "role": role, "csr_data": csr_content}
        res = requests.post(f"{BASE_URL}/register", json = payload, verify = False, timeout = 10)
        
        if res.status_code == 200:
            data = res.json()
            print(f"\n  [✔] {data.get('message')}")
            
            with open(os.path.join(CERT_DIR, f"{username}.crt"), "w") as f:
                f.write(data.get("client_crt"))
            with open(os.path.join(CERT_DIR, "ca.crt"), "w") as f:
                f.write(data.get("ca_crt"))
                
            print(f"  [✔] Certificado mTLS y CA instalados correctamente en '{CERT_DIR}/'.")
        else:
            err_detail = res.json().get('detail', res.text)
            print(f"\n  [✖] Error de registro (HTTP {res.status_code}): {err_detail}")
            
    except requests.exceptions.ConnectionError:
        print("\n  [✖] Error de red: No se pudo conectar con el servidor Gateway (¿Está encendido server_api.py?).")
    except Exception as e:
        print(f"\n  [✖] Error inesperado en el registro: {e}")
        
    input("\n  [⏎] Pulsa ENTER para volver al menú principal...")

def user_session_menu(username, session_token, role, client_certs, ca_file):
    auth_header = {"Authorization": f"Bearer {session_token}"}
    
    while True:
        clear_screen()
        print_banner()
        print(f"\n  [ 🟢 SESIÓN ACTIVA | USUARIO: {username} | ROL: {role} ]")
        print("  ------------------------------------------------")
        print("  1. 🚇 Enviar Mensaje por el Túnel VPN (Seguro HMAC)")
        print("  2. ℹ️  Ver Estado de Conexión y Credenciales")
        print("  3. 🚪 Cerrar Sesión (Logout y Volver al Menú Principal)")
        print("  ------------------------------------------------")
        
        sub_op = input("\n  👉 Selecciona una opción (1-3): ").strip()
        
        if sub_op == "3":
            print("\n  [⏳] Cerrando sesión en el servidor y destruyendo claves efímeras...")
            try:
                logout_res = requests.post(f"{BASE_URL}/logout", headers = auth_header, cert = client_certs, verify = ca_file, timeout = 5)
                if logout_res.status_code == 200:
                    print(f"  [✔] {logout_res.json().get('message')}")
                else:
                    print("  [✔] Sesión finalizada localmente.")
            except Exception:
                print("  [✔] Sesión finalizada localmente (servidor no disponible).")
            input("\n  [⏎] Pulsa ENTER para volver al menú principal...")
            break
            
        elif sub_op == "2":
            clear_screen()
            print_banner()
            print(f"\n  [📊 ESTADO DE LA CONEXIÓN BYOD]")
            print(f"  ---------------------------------------------------")
            print(f"  • Usuario Corporativo : {username}")
            print(f"  • Rol Institucional   : {role}")
            print(f"  • Token de Sesión     : {session_token[:16]}... (Activo)")
            print(f"  • Seguridad de Red    : TLS 1.3 con mTLS Estricto")
            print(f"  • Integridad de Datos : HMAC-SHA256 con Nonce Anti-Replay")
            print(f"  ---------------------------------------------------")
            input("\n  [⏎] Pulsa ENTER para volver al menú de usuario...")
            
        elif sub_op == "1":
            clear_screen()
            print_banner()
            print(f"\n  [🚇 TÚNEL VPN ACTIVO] - Escribe 'salir' para volver al menú de usuario.\n")
            
            while True:
                msg = input(f"  ({username}@u-secure-vpn) ➜ ").strip()
                if not msg:
                    continue
                if msg.lower() == 'salir':
                    break
                
                try:
                    tunnel_data_dict = {"payload": msg}
                    body_str = json.dumps(tunnel_data_dict, separators = (',', ':'))
                    
                    nonce = secrets.token_hex(16)
                    timestamp = str(time.time())
                    
                    payload_to_sign = f"{body_str}|{nonce}|{timestamp}"
                    signature = hmac.new(
                        bytes.fromhex(session_token),
                        payload_to_sign.encode('utf-8'),
                        hashlib.sha256
                    ).hexdigest()
                    
                    headers = {
                        "Authorization": f"Bearer {session_token}",
                        "X-Nonce": nonce,
                        "X-Timestamp": timestamp,
                        "X-Signature": signature,
                        "Content-Type": "application/json"
                    }
                    
                    tunnel_res = requests.post(
                        f"{BASE_URL}/tunnel", 
                        data = body_str, 
                        headers = headers, 
                        cert = client_certs, 
                        verify = ca_file,
                        timeout = 10
                    )
                    
                    if tunnel_res.status_code == 200:
                        print(f"    ↳ [Servidor Corporativo]: {tunnel_res.json().get('echo')}")
                    else:
                        err_msg = tunnel_res.json().get('detail', tunnel_res.text)
                        print(f"    ↳ [✖] Error de seguridad (HTTP {tunnel_res.status_code}): {err_msg}")
                        
                except requests.exceptions.ConnectionError:
                    print(f"    ↳ [✖] Error de red: Se perdió la conexión con el Gateway VPN.")
                    break
                except Exception as e:
                    print(f"    ↳ [✖] Error al procesar el mensaje del túnel: {e}")
                    break
        else:
            input("\n  [!] Opción no válida. Pulsa ENTER para continuar...")

def login_flow():
    clear_screen()
    print_banner()
    print("\n" + "=" * 65)
    print("               🔐 AUTENTICACIÓN Y CONEXIÓN VPN")
    print("=" * 65)
    username = input("  👤 Usuario: ").strip()
    password = input("  🔑 Contraseña: ").strip()
    
    if not username or not password:
        print("\n  [✖] Error: Usuario y contraseña son obligatorios.")
        input("\n  [⏎] Pulsa ENTER para volver al menú principal...")
        return

    cert_file = os.path.join(CERT_DIR, f"{username}.crt")
    key_file = os.path.join(CERT_DIR, f"{username}.key")
    ca_file = os.path.join(CERT_DIR, "ca.crt")
    
    if not os.path.exists(cert_file) or not os.path.exists(key_file) or not os.path.exists(ca_file):
        print(f"\n  [✖] Error: No se encontraron las credenciales mTLS para '{username}' en '{CERT_DIR}/'.")
        print("      Por favor, regístrese primero utilizando la opción 2 del menú principal.")
        input("\n  [⏎] Pulsa ENTER para volver al menú principal...")
        return
        
    client_certs = (cert_file, key_file)
    
    print("\n  [⏳] Estableciendo canal seguro TLS 1.3 con Autenticación Mutua (mTLS)...")
    try:
        login_res = requests.post(
            f"{BASE_URL}/login", 
            json = {"username": username, "password": password}, 
            cert = client_certs, 
            verify = ca_file,
            timeout = 10
        )
        
        if login_res.status_code == 200:
            login_data = login_res.json()
            session_token = login_data.get("session_token")
            role = login_data.get("role")
            
            # Entrar al menú de usuario autenticado
            user_session_menu(username, session_token, role, client_certs, ca_file)
        else:
            print(f"\n  [✖] Error de autenticación (HTTP {login_res.status_code}): {login_res.text}")
            input("\n  [⏎] Pulsa ENTER para volver al menú principal...")
            
    except requests.exceptions.ConnectionError:
        print("\n  [✖] Error de red: No se pudo conectar con el servidor Gateway (¿Está encendido server_api.py?).")
        input("\n  [⏎] Pulsa ENTER para volver al menú principal...")
    except requests.exceptions.SSLError as e:
        print(f"\n  [✖] Error de validación mTLS / TLS 1.3: {e}")
        input("\n  [⏎] Pulsa ENTER para volver al menú principal...")
    except Exception as e:
        print(f"\n  [✖] Error crítico en la conexión segura: {e}")
        input("\n  [⏎] Pulsa ENTER para volver al menú principal...")

def run_client():
    os.makedirs(CERT_DIR, exist_ok = True)
    
    # Bucle principal de la aplicación: nunca crashe ni sale a menos que el usuario lo elija
    while True:
        clear_screen()
        print_banner()
        print("\n  [ MENU PRINCIPAL ]")
        print("  ------------------------------------------------")
        print("  1. 🔑 Iniciar Sesión en la Red Corporativa")
        print("  2. 📝 Registrar Nueva Cuenta y Generar Credenciales")
        print("  3. 🚪 Salir de la Aplicación")
        print("  ------------------------------------------------")
        
        op = input("\n  👉 Selecciona una opción (1-3): ").strip()
        
        if op == "3":
            clear_screen()
            print("\n  👋 Saliendo del portal corporativo U-Secure. ¡Hasta pronto!\n")
            break
        elif op == "1":
            login_flow()
        elif op == "2":
            register_flow()
        else:
            input("\n  [!] Opción no válida. Pulsa ENTER para continuar...")

if __name__ == "__main__":
    run_client()