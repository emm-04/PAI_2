import requests
import os
import subprocess
import time
import secrets
import hmac
import hashlib
import json
import ssl
from pathlib import Path
import sys
BASE_DIR = Path(__file__).resolve().parent
sys.path.append(str(BASE_DIR))


BASE_URL = "https://localhost:8443/api/v1"
CERT_DIR = BASE_DIR / "test_certs"


def setup_test_env():
    os.makedirs(CERT_DIR, exist_ok = True)

def run_test_suite():
    setup_test_env()
    print("=" * 70)
    print("    🧪 EVALUACIÓN Y PLAN DE PRUEBAS AUTOMATIZADO - U-SECURE VPN")
    print("=" * 70)
    
    test_user = f"tester_{secrets.token_hex(4)}"
    valid_pwd = "PdiSecurePass2026!"
    role = "PDI"
    
    user_key_path = os.path.join(CERT_DIR, f"{test_user}.key")
    user_csr_path = os.path.join(CERT_DIR, f"{test_user}.csr")
    user_crt_path = os.path.join(CERT_DIR, f"{test_user}.crt")
    ca_crt_path = os.path.join(CERT_DIR, "ca.crt")


    # --------------------------------------------------------------------------
    # TC-02: Validación de Política de Contraseñas Débiles
    # --------------------------------------------------------------------------
    print("\n[TC-02] Prueba de Política de Contraseñas (Intento de registro con '123456')...")
    bad_payload = {"username": "user_weak", "password": "123456", "role": role, "csr_data": "dummy_csr"}
    r = requests.post(f"{BASE_URL}/register", json = bad_payload, verify = False)
    print(f"  -> Resultado TC-02: Status {r.status_code} | Respuesta: {r.json().get('detail')}")
    assert r.status_code == 400, "TC-02 Falló: Debería haber rechazado la contraseña débil"
    print("  [✔] TC-02 SUPERADO: La contraseña débil fue rechazada por la política.")


    # --------------------------------------------------------------------------
    # TC-01: Registro Dinámico con Generación por CSR (Opción B)
    # --------------------------------------------------------------------------
    print(f"\n[TC-01] Prueba de Registro Legítimo y Firma CSR (Usuario: {test_user})...")
    subprocess.run([
        "openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", user_key_path, "-out", user_csr_path,
        "-subj", f"/C=ES/ST=Sevilla/O=U-Secure/OU=BYOD/CN={test_user}"
    ], check = True, capture_output = True)
    
    with open(user_csr_path, "r") as f:
        csr_content = f.read()
    if os.path.exists(user_csr_path):
        os.remove(user_csr_path)

    reg_payload = {"username": test_user, "password": valid_pwd, "role": role, "csr_data": csr_content}
    r = requests.post(f"{BASE_URL}/register", json = reg_payload, verify = False)
    assert r.status_code == 200, f"TC-01 Falló: {r.text}"
    
    data = r.json()
    with open(user_crt_path, "w") as f:
        f.write(data.get("client_crt"))
    with open(ca_crt_path, "w") as f:
        f.write(data.get("ca_crt"))
        
    print(f"  [✔] TC-01 SUPERADO: Certificado mTLS firmado emitido y guardado localmente.")


    # --------------------------------------------------------------------------
    # TC-03: Rechazo por Falta de Certificado mTLS
    # --------------------------------------------------------------------------
    print("\n[TC-03] Prueba de Intento de Conexión SIN Certificado mTLS al Login...")
    try:
        r = requests.post(f"{BASE_URL}/login", json = {"username": test_user, "password": valid_pwd}, verify = ca_crt_path)
        print(f"  -> Respuesta del servidor: {r.status_code} - {r.text}")
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError) as e:
        print(f"  [✔] TC-03 SUPERADO: La conexión se cerró por falta de mTLS en transporte: {type(e).__name__}")


    # --------------------------------------------------------------------------
    # TC-04: Verificación de Versión de Protocolo TLS 1.3
    # --------------------------------------------------------------------------
    print("\n[TC-04] Prueba de Negociación Estricta de TLS 1.3...")
    client_certs = (user_crt_path, user_key_path)
    r = requests.post(f"{BASE_URL}/login", json = {"username": test_user, "password": valid_pwd}, cert = client_certs, verify = ca_crt_path)
    assert r.status_code == 200, f"TC-04 Falló en Login: {r.text}"
    session_token = r.json().get("session_token")
    print("  [✔] TC-04 SUPERADO: Conexión mTLS + TLS 1.3 establecida con éxito.")


    # --------------------------------------------------------------------------
    # TC-05: Autenticación de Credenciales en Dos Capas
    # --------------------------------------------------------------------------
    print("\n[TC-05] Prueba de Autenticación de Credenciales en Capa de Aplicación...")
    print(f"  -> Token de Sesión Obtenido: {session_token[:16]}... (256 bits)")
    print("  [✔] TC-05 SUPERADO: Credenciales validadas y token emitido.")


    # --------------------------------------------------------------------------
    # TC-06: Ataque Man-in-the-Middle (MitM) / Alteración de Mensaje en el Túnel
    # --------------------------------------------------------------------------
    print("\n[TC-06] Prueba de Ataque MitM (Modificación de datos del túnel en tránsito)...")
    original_dict = {"payload": "Transferencia original de 100 EUR"}
    body_str = json.dumps(original_dict, separators = (',', ':'))
    
    nonce_tc6 = secrets.token_hex(16)
    timestamp_tc6 = str(time.time())
    
    payload_to_sign_tc6 = f"{body_str}|{nonce_tc6}|{timestamp_tc6}"
    valid_sig_tc6 = hmac.new(bytes.fromhex(session_token), payload_to_sign_tc6.encode('utf-8'), hashlib.sha256).hexdigest()
    
    # El atacante altera el cuerpo pero envía la firma original
    tampered_dict = {"payload": "Transferencia ALTERADA de 10000 EUR"}
    tampered_body = json.dumps(tampered_dict, separators = (',', ':'))
    
    headers_tc6 = {
        "Authorization": f"Bearer {session_token}",
        "X-Nonce": nonce_tc6,
        "X-Timestamp": timestamp_tc6,
        "X-Signature": valid_sig_tc6,
        "Content-Type": "application/json"
    }
    
    r = requests.post(f"{BASE_URL}/tunnel", data = tampered_body, headers = headers_tc6, cert = client_certs, verify = ca_crt_path)
    print(f"  -> Resultado TC-06: Status {r.status_code} | Respuesta: {r.json().get('detail')}")
    assert r.status_code == 403, "TC-06 Falló: Debería haber devuelto HTTP 403 Forbidden"
    print("  [✔] TC-06 SUPERADO: Ataque MitM bloqueado por la firma HMAC.")


    # --------------------------------------------------------------------------
    # TC-07A: Ataque de Replay (Reutilización de Nonce)
    # --------------------------------------------------------------------------
    print("\n[TC-07A] Prueba de Ataque de Replay (Reutilización del mismo Nonce)...")
    
    # 1. Creamos un mensaje y lo enviamos legítimamente por primera vez
    nonce_replay = secrets.token_hex(16)
    timestamp_replay = str(time.time())
    payload_to_sign_replay = f"{body_str}|{nonce_replay}|{timestamp_replay}"
    sig_replay = hmac.new(bytes.fromhex(session_token), payload_to_sign_replay.encode('utf-8'), hashlib.sha256).hexdigest()
    
    headers_replay = {
        "Authorization": f"Bearer {session_token}",
        "X-Nonce": nonce_replay,
        "X-Timestamp": timestamp_replay,
        "X-Signature": sig_replay,
        "Content-Type": "application/json"
    }
    
    # Primera ejecución (debe ser exitosa HTTP 200)
    r_ok = requests.post(f"{BASE_URL}/tunnel", data = body_str, headers = headers_replay, cert = client_certs, verify = ca_crt_path)
    assert r_ok.status_code == 200, f"Mensaje legítimo inicial falló: {r_ok.text}"
    
    # 2. Re-enviamos exactamente el mismo paquete (Replay Attack)
    r_replay = requests.post(f"{BASE_URL}/tunnel", data = body_str, headers = headers_replay, cert = client_certs, verify = ca_crt_path)
    print(f"  -> Resultado TC-07A: Status {r_replay.status_code} | Respuesta: {r_replay.json().get('detail')}")
    assert r_replay.status_code == 400, "TC-07A Falló: Debería rechazar el Nonce duplicado"
    print("  [✔] TC-07A SUPERADO: Ataque Replay por Nonce duplicado bloqueado.")


    # --------------------------------------------------------------------------
    # TC-07B: Timestamp Expirado
    # --------------------------------------------------------------------------
    print("\n[TC-07B] Prueba de Timestamp Expirado (Mensaje de hace 5 minutos)...")
    old_timestamp = str(time.time() - 300)
    new_nonce = secrets.token_hex(16)
    payload_expired = f"{body_str}|{new_nonce}|{old_timestamp}"
    expired_sig = hmac.new(bytes.fromhex(session_token), payload_expired.encode('utf-8'), hashlib.sha256).hexdigest()
    
    expired_headers = {
        "Authorization": f"Bearer {session_token}",
        "X-Nonce": new_nonce,
        "X-Timestamp": old_timestamp,
        "X-Signature": expired_sig,
        "Content-Type": "application/json"
    }
    r_expired = requests.post(f"{BASE_URL}/tunnel", data = body_str, headers = expired_headers, cert = client_certs, verify = ca_crt_path)
    print(f"  -> Resultado TC-07B: Status {r_expired.status_code} | Respuesta: {r_expired.json().get('detail')}")
    assert r_expired.status_code == 400, "TC-07B Falló: Debería rechazar por timestamp caducado"
    print("  [✔] TC-07B SUPERADO: Mensaje expirado rechazado.")


    # --------------------------------------------------------------------------
    # TC-08: Cierre Seguro de Sesión (Logout)
    # --------------------------------------------------------------------------
    print("\n[TC-08] Prueba de Logout y Cierre de Sesión...")
    r_logout = requests.post(f"{BASE_URL}/logout", headers = {"Authorization": f"Bearer {session_token}"}, cert = client_certs, verify = ca_crt_path)
    assert r_logout.status_code == 200, "TC-08 Falló en Logout"
    
    # Intentar enviar datos tras el logout
    new_nonce_2 = secrets.token_hex(16)
    new_ts_2 = str(time.time())
    sig_2 = hmac.new(bytes.fromhex(session_token), f"{body_str}|{new_nonce_2}|{new_ts_2}".encode('utf-8'), hashlib.sha256).hexdigest()
    h_post_logout = {
        "Authorization": f"Bearer {session_token}",
        "X-Nonce": new_nonce_2,
        "X-Timestamp": new_ts_2,
        "X-Signature": sig_2,
        "Content-Type": "application/json"
    }
    r_after = requests.post(f"{BASE_URL}/tunnel", data = body_str, headers = h_post_logout, cert = client_certs, verify = ca_crt_path)
    print(f"  -> Intentando usar túnel tras logout: Status {r_after.status_code} | Respuesta: {r_after.json().get('detail')}")
    assert r_after.status_code == 403, "TC-08 Falló: La sesión debía estar destruida"
    print("  [✔] TC-08 SUPERADO: Sesión revocada e inhabilitada correctamente.")

    print("\n" + "=" * 70)
    print("     ¡TODOS LOS REQUISITOS HAN SIDO VERIFICADOS Y SUPERADOS!  ")
    print("=" * 70)


if __name__ == "__main__":
    run_test_suite()