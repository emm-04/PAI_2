import socket
import ssl
import time
import concurrent.futures
import statistics
import requests
import os
import subprocess
import secrets
import hmac
import hashlib
import json
from pathlib import Path
import sys
BASE_DIR = Path(__file__).resolve().parent
sys.path.append(str(BASE_DIR))


SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8443
BASE_URL = f"https://{SERVER_HOST}:{SERVER_PORT}/api/v1"
CONCURRENT_USERS = 300  # Requisito de concurrencia del proyecto
CERT_DIR = BASE_DIR / "bench_certs"


def setup_user(user_id: int) -> tuple:
    """Registra y genera credenciales mTLS únicas para cada usuario del benchmark."""
    username = f"user_bench_{user_id}"
    cert_file = os.path.join(CERT_DIR, f"{username}.crt")
    key_file = os.path.join(CERT_DIR, f"{username}.key")
    csr_file = os.path.join(CERT_DIR, f"{username}.csr")
    
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return cert_file, key_file  # Ya existen

    os.makedirs(CERT_DIR, exist_ok = True)
    try:
        # Generar clave privada y CSR local para el usuario
        subprocess.run([
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key_file, "-out", csr_file,
            "-subj", f"/C=ES/ST=Sevilla/O=U-Secure/OU=Bench/CN={username}"
        ], check = True, capture_output = True)
        
        with open(csr_file, "r") as f:
            csr_content = f.read()
        if os.path.exists(csr_file):
            os.remove(csr_file)
            
        # Registrar en el servidor
        res = requests.post(f"{BASE_URL}/register", json = {
            "username": username,
            "password": "PdiSecurePass2026!",
            "role": "PDI",
            "csr_data": csr_content
        }, verify = False, timeout = 10)
        
        if res.status_code == 200:
            data = res.json()
            with open(cert_file, "w") as f:
                f.write(data.get("client_crt"))
            with open(os.path.join(CERT_DIR, "ca.crt"), "w") as f:
                f.write(data.get("ca_crt"))
            return cert_file, key_file
    except Exception as e:
        print(f"[!] Error preparando usuario {username}: {e}")
    return None, None

def simulate_user_session(user_id: int) -> tuple:
    """Simula el flujo completo de un usuario único (Login + Túnel con HMAC)."""
    username = f"user_bench_{user_id}"
    cert_file = os.path.join(CERT_DIR, f"{username}.crt")
    key_file = os.path.join(CERT_DIR, f"{username}.key")
    ca_file = os.path.join(CERT_DIR, "ca.crt")
    
    client_certs = (cert_file, key_file)
    start_time = time.time()
    
    try:
        # 1. Petición de Login a través de mTLS y TLS 1.3
        login_res = requests.post(
            f"{BASE_URL}/login",
            json = {"username": username, "password": "PdiSecurePass2026!"},
            cert = client_certs,
            verify = ca_file,
            timeout = 15
        )
        if login_res.status_code != 200:
            return False, time.time() - start_time, f"Login falló: HTTP {login_res.status_code} - {login_res.text}"
            
        session_token = login_res.json().get("session_token")
        
        # 2. Envío de datos por el túnel cifrado aplicando integridad HMAC (PAI-1)
        tunnel_data_dict = {"payload": f"Benchmark payload from {username}"}
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
            timeout = 15
        )
        
        if tunnel_res.status_code != 200:
            return False, time.time() - start_time, f"Tunnel falló: HTTP {tunnel_res.status_code} - {tunnel_res.text}"
            
        elapsed = time.time() - start_time
        return True, elapsed, "OK"
        
    except Exception as e:
        return False, time.time() - start_time, str(e)

def run_benchmark():
    print("=" * 65)
    print(f"    🚀 BENCHMARK MULTIUSUARIO REAL ({CONCURRENT_USERS} CLIENTES)")
    print("=" * 65)
    
    print(f"[*] Preparando y registrando credenciales únicas para {CONCURRENT_USERS} usuarios...")
    start_prep = time.time()
    
    # Pre-generar credenciales en paralelo para acelerar el inicio de la prueba
    with concurrent.futures.ThreadPoolExecutor(max_workers = 30) as executor:
        list(executor.map(setup_user, range(CONCURRENT_USERS)))
        
    print(f"[+] Credenciales listas en {time.time() - start_prep:.2f} segundos.\n")
    print(f"[*] Lanzando carga concurrente sobre el Gateway U-Secure...")
    
    latencies = []
    success_count = 0
    fail_count = 0
    error_reasons = {}
    
    start_total = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers = 50) as executor:
        futures = [executor.submit(simulate_user_session, i) for i in range(CONCURRENT_USERS)]
        for future in concurrent.futures.as_completed(futures):
            success, elapsed, reason = future.result()
            if success:
                success_count += 1
                latencies.append(elapsed)
            else:
                fail_count += 1
                error_reasons[reason] = error_reasons.get(reason, 0) + 1
                
    total_time = time.time() - start_total
    
    print("\n" + "=" * 65)
    print("               📊 INFORME DE RESULTADOS DEL BENCHMARK")
    print("=" * 65)
    print(f" • Total de Sesiones Simuladas : {CONCURRENT_USERS}")
    print(f" • Sesiones Exitosas           : {success_count} ({success_count/CONCURRENT_USERS*100:.1f}%)")
    print(f" • Sesiones Fallidas           : {fail_count} ({fail_count/CONCURRENT_USERS*100:.1f}%)")
    print(f" • Tiempo Total de Ejecución   : {total_time:.2f} segundos")
    
    if latencies:
        print(f" • Latencia Media (mTLS+API)   : {statistics.mean(latencies)*1000:.2f} ms")
        print(f" • Latencia Mínima             : {min(latencies)*1000:.2f} ms")
        print(f" • Latencia Máxima             : {max(latencies)*1000:.2f} ms")
        print(f" • Throughput del Sistema      : {CONCURRENT_USERS/total_time:.2f} peticiones/segundo")
        
    if error_reasons:
        print("\n [!] Motivos de fallo registrados:")
        for reason, count in error_reasons.items():
            print(f"     - {reason}: {count} ocurrencias")
    print("=" * 65)


if __name__ == "__main__":
    run_benchmark()