import os
import subprocess
from pathlib import Path
import sys
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

CERT_DIR = BASE_DIR / "DB/certs"


def run_cmd(cmd_list: list) -> bool:
    result = subprocess.run(cmd_list, capture_output = True, text = True)
    if result.returncode != 0:
        print(f"[!] Error ejecutando comando: {' '.join(cmd_list)}\n{result.stderr}")
        return False
    return True

def generate_pki():
    os.makedirs(CERT_DIR, exist_ok = True)
    print("[*] Limpiando certificados anteriores...")
    for f in os.listdir(CERT_DIR):
        if f.endswith(('.crt', '.key', '.csr', '.srl')):
            try:
                os.remove(os.path.join(CERT_DIR, f))
            except Exception:
                pass


    print("[*] Generando Autoridad de Certificación (CA) Corporativa U-Secure...")
    # 1. CA Root
    run_cmd([
        "openssl", "req", "-x509", "-newkey", "rsa:4096", "-nodes",
        "-keyout", f"{CERT_DIR}/ca.key", "-out", f"{CERT_DIR}/ca.crt",
        "-days", "365", "-subj", "/C=ES/ST=Sevilla/O=U-Secure/CN=U-Secure-Root-CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign"
    ])

    
    print("[*] Generando Certificado Digital para el Servidor VPN (Gateway)...")
    # 2. Servidor VPN con SANs para localhost y 127.0.0.1
    run_cmd([
        "openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", f"{CERT_DIR}/server.key", "-out", f"{CERT_DIR}/server.csr",
        "-subj", "/C=ES/ST=Sevilla/O=U-Secure/CN=vpn.usecure.es",
        "-addext", "subjectAltName=DNS:vpn.usecure.es,DNS:localhost,IP:127.0.0.1"
    ])
    
    # IMPORTANTE: -copy_extensions copy permite heredar el subjectAltName del CSR al certificado final
    run_cmd([
        "openssl", "x509", "-req", "-in", f"{CERT_DIR}/server.csr",
        "-CA", f"{CERT_DIR}/ca.crt", "-CAkey", f"{CERT_DIR}/ca.key",
        "-CAcreateserial", "-out", f"{CERT_DIR}/server.crt", "-days", "365",
        "-copy_extensions", "copy"
    ])

    if os.path.exists(CERT_DIR/"server.csr"):
            os.remove(CERT_DIR/"server.csr")
    
    # # 3. Certificados para dispositivos BYOD (mTLS Clientes)
    # clients = ["pdi_alice", "pas_bob", "investigador_carol"]
    # for user in clients:
    #     print(f"[*] Emitiendo certificado cliente mTLS para: {user}...")
    #     run_cmd([
    #         "openssl", "req", "-newkey", "rsa:2048", "-nodes",
    #         "-keyout", f"{CERT_DIR}/{user}.key", "-out", f"{CERT_DIR}/{user}.csr",
    #         "-subj", f"/C=ES/ST=Sevilla/O=U-Secure/OU=BYOD/CN={user}"
    #     ])
    #     run_cmd([
    #         "openssl", "x509", "-req", "-in", f"{CERT_DIR}/{user}.csr",
    #         "-CA", f"{CERT_DIR}/ca.crt", "-CAkey", f"{CERT_DIR}/ca.key",
    #         "-CAcreateserial", f"-out", f"{CERT_DIR}/{user}.crt", "-days", "365"
    #     ])

    print("[+] PKI corporativa generada exitosamente en la carpeta './certs'.")
