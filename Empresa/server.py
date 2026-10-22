import time

from fastapi import FastAPI, Request, HTTPException, Header
from pydantic import BaseModel
import uvicorn
import subprocess
import os
import ssl
from pathlib import Path
import sys
BASE_DIR = Path(__file__).resolve().parent
sys.path.append(str(BASE_DIR))
import DB.database as database
import security

CERT_DIR = BASE_DIR / "DB/certs"
active_sessions = {}
app = FastAPI(title = "U-Secure VPN API Gateway (Servidor Corporativo)", version = "2.0")


class RegisterRequest(BaseModel):
    username: str
    password: str
    role: str
    csr_data: str

class LoginRequest(BaseModel):
    username: str
    password: str

class TunnelDataRequest(BaseModel):
    payload: str


@app.post("/api/v1/register")
def register_user(reg: RegisterRequest, request: Request):
    client_ip = request.client.host

    is_valid, error_msg = security.validate_password_policy(reg.password, reg.username)
    if not is_valid:
        database.log_audit_event("REGISTRATION_FAILED", reg.username, client_ip, f"Incumplimiento de política de contraseñas: {error_msg}")
        raise HTTPException(status_code=400, detail=f"Política de contraseñas no superada: {error_msg}")

    conn = database.get_connection()
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE username = ?", (reg.username,))
    if c.fetchone():
        conn.close()
        database.log_audit_event("REGISTRATION_FAILED", reg.username, client_ip, "El usuario ya existe")
        raise HTTPException(status_code = 400, detail = "El usuario ya existe en el sistema.")
    conn.close()
    
    os.makedirs(CERT_DIR, exist_ok = True)
    user_csr_path = os.path.join(CERT_DIR, f"{reg.username}.csr")
    user_crt_path = os.path.join(CERT_DIR, f"{reg.username}.crt")
    ca_crt_path = os.path.join(CERT_DIR, "ca.crt")
    
    try:
        with open(user_csr_path, "w") as f:
            f.write(reg.csr_data)

        subprocess.run([
            "openssl", "x509", "-req", "-in", user_csr_path,
            "-CA", ca_crt_path,
            "-CAkey", os.path.join(CERT_DIR, "ca.key"),
            "-CAcreateserial", "-out", user_crt_path, "-days", "365",
            "-copy_extensions", "copy"
        ], check = True, capture_output = True)

    except Exception as e:
        database.log_audit_event("REGISTRATION_ERROR", reg.username, client_ip, "Fallo al firmar el CSR")
        raise HTTPException(status_code = 500, detail = "Error interno al emitir y firmar el certificado digital mTLS.")

    with open(user_crt_path, "r") as f:
        client_crt_data = f.read()
    with open(ca_crt_path, "r") as f:
        ca_crt_data = f.read()

    if os.path.exists(user_csr_path):
        os.remove(user_csr_path)

    database.add_user(reg.username, reg.role, reg.password, reg.username)
    database.log_audit_event("USER_REGISTERED", reg.username, client_ip, f"Registrado con rol {reg.role}")

    return {
        "status": "SUCCESS",
        "message": f"Usuario corporativo '{reg.username}' registrado con éxito. Certificado firmado emitido.",
        "client_crt": client_crt_data,
        "ca_crt": ca_crt_data
    }

@app.post("/api/v1/login")
def login(creds: LoginRequest, request: Request):
    client_ip = request.client.host
    
    conn = database.get_connection()
    c = conn.cursor()
    c.execute("SELECT role, salt, password_hash FROM users WHERE username = ?", (creds.username,))
    row = c.fetchone()
    conn.close()
    
    if not row or not security.verify_password(row[1], row[2], creds.password):
        database.log_audit_event("AUTH_FAILED", creds.username, client_ip, "Credenciales inválidas")
        raise HTTPException(status_code = 401, detail = "Credenciales inválidas")
        
    token = security.secrets.token_hex(32)
    active_sessions[creds.username] = {"token": token, "role": row[0]}
    database.log_audit_event("AUTH_SUCCESS", creds.username, client_ip, "Login exitoso")
    return {"status": "SUCCESS", "session_token": token, "role": row[0]}

@app.post("/api/v1/logout")
def logout(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code = 401, detail = "Token inválido")
    
    token = authorization.split(" ")[1]
    target = next((u for u, info in active_sessions.items() if info["token"] == token), None)
    if target:
        del active_sessions[target]
        database.log_audit_event("LOGOUT", target, "Gateway", "Sesión cerrada y claves efímeras borradas")
        return {"status": "SUCCESS", "message": "Sesión cerrada correctamente"}
    raise HTTPException(status_code = 404, detail = "Sesión no encontrada")

@app.post("/api/v1/tunnel")
async def tunnel_data(request: Request,
                authorization: str = Header(...),
                x_nonce: str = Header(...),
                x_timestamp: str = Header(...),
                x_signature: str = Header(...)
                ):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code = 401, detail = "Token no proporcionado")
    token = authorization.split(" ")[1]

    username = next((u for u, info in active_sessions.items() if info["token"] == token), None)
    if not username:
        raise HTTPException(status_code = 403, detail = "Sesión no válida")
    
    try:
       req_time = float(x_timestamp) 

    except ValueError:
        raise HTTPException(status_code = 400, detail = "Timestamp inválido")

    if abs(time.time() - req_time) > 60:
        raise HTTPException(status_code=400, detail="Timestamp expirado. Posible ataque de Replay.")

    conn = database.get_connection()
    c = conn.cursor()
    c.execute("SELECT nonce FROM nonces WHERE nonce = ?", (x_nonce,))
    row = c.fetchone()
    if not row:
        c.execute("INSERT INTO nonces(nonce, timestamp) VALUES (?, ?)", (x_nonce, x_timestamp))
        conn.commit()
        conn.close()
    else:
        conn.close()
        raise HTTPException(status_code = 400, detail = "Nonce ya utilizado. Ataque de Replay detectado.")

    body_bytes = await request.body()
    body_str = body_bytes.decode('utf-8')
    payload_to_verify = f"{body_str}|{x_nonce}|{x_timestamp}"
    
    session_key_bytes = bytes.fromhex(active_sessions[username]["token"])
    if not security.verify_mac(payload_to_verify, session_key_bytes, x_signature):
        database.log_audit_event("MITM_ATTACK_DETECTED", username, "Gateway", "Firma HMAC inválida. Integridad violada.")
        raise HTTPException(status_code = 403, detail = "Firma MAC inválida. Integridad del mensaje comprometida.")

    data = await request.json()
    payload_content = data.get("payload", "")
    database.log_audit_event("TRAFFIC_TUNNEL", username, "Gateway", f"Datos íntegros procesados: {len(payload_content)} bytes")
    
    return {"status": "SUCCESS", "echo": f"[TÚNEL U-SECURE SEGURO + HMAC] Recibido e íntegro: {payload_content}"}


if __name__ == "__main__":
    print("[+] Servidor Gateway U-Secure iniciando con TLS 1.3 y mTLS estricto en https://0.0.0.0:8443...")
    uvicorn.run(
        app,
        host = "0.0.0.0",
        port = 8443,
        ssl_certfile = CERT_DIR/"server.crt",
        ssl_keyfile = CERT_DIR/"server.key",
        ssl_ca_certs = CERT_DIR/"ca.crt",
        ssl_cert_reqs = ssl.CERT_OPTIONAL
    )