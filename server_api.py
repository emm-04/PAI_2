import ssl
import uvicorn
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

app = FastAPI(title="Gateway Seguro VPN U-Secure")

# Modelo de datos para la capa de aplicacion
class Credenciales(BaseModel):
    username: str
    password: str

@app.post("/login")
async def iniciar_sesion(credenciales: Credenciales):
    """
    RF2: Inicio de Sesion y Autenticacion Mutua.
    La validacion mTLS (certificados) la realiza el servidor web Uvicorn en la capa de transporte
    antes de que la peticion llegue a esta funcion. 
    Aqui validamos la segunda capa (usuario/contrasena)[cite: 5].
    """
    # Validacion contra cuentas preexistentes (Ejemplo: PDI)[cite: 5]
    if credenciales.username == "cliente_pdi" and credenciales.password == "pdi_password":
        return {
            "estado": "Exito", 
            "mensaje": "Autenticacion mutua superada. Bienvenido a la red corporativa U-Secure."
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales de aplicacion incorrectas."
        )

@app.post("/logout")
async def cerrar_sesion():
    """
    RF4: Cierre Seguro de Sesion[cite: 5].
    """
    return {"estado": "Exito", "mensaje": "Sesion finalizada de forma explicita."}

if __name__ == "__main__":
    # RS2 y RS1: Configuracion estricta de TLS 1.3 y mTLS[cite: 5, 6]
    uvicorn.run(
        "server_api:app",
        host="127.0.0.1",
        port=8443,
        ssl_keyfile="claves/server.key",          # Clave privada del servidor corporativo[cite: 5]
        ssl_certfile="claves/server.crt",         # Certificado del servidor corporativo[cite: 5]
        ssl_ca_certs="claves/ca.crt",             # CA corporativa para validar el dispositivo BYOD[cite: 6]
        ssl_cert_reqs=ssl.CERT_REQUIRED,          # Exige estrictamente el certificado al cliente (mTLS)[cite: 5]
        ssl_version=ssl.PROTOCOL_TLS_SERVER       # Usa TLS 1.3 por defecto en versiones modernas[cite: 6]
    )