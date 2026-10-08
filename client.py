import requests
import json
import time

# URLs del servidor
URL_LOGIN = "https://127.0.0.1:8443/login"
URL_LOGOUT = "https://127.0.0.1:8443/logout"

payload = {
    "username": "cliente_pdi",
    "password": "pdi_password"
}

print("Iniciando cliente VPN BYOD...")

# Usamos una 'Session' para mantener el túnel de transporte vivo entre peticiones
with requests.Session() as sesion_vpn:
    # 1. Aplicamos la configuración mTLS a toda la sesión
    sesion_vpn.verify = "claves/ca.crt"
    sesion_vpn.cert = ("claves/cliente.crt", "claves/cliente.key")
    
    try:
        # 2. INICIO DE SESIÓN (Establecimiento del túnel y autenticación)
        print("\n--- 1. Estableciendo túnel e iniciando sesión ---")
        respuesta_login = sesion_vpn.post(URL_LOGIN, json=payload)
        print(f"Estado HTTP: {respuesta_login.status_code}")
        print(json.dumps(respuesta_login.json(), indent=4, ensure_ascii=False))
        
        # Simulamos que el usuario está trabajando dentro de la red corporativa
        print("\n[Túnel mTLS activo - Usuario conectado a la VPN]")
        time.sleep(2) # Pausa de 2 segundos para simular actividad
        
        # 3. CIERRE DE SESIÓN EXPLÍCITO (Requisito RF4)
        print("\n--- 2. Cerrando sesión y desmontando el túnel ---")
        respuesta_logout = sesion_vpn.post(URL_LOGOUT)
        print(f"Estado HTTP: {respuesta_logout.status_code}")
        print(json.dumps(respuesta_logout.json(), indent=4, ensure_ascii=False))
        
    except requests.exceptions.SSLError as e:
        print(f"Error de cifrado/TLS (Autenticación fallida): {e}")
    except requests.exceptions.ConnectionError:
        print("Error de conexión. Asegúrate de que el servidor FastAPI está en ejecución.")

# Al salir del bloque 'with', la sesión se cierra automáticamente.
# Esto destruye el socket a nivel de sistema operativo y borra las claves de Perfect Forward Secrecy.
print("\n[Túnel destruido a nivel de transporte (Cierre RF4 completado).]")