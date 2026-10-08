import requests
import time
import concurrent.futures

URL_SEGURO = "https://127.0.0.1:8443/login"
URL_INSEGURO = "http://127.0.0.1:8080/login"
NUM_USUARIOS = 300

payload = {"username": "cliente_pdi", "password": "pdi_password"}

def peticion_insegura(_):
    """Petición HTTP normal sin cifrado (Baseline)"""
    try:
        requests.post(URL_INSEGURO, json=payload)
    except Exception as e:
        pass # Ignoramos errores individuales para no ensuciar la consola

def peticion_segura(_):
    """Petición HTTPS exigiendo TLS 1.3 y mTLS"""
    try:
        requests.post(
            URL_SEGURO,
            json=payload,
            verify="claves/ca.crt",
            cert=("claves/cliente.crt", "claves/cliente.key")
        )
    except Exception as e:
        pass

if __name__ == "__main__":
    print(f"--- Iniciando Benchmarking: {NUM_USUARIOS} usuarios concurrentes ---")
    
    # 1. Prueba Baseline (HTTP)
    print("\n1. Atacando servidor HTTP (Sin Cifrar)...")
    inicio_http = time.time()
    # Usamos 100 hilos de trabajo paralelos para procesar las 300 peticiones
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(peticion_insegura, range(NUM_USUARIOS))
    tiempo_http = time.time() - inicio_http
    print(f"-> Tiempo total HTTP: {tiempo_http:.3f} segundos")

    # 2. Prueba VPN (HTTPS + mTLS)
    print("\n2. Atacando servidor HTTPS (TLS 1.3 + mTLS)...")
    inicio_https = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(peticion_segura, range(NUM_USUARIOS))
    tiempo_https = time.time() - inicio_https
    print(f"-> Tiempo total HTTPS: {tiempo_https:.3f} segundos")

    # 3. Resultados y Conclusiones (RS3)
    overhead = tiempo_https - tiempo_http
    aumento_porcentaje = (overhead / tiempo_http) * 100
    
    print("\n--- RESULTADOS DEL REQUISITO RS3 ---")
    print(f"Sobrecarga (Overhead) criptográfica total: {overhead:.3f} segundos")
    print(f"El cifrado y los certificados hacen la conexión un {aumento_porcentaje:.1f}% más lenta.")
    print("Nota para el informe: Este overhead es el coste del handshake de TLS 1.3 y la validación de certificados X.509v3.")