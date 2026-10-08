import socket
import threading
import requests
import urllib3
import sys
import time

# Ocultamos las advertencias de consola para simular un ataque limpio
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def ataque_suplantacion():
    print("\n" + "="*50)
    print("🚀 INICIANDO ATAQUE 1: SUPLANTACIÓN (ROGUE ACCESS)")
    print("="*50)
    print("[!] El atacante ha robado las credenciales en texto plano.")
    print("[!] Intentando login contra el servidor SIN poseer el certificado mTLS...")
    
    URL_SEGURO = "https://127.0.0.1:8443/login"
    payload_robado = {"username": "cliente_pdi", "password": "pdi_password"}

    try:
        # El atacante intenta conectar ignorando la seguridad y sin certificado
        requests.post(URL_SEGURO, json=payload_robado, verify=False, timeout=3)
        print("❌ FALLO CRÍTICO: El servidor permitió el acceso sin certificado.")
        
    except requests.exceptions.SSLError as e:
        print("✅ ATAQUE BLOQUEADO: El servidor exige certificado (mTLS).")
        print(f"Motivo de rechazo SSL: {e}")
        
    except requests.exceptions.ConnectionError:
        # Si el servidor corta la conexión TCP de raíz al no ver certificado
        print("✅ ATAQUE BLOQUEADO: El servidor exige certificado (mTLS).")
        print("Motivo: El servidor detectó la falta de certificado y cerró el socket abruptamente (Connection Reset).")

def espiar_trafico(origen, destino, direccion):
    try:
        while True:
            datos = origen.recv(4096)
            if not datos:
                break
            
            if direccion == "Cliente -> Servidor":
                print(f"\n[☠️ INTERCEPTANDO PAQUETE - {direccion}]")
                try:
                    # Intenta leer las contraseñas en texto plano
                    texto_plano = datos.decode('utf-8')
                    print(f"🔓 Texto capturado: {texto_plano}")
                except UnicodeDecodeError:
                    # Mensaje visual limpio sin mostrar los bytes crudos
                    print("    [!] Intentando extraer credenciales en texto claro...")
                    print("    ❌ ERROR DE LECTURA: Carga útil ininteligible.")
                    print("    🔒 ESTADO: Tráfico blindado por TLS 1.3 (Cifrado AEAD).")
                    
            destino.sendall(datos)
    except Exception:
        pass
    finally:
        origen.close()
        destino.close()

def servidor_mitm_en_segundo_plano(stop_event):
    HOST = "127.0.0.1"
    PUERTO_ATACANTE = 8444
    PUERTO_SERVIDOR_REAL = 8443

    socket_mitm = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_mitm.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        socket_mitm.bind((HOST, PUERTO_ATACANTE))
        socket_mitm.listen(5)
        socket_mitm.settimeout(1.0)
    except OSError:
        print(f"⚠️ El puerto {PUERTO_ATACANTE} está ocupado.")
        return

    while not stop_event.is_set():
        try:
            cliente_sock, direccion_victima = socket_mitm.accept()
            print(f"\n[!] Víctima conectada desde {direccion_victima}. Espiando el tráfico de red...")
            
            servidor_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            servidor_sock.connect((HOST, PUERTO_SERVIDOR_REAL))
            
            threading.Thread(target=espiar_trafico, args=(cliente_sock, servidor_sock, "Cliente -> Servidor"), daemon=True).start()
            threading.Thread(target=espiar_trafico, args=(servidor_sock, cliente_sock, "Servidor -> Cliente"), daemon=True).start()
        except socket.timeout:
            continue
        except Exception:
            break
            
    socket_mitm.close()

def ataque_mitm():
    print("\n" + "="*50)
    print("🕵️ INICIANDO ATAQUE 2: MAN-IN-THE-MIDDLE AUTOMATIZADO")
    print("="*50)
    
    # 1. Arrancar el nodo atacante en un hilo separado
    stop_event = threading.Event()
    hilo_mitm = threading.Thread(target=servidor_mitm_en_segundo_plano, args=(stop_event,))
    hilo_mitm.start()
    
    print("[!] Nodo atacante encendido. Esperando a la víctima...")
    time.sleep(1.5) # Damos tiempo al atacante a prepararse
    
    # 2. Simular a la víctima conectándose accidentalmente a la trampa (8444)
    print("[*] Simulando a la víctima enviando sus credenciales...")
    URL_TRAMPA = "https://127.0.0.1:8444/login"
    payload = {"username": "cliente_pdi", "password": "pdi_password"}
    certificados = ('claves/cliente.crt', 'claves/cliente.key')
    
    try:
        requests.post(URL_TRAMPA, json=payload, cert=certificados, verify="claves/ca.crt", timeout=5)
    except Exception as e:
        pass # Ignoramos los errores de la víctima, nos importa la consola del atacante
        
    time.sleep(1) # Esperamos a que los hilos de intercepción impriman en pantalla
    
    # 3. Apagar el ataque limpiamente
    print("\n[!] Simulación terminada. Cerrando nodo atacante.")
    stop_event.set()
    hilo_mitm.join()

def mostrar_menu():
    while True:
        print("\n" + "*"*50)
        print("🛡️  SUITE DE AUDITORÍA Y SIMULACIÓN DE ATAQUES 🛡️")
        print("*"*50)
        print("1. Simular Suplantación de Identidad (Rogue Access)")
        print("2. Simular Interceptación de Tráfico (Man-in-the-Middle)")
        print("3. Salir")
        
        opcion = input("\nSelecciona el vector de ataque (1-3): ").strip()
        
        if opcion == "1":
            ataque_suplantacion()
        elif opcion == "2":
            ataque_mitm()
        elif opcion == "3":
            print("Cerrando suite de auditoría...")
            sys.exit(0)
        else:
            print("Opción no válida. Introduce 1, 2 o 3.")

if __name__ == "__main__":
    mostrar_menu()