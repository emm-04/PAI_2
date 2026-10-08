import os
import subprocess
import json

ARCHIVO_BBDD = "bd_usuarios.json"

# Novedad: Detectar automáticamente la ruta de OpenSSL para que funcione en PowerShell / VS Code
RUTA_OPENSSL = "openssl"
ruta_git_windows = r"C:\Program Files\Git\usr\bin\openssl.exe"

if os.name == "nt" and os.path.exists(ruta_git_windows):
    RUTA_OPENSSL = f'"{ruta_git_windows}"'

def ejecutar_comando(comando):
    """Ejecuta comandos de OpenSSL en la terminal desde Python"""
    # Usamos MSYS_NO_PATHCONV=1 para evitar problemas con las rutas en entornos mixtos
    entorno = dict(os.environ, MSYS_NO_PATHCONV="1")
    resultado = subprocess.run(comando, shell=True, env=entorno, capture_output=True, text=True)
    
    if resultado.returncode != 0:
        print(f"Error criptográfico:\n{resultado.stderr}")
        exit(1)

def inicializar_bd():
    if not os.path.exists(ARCHIVO_BBDD):
        with open(ARCHIVO_BBDD, "w") as f:
            json.dump({}, f)

def registrar_usuario():
    print("=== Sistema de Registro Inmutable VPN U-Secure ===")
    username = input("Introduce el ID del nuevo empleado (ej. cliente_pas): ").strip()
    role = input("Introduce el rol corporativo (PDI, PAS, Investigador): ").strip()
    password = input("Introduce la contraseña de acceso: ").strip()

    inicializar_bd()
    with open(ARCHIVO_BBDD, "r") as f:
        usuarios = json.load(f)

    if username in usuarios:
        print("Error: El usuario ya existe. Modificarlo requiere revocación.")
        return

    print(f"\nGenerando identidad criptográfica inmutable para {username}...")

    # Asegurar que la carpeta claves existe por si acaso
    os.makedirs("claves", exist_ok=True)

    # Rutas dentro de la carpeta 'claves'
    key_path = f"claves/{username}.key"
    csr_path = f"claves/{username}.csr"
    crt_path = f"claves/{username}.crt"
    ca_crt = "claves/ca.crt"
    ca_key = "claves/ca.key"

    # 1. Generación de clave privada efímera
    print("1. Creando par de claves RSA 4096...")
    ejecutar_comando(f"{RUTA_OPENSSL} genrsa -out {key_path} 4096")

    # 2. Petición de firma (CSR) vinculando rígidamente la identidad
    print("2. Vinculando identidad (CN) a la petición de certificado...")
    sujeto = f"/C=ES/ST=Sevilla/O=Universidad U-Secure/OU={role}/CN={username}"
    ejecutar_comando(f'{RUTA_OPENSSL} req -new -key {key_path} -out {csr_path} -subj "{sujeto}"')

    # 3. Firma automática por parte de la CA corporativa
    print("3. CA firmando el certificado oficial X.509v3...")
    ejecutar_comando(f"{RUTA_OPENSSL} x509 -req -in {csr_path} -CA {ca_crt} -CAkey {ca_key} -CAcreateserial -out {crt_path} -days 365 -sha256")

    # 4. Sellado de base de datos
    usuarios[username] = {
        "password": password,
        "rol": role,
        "certificado_asociado": crt_path,
        "estado": "ACTIVO"
    }
    
    with open(ARCHIVO_BBDD, "w") as f:
        json.dump(usuarios, f, indent=4)

    print(f"\n¡Éxito! El empleado '{username}' ha sido registrado.")
    print(f"Sus credenciales están vinculadas permanentemente al certificado: {crt_path}")
    print("Para modificar sus datos (ej. cambio de rol), este certificado deberá ser revocado (Lista CRL).")

if __name__ == "__main__":
    registrar_usuario()