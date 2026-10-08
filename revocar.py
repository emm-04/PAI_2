import json
import os

ARCHIVO_BBDD = "bd_usuarios.json"

def revocar_usuario():
    print("=== Sistema de Revocación de Identidades (CRL) ===")
    
    if not os.path.exists(ARCHIVO_BBDD):
        print("Error: No existe la base de datos de usuarios. Ejecuta primero registro.py")
        return

    # Cargamos el "Directorio Activo" (Nuestra BBDD)
    with open(ARCHIVO_BBDD, "r") as f:
        usuarios = json.load(f)

    print("Usuarios registrados en el sistema:")
    for user, datos in usuarios.items():
        print(f" - {user} (Estado: {datos.get('estado', 'DESCONOCIDO')})")

    username = input("\nIntroduce el ID del empleado a revocar el acceso: ").strip()

    if username not in usuarios:
        print("Error: El usuario no existe en el sistema.")
        return

    if usuarios[username].get("estado") == "REVOCADO":
        print(f"El certificado del usuario '{username}' ya estaba revocado.")
        return

    # 1. Invalidación Lógica (Añadir a nuestra Lista de Revocación interna)
    usuarios[username]["estado"] = "REVOCADO"
    ruta_cert = usuarios[username]["certificado_asociado"]

    # 2. Invalidación Física (Romper el archivo para que mTLS falle instantáneamente)
    if os.path.exists(ruta_cert):
        nueva_ruta = ruta_cert + ".revocado"
        os.rename(ruta_cert, nueva_ruta) # Renombramos para que el cliente no lo encuentre
        usuarios[username]["certificado_asociado"] = nueva_ruta
        print(f"\n[OK] Certificado físico invalidado: {nueva_ruta}")
    else:
        print(f"\n[AVISO] No se encontró el archivo físico '{ruta_cert}', pero ha sido bloqueado en BBDD.")

    # Guardamos los cambios
    with open(ARCHIVO_BBDD, "w") as f:
        json.dump(usuarios, f, indent=4)

    print(f"\n¡Éxito! La identidad corporativa de '{username}' ha sido revocada.")
    print("Si el empleado necesita cambiar sus datos o rol, deberá pasar por un nuevo proceso de registro completo (generando nuevas claves RSA).")

if __name__ == "__main__":
    revocar_usuario()