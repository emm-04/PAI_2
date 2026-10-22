import database
import pki_generator

def seed():
    print("[*] Iniciando despliegue de la PKI...")
    pki_generator.generate_pki()
    
    print("[*] Inicializando esquemas de Base de Datos...")
    database.init_db()
    
    # Cuentas iniciales precargadas
    # users = [
    #     ("pdi_alice", "PDI", "PdiSecurePass2026!", "pdi_alice"),
    #     ("pas_bob", "PAS", "PasAdminPass2026!", "pas_bob"),
    #     ("investigador_carol", "Investigador", "LabResearchPass2026!", "investigador_carol")
    # ]
    
    # for username, role, password, cert_cn in users:
    #     database.add_user(username, role, password, cert_cn)
    #     print(f"[+] Usuario '{username}' registrado con rol [{role}] y certificado asignado.")

    # print("[+] Entorno de datos poblado y preparado para el despliegue.")


if __name__ == "__main__":
    seed()
    print("[+] Base de datos inicializada con infraestructura de clave pública.")