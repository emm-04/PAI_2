import uvicorn
# Importamos la misma aplicación (con sus rutas /login y /logout) que ya creaste
from server_api import app 

if __name__ == "__main__":
    print("Iniciando servidor HTTP de prueba (SIN CIFRAR) en el puerto 8080...")
    # Levantamos Uvicorn en texto plano, sin certificados ni mTLS
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8080
    )