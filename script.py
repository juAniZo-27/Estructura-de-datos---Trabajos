import os
import json
import re
import requests

# Conjuntos para guardar datos únicos
ips_unicas = set()
fechas_unicas = set()
codigos_http = set()

# Expresión regular para extraer IP, fecha y código
patron = r"(\d{1,3}(?:\.\d{1,3}){3}).+?\[(\d{2})\/[a-zA-Z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}).*?\b[A-Z]{1,7}\s+\S+\s+(\d{3})"

def extraer_por_regex(patron, texto):
    return re.findall(patron, texto) if texto else []

# 1) Ruta base donde se hallan los logs
base_dir = os.path.join("C:", "Users", "306", "Downloads", "SotB34", "http")

# 2) Recorrer archivos access_log, access_log_1, ..., access_log_6
for i in range(7):
    nombre_archivo = f"access_log{'_' + str(i) if i != 0 else ''}"
    # Esto generará "access_log", "access_log_1", ..., "access_log_6"

    # Ruta absoluta al archivo
    ruta_archivo = os.path.join(base_dir, nombre_archivo)
    
    # (Solo para debug, revisa la ruta que se está abriendo)
    print(f"C:\Users\306\Downloads\SotM34\http: {ruta_archivo}")

    try:
        with open(ruta_archivo, "r") as archivo:
            contenido = archivo.read()
        resultados = extraer_por_regex(patron, contenido)
        for ip, fecha, codigo in resultados:
            ips_unicas.add(ip)
            fechas_unicas.add(fecha)
            codigos_http.add(codigo)

    except FileNotFoundError:
        print(f"No se encontró el archivo: {ruta_archivo}")
    except PermissionError:
        print(f"No tienes permisos para abrir: {ruta_archivo}")
    except Exception as e:
        print(f"Error leyendo '{ruta_archivo}': {e}")

# 3) Geolocalización de IPs
datos_geo = []
S
for ip in ips_unicas:
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}").json()
        info = {
            "ip": ip,
            "fecha": None,
            "país": resp.get("country"),
            "ciudad": resp.get("city"),
            "código": resp.get("zip"),
        }
    except Exception as e:
        print(f"Error geolocalizando IP {ip}: {e}")
        info = {
            "ip": ip,
            "fecha": None,
            "país": None,
            "ciudad": None,
            "código": None
        }

    datos_geo.append(info)

# 4) Imprime datos finales en pantalla
print(json.dumps(datos_geo, indent=4, ensure_ascii=False))

# 5) Guarda datos en JSON
with open("ips_geolocalizadas.json", "w", encoding="utf-8") as f:
    json.dump(datos_geo, f, indent=4, ensure_ascii=False)