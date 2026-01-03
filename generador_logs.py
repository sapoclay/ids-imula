"""
Generador de logs de ejemplo para IDS-IMULA
Crea logs simulados con diferentes tipos de ataques
"""

import os
import random
from datetime import datetime, timedelta
import config


def generar_logs_ejemplo():
    """Genera archivos de log de ejemplo con patrones de ataques simulados"""
    
    os.makedirs(config.RUTA_LOGS_EJEMPLO, exist_ok=True)
    
    # IPs de ejemplo
    ips_normales = ['192.168.1.10', '192.168.1.20', '192.168.1.30', '10.0.0.5']
    ips_atacantes = ['45.33.32.156', '185.220.101.45', '23.129.64.201', '103.75.201.4']
    usuarios = ['admin', 'root', 'user1', 'test', 'guest', 'administrator']
    
    # Rutas web normales y sospechosas
    rutas_normales = ['/', '/index.html', '/css/style.css', '/js/app.js', '/images/logo.png', '/api/data']
    rutas_maliciosas = [
        '/admin', '/wp-admin', '/phpmyadmin', '/.git/config', '/.env',
        "/api/users?id=1' OR '1'='1", "/search?q=<script>alert('xss')</script>",
        '/../../etc/passwd', '/backup/db.sql', '/config.php.bak'
    ]
    
    user_agents_normales = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    ]
    user_agents_maliciosos = [
        'sqlmap/1.4.7#stable (http://sqlmap.org)',
        'nikto/2.1.6',
        'Nmap Scripting Engine',
        'masscan/1.0',
    ]
    
    fecha_base = datetime.now()
    logs = []
    
    # ==================== AUTH.LOG ====================
    print("📝 Generando auth.log de ejemplo...")
    auth_logs = []
    
    # Tráfico normal de SSH
    for i in range(50):
        tiempo = fecha_base - timedelta(minutes=random.randint(1, 1440))
        ip = random.choice(ips_normales)
        usuario = random.choice(['user1', 'admin'])
        auth_logs.append(
            f"{tiempo.strftime('%b %d %H:%M:%S')} servidor sshd[{random.randint(1000,9999)}]: "
            f"Accepted publickey for {usuario} from {ip} port {random.randint(40000,60000)} ssh2"
        )
    
    # Simular ataque de fuerza bruta
    atacante = ips_atacantes[0]
    tiempo_ataque = fecha_base - timedelta(minutes=5)
    for i in range(15):  # 15 intentos en pocos segundos
        tiempo = tiempo_ataque + timedelta(seconds=i*2)
        usuario = random.choice(usuarios)
        auth_logs.append(
            f"{tiempo.strftime('%b %d %H:%M:%S')} servidor sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {usuario} from {atacante} port {random.randint(40000,60000)} ssh2"
        )
    
    # Más intentos fallidos de diferentes IPs
    for atacante in ips_atacantes[1:]:
        for i in range(random.randint(3, 8)):
            tiempo = fecha_base - timedelta(minutes=random.randint(10, 60))
            usuario = random.choice(usuarios)
            auth_logs.append(
                f"{tiempo.strftime('%b %d %H:%M:%S')} servidor sshd[{random.randint(1000,9999)}]: "
                f"Failed password for invalid user {usuario} from {atacante} port {random.randint(40000,60000)} ssh2"
            )
    
    # Usuario inválido
    for i in range(5):
        tiempo = fecha_base - timedelta(minutes=random.randint(1, 30))
        auth_logs.append(
            f"{tiempo.strftime('%b %d %H:%M:%S')} servidor sshd[{random.randint(1000,9999)}]: "
            f"Invalid user administrator from {ips_atacantes[1]} port {random.randint(40000,60000)}"
        )
    
    # Ordenar y guardar
    auth_logs.sort()
    with open(os.path.join(config.RUTA_LOGS_EJEMPLO, 'auth.log'), 'w') as f:
        f.write('\n'.join(auth_logs))
    print(f"   ✅ Generadas {len(auth_logs)} líneas en auth.log")
    
    # ==================== ACCESS.LOG (Apache/Nginx) ====================
    print("📝 Generando access.log de ejemplo...")
    access_logs = []
    
    # Tráfico normal
    for i in range(100):
        tiempo = fecha_base - timedelta(minutes=random.randint(1, 1440))
        ip = random.choice(ips_normales)
        ruta = random.choice(rutas_normales)
        codigo = random.choice([200, 200, 200, 200, 304, 301])
        ua = random.choice(user_agents_normales)
        access_logs.append(
            f'{ip} - - [{tiempo.strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
            f'"GET {ruta} HTTP/1.1" {codigo} {random.randint(500, 15000)} "-" "{ua}"'
        )
    
    # Ataques: SQL Injection
    atacante = ips_atacantes[0]
    for payload in [
        "/api/user?id=1' OR '1'='1",
        "/api/user?id=1; DROP TABLE users--",
        "/search?q=admin' AND '1'='1",
        "/login?user=admin'--&pass=x",
        "/api/data?id=1 UNION SELECT * FROM passwords",
    ]:
        tiempo = fecha_base - timedelta(minutes=random.randint(1, 60))
        access_logs.append(
            f'{atacante} - - [{tiempo.strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
            f'"GET {payload} HTTP/1.1" 500 1234 "-" "sqlmap/1.4.7"'
        )
    
    # Ataques: XSS
    atacante = ips_atacantes[1]
    for payload in [
        "/search?q=<script>alert('XSS')</script>",
        "/comment?text=<img onerror=alert(1) src=x>",
        "/page?name=<body onload=alert('hacked')>",
    ]:
        tiempo = fecha_base - timedelta(minutes=random.randint(1, 60))
        access_logs.append(
            f'{atacante} - - [{tiempo.strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
            f'"GET {payload} HTTP/1.1" 200 5678 "-" "{random.choice(user_agents_normales)}"'
        )
    
    # Escaneo de directorios
    atacante = ips_atacantes[2]
    for ruta in rutas_maliciosas[:5]:
        tiempo = fecha_base - timedelta(minutes=random.randint(1, 30))
        access_logs.append(
            f'{atacante} - - [{tiempo.strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
            f'"GET {ruta} HTTP/1.1" 404 1234 "-" "nikto/2.1.6"'
        )
    
    # Path traversal
    atacante = ips_atacantes[3]
    for i in range(5):
        tiempo = fecha_base - timedelta(minutes=random.randint(1, 30))
        access_logs.append(
            f'{atacante} - - [{tiempo.strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
            f'"GET /../../../../../../etc/passwd HTTP/1.1" 400 0 "-" "curl/7.68.0"'
        )
    
    # DDoS simulado (muchas peticiones de una IP)
    atacante = ips_atacantes[0]
    tiempo_ddos = fecha_base - timedelta(minutes=2)
    for i in range(80):
        tiempo = tiempo_ddos + timedelta(milliseconds=i*50)
        access_logs.append(
            f'{atacante} - - [{tiempo.strftime("%d/%b/%Y:%H:%M:%S")} +0000] '
            f'"GET / HTTP/1.1" 200 5000 "-" "python-requests/2.25.1"'
        )
    
    # Ordenar y guardar
    with open(os.path.join(config.RUTA_LOGS_EJEMPLO, 'access.log'), 'w') as f:
        f.write('\n'.join(access_logs))
    print(f"   ✅ Generadas {len(access_logs)} líneas en access.log")
    
    # ==================== UFW.LOG (Firewall) ====================
    print("📝 Generando ufw.log de ejemplo...")
    ufw_logs = []
    
    # Conexiones bloqueadas normales
    puertos_comunes = [22, 23, 80, 443, 3306, 5432, 6379, 27017, 8080, 8443]
    
    for i in range(30):
        tiempo = fecha_base - timedelta(minutes=random.randint(1, 1440))
        ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        puerto = random.choice(puertos_comunes)
        ufw_logs.append(
            f"{tiempo.strftime('%b %d %H:%M:%S')} servidor kernel: [UFW BLOCK] "
            f"IN=eth0 OUT= MAC=00:00:00:00:00:00 SRC={ip} DST=192.168.1.100 "
            f"LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP "
            f"SPT={random.randint(40000,60000)} DPT={puerto} WINDOW=65535 RES=0x00 SYN URGP=0"
        )
    
    # Escaneo de puertos (misma IP, muchos puertos)
    atacante = ips_atacantes[0]
    tiempo_escaneo = fecha_base - timedelta(minutes=10)
    for puerto in range(1, 1025, 50):  # Escaneo de puertos
        tiempo = tiempo_escaneo + timedelta(milliseconds=puerto*10)
        ufw_logs.append(
            f"{tiempo.strftime('%b %d %H:%M:%S')} servidor kernel: [UFW BLOCK] "
            f"IN=eth0 OUT= MAC=00:00:00:00:00:00 SRC={atacante} DST=192.168.1.100 "
            f"LEN=44 TOS=0x00 PREC=0x00 TTL=64 ID={random.randint(1000,9999)} PROTO=TCP "
            f"SPT={random.randint(40000,60000)} DPT={puerto} WINDOW=1024 RES=0x00 SYN URGP=0"
        )
    
    # Ordenar y guardar
    ufw_logs.sort()
    with open(os.path.join(config.RUTA_LOGS_EJEMPLO, 'ufw.log'), 'w') as f:
        f.write('\n'.join(ufw_logs))
    print(f"   ✅ Generadas {len(ufw_logs)} líneas en ufw.log")
    
    print(f"\n✅ Logs de ejemplo generados en: {config.RUTA_LOGS_EJEMPLO}")
    return config.RUTA_LOGS_EJEMPLO


if __name__ == '__main__':
    generar_logs_ejemplo()
