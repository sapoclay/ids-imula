"""
Configuración de IDS-IMULA
Simulador de Sistema de Detección de Intrusos
MF0488 - Gestión de incidentes de seguridad informática
"""

import os

# Directorio base del proyecto
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Rutas de logs del sistema (Linux)
RUTAS_LOGS_SISTEMA = {
    'auth': '/var/log/auth.log',           # Logs de autenticación
    'syslog': '/var/log/syslog',           # Logs del sistema
    'apache_access': '/var/log/apache2/access.log',  # Apache access
    'apache_error': '/var/log/apache2/error.log',    # Apache error
    'nginx_access': '/var/log/nginx/access.log',     # Nginx access
    'nginx_error': '/var/log/nginx/error.log',       # Nginx error
    'firewall': '/var/log/ufw.log',         # Firewall UFW
    'ssh': '/var/log/auth.log',             # SSH (mismo que auth)
}

# Ruta para logs de ejemplo/pruebas
RUTA_LOGS_EJEMPLO = os.path.join(BASE_DIR, 'logs_ejemplo')

# Ruta para almacenar alertas
RUTA_ALERTAS = os.path.join(BASE_DIR, 'alertas')

# Base de datos SQLite
RUTA_BD = os.path.join(BASE_DIR, 'ids_simula.db')

# Niveles de severidad
SEVERIDAD = {
    'INFO': 0,
    'BAJA': 1,
    'MEDIA': 2,
    'ALTA': 3,
    'CRITICA': 4
}

# Colores para la terminal
COLORES = {
    'INFO': '\033[94m',      # Azul
    'BAJA': '\033[92m',      # Verde
    'MEDIA': '\033[93m',     # Amarillo
    'ALTA': '\033[91m',      # Rojo
    'CRITICA': '\033[95m',   # Magenta
    'RESET': '\033[0m',      # Reset
    'NEGRITA': '\033[1m'     # Negrita
}

# Umbrales de detección
UMBRALES = {
    'intentos_login_fallidos': 5,      # Intentos antes de alerta
    'conexiones_por_ip': 100,          # Conexiones máximas por IP
    'intervalo_tiempo': 60,            # Segundos para evaluar
    'escaneo_puertos': 10,             # Puertos diferentes en poco tiempo
    'peticiones_por_segundo': 50,      # Rate limiting
}

# Patrones de ataques conocidos (User-Agents maliciosos, etc.)
USER_AGENTS_SOSPECHOSOS = [
    'sqlmap',
    'nikto',
    'nmap',
    'masscan',
    'zgrab',
    'python-requests',  # Puede ser legítimo pero sospechoso en exceso
    'curl',             # Puede ser legítimo pero sospechoso en exceso
    'wget',
]

# Rutas web sospechosas (intentos de acceso a recursos sensibles)
RUTAS_SOSPECHOSAS = [
    '/admin',
    '/wp-admin',
    '/phpmyadmin',
    '/mysql',
    '/.git',
    '/.env',
    '/config',
    '/backup',
    '/shell',
    '/cmd',
    '/etc/passwd',
    '/etc/shadow',
    '../',  # Path traversal
    'wp-login.php',
    'xmlrpc.php',
]

# Palabras clave de inyección SQL
PATRONES_SQL_INJECTION = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE",
    "UNION SELECT",
    "' AND '1'='1",
    "<script>",
    "javascript:",
    "eval(",
    "exec(",
]
