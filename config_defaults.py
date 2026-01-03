"""
Valores por defecto de IDS-IMULA
Este archivo contiene los valores iniciales de configuración.
Se usa para restaurar la configuración a valores funcionales.
⚠️ NO MODIFICAR este archivo - los cambios se hacen en config.py ⚠️
"""

# Rutas de logs del sistema (Linux) - Valores por defecto
RUTAS_LOGS_SISTEMA_DEFAULT = {
    'auth': '/var/log/auth.log',
    'syslog': '/var/log/syslog',
    'apache_access': '/var/log/apache2/access.log',
    'apache_error': '/var/log/apache2/error.log',
    'nginx_access': '/var/log/nginx/access.log',
    'nginx_error': '/var/log/nginx/error.log',
    'firewall': '/var/log/ufw.log',
    'ssh': '/var/log/auth.log',
}

# Umbrales de detección - Valores por defecto
UMBRALES_DEFAULT = {
    'intentos_login_fallidos': 5,
    'conexiones_por_ip': 100,
    'intervalo_tiempo': 60,
    'escaneo_puertos': 10,
    'peticiones_por_segundo': 50,
}

# User-Agents sospechosos - Valores por defecto
USER_AGENTS_SOSPECHOSOS_DEFAULT = [
    'sqlmap',
    'nikto',
    'nmap',
    'masscan',
    'zgrab',
    'python-requests',
    'curl',
    'wget',
]

# Rutas web sospechosas - Valores por defecto
RUTAS_SOSPECHOSAS_DEFAULT = [
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
    '../',
    'wp-login.php',
    'xmlrpc.php',
]

# Patrones SQL Injection - Valores por defecto
PATRONES_SQL_INJECTION_DEFAULT = [
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
