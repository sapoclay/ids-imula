"""
Módulo de lectura y parseo de logs para IDS-IMULA
Soporta diferentes formatos de logs: auth, apache, nginx, syslog, etc.
"""

import re
import os
from datetime import datetime
from typing import Generator, Optional, List
from modelos import EventoLog, TipoEvento


class LectorLogs:
    """Clase para leer y parsear diferentes tipos de archivos de log"""
    
    # Patrones de expresiones regulares para diferentes formatos de log
    PATRONES = {
        # Auth.log / Syslog: "Jan  2 10:15:30 hostname sshd[1234]: mensaje"
        'syslog': re.compile(
            r'^(?P<mes>\w{3})\s+(?P<dia>\d{1,2})\s+(?P<hora>\d{2}:\d{2}:\d{2})\s+'
            r'(?P<host>\S+)\s+(?P<servicio>\S+?)(\[(?P<pid>\d+)\])?:\s+(?P<mensaje>.*)$'
        ),
        
        # Formato ISO 8601 (Ubuntu 22.04+ / systemd): "2026-01-02T18:30:01.335318+01:00 hostname servicio[pid]: mensaje"
        'syslog_iso': re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:[+-]\d{2}:\d{2})?\s+'
            r'(?P<host>\S+)\s+(?P<servicio>\S+?)(\[(?P<pid>\d+)\])?:\s+(?P<mensaje>.*)$'
        ),
        
        # Apache/Nginx access log: IP - - [fecha] "método ruta protocolo" código tamaño
        'apache_access': re.compile(
            r'^(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+-\s+\S+\s+'
            r'\[(?P<fecha>[^\]]+)\]\s+"(?P<metodo>\w+)\s+(?P<ruta>\S+)\s+(?P<protocolo>[^"]+)"\s+'
            r'(?P<codigo>\d{3})\s+(?P<tamano>\d+|-)'
            r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
        ),
        
        # Apache error log
        'apache_error': re.compile(
            r'^\[(?P<dia>\w+)\s+(?P<mes>\w+)\s+(?P<num_dia>\d+)\s+(?P<hora>\d{2}:\d{2}:\d{2})\.?\d*\s+'
            r'(?P<anio>\d{4})\]\s+\[(?P<modulo>[^\]]+)\]\s+\[pid\s+(?P<pid>\d+)[^\]]*\]\s*'
            r'(?:\[client\s+(?P<ip>[^\]]+)\]\s*)?(?P<mensaje>.*)$'
        ),
        
        # UFW Firewall log
        'ufw': re.compile(
            r'^(?P<mes>\w{3})\s+(?P<dia>\d{1,2})\s+(?P<hora>\d{2}:\d{2}:\d{2})\s+\S+\s+kernel:.*'
            r'\[UFW\s+(?P<accion>\w+)\].*SRC=(?P<src>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'
            r'DST=(?P<dst>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*'
            r'PROTO=(?P<proto>\w+)(?:.*SPT=(?P<spt>\d+))?(?:.*DPT=(?P<dpt>\d+))?'
        ),
        
        # Patrón genérico para IPs
        'ip': re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'),
        
        # Patrones de autenticación
        'auth_fallido': re.compile(
            r'(?:Failed password|authentication failure|FAILED LOGIN|'
            r'Invalid user|Failed publickey|Connection closed by authenticating user)'
        ),
        'auth_exitoso': re.compile(
            r'(?:Accepted password|Accepted publickey|session opened|'
            r'Successful login|authentication success)'
        ),
    }
    
    # Mapeo de meses en inglés a número
    MESES = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
        'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }
    
    def __init__(self, ruta_archivo: str):
        """
        Inicializa el lector de logs
        
        Args:
            ruta_archivo: Ruta al archivo de log a analizar
        """
        self.ruta_archivo = ruta_archivo
        self.tipo_log = self._detectar_tipo_log()
        self.anio_actual = datetime.now().year
    
    def _detectar_tipo_log(self) -> str:
        """Detecta el tipo de log basándose en el nombre del archivo"""
        nombre = os.path.basename(self.ruta_archivo).lower()
        
        if 'access' in nombre:
            return 'apache_access'
        elif 'error' in nombre and ('apache' in nombre or 'nginx' in nombre):
            return 'apache_error'
        elif 'ufw' in nombre or 'firewall' in nombre:
            return 'ufw'
        elif 'auth' in nombre or 'secure' in nombre:
            return 'syslog'  # auth.log usa formato syslog
        else:
            return 'syslog'  # Por defecto, intentamos syslog
    
    def _parsear_fecha_syslog(self, mes: str, dia: str, hora: str) -> datetime:
        """Convierte fecha de formato syslog a datetime"""
        mes_num = self.MESES.get(mes, 1)
        return datetime(
            year=self.anio_actual,
            month=mes_num,
            day=int(dia),
            hour=int(hora[:2]),
            minute=int(hora[3:5]),
            second=int(hora[6:8])
        )
    
    def _parsear_fecha_apache(self, fecha_str: str) -> datetime:
        """Convierte fecha de formato Apache a datetime"""
        # Formato: "02/Jan/2026:10:15:30 +0000"
        try:
            return datetime.strptime(fecha_str.split()[0], "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return datetime.now()
    
    def _parsear_fecha_iso(self, timestamp_str: str) -> datetime:
        """Convierte fecha de formato ISO 8601 a datetime"""
        # Formato: "2026-01-02T18:30:01"
        try:
            return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return datetime.now()
    
    def _parsear_linea_syslog(self, linea: str) -> Optional[EventoLog]:
        """Parsea una línea en formato syslog (tradicional o ISO 8601)"""
        # Intentar primero formato ISO 8601 (Ubuntu 22.04+)
        match = self.PATRONES['syslog_iso'].match(linea)
        if match:
            return self._parsear_linea_syslog_iso(linea, match)
        
        # Si no, intentar formato tradicional
        match = self.PATRONES['syslog'].match(linea)
        if not match:
            return None
        
        datos = match.groupdict()
        timestamp = self._parsear_fecha_syslog(
            datos['mes'], datos['dia'], datos['hora']
        )
        
        # Extraer IP si existe
        ip_match = self.PATRONES['ip'].search(datos['mensaje'])
        ip_origen = ip_match.group(1) if ip_match else None
        
        # Determinar tipo de evento
        mensaje = datos['mensaje']
        if self.PATRONES['auth_fallido'].search(mensaje):
            tipo = TipoEvento.LOGIN_FALLIDO
        elif self.PATRONES['auth_exitoso'].search(mensaje):
            tipo = TipoEvento.LOGIN_EXITOSO
        else:
            tipo = TipoEvento.DESCONOCIDO
        
        # Extraer usuario si existe
        usuario_match = re.search(r'(?:user[=:\s]+|for\s+)(\w+)', mensaje, re.I)
        usuario = usuario_match.group(1) if usuario_match else None
        
        return EventoLog(
            timestamp=timestamp,
            origen=self.ruta_archivo,
            linea_original=linea,
            ip_origen=ip_origen,
            usuario=usuario,
            tipo_evento=tipo,
            mensaje=mensaje,
            datos_extra={
                'host': datos['host'],
                'servicio': datos['servicio'],
                'pid': datos.get('pid')
            }
        )
    
    def _parsear_linea_syslog_iso(self, linea: str, match) -> Optional[EventoLog]:
        """Parsea una línea en formato syslog ISO 8601 (Ubuntu 22.04+/systemd)"""
        datos = match.groupdict()
        timestamp = self._parsear_fecha_iso(datos['timestamp'])
        
        # Extraer IP si existe
        ip_match = self.PATRONES['ip'].search(datos['mensaje'])
        ip_origen = ip_match.group(1) if ip_match else None
        
        # Determinar tipo de evento
        mensaje = datos['mensaje']
        if self.PATRONES['auth_fallido'].search(mensaje):
            tipo = TipoEvento.LOGIN_FALLIDO
        elif self.PATRONES['auth_exitoso'].search(mensaje):
            tipo = TipoEvento.LOGIN_EXITOSO
        else:
            tipo = TipoEvento.DESCONOCIDO
        
        # Extraer usuario si existe
        usuario_match = re.search(r'(?:user[=:\s]+|for\s+)(\w+)', mensaje, re.I)
        usuario = usuario_match.group(1) if usuario_match else None
        
        return EventoLog(
            timestamp=timestamp,
            origen=self.ruta_archivo,
            linea_original=linea,
            ip_origen=ip_origen,
            usuario=usuario,
            tipo_evento=tipo,
            mensaje=mensaje,
            datos_extra={
                'host': datos['host'],
                'servicio': datos['servicio'],
                'pid': datos.get('pid')
            }
        )
    
    def _parsear_linea_apache_access(self, linea: str) -> Optional[EventoLog]:
        """Parsea una línea de access.log de Apache/Nginx"""
        match = self.PATRONES['apache_access'].match(linea)
        if not match:
            return None
        
        datos = match.groupdict()
        timestamp = self._parsear_fecha_apache(datos['fecha'])
        
        # Determinar tipo de evento según el código de respuesta
        codigo = int(datos['codigo'])
        if codigo >= 400 and codigo < 500:
            tipo = TipoEvento.ACCESO_SOSPECHOSO
        elif codigo >= 500:
            tipo = TipoEvento.ERROR_SISTEMA
        else:
            tipo = TipoEvento.PETICION_WEB
        
        return EventoLog(
            timestamp=timestamp,
            origen=self.ruta_archivo,
            linea_original=linea,
            ip_origen=datos['ip'],
            tipo_evento=tipo,
            mensaje=f"{datos['metodo']} {datos['ruta']} -> {codigo}",
            datos_extra={
                'metodo': datos['metodo'],
                'ruta': datos['ruta'],
                'codigo': codigo,
                'tamano': datos['tamano'],
                'user_agent': datos.get('user_agent', ''),
                'referer': datos.get('referer', '')
            }
        )
    
    def _parsear_linea_ufw(self, linea: str) -> Optional[EventoLog]:
        """Parsea una línea de log de UFW firewall"""
        match = self.PATRONES['ufw'].search(linea)
        if not match:
            return None
        
        datos = match.groupdict()
        timestamp = self._parsear_fecha_syslog(
            datos['mes'], datos['dia'], datos['hora']
        )
        
        accion = datos['accion']
        if accion == 'BLOCK':
            tipo = TipoEvento.FIREWALL
        else:
            tipo = TipoEvento.CONEXION_RED
        
        puerto_destino = int(datos['dpt']) if datos.get('dpt') else None
        
        return EventoLog(
            timestamp=timestamp,
            origen=self.ruta_archivo,
            linea_original=linea,
            ip_origen=datos['src'],
            ip_destino=datos['dst'],
            puerto=puerto_destino,
            tipo_evento=tipo,
            mensaje=f"UFW {accion}: {datos['src']} -> {datos['dst']}:{puerto_destino}",
            datos_extra={
                'accion': accion,
                'protocolo': datos['proto'],
                'puerto_origen': datos.get('spt'),
                'puerto_destino': datos.get('dpt')
            }
        )
    
    def _parsear_linea(self, linea: str) -> Optional[EventoLog]:
        """Parsea una línea según el tipo de log detectado"""
        linea = linea.strip()
        if not linea:
            return None
        
        if self.tipo_log == 'apache_access':
            return self._parsear_linea_apache_access(linea)
        elif self.tipo_log == 'ufw':
            return self._parsear_linea_ufw(linea)
        else:  # syslog y otros
            return self._parsear_linea_syslog(linea)
    
    def leer_logs(self) -> Generator[EventoLog, None, None]:
        """
        Lee el archivo de log y genera eventos parseados
        
            EventoLog: Eventos extraídos del archivo
        """
        if not os.path.exists(self.ruta_archivo):
            print(f"⚠️  Archivo no encontrado: {self.ruta_archivo}")
            return
        
        try:
            with open(self.ruta_archivo, 'r', encoding='utf-8', errors='ignore') as f:
                for linea in f:
                    evento = self._parsear_linea(linea)
                    if evento:
                        yield evento
        except PermissionError:
            print(f"❌ Sin permisos para leer: {self.ruta_archivo}")
            print("   Intenta ejecutar con sudo o como root")
        except Exception as e:
            print(f"❌ Error leyendo {self.ruta_archivo}: {e}")
    
    def contar_lineas(self) -> int:
        """Cuenta el número total de líneas en el archivo"""
        try:
            with open(self.ruta_archivo, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except:
            return 0


class LectorMultiple:
    """Clase para leer múltiples archivos de log"""
    
    def __init__(self, rutas: List[str]):
        """
        Inicializa el lector múltiple
        
        Args:
            rutas: Lista de rutas a archivos de log
        """
        self.rutas = rutas
        self.lectores = [LectorLogs(ruta) for ruta in rutas if os.path.exists(ruta)]
    
    def leer_todos(self) -> Generator[EventoLog, None, None]:
        """Lee todos los archivos y genera eventos"""
        for lector in self.lectores:
            yield from lector.leer_logs()
    
    def obtener_archivos_existentes(self) -> List[str]:
        """Devuelve la lista de archivos que existen y son accesibles"""
        return [lector.ruta_archivo for lector in self.lectores]
