"""
IDS-IMULA - Analizador de Logs con Clasificación de Eventos
MF0488 - Gestión de incidentes de seguridad informática

Funcionalidades:
- Cargar logs en múltiples formatos (CSV, JSON, texto)
- Clasificar eventos de seguridad (éxitos, fallos, intrusiones)
- Generar reportes con estadísticas y visualizaciones
"""

import os
import re
import csv
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import List, Dict, Optional, Tuple, TYPE_CHECKING
from dataclasses import dataclass, field
from enum import Enum

# Importar matplotlib (opcional)
MATLOTLIB_DISPONIBLE = False
plt = None
mdates = None
Patch = None

try:
    import matplotlib.pyplot as plt  # type: ignore
    import matplotlib.dates as mdates  # type: ignore
    from matplotlib.patches import Patch  # type: ignore
    MATPLOTLIB_DISPONIBLE = True
except ImportError:
    print("⚠️  Matplotlib no instalado. Ejecuta: pip install matplotlib")


class CategoriaEvento(Enum):
    """Categorías de clasificación de eventos de seguridad"""
    EXITO = "exito"
    FALLO = "fallo"
    INTRUSION = "intrusion"
    SOSPECHOSO = "sospechoso"
    INFORMATIVO = "informativo"
    ERROR_SISTEMA = "error_sistema"
    DESCONOCIDO = "desconocido"


@dataclass
class EventoSeguridad:
    """Representa un evento de seguridad clasificado"""
    timestamp: datetime
    categoria: CategoriaEvento
    tipo: str                      # login_ssh, acceso_web, firewall, etc.
    descripcion: str
    ip_origen: Optional[str] = None
    usuario: Optional[str] = None
    severidad: int = 0             # 0-4 (info -> crítico)
    origen_log: str = ""
    linea_original: str = ""
    datos_extra: Dict = field(default_factory=dict)


class ClasificadorEventos:
    """
    Clasifica eventos de seguridad basándose en patrones predefinidos
    """
    
    # Patrones para clasificación
    PATRONES_EXITO = [
        (r'Accepted\s+(password|publickey)', 'login_ssh_exitoso'),
        (r'session opened', 'sesion_abierta'),
        (r'authentication success', 'auth_exitoso'),
        (r'Successful login', 'login_exitoso'),
        (r'New session', 'nueva_sesion'),
        (r'sudo:.*COMMAND=', 'sudo_ejecutado'),
        (r'" 200 ', 'peticion_web_ok'),
        (r'" 301 ', 'redireccion_web'),
    ]
    
    PATRONES_FALLO = [
        (r'Failed password', 'login_ssh_fallido'),
        (r'authentication failure', 'auth_fallido'),
        (r'Invalid user', 'usuario_invalido'),
        (r'FAILED LOGIN', 'login_fallido'),
        (r'Connection closed by authenticating', 'conexion_cerrada'),
        (r'permission denied', 'permiso_denegado'),
        (r'" 401 ', 'no_autorizado'),
        (r'" 403 ', 'prohibido'),
        (r'" 404 ', 'no_encontrado'),
    ]
    
    PATRONES_INTRUSION = [
        (r"(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|--\s*$)", 'sql_injection'),
        (r'(?i)(<script|javascript:|onerror\s*=)', 'xss_attempt'),
        (r'\.\./', 'path_traversal'),
        (r'(?i)(sqlmap|nikto|nmap|masscan|dirbuster)', 'herramienta_ataque'),
        (r'/etc/passwd|/etc/shadow', 'acceso_ficheros_sistema'),
        (r'(?i)(cmd\.exe|powershell|/bin/sh)', 'ejecucion_comandos'),
        (r'\[UFW BLOCK\]', 'firewall_bloqueo'),
    ]
    
    PATRONES_SOSPECHOSO = [
        (r'/admin|/wp-admin|/phpmyadmin', 'acceso_admin'),
        (r'/\.git|/\.env|/config', 'acceso_ficheros_sensibles'),
        (r'/backup|/\.bak', 'acceso_backup'),
        (r'" 500 ', 'error_servidor'),
        (r'curl/|wget/', 'user_agent_automatico'),
    ]
    
    PATRON_IP = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    PATRON_USUARIO = re.compile(r'(?:user[=:\s]+|for\s+(?:invalid\s+user\s+)?)(\w+)', re.I)
    
    def __init__(self):
        """Inicializa el clasificador compilando los patrones"""
        self.patrones_compilados = {
            CategoriaEvento.EXITO: [(re.compile(p, re.I), t) for p, t in self.PATRONES_EXITO],
            CategoriaEvento.FALLO: [(re.compile(p, re.I), t) for p, t in self.PATRONES_FALLO],
            CategoriaEvento.INTRUSION: [(re.compile(p, re.I), t) for p, t in self.PATRONES_INTRUSION],
            CategoriaEvento.SOSPECHOSO: [(re.compile(p, re.I), t) for p, t in self.PATRONES_SOSPECHOSO],
        }
        
        # Severidad por categoría
        self.severidad_categoria = {
            CategoriaEvento.EXITO: 0,
            CategoriaEvento.INFORMATIVO: 0,
            CategoriaEvento.FALLO: 1,
            CategoriaEvento.SOSPECHOSO: 2,
            CategoriaEvento.ERROR_SISTEMA: 2,
            CategoriaEvento.INTRUSION: 4,
            CategoriaEvento.DESCONOCIDO: 0,
        }
    
    def clasificar(self, linea: str, timestamp: Optional[datetime] = None, 
                   origen: str = "") -> EventoSeguridad:
        """
        Clasifica una línea de log en una categoría de evento
        
        Args:
            linea: Línea de log a clasificar
            timestamp: Fecha/hora del evento (se intenta extraer si no se proporciona)
            origen: Archivo de origen del log
            
        Returns:
            EventoSeguridad clasificado
        """
        if timestamp is None:
            timestamp = self._extraer_timestamp(linea)
        
        # Extraer IP y usuario
        ip_match = self.PATRON_IP.search(linea)
        ip_origen = ip_match.group(1) if ip_match else None
        
        usuario_match = self.PATRON_USUARIO.search(linea)
        usuario = usuario_match.group(1) if usuario_match else None
        
        # Clasificar por patrones (orden de prioridad)
        for categoria in [CategoriaEvento.INTRUSION, CategoriaEvento.FALLO, 
                          CategoriaEvento.SOSPECHOSO, CategoriaEvento.EXITO]:
            for patron, tipo in self.patrones_compilados[categoria]:
                if patron.search(linea):
                    return EventoSeguridad(
                        timestamp=timestamp,
                        categoria=categoria,
                        tipo=tipo,
                        descripcion=self._generar_descripcion(categoria, tipo),
                        ip_origen=ip_origen,
                        usuario=usuario,
                        severidad=self.severidad_categoria[categoria],
                        origen_log=origen,
                        linea_original=linea.strip()
                    )
        
        # Si no coincide con ningún patrón conocido
        return EventoSeguridad(
            timestamp=timestamp,
            categoria=CategoriaEvento.INFORMATIVO,
            tipo="evento_general",
            descripcion="Evento informativo del sistema",
            ip_origen=ip_origen,
            usuario=usuario,
            severidad=0,
            origen_log=origen,
            linea_original=linea.strip()
        )
    
    def _extraer_timestamp(self, linea: str) -> datetime:
        """Intenta extraer timestamp de la línea"""
        # Formato ISO 8601
        iso_match = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', linea)
        if iso_match:
            try:
                return datetime.strptime(iso_match.group(1), "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                pass
        
        # Formato syslog tradicional
        syslog_match = re.match(r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})', linea)
        if syslog_match:
            meses = {'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
                     'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12}
            try:
                mes = meses.get(syslog_match.group(1), 1)
                dia = int(syslog_match.group(2))
                hora = syslog_match.group(3)
                return datetime(datetime.now().year, mes, dia,
                               int(hora[:2]), int(hora[3:5]), int(hora[6:8]))
            except ValueError:
                pass
        
        # Formato Apache
        apache_match = re.search(r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})', linea)
        if apache_match:
            try:
                return datetime.strptime(apache_match.group(1), "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                pass
        
        return datetime.now()
    
    def _generar_descripcion(self, categoria: CategoriaEvento, tipo: str) -> str:
        """Genera una descripción legible del evento"""
        descripciones = {
            'login_ssh_exitoso': 'Inicio de sesión SSH exitoso',
            'login_ssh_fallido': 'Intento de login SSH fallido',
            'sesion_abierta': 'Sesión de usuario abierta',
            'auth_exitoso': 'Autenticación exitosa',
            'auth_fallido': 'Fallo de autenticación',
            'usuario_invalido': 'Intento con usuario inválido',
            'login_fallido': 'Inicio de sesión fallido',
            'login_exitoso': 'Inicio de sesión exitoso',
            'nueva_sesion': 'Nueva sesión iniciada',
            'sudo_ejecutado': 'Comando sudo ejecutado',
            'conexion_cerrada': 'Conexión cerrada durante autenticación',
            'permiso_denegado': 'Permiso denegado',
            'peticion_web_ok': 'Petición web exitosa (200)',
            'redireccion_web': 'Redirección web (301)',
            'no_autorizado': 'Acceso no autorizado (401)',
            'prohibido': 'Acceso prohibido (403)',
            'no_encontrado': 'Recurso no encontrado (404)',
            'sql_injection': '⚠️ Posible intento de SQL Injection',
            'xss_attempt': '⚠️ Posible intento de XSS',
            'path_traversal': '⚠️ Intento de Path Traversal',
            'herramienta_ataque': '🚨 Herramienta de ataque detectada',
            'acceso_ficheros_sistema': '🚨 Intento de acceso a ficheros del sistema',
            'ejecucion_comandos': '🚨 Posible ejecución de comandos',
            'firewall_bloqueo': 'Conexión bloqueada por firewall',
            'acceso_admin': 'Acceso a ruta administrativa',
            'acceso_ficheros_sensibles': 'Acceso a ficheros sensibles',
            'acceso_backup': 'Intento de acceso a backups',
            'error_servidor': 'Error interno del servidor (500)',
            'user_agent_automatico': 'User-Agent de herramienta automatizada',
        }
        return descripciones.get(tipo, f"Evento de tipo: {tipo}")


class CargadorLogs:
    """
    Carga logs desde diferentes formatos de archivo
    """
    
    def __init__(self):
        self.clasificador = ClasificadorEventos()
    
    def cargar(self, ruta: str) -> List[EventoSeguridad]:
        """
        Carga logs detectando automáticamente el formato
        
        Args:
            ruta: Ruta al archivo de logs
            
        Returns:
            Lista de eventos clasificados
        """
        if not os.path.exists(ruta):
            print(f"❌ Archivo no encontrado: {ruta}")
            return []
        
        extension = os.path.splitext(ruta)[1].lower()
        
        if extension == '.csv':
            return self.cargar_csv(ruta)
        elif extension == '.json':
            return self.cargar_json(ruta)
        else:
            return self.cargar_texto(ruta)
    
    def cargar_texto(self, ruta: str) -> List[EventoSeguridad]:
        """Carga logs desde archivo de texto plano"""
        eventos = []
        try:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for linea in f:
                    if linea.strip():
                        evento = self.clasificador.clasificar(linea, origen=ruta)
                        eventos.append(evento)
        except Exception as e:
            print(f"❌ Error leyendo {ruta}: {e}")
        return eventos
    
    def cargar_csv(self, ruta: str) -> List[EventoSeguridad]:
        """Carga logs desde archivo CSV"""
        eventos = []
        try:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                # Detectar delimitador
                muestra = f.read(1024)
                f.seek(0)
                
                try:
                    dialect = csv.Sniffer().sniff(muestra)
                except csv.Error:
                    dialect = csv.excel
                
                reader = csv.DictReader(f, dialect=dialect)
                
                for fila in reader:
                    # Buscar columna de mensaje/log
                    mensaje = (fila.get('message') or fila.get('mensaje') or 
                              fila.get('log') or fila.get('raw') or 
                              str(fila))
                    
                    # Buscar timestamp
                    ts_str = (fila.get('timestamp') or fila.get('fecha') or 
                             fila.get('time') or fila.get('datetime'))
                    timestamp = self._parsear_timestamp_flexible(ts_str)
                    
                    evento = self.clasificador.clasificar(mensaje, timestamp, ruta)
                    
                    # Agregar datos extra del CSV
                    evento.datos_extra = dict(fila)
                    if fila.get('ip') or fila.get('ip_origen'):
                        evento.ip_origen = fila.get('ip') or fila.get('ip_origen')
                    if fila.get('user') or fila.get('usuario'):
                        evento.usuario = fila.get('user') or fila.get('usuario')
                    
                    eventos.append(evento)
                    
        except Exception as e:
            print(f"❌ Error leyendo CSV {ruta}: {e}")
        return eventos
    
    def cargar_json(self, ruta: str) -> List[EventoSeguridad]:
        """Carga logs desde archivo JSON"""
        eventos = []
        try:
            with open(ruta, 'r', encoding='utf-8') as f:
                contenido = f.read().strip()
                
                # Puede ser un array o líneas JSON (JSONL)
                if contenido.startswith('['):
                    datos = json.loads(contenido)
                else:
                    # JSONL - una línea por JSON
                    datos = [json.loads(linea) for linea in contenido.split('\n') if linea.strip()]
                
                for item in datos:
                    if isinstance(item, dict):
                        mensaje = (item.get('message') or item.get('mensaje') or 
                                  item.get('log') or item.get('raw') or str(item))
                        
                        ts_str = (item.get('timestamp') or item.get('fecha') or 
                                 item.get('time') or item.get('@timestamp'))
                        timestamp = self._parsear_timestamp_flexible(ts_str)
                        
                        evento = self.clasificador.clasificar(mensaje, timestamp, ruta)
                        evento.datos_extra = item
                        
                        if item.get('ip') or item.get('ip_origen') or item.get('source_ip'):
                            evento.ip_origen = item.get('ip') or item.get('ip_origen') or item.get('source_ip')
                        if item.get('user') or item.get('usuario'):
                            evento.usuario = item.get('user') or item.get('usuario')
                        
                        eventos.append(evento)
                    else:
                        evento = self.clasificador.clasificar(str(item), origen=ruta)
                        eventos.append(evento)
                        
        except Exception as e:
            print(f"❌ Error leyendo JSON {ruta}: {e}")
        return eventos
    
    def _parsear_timestamp_flexible(self, ts_str: Optional[str]) -> datetime:
        """Intenta parsear timestamp en varios formatos"""
        if not ts_str:
            return datetime.now()
        
        formatos = [
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%d-%m-%Y %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
        ]
        
        # Limpiar timezone
        ts_str = re.sub(r'[+-]\d{2}:\d{2}$', '', str(ts_str))
        ts_str = re.sub(r'Z$', '', ts_str)
        
        for fmt in formatos:
            try:
                return datetime.strptime(ts_str[:19], fmt)
            except ValueError:
                continue
        
        return datetime.now()


@dataclass
class ReporteAnalisis:
    """Contiene los resultados del análisis de logs"""
    total_eventos: int = 0
    eventos_por_categoria: Dict[str, int] = field(default_factory=dict)
    eventos_por_hora: Dict[int, int] = field(default_factory=dict)
    eventos_por_dia: Dict[str, int] = field(default_factory=dict)
    top_ips: List[Tuple[str, int]] = field(default_factory=list)
    top_usuarios: List[Tuple[str, int]] = field(default_factory=list)
    top_tipos: List[Tuple[str, int]] = field(default_factory=list)
    eventos_criticos: List[EventoSeguridad] = field(default_factory=list)
    periodo_inicio: Optional[datetime] = None
    periodo_fin: Optional[datetime] = None
    archivos_analizados: List[str] = field(default_factory=list)


class AnalizadorLogs:
    """
    Analiza logs clasificados y genera estadísticas y reportes
    """
    
    def __init__(self):
        self.cargador = CargadorLogs()
        self.eventos: List[EventoSeguridad] = []
    
    def cargar_logs(self, rutas: List[str]) -> int:
        """
        Carga logs desde múltiples archivos
        
        Args:
            rutas: Lista de rutas a archivos de log
            
        Returns:
            Número total de eventos cargados
        """
        self.eventos = []
        for ruta in rutas:
            if os.path.exists(ruta):
                print(f"  📂 Cargando: {ruta}")
                eventos_archivo = self.cargador.cargar(ruta)
                self.eventos.extend(eventos_archivo)
                print(f"     ✅ {len(eventos_archivo):,} eventos")
        
        # Ordenar por timestamp
        self.eventos.sort(key=lambda e: e.timestamp)
        return len(self.eventos)
    
    def generar_reporte(self) -> ReporteAnalisis:
        """
        Genera un reporte con estadísticas del análisis
        
        Returns:
            ReporteAnalisis con todas las estadísticas
        """
        reporte = ReporteAnalisis()
        reporte.total_eventos = len(self.eventos)
        
        if not self.eventos:
            return reporte
        
        # Contadores
        por_categoria = Counter()
        por_hora = Counter()
        por_dia = Counter()
        por_ip = Counter()
        por_usuario = Counter()
        por_tipo = Counter()
        
        for evento in self.eventos:
            por_categoria[evento.categoria.value] += 1
            por_hora[evento.timestamp.hour] += 1
            por_dia[evento.timestamp.strftime('%Y-%m-%d')] += 1
            por_tipo[evento.tipo] += 1
            
            if evento.ip_origen:
                por_ip[evento.ip_origen] += 1
            if evento.usuario:
                por_usuario[evento.usuario] += 1
            
            # Eventos críticos (intrusiones y severidad alta)
            if evento.categoria == CategoriaEvento.INTRUSION or evento.severidad >= 3:
                reporte.eventos_criticos.append(evento)
        
        reporte.eventos_por_categoria = dict(por_categoria)
        reporte.eventos_por_hora = dict(por_hora)
        reporte.eventos_por_dia = dict(por_dia)
        reporte.top_ips = por_ip.most_common(15)
        reporte.top_usuarios = por_usuario.most_common(10)
        reporte.top_tipos = por_tipo.most_common(15)
        reporte.periodo_inicio = self.eventos[0].timestamp
        reporte.periodo_fin = self.eventos[-1].timestamp
        reporte.archivos_analizados = list(set(e.origen_log for e in self.eventos))
        
        return reporte
    
    def imprimir_reporte(self, reporte: ReporteAnalisis):
        """Imprime el reporte en consola con formato"""
        print("\n" + "═" * 70)
        print("            📊 REPORTE DE ANÁLISIS DE LOGS DE SEGURIDAD")
        print("═" * 70)
        
        print(f"\n📅 Período analizado:")
        print(f"   Desde: {reporte.periodo_inicio}")
        print(f"   Hasta: {reporte.periodo_fin}")
        
        print(f"\n📈 Total de eventos: {reporte.total_eventos:,}")
        
        # Por categoría
        print("\n📊 Eventos por categoría:")
        colores_cat = {
            'exito': '\033[92m',      # Verde
            'fallo': '\033[91m',      # Rojo
            'intrusion': '\033[95m',  # Magenta
            'sospechoso': '\033[93m', # Amarillo
            'informativo': '\033[94m', # Azul
            'error_sistema': '\033[91m',
            'desconocido': '\033[90m',
        }
        reset = '\033[0m'
        
        for cat, count in sorted(reporte.eventos_por_categoria.items(), 
                                  key=lambda x: x[1], reverse=True):
            color = colores_cat.get(cat, '')
            porcentaje = (count / reporte.total_eventos) * 100
            barra = "█" * int(porcentaje / 2)
            print(f"   {color}{cat:15}{reset} {count:>8,} ({porcentaje:5.1f}%) {barra}")
        
        # Top IPs
        if reporte.top_ips:
            print("\n🌐 Top 10 IPs más activas:")
            for ip, count in reporte.top_ips[:10]:
                print(f"   {ip:20} → {count:,} eventos")
        
        # Top usuarios
        if reporte.top_usuarios:
            print("\n👤 Top usuarios:")
            for user, count in reporte.top_usuarios[:10]:
                print(f"   {user:20} → {count:,} eventos")
        
        # Tipos de eventos
        if reporte.top_tipos:
            print("\n🏷️  Top tipos de eventos:")
            for tipo, count in reporte.top_tipos[:10]:
                print(f"   {tipo:30} → {count:,}")
        
        # Eventos críticos
        if reporte.eventos_criticos:
            print(f"\n🚨 Eventos críticos/intrusiones: {len(reporte.eventos_criticos)}")
            for evento in reporte.eventos_criticos[:5]:
                print(f"   [{evento.timestamp}] {evento.descripcion}")
                if evento.ip_origen:
                    print(f"      IP: {evento.ip_origen}")
        
        print("\n" + "═" * 70)
    
    def exportar_reporte_json(self, reporte: ReporteAnalisis, ruta: str):
        """Exporta el reporte a JSON"""
        datos = {
            'generado': datetime.now().isoformat(),
            'total_eventos': reporte.total_eventos,
            'periodo': {
                'inicio': reporte.periodo_inicio.isoformat() if reporte.periodo_inicio else None,
                'fin': reporte.periodo_fin.isoformat() if reporte.periodo_fin else None,
            },
            'eventos_por_categoria': reporte.eventos_por_categoria,
            'eventos_por_hora': reporte.eventos_por_hora,
            'top_ips': reporte.top_ips,
            'top_usuarios': reporte.top_usuarios,
            'top_tipos': reporte.top_tipos,
            'eventos_criticos': [
                {
                    'timestamp': e.timestamp.isoformat(),
                    'categoria': e.categoria.value,
                    'tipo': e.tipo,
                    'descripcion': e.descripcion,
                    'ip': e.ip_origen,
                    'usuario': e.usuario,
                }
                for e in reporte.eventos_criticos[:50]
            ]
        }
        
        with open(ruta, 'w', encoding='utf-8') as f:
            json.dump(datos, f, indent=2, ensure_ascii=False)
        print(f"📄 Reporte JSON guardado: {ruta}")


class GeneradorGraficos:
    """
    Genera visualizaciones de los datos de seguridad usando Matplotlib
    """
    
    # Colores para categorías
    COLORES = {
        'exito': '#28a745',
        'fallo': '#dc3545',
        'intrusion': '#9b59b6',
        'sospechoso': '#ffc107',
        'informativo': '#17a2b8',
        'error_sistema': '#e74c3c',
        'desconocido': '#6c757d',
    }
    
    def __init__(self, directorio_salida: str = "reportes"):
        """
        Inicializa el generador de gráficos
        
        Args:
            directorio_salida: Directorio donde guardar los gráficos
        """
        self.directorio = directorio_salida
        os.makedirs(directorio_salida, exist_ok=True)
        
        if not MATPLOTLIB_DISPONIBLE:
            print("⚠️  Matplotlib no disponible. No se generarán gráficos.")
    
    def generar_todos(self, reporte: ReporteAnalisis, eventos: List[EventoSeguridad]):
        """Genera todos los gráficos disponibles"""
        if not MATPLOTLIB_DISPONIBLE or plt is None:
            return
        
        print("\n📊 Generando visualizaciones...")
        
        # Configurar estilo
        plt.style.use('ggplot')  # type: ignore
        plt.rcParams['figure.facecolor'] = '#1a1a2e'  # type: ignore
        plt.rcParams['axes.facecolor'] = '#16213e'  # type: ignore
        plt.rcParams['text.color'] = 'white'  # type: ignore
        plt.rcParams['axes.labelcolor'] = 'white'  # type: ignore
        plt.rcParams['xtick.color'] = 'white'  # type: ignore
        plt.rcParams['ytick.color'] = 'white'  # type: ignore
        
        self._grafico_categorias(reporte)
        self._grafico_timeline(reporte)
        self._grafico_horas(reporte)
        self._grafico_top_ips(reporte)
        self._grafico_dashboard(reporte, eventos)
        
        print(f"   ✅ Gráficos guardados en: {self.directorio}/")
    
    def _grafico_categorias(self, reporte: ReporteAnalisis):
        """Gráfico de pastel de categorías"""
        if not reporte.eventos_por_categoria or plt is None:
            return
        
        fig, ax = plt.subplots(figsize=(10, 8))  # type: ignore
        
        categorias = list(reporte.eventos_por_categoria.keys())
        valores = list(reporte.eventos_por_categoria.values())
        colores = [self.COLORES.get(c, '#6c757d') for c in categorias]
        
        # Destacar intrusiones
        explode = [0.1 if c == 'intrusion' else 0 for c in categorias]
        
        wedges, texts, autotexts = ax.pie(  # type: ignore
            valores, labels=categorias, autopct='%1.1f%%',
            colors=colores, explode=explode,
            shadow=True, startangle=90
        )
        
        plt.setp(autotexts, size=10, weight='bold', color='white')  # type: ignore
        plt.setp(texts, size=11, color='white')  # type: ignore
        
        ax.set_title('Distribución de Eventos por Categoría', 
                     fontsize=14, fontweight='bold', color='white', pad=20)
        
        ruta = os.path.join(self.directorio, 'categorias.png')
        plt.savefig(ruta, dpi=150, bbox_inches='tight',   # type: ignore
                   facecolor='#1a1a2e', edgecolor='none')
        plt.close()  # type: ignore
        print(f"   📈 {ruta}")
    
    def _grafico_timeline(self, reporte: ReporteAnalisis):
        """Gráfico de línea temporal de eventos por día"""
        if not reporte.eventos_por_dia or plt is None:
            return
        
        fig, ax = plt.subplots(figsize=(14, 6))  # type: ignore
        
        fechas = sorted(reporte.eventos_por_dia.keys())
        valores = [reporte.eventos_por_dia[f] for f in fechas]
        
        ax.fill_between(range(len(fechas)), valores, alpha=0.3, color='#00d9ff')  # type: ignore
        ax.plot(range(len(fechas)), valores, color='#00d9ff', linewidth=2, marker='o')
        
        ax.set_xlabel('Fecha', fontsize=12)
        ax.set_ylabel('Número de Eventos', fontsize=12)
        ax.set_title('Eventos de Seguridad por Día', 
                     fontsize=14, fontweight='bold', color='white')
        
        # Mostrar solo algunas etiquetas
        step = max(1, len(fechas) // 10)
        ax.set_xticks(range(0, len(fechas), step))
        ax.set_xticklabels([fechas[i] for i in range(0, len(fechas), step)], rotation=45)
        
        ax.grid(True, alpha=0.3)
        
        ruta = os.path.join(self.directorio, 'timeline.png')
        plt.savefig(ruta, dpi=150, bbox_inches='tight',  # type: ignore
                   facecolor='#1a1a2e', edgecolor='none')
        plt.close()  # type: ignore
        print(f"   📈 {ruta}")
    
    def _grafico_horas(self, reporte: ReporteAnalisis):
        """Gráfico de barras de eventos por hora del día"""
        if plt is None:
            return
        
        fig, ax = plt.subplots(figsize=(12, 6))  # type: ignore
        
        horas = list(range(24))
        valores = [reporte.eventos_por_hora.get(h, 0) for h in horas]
        
        # Colorear según actividad
        colores = []
        max_val = max(valores) if valores else 1
        for v in valores:
            intensidad = v / max_val
            if intensidad > 0.7:
                colores.append('#dc3545')  # Rojo
            elif intensidad > 0.4:
                colores.append('#ffc107')  # Amarillo
            else:
                colores.append('#28a745')  # Verde
        
        bars = ax.bar(horas, valores, color=colores, edgecolor='white', linewidth=0.5)
        
        ax.set_xlabel('Hora del Día', fontsize=12)
        ax.set_ylabel('Número de Eventos', fontsize=12)
        ax.set_title('Distribución de Eventos por Hora', 
                     fontsize=14, fontweight='bold', color='white')
        ax.set_xticks(horas)
        ax.grid(True, alpha=0.3, axis='y')
        
        ruta = os.path.join(self.directorio, 'horas.png')
        plt.savefig(ruta, dpi=150, bbox_inches='tight',  # type: ignore
                   facecolor='#1a1a2e', edgecolor='none')
        plt.close()  # type: ignore
        print(f"   📈 {ruta}")
    
    def _grafico_top_ips(self, reporte: ReporteAnalisis):
        """Gráfico de barras horizontales de top IPs"""
        if not reporte.top_ips or plt is None:
            return
        
        fig, ax = plt.subplots(figsize=(12, 8))  # type: ignore
        
        ips = [ip for ip, _ in reporte.top_ips[:15]]
        valores = [count for _, count in reporte.top_ips[:15]]
        
        y_pos = range(len(ips))
        bars = ax.barh(y_pos, valores, color='#00d9ff', edgecolor='white', linewidth=0.5)
        
        ax.set_yticks(y_pos)
        ax.set_yticklabels(ips)
        ax.invert_yaxis()
        ax.set_xlabel('Número de Eventos', fontsize=12)
        ax.set_title('Top 15 IPs Más Activas', 
                     fontsize=14, fontweight='bold', color='white')
        ax.grid(True, alpha=0.3, axis='x')
        
        # Añadir valores en las barras
        for bar, valor in zip(bars, valores):
            ax.text(bar.get_width() + max(valores)*0.01, bar.get_y() + bar.get_height()/2,
                   f'{valor:,}', va='center', color='white', fontsize=9)
        
        ruta = os.path.join(self.directorio, 'top_ips.png')
        plt.savefig(ruta, dpi=150, bbox_inches='tight',  # type: ignore
                   facecolor='#1a1a2e', edgecolor='none')
        plt.close()  # type: ignore
        print(f"   📈 {ruta}")
    
    def _grafico_dashboard(self, reporte: ReporteAnalisis, eventos: List[EventoSeguridad]):
        """Dashboard completo con múltiples gráficos"""
        if plt is None:
            return
        
        fig = plt.figure(figsize=(20, 12))  # type: ignore
        fig.suptitle('🛡️ Dashboard de Seguridad - Análisis de Logs', 
                     fontsize=18, fontweight='bold', color='white', y=0.98)
        
        # Grid de subplots
        gs = fig.add_gridspec(2, 3, hspace=0.3, wspace=0.3)
        
        # 1. Categorías (pie)
        ax1 = fig.add_subplot(gs[0, 0])
        if reporte.eventos_por_categoria:
            categorias = list(reporte.eventos_por_categoria.keys())
            valores = list(reporte.eventos_por_categoria.values())
            colores = [self.COLORES.get(c, '#6c757d') for c in categorias]
            ax1.pie(valores, labels=categorias, autopct='%1.1f%%', colors=colores)
        ax1.set_title('Por Categoría', color='white', fontweight='bold')
        
        # 2. Por hora (barras)
        ax2 = fig.add_subplot(gs[0, 1])
        horas = list(range(24))
        valores = [reporte.eventos_por_hora.get(h, 0) for h in horas]
        ax2.bar(horas, valores, color='#00d9ff', alpha=0.8)
        ax2.set_title('Por Hora del Día', color='white', fontweight='bold')
        ax2.set_xlabel('Hora')
        
        # 3. Métricas clave
        ax3 = fig.add_subplot(gs[0, 2])
        ax3.axis('off')
        metricas = f"""
        📊 MÉTRICAS CLAVE
        
        Total Eventos: {reporte.total_eventos:,}
        
        ✅ Éxitos: {reporte.eventos_por_categoria.get('exito', 0):,}
        ❌ Fallos: {reporte.eventos_por_categoria.get('fallo', 0):,}
        🚨 Intrusiones: {reporte.eventos_por_categoria.get('intrusion', 0):,}
        ⚠️ Sospechosos: {reporte.eventos_por_categoria.get('sospechoso', 0):,}
        
        🌐 IPs únicas: {len(reporte.top_ips)}
        👤 Usuarios: {len(reporte.top_usuarios)}
        """
        ax3.text(0.1, 0.9, metricas, transform=ax3.transAxes,
                fontsize=12, verticalalignment='top', color='white',
                fontfamily='monospace',
                bbox=dict(boxstyle='round', facecolor='#16213e', alpha=0.8))
        
        # 4. Timeline (línea)
        ax4 = fig.add_subplot(gs[1, :2])
        if reporte.eventos_por_dia:
            fechas = sorted(reporte.eventos_por_dia.keys())
            valores = [reporte.eventos_por_dia[f] for f in fechas]
            ax4.fill_between(range(len(fechas)), valores, alpha=0.3, color='#00d9ff')  # type: ignore
            ax4.plot(range(len(fechas)), valores, color='#00d9ff', linewidth=2)
            step = max(1, len(fechas) // 8)
            ax4.set_xticks(range(0, len(fechas), step))
            ax4.set_xticklabels([fechas[i][-5:] for i in range(0, len(fechas), step)])
        ax4.set_title('Timeline de Eventos', color='white', fontweight='bold')
        ax4.grid(True, alpha=0.3)
        
        # 5. Top IPs
        ax5 = fig.add_subplot(gs[1, 2])
        if reporte.top_ips:
            ips = [ip[:15] for ip, _ in reporte.top_ips[:8]]
            valores = [c for _, c in reporte.top_ips[:8]]
            ax5.barh(range(len(ips)), valores, color='#e74c3c', alpha=0.8)
            ax5.set_yticks(range(len(ips)))
            ax5.set_yticklabels(ips, fontsize=9)
            ax5.invert_yaxis()
        ax5.set_title('Top IPs', color='white', fontweight='bold')
        
        ruta = os.path.join(self.directorio, 'dashboard.png')
        plt.savefig(ruta, dpi=150, bbox_inches='tight',  # type: ignore
                   facecolor='#1a1a2e', edgecolor='none')
        plt.close()  # type: ignore
        print(f"   📈 {ruta}")


def main():
    """Función principal de demostración"""
    import sys
    
    print("\n" + "=" * 60)
    print("   📊 IDS-SIMULA - Analizador de Logs de Seguridad")
    print("   MF0488 - Gestión de incidentes de seguridad")
    print("=" * 60)
    
    # Determinar archivos a analizar
    if len(sys.argv) > 1:
        rutas = sys.argv[1:]
    else:
        # Usar logs de ejemplo o del sistema
        base_dir = os.path.dirname(os.path.abspath(__file__))
        logs_ejemplo = os.path.join(base_dir, 'logs_ejemplo')
        
        if os.path.exists(logs_ejemplo):
            rutas = [
                os.path.join(logs_ejemplo, 'auth.log'),
                os.path.join(logs_ejemplo, 'access.log'),
            ]
        else:
            print("❌ No se encontraron logs. Usa: python analizador_logs.py <archivo>")
            return
    
    # Crear analizador
    analizador = AnalizadorLogs()
    
    print("\n📂 Cargando logs...")
    total = analizador.cargar_logs(rutas)
    
    if total == 0:
        print("❌ No se cargaron eventos")
        return
    
    print(f"\n✅ Total eventos cargados: {total:,}")
    
    # Generar reporte
    print("\n📊 Analizando eventos...")
    reporte = analizador.generar_reporte()
    
    # Mostrar reporte
    analizador.imprimir_reporte(reporte)
    
    # Exportar JSON
    base_dir = os.path.dirname(os.path.abspath(__file__))
    reportes_dir = os.path.join(base_dir, 'reportes')
    os.makedirs(reportes_dir, exist_ok=True)
    
    json_path = os.path.join(reportes_dir, f"reporte_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    analizador.exportar_reporte_json(reporte, json_path)
    
    # Generar gráficos
    if MATPLOTLIB_DISPONIBLE:
        generador = GeneradorGraficos(reportes_dir)
        generador.generar_todos(reporte, analizador.eventos)
    else:
        print("\n💡 Instala matplotlib para gráficos: pip install matplotlib")
    
    print("\n✅ Análisis completado")


if __name__ == '__main__':
    main()
