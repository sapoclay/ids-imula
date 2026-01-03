"""
Modelos de datos para IDS-IMULA
Define las estructuras de datos para eventos, alertas y reglas
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict
from enum import Enum


class TipoEvento(Enum):
    """Tipos de eventos que puede detectar IDS-IMULA"""
    LOGIN_FALLIDO = "login_fallido"
    LOGIN_EXITOSO = "login_exitoso"
    CONEXION_RED = "conexion_red"
    PETICION_WEB = "peticion_web"
    ERROR_SISTEMA = "error_sistema"
    FIREWALL = "firewall"
    ESCANEO_PUERTOS = "escaneo_puertos"
    FUERZA_BRUTA = "fuerza_bruta"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    ACCESO_SOSPECHOSO = "acceso_sospechoso"
    DENEGACION_SERVICIO = "dos"
    DESCONOCIDO = "desconocido"


class Severidad(Enum):
    """Niveles de severidad de las alertas"""
    INFO = 0
    BAJA = 1
    MEDIA = 2
    ALTA = 3
    CRITICA = 4


@dataclass
class EventoLog:
    """Representa un evento extraído de un archivo de log"""
    timestamp: datetime
    origen: str                    # Archivo de origen
    linea_original: str            # Línea completa del log
    ip_origen: Optional[str] = None
    ip_destino: Optional[str] = None
    puerto: Optional[int] = None
    usuario: Optional[str] = None
    tipo_evento: TipoEvento = TipoEvento.DESCONOCIDO
    mensaje: str = ""
    datos_extra: Dict = field(default_factory=dict)
    
    def __str__(self):
        return f"[{self.timestamp}] {self.tipo_evento.value}: {self.mensaje}"


@dataclass
class Alerta:
    """Representa una alerta generada por IDS-IMULA"""
    id: Optional[int] = None
    timestamp: datetime = field(default_factory=datetime.now)
    severidad: Severidad = Severidad.INFO
    tipo_ataque: TipoEvento = TipoEvento.DESCONOCIDO
    ip_origen: Optional[str] = None
    descripcion: str = ""
    eventos_relacionados: List[EventoLog] = field(default_factory=list)
    regla_activada: str = ""
    recomendacion: str = ""
    falso_positivo: bool = False
    
    def __str__(self):
        return f"[{self.severidad.name}] {self.tipo_ataque.value}: {self.descripcion}"
    
    def to_dict(self) -> Dict:
        """Convierte la alerta a diccionario para almacenamiento"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'severidad': self.severidad.name,
            'tipo_ataque': self.tipo_ataque.value,
            'ip_origen': self.ip_origen,
            'descripcion': self.descripcion,
            'regla_activada': self.regla_activada,
            'recomendacion': self.recomendacion,
            'falso_positivo': self.falso_positivo,
            'num_eventos': len(self.eventos_relacionados)
        }


@dataclass
class ReglaDeteccion:
    """Define una regla de detección para IDS-IMULA"""
    nombre: str
    descripcion: str
    patron: str                    # Expresión regular o patrón
    tipo_evento: TipoEvento
    severidad: Severidad
    umbral: int = 1               # Número de ocurrencias para activar
    intervalo: int = 60           # Segundos para evaluar el umbral
    activa: bool = True
    recomendacion: str = ""
    
    def __str__(self):
        return f"Regla: {self.nombre} [{self.severidad.name}]"


@dataclass
class EstadisticasIDS:
    """Estadísticas de ejecución de IDS-IMULA"""
    inicio_analisis: datetime = field(default_factory=datetime.now)
    fin_analisis: Optional[datetime] = None
    lineas_procesadas: int = 0
    eventos_detectados: int = 0
    alertas_generadas: int = 0
    alertas_por_severidad: Dict[str, int] = field(default_factory=lambda: {
        'INFO': 0, 'BAJA': 0, 'MEDIA': 0, 'ALTA': 0, 'CRITICA': 0
    })
    ips_detectadas: set = field(default_factory=set)
    archivos_analizados: List[str] = field(default_factory=list)
    
    def resumen(self) -> str:
        """Genera un resumen de las estadísticas"""
        duracion = ""
        if self.fin_analisis:
            delta = self.fin_analisis - self.inicio_analisis
            duracion = f"Duración: {delta.total_seconds():.2f} segundos"
        
        return f"""
═══════════════════════════════════════════════════════
                 RESUMEN DEL ANÁLISIS IDS-IMULA
═══════════════════════════════════════════════════════
  Inicio: {self.inicio_analisis.strftime('%Y-%m-%d %H:%M:%S')}
  {duracion}
  
  📁 Archivos analizados: {len(self.archivos_analizados)}
  📝 Líneas procesadas: {self.lineas_procesadas:,}
  🔍 Eventos detectados: {self.eventos_detectados:,}
  🚨 Alertas generadas: {self.alertas_generadas:,}
  
  Alertas por severidad:
    ℹ️  INFO:    {self.alertas_por_severidad['INFO']}
    🟢 BAJA:    {self.alertas_por_severidad['BAJA']}
    🟡 MEDIA:   {self.alertas_por_severidad['MEDIA']}
    🔴 ALTA:    {self.alertas_por_severidad['ALTA']}
    🟣 CRITICA: {self.alertas_por_severidad['CRITICA']}
  
  🌐 IPs únicas detectadas: {len(self.ips_detectadas)}
═══════════════════════════════════════════════════════
"""
