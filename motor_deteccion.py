#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
    IDS-IMULA - MF0488 - Gestión de incidentes de seguridad informática
═══════════════════════════════════════════════════════════════════════════════

Motor de detección que analiza eventos de log y detecta patrones de ataques.
Incluye reglas configurables para diferentes tipos de amenazas.
"""

import re
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field
from collections import defaultdict

from modelos import EventoLog, Alerta, Severidad, TipoEvento


@dataclass
class ReglaDeteccion:
    """Define una regla de detección de intrusos"""
    id: str
    nombre: str
    descripcion: str
    patron: str                     # Expresión regular a buscar
    severidad: Severidad
    umbral: int = 1                 # Número de coincidencias para activar
    intervalo: int = 60             # Segundos para contar coincidencias
    activa: bool = True
    categoria: str = "general"
    
    def __post_init__(self):
        """Compila el patrón regex"""
        self._regex = re.compile(self.patron, re.IGNORECASE)
    
    @property
    def regex(self):
        return self._regex


class MotorDeteccion:
    """
    Motor de detección de intrusos basado en reglas
    
    Analiza eventos de log buscando patrones sospechosos y genera
    alertas cuando se detectan coincidencias.
    """
    
    def __init__(self):
        """Inicializa el motor con las reglas predeterminadas"""
        self.reglas: List[ReglaDeteccion] = []
        self.contadores: Dict[str, Dict[str, List[datetime]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self._cargar_reglas_predeterminadas()
    
    def _cargar_reglas_predeterminadas(self):
        """Carga las reglas de detección predeterminadas"""
        self.reglas = [
            ReglaDeteccion(
                id="bruteforce_ssh",
                nombre="Fuerza Bruta SSH",
                descripcion="Múltiples intentos de login fallidos desde la misma IP",
                patron=r"Failed password|authentication failure|Invalid user",
                severidad=Severidad.ALTA,
                umbral=5,
                intervalo=60,
                categoria="autenticacion"
            ),
            ReglaDeteccion(
                id="port_scan",
                nombre="Escaneo de Puertos",
                descripcion="Conexiones a múltiples puertos desde la misma IP",
                patron=r"\[UFW BLOCK\]|connection refused|port \d+",
                severidad=Severidad.MEDIA,
                umbral=10,
                intervalo=30,
                categoria="red"
            ),
            ReglaDeteccion(
                id="sql_injection",
                nombre="SQL Injection",
                descripcion="Intento de inyección SQL en petición web",
                patron=r"(?:union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|--\s*$|;\s*drop\s+table)",
                severidad=Severidad.CRITICA,
                umbral=1,
                intervalo=60,
                categoria="web"
            ),
            ReglaDeteccion(
                id="xss_attempt",
                nombre="XSS Attempt",
                descripcion="Intento de Cross-Site Scripting",
                patron=r"<script|javascript:|onerror\s*=|onload\s*=",
                severidad=Severidad.ALTA,
                umbral=1,
                intervalo=60,
                categoria="web"
            ),
            ReglaDeteccion(
                id="path_traversal",
                nombre="Path Traversal",
                descripcion="Intento de acceso a directorios superiores",
                patron=r"\.\./|\.\.\\|%2e%2e|%252e",
                severidad=Severidad.ALTA,
                umbral=1,
                intervalo=60,
                categoria="web"
            ),
            ReglaDeteccion(
                id="sensitive_path",
                nombre="Acceso a Rutas Sensibles",
                descripcion="Intento de acceso a recursos administrativos o sensibles",
                patron=r"/admin|/wp-admin|/phpmyadmin|/\.git|/\.env|/config\.|/backup",
                severidad=Severidad.MEDIA,
                umbral=3,
                intervalo=60,
                categoria="web"
            ),
            ReglaDeteccion(
                id="suspicious_ua",
                nombre="User-Agent Sospechoso",
                descripcion="Herramientas de escaneo automatizado detectadas",
                patron=r"sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|hydra|medusa",
                severidad=Severidad.ALTA,
                umbral=1,
                intervalo=60,
                categoria="web"
            ),
            ReglaDeteccion(
                id="ddos_rate",
                nombre="DDoS/Rate Limit",
                descripcion="Demasiadas peticiones desde una IP en poco tiempo",
                patron=r"(?:GET|POST|PUT|DELETE)\s+/",
                severidad=Severidad.CRITICA,
                umbral=50,
                intervalo=1,
                categoria="red"
            ),
            ReglaDeteccion(
                id="firewall_block",
                nombre="Firewall Block",
                descripcion="Conexión bloqueada por firewall",
                patron=r"\[UFW BLOCK\]",
                severidad=Severidad.BAJA,
                umbral=10,
                intervalo=60,
                categoria="red"
            ),
        ]
    
    def analizar_evento(self, evento: EventoLog) -> List[Alerta]:
        """
        Analiza un evento y genera alertas si coincide con alguna regla
        
        Args:
            evento: Evento de log a analizar
            
        Devuelve:
            Lista de alertas generadas (puede estar vacía)
        """
        alertas = []
        contenido = evento.linea_original or evento.mensaje
        
        for regla in self.reglas:
            if not regla.activa:
                continue
            
            # Buscar coincidencia con el patrón
            if regla.regex.search(contenido):
                # Clave única para este origen (IP o identificador)
                origen = evento.ip_origen or evento.origen or "desconocido"
                
                # Registrar timestamp
                ahora = evento.timestamp or datetime.now()
                self.contadores[regla.id][origen].append(ahora)
                
                # Limpiar timestamps antiguos
                limite = ahora - timedelta(seconds=regla.intervalo)
                self.contadores[regla.id][origen] = [
                    ts for ts in self.contadores[regla.id][origen]
                    if ts > limite
                ]
                
                # Verificar si se supera el umbral
                coincidencias = len(self.contadores[regla.id][origen])
                
                if coincidencias >= regla.umbral:
                    alerta = Alerta(
                        timestamp=ahora,
                        severidad=regla.severidad,
                        tipo_ataque=self._mapear_tipo_ataque(regla.id),
                        descripcion=f"{regla.descripcion} (Origen: {origen}, {coincidencias} coincidencias)",
                        ip_origen=evento.ip_origen,
                        regla_activada=regla.id,
                        recomendacion=self._obtener_recomendacion(regla.id)
                    )
                    alertas.append(alerta)
                    
                    # Resetear contador para evitar alertas duplicadas
                    self.contadores[regla.id][origen] = []
        
        return alertas
    
    def _mapear_tipo_ataque(self, regla_id: str) -> TipoEvento:
        """Mapea el ID de regla a un TipoEvento"""
        mapeo = {
            'bruteforce_ssh': TipoEvento.FUERZA_BRUTA,
            'port_scan': TipoEvento.ESCANEO_PUERTOS,
            'sql_injection': TipoEvento.SQL_INJECTION,
            'xss_attempt': TipoEvento.XSS,
            'path_traversal': TipoEvento.PATH_TRAVERSAL,
            'sensitive_path': TipoEvento.ACCESO_SOSPECHOSO,
            'suspicious_ua': TipoEvento.ACCESO_SOSPECHOSO,
            'ddos_rate': TipoEvento.DENEGACION_SERVICIO,
            'firewall_block': TipoEvento.FIREWALL,
        }
        return mapeo.get(regla_id, TipoEvento.DESCONOCIDO)
    
    def _obtener_recomendacion(self, regla_id: str) -> str:
        """Obtiene una recomendación para la regla"""
        recomendaciones = {
            'bruteforce_ssh': 'Considera bloquear la IP con fail2ban o firewall',
            'port_scan': 'Monitoriza la IP y considera bloquearla temporalmente',
            'sql_injection': 'Revisa y sanitiza las entradas de usuario en la aplicación',
            'xss_attempt': 'Implementa Content Security Policy y escapa las salidas',
            'path_traversal': 'Valida y normaliza las rutas de archivo en la aplicación',
            'sensitive_path': 'Restringe el acceso a rutas administrativas',
            'suspicious_ua': 'Bloquea User-Agents de herramientas de escaneo',
            'ddos_rate': 'Implementa rate limiting y considera un WAF',
            'firewall_block': 'Revisa las reglas del firewall y las IPs bloqueadas',
        }
        return recomendaciones.get(regla_id, 'Investiga el evento y toma medidas apropiadas')
    
    def analizar_eventos(self, eventos: List[EventoLog]) -> List[Alerta]:
        """
        Analiza múltiples eventos y genera alertas
        
        Args:
            eventos: Lista de eventos a analizar
            
        DEvuelve:
            Lista de todas las alertas generadas
        """
        alertas = []
        for evento in eventos:
            alertas.extend(self.analizar_evento(evento))
        return alertas
    
    def listar_reglas(self) -> List[Dict]:
        """
        Lista todas las reglas como diccionarios para la interfaz
        
        Devuelve:
            Lista de diccionarios con información de cada regla
        """
        return [
            {
                'id': regla.id,
                'nombre': regla.nombre,
                'descripcion': regla.descripcion,
                'severidad': regla.severidad.name,
                'umbral': regla.umbral,
                'intervalo': regla.intervalo,
                'activa': regla.activa,
                'categoria': regla.categoria,
            }
            for regla in self.reglas
        ]
    
    def obtener_regla_por_indice(self, indice: int) -> Optional[ReglaDeteccion]:
        """
        Obtiene una regla por su índice en la lista
        
        Args:
            indice: Índice de la regla (0-based)
            
        Devuelve:
            ReglaDeteccion o None si el índice es inválido
        """
        if 0 <= indice < len(self.reglas):
            return self.reglas[indice]
        return None
    
    def obtener_reglas(self) -> List[ReglaDeteccion]:
        """Devuelve la lista de reglas de detección"""
        return self.reglas
    
    def obtener_regla(self, id_regla: str) -> Optional[ReglaDeteccion]:
        """
        Obtiene una regla por su ID
        
        Args:
            id_regla: Identificador de la regla
            
        Revuelve:
            ReglaDeteccion o None si no existe
        """
        for regla in self.reglas:
            if regla.id == id_regla:
                return regla
        return None
    
    def modificar_regla(self, id_regla: str, **kwargs) -> bool:
        """
        Modifica los parámetros de una regla
        
        Args:
            id_regla: Identificador de la regla
            **kwargs: Parámetros a modificar (umbral, intervalo, severidad, activa)
            
        Devuelve:
            True si se modificó correctamente
        """
        regla = self.obtener_regla(id_regla)
        if not regla:
            return False
        
        for key, value in kwargs.items():
            if hasattr(regla, key):
                setattr(regla, key, value)
        
        return True
    
    def activar_regla(self, id_regla: str) -> bool:
        """Activa una regla de detección"""
        return self.modificar_regla(id_regla, activa=True)
    
    def desactivar_regla(self, id_regla: str) -> bool:
        """Desactiva una regla de detección"""
        return self.modificar_regla(id_regla, activa=False)
    
    def cambiar_umbral(self, id_regla: str, nuevo_umbral: int) -> bool:
        """Cambia el umbral de activación de una regla"""
        if nuevo_umbral < 1:
            return False
        return self.modificar_regla(id_regla, umbral=nuevo_umbral)
    
    def cambiar_severidad(self, id_regla: str, nueva_severidad: Severidad) -> bool:
        """Cambia la severidad de una regla"""
        return self.modificar_regla(id_regla, severidad=nueva_severidad)
    
    # Métodos con índice para compatibilidad con la interfaz
    def modificar_regla_por_indice(self, indice: int, campo: str, valor) -> bool:
        """
        Modifica un campo de una regla por su índice
        
        Args:
            indice: Índice de la regla (0-based)
            campo: Nombre del campo a modificar
            valor: Nuevo valor
        """
        regla = self.obtener_regla_por_indice(indice)
        if not regla:
            return False
        
        if campo == 'severidad' and isinstance(valor, str):
            # Convertir string a Severidad
            try:
                valor = Severidad[valor.upper()]
            except KeyError:
                return False
        
        if hasattr(regla, campo):
            setattr(regla, campo, valor)
            return True
        return False
    
    def cambiar_umbral_por_indice(self, indice: int, nuevo_umbral: int) -> bool:
        """Cambia el umbral de una regla por su índice"""
        if nuevo_umbral < 1:
            return False
        return self.modificar_regla_por_indice(indice, 'umbral', nuevo_umbral)
    
    def cambiar_severidad_por_indice(self, indice: int, nueva_severidad: str) -> bool:
        """Cambia la severidad de una regla por su índice (acepta string)"""
        return self.modificar_regla_por_indice(indice, 'severidad', nueva_severidad)
    
    def agregar_regla(self, regla: ReglaDeteccion) -> bool:
        """
        Añade una nueva regla de detección
        
        Args:
            regla: ReglaDeteccion a agregar
            
        Devuelve:
            True si se agregó correctamente
        """
        # Verificar que no existe una regla con el mismo ID
        if self.obtener_regla(regla.id):
            return False
        
        self.reglas.append(regla)
        return True
    
    def eliminar_regla(self, id_regla: str) -> bool:
        """
        Elimina una regla de detección
        
        Args:
            id_regla: Identificador de la regla a eliminar
            
        Devuelve:
            True si se eliminó correctamente
        """
        for i, regla in enumerate(self.reglas):
            if regla.id == id_regla:
                del self.reglas[i]
                return True
        return False
    
    def resetear_contadores(self):
        """Resetea todos los contadores de coincidencias"""
        self.contadores.clear()
    
    def obtener_estadisticas(self) -> Dict:
        """
        Obtiene estadísticas del motor de detección
        
        Devuelve:
            Diccionario con estadísticas
        """
        return {
            'total_reglas': len(self.reglas),
            'reglas_activas': sum(1 for r in self.reglas if r.activa),
            'reglas_inactivas': sum(1 for r in self.reglas if not r.activa),
            'por_severidad': {
                'critica': sum(1 for r in self.reglas if r.severidad == Severidad.CRITICA),
                'alta': sum(1 for r in self.reglas if r.severidad == Severidad.ALTA),
                'media': sum(1 for r in self.reglas if r.severidad == Severidad.MEDIA),
                'baja': sum(1 for r in self.reglas if r.severidad == Severidad.BAJA),
            },
            'por_categoria': {
                cat: sum(1 for r in self.reglas if r.categoria == cat)
                for cat in set(r.categoria for r in self.reglas)
            }
        }


def main():
    """Función de prueba del motor de detección"""
    print("=" * 60)
    print("   IDS-SIMULA - Motor de Detección")
    print("=" * 60)
    
    motor = MotorDeteccion()
    
    print(f"\n📋 Reglas cargadas: {len(motor.reglas)}")
    
    for regla in motor.reglas:
        estado = "✅" if regla.activa else "❌"
        print(f"   {estado} [{regla.severidad.name}] {regla.nombre}")
        print(f"      {regla.descripcion}")
        print(f"      Umbral: {regla.umbral} en {regla.intervalo}s")
    
    # Prueba de detección
    print("\n🧪 Prueba de detección:")
    
    eventos_prueba = [
        EventoLog(
            timestamp=datetime.now(),
            origen="test",
            linea_original="Failed password for root from 192.168.1.100",
            ip_origen="192.168.1.100"
        ),
        EventoLog(
            timestamp=datetime.now(),
            origen="test",
            linea_original="GET /admin?id=1' OR '1'='1 HTTP/1.1",
            ip_origen="10.0.0.50"
        ),
    ]
    
    for evento in eventos_prueba:
        alertas = motor.analizar_evento(evento)
        if alertas:
            for alerta in alertas:
                print(f"   🚨 [{alerta.severidad.name}] {alerta.tipo_ataque.value}")
                print(f"      {alerta.descripcion}")
        else:
            print(f"   ℹ️  Sin alertas para: {evento.linea_original[:50]}...")


if __name__ == '__main__':
    main()
