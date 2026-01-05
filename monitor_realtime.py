#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
    IDS-IMULA - Monitor en Tiempo Real - MF0488
═══════════════════════════════════════════════════════════════════════════════

Módulo para monitorización en tiempo real de logs:
- Monitoriza archivos de log continuamente (tail -f)
- Detecta amenazas en tiempo real
- Genera alertas instantáneas
- Dashboard en consola con estadísticas en vivo
"""

import os
import sys
import time
import signal
import threading
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Callable, Set
from dataclasses import dataclass, field
from collections import defaultdict, deque
from queue import Queue, Empty

from config import COLORES, RUTAS_LOGS_SISTEMA, BASE_DIR
from modelos import EventoLog, Alerta, Severidad
from motor_deteccion import MotorDeteccion
from lector_logs import LectorLogs


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURACIÓN DEL MONITOR
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ConfiguracionMonitor:
    """Configuración del monitor en tiempo real"""
    intervalo_actualizacion: float = 1.0    # Segundos entre actualizaciones de pantalla
    intervalo_lectura: float = 0.5          # Segundos entre lecturas de log
    max_lineas_buffer: int = 1000           # Líneas máximas en buffer
    mostrar_todas_lineas: bool = False      # Mostrar todas las líneas o solo alertas
    sonido_alertas: bool = True             # Reproducir sonido en alertas
    colores_habilitados: bool = True        # Usar colores en terminal
    max_alertas_pantalla: int = 10          # Alertas máximas a mostrar
    pausar_scroll_alerta: bool = False      # Pausar al detectar alerta crítica


# ═══════════════════════════════════════════════════════════════════════════════
# ESTADÍSTICAS EN TIEMPO REAL
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class EstadisticasRealtime:
    """Estadísticas actualizadas en tiempo real"""
    inicio_monitoreo: datetime = field(default_factory=datetime.now)
    lineas_procesadas: int = 0
    eventos_detectados: int = 0
    alertas_generadas: int = 0
    alertas_por_severidad: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    alertas_por_tipo: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    ips_detectadas: Set[str] = field(default_factory=set)
    ips_maliciosas: Set[str] = field(default_factory=set)
    ultimo_evento: Optional[datetime] = None
    eventos_por_minuto: deque = field(default_factory=lambda: deque(maxlen=60))
    
    def registrar_alerta(self, alerta: Alerta):
        """Registra una nueva alerta en las estadísticas"""
        self.alertas_generadas += 1
        self.alertas_por_severidad[alerta.severidad.name] += 1
        self.alertas_por_tipo[alerta.tipo_ataque.value] += 1
        
        if alerta.ip_origen:
            self.ips_detectadas.add(alerta.ip_origen)
            if alerta.severidad in [Severidad.ALTA, Severidad.CRITICA]:
                self.ips_maliciosas.add(alerta.ip_origen)
        
        self.ultimo_evento = datetime.now()
    
    def registrar_linea(self):
        """Registra una línea procesada"""
        self.lineas_procesadas += 1
        ahora = datetime.now()
        # Limpiar eventos antiguos (más de 1 minuto)
        while self.eventos_por_minuto and self.eventos_por_minuto[0] < ahora - timedelta(minutes=1):
            self.eventos_por_minuto.popleft()
        self.eventos_por_minuto.append(ahora)
    
    @property
    def tasa_eventos_minuto(self) -> int:
        """Eventos por minuto actual"""
        return len(self.eventos_por_minuto)
    
    @property
    def tiempo_activo(self) -> str:
        """Tiempo transcurrido desde el inicio"""
        delta = datetime.now() - self.inicio_monitoreo
        horas, resto = divmod(int(delta.total_seconds()), 3600)
        minutos, segundos = divmod(resto, 60)
        return f"{horas:02d}:{minutos:02d}:{segundos:02d}"


# ═════════════════════════════════════
# LECTOR DE LOGS EN TIEMPO REAL
# ═══════════════════════════════════════════════════════════

class LectorLogRealtime:
    """
    Lee logs en tiempo real (similar a tail -f)
    """
    
    def __init__(self, ruta: str, desde_final: bool = True):
        """
        Inicializa el lector en tiempo real
        
        Args:
            ruta: Ruta al archivo de log
            desde_final: Si True, empieza desde el final del archivo
        """
        self.ruta = ruta
        self.desde_final = desde_final
        self.archivo = None
        self.posicion = 0
        self.inode = None
        self._abierto = False
    
    def abrir(self) -> bool:
        """Abre el archivo y posiciona el cursor"""
        try:
            if not os.path.exists(self.ruta):
                return False
            
            self.archivo = open(self.ruta, 'r', encoding='utf-8', errors='ignore')
            stat = os.stat(self.ruta)
            self.inode = stat.st_ino
            
            if self.desde_final:
                self.archivo.seek(0, 2)  # Ir al final
            
            self.posicion = self.archivo.tell()
            self._abierto = True
            return True
            
        except Exception as e:
            print(f"Error abriendo {self.ruta}: {e}")
            return False
    
    def cerrar(self):
        """Cierra el archivo"""
        if self.archivo:
            self.archivo.close()
            self._abierto = False
    
    def _verificar_rotacion(self) -> bool:
        """Verifica si el archivo fue rotado"""
        try:
            stat = os.stat(self.ruta)
            if stat.st_ino != self.inode:
                # El archivo fue rotado, reabrirlo
                self.cerrar()
                return self.abrir()
            return True
        except:
            return False
    
    def leer_nuevas_lineas(self) -> List[str]:
        """Lee las nuevas líneas del archivo"""
        if not self._abierto or self.archivo is None:
            if not self.abrir():
                return []
        
        # Verificar rotación del log
        self._verificar_rotacion()
        
        lineas = []
        try:
            if self.archivo is not None:
                self.archivo.seek(self.posicion)
                nuevas_lineas = self.archivo.readlines()
                self.posicion = self.archivo.tell()
                
                for linea in nuevas_lineas:
                    linea = linea.rstrip('\n\r')
                    if linea:
                        lineas.append(linea)
                    
        except Exception as e:
            pass
        
        return lineas


# ═════════════════════════════════
# MONITOR EN TIEMPO REAL
# ════════════════════════════════════

class MonitorRealtime:
    """
    Monitor principal de logs en tiempo real
    """
    
    def __init__(self, config: Optional[ConfiguracionMonitor] = None):
        """
        Inicializa el monitor
        
        Args:
            config: Configuración del monitor
        """
        self.config = config or ConfiguracionMonitor()
        self.motor = MotorDeteccion()
        self.estadisticas = EstadisticasRealtime()
        
        self.lectores: Dict[str, LectorLogRealtime] = {}
        self.cola_eventos: Queue = Queue()
        self.cola_alertas: Queue = Queue()
        self.alertas_recientes: deque = deque(maxlen=100)
        
        self._ejecutando = False
        self._pausado = False
        self._hilos: List[threading.Thread] = []
        
        # Callbacks para eventos
        self.on_alerta: Optional[Callable[[Alerta], None]] = None
        self.on_linea: Optional[Callable[[str, str], None]] = None
    
    def agregar_log(self, nombre: str, ruta: str, desde_final: bool = True) -> bool:
        """
        Agrega un archivo de log para monitorizar
        
        Args:
            nombre: Nombre identificativo del log
            ruta: Ruta al archivo
            desde_final: Empezar desde el final del archivo
        
        Devuelve:
            True si se agregó correctamente
        """
        if not os.path.exists(ruta):
            return False
        
        lector = LectorLogRealtime(ruta, desde_final)
        if lector.abrir():
            self.lectores[nombre] = lector
            return True
        return False
    
    def agregar_logs_sistema(self, desde_final: bool = True) -> int:
        """
        Agrega los logs del sistema disponibles
        
        Devuelve:
            Número de logs agregados
        """
        agregados = 0
        for nombre, ruta in RUTAS_LOGS_SISTEMA.items():
            if self.agregar_log(nombre, ruta, desde_final):
                agregados += 1
        return agregados
    
    def _parsear_linea_simple(self, linea: str, nombre_log: str) -> Optional[EventoLog]:
        """
        Parsea una línea de log de forma simple para el monitor
        
        Args:
            linea: Línea de texto del log
            nombre_log: Nombre del archivo de origen
        
        Devuelve:
            EventoLog o None si no se pudo parsear
        """
        import re
        from modelos import TipoEvento
        
        # Extraer IP si existe
        patron_ip = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        match_ip = re.search(patron_ip, linea)
        ip_origen = match_ip.group(1) if match_ip else None
        
        # Determinar tipo de evento básico
        linea_lower = linea.lower()
        if 'failed' in linea_lower or 'invalid' in linea_lower or 'error' in linea_lower:
            tipo = TipoEvento.LOGIN_FALLIDO
        elif 'accepted' in linea_lower or 'success' in linea_lower:
            tipo = TipoEvento.LOGIN_EXITOSO
        elif 'ufw' in linea_lower or 'firewall' in linea_lower:
            tipo = TipoEvento.FIREWALL
        else:
            tipo = TipoEvento.DESCONOCIDO
        
        return EventoLog(
            timestamp=datetime.now(),
            origen=nombre_log,
            linea_original=linea,
            ip_origen=ip_origen,
            tipo_evento=tipo,
            mensaje=linea[:200]
        )
    
    def _emitir_alerta_sonora(self, severidad: Severidad):
        """Emite un sonido de alerta según la severidad"""
        if not self.config.sonido_alertas:
            return
        
        try:
            if severidad == Severidad.CRITICA:
                # Triple beep para críticas
                print('\a\a\a', end='', flush=True)
            elif severidad == Severidad.ALTA:
                # Doble beep para altas
                print('\a\a', end='', flush=True)
            else:
                # Simple beep para otras
                print('\a', end='', flush=True)
        except:
            pass
    
    def _procesar_linea(self, nombre_log: str, linea: str):
        """Procesa una línea de log"""
        self.estadisticas.registrar_linea()
        
        # Crear evento directamente desde la línea
        evento = self._parsear_linea_simple(linea, nombre_log)
        
        if evento:
            self.estadisticas.eventos_detectados += 1
            
            # Analizar con motor de detección
            alertas = self.motor.analizar_evento(evento)
            
            for alerta in alertas:
                self.estadisticas.registrar_alerta(alerta)
                self.alertas_recientes.append(alerta)
                self.cola_alertas.put(alerta)
                
                # Callback
                if self.on_alerta:
                    self.on_alerta(alerta)
                
                # Sonido
                self._emitir_alerta_sonora(alerta.severidad)
        
        # Callback línea
        if self.on_linea:
            self.on_linea(nombre_log, linea)
    
    def _hilo_lector(self):
        """Hilo que lee los archivos de log"""
        while self._ejecutando:
            if self._pausado:
                time.sleep(0.1)
                continue
            
            for nombre, lector in self.lectores.items():
                lineas = lector.leer_nuevas_lineas()
                for linea in lineas:
                    self._procesar_linea(nombre, linea)
            
            time.sleep(self.config.intervalo_lectura)
    
    def _hilo_dashboard(self):
        """Hilo que actualiza el dashboard (modo simple)"""
        ultima_actualizacion = 0
        while self._ejecutando:
            ahora = time.time()
            if ahora - ultima_actualizacion >= 5:  # Actualizar cada 5 segundos
                self._mostrar_resumen_stats()
                ultima_actualizacion = ahora
            time.sleep(0.5)
    
    def _mostrar_resumen_stats(self):
        """Muestra un resumen de estadísticas sin limpiar pantalla"""
        c = COLORES
        stats = self.estadisticas
        print(f"\n{c['INFO']}--- Estado: {stats.tiempo_activo} | Líneas: {stats.lineas_procesadas} | Alertas: {stats.alertas_generadas} ---{c['RESET']}")
    
    def iniciar(self, modo_dashboard: bool = True):
        """
        Inicia la monitorización en tiempo real
        
        Args:
            modo_dashboard: Si True, muestra estadísticas periódicas
        """
        if not self.lectores:
            print(f"{COLORES['ALTA']}❌ No hay logs configurados para monitorizar{COLORES['RESET']}")
            return
        
        self._ejecutando = True
        self._pausado = False
        
        # Mostrar cabecera inicial
        print(f"\n{COLORES['NEGRITA']}{COLORES['INFO']}")
        print("=" * 60)
        print("       IDS-IMULA - MONITOR EN TIEMPO REAL")
        print("=" * 60)
        print(f"{COLORES['RESET']}")
        print(f"  Logs monitorizados:")
        for nombre, lector in self.lectores.items():
            print(f"    - {nombre}: {lector.ruta}")
        print(f"\n  {COLORES['INFO']}Pulsa Ctrl+C para detener la monitorización{COLORES['RESET']}")
        print("=" * 60)
        
        # Iniciar hilo lector
        hilo_lector = threading.Thread(target=self._hilo_lector, daemon=True)
        hilo_lector.start()
        self._hilos.append(hilo_lector)
        
        if modo_dashboard:
            # Iniciar hilo de estadísticas
            hilo_dashboard = threading.Thread(target=self._hilo_dashboard, daemon=True)
            hilo_dashboard.start()
            self._hilos.append(hilo_dashboard)
        
        # Bucle principal - mostrar alertas en tiempo real
        try:
            while self._ejecutando:
                # Procesar alertas de la cola
                try:
                    alerta = self.cola_alertas.get_nowait()
                    self._mostrar_alerta_simple(alerta)
                except Empty:
                    pass
                time.sleep(0.1)
        except KeyboardInterrupt:
            self._ejecutando = False
        
        self.detener()
    
    def _mostrar_alerta_simple(self, alerta: Alerta):
        """Muestra una alerta en modo simple"""
        c = COLORES
        color = {
            Severidad.CRITICA: c['CRITICA'],
            Severidad.ALTA: c['ALTA'],
            Severidad.MEDIA: c['MEDIA'],
            Severidad.BAJA: c['BAJA'],
            Severidad.INFO: c['INFO'],
        }.get(alerta.severidad, c['RESET'])
        
        hora = alerta.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        print(f"{color}[{hora}] [{alerta.severidad.name}] {alerta.tipo_ataque}{c['RESET']}")
        print(f"  IP: {alerta.ip_origen or 'N/A'} | {alerta.descripcion}")
        if alerta.recomendacion:
            print(f"  💡 {alerta.recomendacion}")
        print()
    
    def detener(self):
        """Detiene la monitorización"""
        self._ejecutando = False
        
        # Cerrar lectores
        for lector in self.lectores.values():
            lector.cerrar()
        
        # Esperar hilos
        for hilo in self._hilos:
            hilo.join(timeout=1)
        
        print(f"\n{COLORES['INFO']}{'=' * 60}{COLORES['RESET']}")
        print(f"{COLORES['INFO']}✅ Monitor detenido{COLORES['RESET']}")
        print(f"  Tiempo activo: {self.estadisticas.tiempo_activo}")
        print(f"  Líneas procesadas: {self.estadisticas.lineas_procesadas:,}")
        print(f"  Alertas generadas: {self.estadisticas.alertas_generadas}")


# ═══════════════════════════════════════════════════════════════════════════════
# INTERFAZ DE MENÚ
# ═══════════════════════════════════════════════════════════════════════════════

def menu_monitor_realtime():
    """Menú interactivo para el monitor en tiempo real"""
    
    while True:
        print(f"""
{COLORES['NEGRITA']}╔═══════════════════════════════════════════════════╗
║       🔴 MONITORIZACIÓN EN TIEMPO REAL            ║
╠═══════════════════════════════════════════════════╣{COLORES['RESET']}
║  1. 🖥️  Monitorizar logs del sistema               ║
║  2. 📁 Monitorizar archivo específico             ║
║  3. 📋 Monitorizar logs de ejemplo                ║
║  4. ⚙️  Configurar opciones de monitor             ║
║  0. ↩️  Volver al menú principal                   ║
{COLORES['NEGRITA']}╚═══════════════════════════════════════════════════╝{COLORES['RESET']}
""")
        
        opcion = input("  Selecciona una opción: ").strip()
        
        if opcion == '1':
            monitor = MonitorRealtime()
            agregados = monitor.agregar_logs_sistema()
            
            if agregados > 0:
                print(f"\n{COLORES['INFO']}  ✅ {agregados} logs del sistema detectados{COLORES['RESET']}")
                print("  Iniciando monitor... (puede requerir permisos de root)")
                input("  Pulsa Intro para continuar...")
                monitor.iniciar()
            else:
                print(f"\n{COLORES['ALTA']}  ❌ No se encontraron logs del sistema accesibles{COLORES['RESET']}")
                print("  Puede que necesites ejecutar como root")
        
        elif opcion == '2':
            ruta = input("\n  Ruta del archivo de log: ").strip()
            if os.path.exists(ruta):
                monitor = MonitorRealtime()
                nombre = os.path.basename(ruta)
                
                desde_inicio = input("  ¿Empezar desde el inicio del archivo? (s/N): ").strip().lower()
                desde_final = desde_inicio != 's'
                
                if monitor.agregar_log(nombre, ruta, desde_final):
                    print(f"\n{COLORES['INFO']}  ✅ Monitorizando: {ruta}{COLORES['RESET']}")
                    input("  Pulsa Intro para iniciar...")
                    monitor.iniciar()
                else:
                    print(f"\n{COLORES['ALTA']}  ❌ No se pudo abrir el archivo{COLORES['RESET']}")
            else:
                print(f"\n{COLORES['ALTA']}  ❌ Archivo no encontrado{COLORES['RESET']}")
        
        elif opcion == '3':
            from config import RUTA_LOGS_EJEMPLO
            
            if os.path.exists(RUTA_LOGS_EJEMPLO):
                monitor = MonitorRealtime()
                archivos = [f for f in os.listdir(RUTA_LOGS_EJEMPLO) 
                           if f.endswith('.log') or f.endswith('.txt')]
                
                agregados = 0
                for archivo in archivos:
                    ruta = os.path.join(RUTA_LOGS_EJEMPLO, archivo)
                    if monitor.agregar_log(archivo, ruta, desde_final=False):
                        agregados += 1
                
                if agregados > 0:
                    print(f"\n{COLORES['INFO']}  ✅ {agregados} logs de ejemplo detectados{COLORES['RESET']}")
                    input("  Pulsa Intro para iniciar...")
                    monitor.iniciar()
                else:
                    print(f"\n{COLORES['MEDIA']}  ⚠️  No hay logs de ejemplo{COLORES['RESET']}")
                    print("  Ejecuta primero la opción 1 del menú principal para generarlos")
            else:
                print(f"\n{COLORES['MEDIA']}  ⚠️  Directorio de logs de ejemplo no existe{COLORES['RESET']}")
        
        elif opcion == '4':
            print(f"\n{COLORES['INFO']}  Opciones de configuración:{COLORES['RESET']}")
            print("  - Intervalo de actualización: 1 segundo")
            print("  - Alertas sonoras: Activadas")
            print("  - Máximo alertas en pantalla: 10")
            print("\n  (Configuración avanzada disponible en config.py)")
        
        elif opcion == '0':
            break
        
        input("\n  Pulsa Intro para continuar...")


if __name__ == "__main__":
    menu_monitor_realtime()
