"""
Gestor de Alertas de IDS-IMULA
Maneja la generación, almacenamiento y notificación de alertas
"""

import os
import json
import sqlite3
from datetime import datetime
from typing import List, Optional
from modelos import Alerta, Severidad
import config


class GestorAlertas:
    """
    Gestiona las alertas generadas por el IDS:
    - Muestra alertas en consola con colores
    - Guarda alertas en archivo de texto/JSON
    - Almacena alertas en base de datos SQLite
    """
    
    def __init__(self, guardar_archivo: bool = True, 
                 guardar_bd: bool = True,
                 mostrar_consola: bool = True,
                 ruta_bd: Optional[str] = None):
        """
        Inicializa el gestor de alertas
        
        Args:
            guardar_archivo: Si True, guarda alertas en archivo
            guardar_bd: Si True, guarda alertas en SQLite
            mostrar_consola: Si True, muestra alertas en consola
            ruta_bd: Ruta personalizada a la base de datos (opcional)
        """
        self.guardar_archivo = guardar_archivo
        self.guardar_bd = guardar_bd
        self.mostrar_consola = mostrar_consola
        self.alertas: List[Alerta] = []
        self.ruta_bd = ruta_bd or config.RUTA_BD
        
        # Crear directorio de alertas si no existe
        os.makedirs(config.RUTA_ALERTAS, exist_ok=True)
        
        # Inicializar base de datos si es necesario
        if self.guardar_bd:
            self._inicializar_bd()
    
    def _inicializar_bd(self):
        """Crea la base de datos y tablas si no existen"""
        try:
            conn = sqlite3.connect(self.ruta_bd)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alertas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    severidad TEXT NOT NULL,
                    tipo_ataque TEXT NOT NULL,
                    ip_origen TEXT,
                    descripcion TEXT,
                    regla_activada TEXT,
                    recomendacion TEXT,
                    falso_positivo INTEGER DEFAULT 0,
                    num_eventos INTEGER DEFAULT 1,
                    creado_en TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS estadisticas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fecha TEXT NOT NULL,
                    total_alertas INTEGER,
                    alertas_criticas INTEGER,
                    alertas_altas INTEGER,
                    alertas_medias INTEGER,
                    alertas_bajas INTEGER,
                    ips_unicas INTEGER,
                    archivos_analizados INTEGER
                )
            ''')
            
            # Crear índices para búsquedas rápidas
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_alertas_timestamp 
                ON alertas(timestamp)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_alertas_ip 
                ON alertas(ip_origen)
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_alertas_severidad 
                ON alertas(severidad)
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"❌ Error inicializando BD: {e}")
    
    def cambiar_base_datos(self, nueva_ruta: str) -> bool:
        """
        Cambia la base de datos activa
        
        Args:
            nueva_ruta: Ruta al nuevo archivo .db
            
        Devuelve:
            True si se cambió correctamente
        """
        if not os.path.exists(nueva_ruta):
            print(f"❌ El archivo no existe: {nueva_ruta}")
            return False
        
        if not nueva_ruta.endswith('.db'):
            print(f"⚠️  El archivo no parece ser una base de datos SQLite (.db)")
        
        self.ruta_bd = nueva_ruta
        
        # Verificar que la BD tiene la estructura correcta
        try:
            conn = sqlite3.connect(self.ruta_bd)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alertas'")
            if cursor.fetchone() is None:
                print(f"⚠️  La BD no contiene tabla 'alertas'. Creándola...")
                self._inicializar_bd()
            conn.close()
            print(f"✅ Base de datos cambiada a: {self.ruta_bd}")
            return True
        except Exception as e:
            print(f"❌ Error abriendo la BD: {e}")
            return False
    
    def obtener_ruta_bd(self) -> str:
        """Devuelve la ruta de la base de datos actual"""
        return self.ruta_bd
    
    def procesar_alerta(self, alerta: Alerta):
        """
        Procesa una alerta: la muestra, guarda y almacena según configuración
        
        Args:
            alerta: Alerta a procesar
        """
        self.alertas.append(alerta)
        
        if self.mostrar_consola:
            self._mostrar_en_consola(alerta)
        
        if self.guardar_archivo:
            self._guardar_en_archivo(alerta)
        
        if self.guardar_bd:
            self._guardar_en_bd(alerta)
    
    def _mostrar_en_consola(self, alerta: Alerta):
        """Muestra la alerta en consola con colores según severidad"""
        color = config.COLORES.get(alerta.severidad.name, '')
        reset = config.COLORES['RESET']
        negrita = config.COLORES['NEGRITA']
        
        # Iconos según severidad
        iconos = {
            'INFO': 'ℹ️ ',
            'BAJA': '🟢',
            'MEDIA': '🟡',
            'ALTA': '🔴',
            'CRITICA': '🚨'
        }
        icono = iconos.get(alerta.severidad.name, '•')
        
        print(f"\n{color}{negrita}{'═' * 60}{reset}")
        print(f"{color}{icono} [{alerta.severidad.name}] {alerta.tipo_ataque.value.upper()}{reset}")
        print(f"{color}{'─' * 60}{reset}")
        print(f"  📅 Fecha: {alerta.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  🌐 IP: {alerta.ip_origen or 'Desconocida'}")
        print(f"  📋 Descripción: {alerta.descripcion}")
        print(f"  📜 Regla: {alerta.regla_activada}")
        if alerta.recomendacion:
            print(f"  💡 Recomendación: {alerta.recomendacion}")
        print(f"{color}{'═' * 60}{reset}")
    
    def _guardar_en_archivo(self, alerta: Alerta):
        """Guarda la alerta en archivo de texto y JSON"""
        fecha_hoy = datetime.now().strftime('%Y-%m-%d')
        
        # Archivo de texto legible
        archivo_txt = os.path.join(config.RUTA_ALERTAS, f"alertas_{fecha_hoy}.txt")
        with open(archivo_txt, 'a', encoding='utf-8') as f:
            f.write(f"\n{'=' * 60}\n")
            f.write(f"[{alerta.severidad.name}] {alerta.tipo_ataque.value}\n")
            f.write(f"Fecha: {alerta.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"IP: {alerta.ip_origen or 'Desconocida'}\n")
            f.write(f"Descripción: {alerta.descripcion}\n")
            f.write(f"Regla: {alerta.regla_activada}\n")
            f.write(f"Recomendación: {alerta.recomendacion}\n")
            f.write(f"{'=' * 60}\n")
        
        # Archivo JSON para procesamiento
        archivo_json = os.path.join(config.RUTA_ALERTAS, f"alertas_{fecha_hoy}.json")
        alertas_json = []
        
        # Leer alertas existentes si el archivo existe
        if os.path.exists(archivo_json):
            try:
                with open(archivo_json, 'r', encoding='utf-8') as f:
                    alertas_json = json.load(f)
            except:
                alertas_json = []
        
        # Agregar nueva alerta
        alertas_json.append(alerta.to_dict())
        
        # Guardar
        with open(archivo_json, 'w', encoding='utf-8') as f:
            json.dump(alertas_json, f, indent=2, ensure_ascii=False)
    
    def _guardar_en_bd(self, alerta: Alerta):
        """Guarda la alerta en la base de datos SQLite"""
        try:
            conn = sqlite3.connect(self.ruta_bd)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO alertas 
                (timestamp, severidad, tipo_ataque, ip_origen, descripcion, 
                 regla_activada, recomendacion, num_eventos)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alerta.timestamp.isoformat(),
                alerta.severidad.name,
                alerta.tipo_ataque.value,
                alerta.ip_origen,
                alerta.descripcion,
                alerta.regla_activada,
                alerta.recomendacion,
                len(alerta.eventos_relacionados)
            ))
            
            alerta.id = cursor.lastrowid
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"⚠️  Error guardando en BD: {e}")
    
    def consultar_alertas(self, severidad: Optional[str] = None,
                          ip: Optional[str] = None,
                          limite: int = 100) -> List[dict]:
        """
        Consulta alertas de la base de datos con filtros
        
        Args:
            severidad: Filtrar por severidad (BAJA, MEDIA, ALTA, CRITICA)
            ip: Filtrar por IP de origen
            limite: Número máximo de resultados
            
        Devuelve:
            Lista de alertas como diccionarios
        """
        try:
            conn = sqlite3.connect(self.ruta_bd)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT * FROM alertas WHERE 1=1"
            params = []
            
            if severidad:
                query += " AND severidad = ?"
                params.append(severidad.upper())
            
            if ip:
                query += " AND ip_origen = ?"
                params.append(ip)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limite)
            
            cursor.execute(query, params)
            resultados = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            return resultados
        except Exception as e:
            print(f"❌ Error consultando BD: {e}")
            return []
    
    def obtener_estadisticas_bd(self) -> dict:
        """Obtiene estadísticas de las alertas almacenadas"""
        try:
            conn = sqlite3.connect(self.ruta_bd)
            cursor = conn.cursor()
            
            # Total de alertas
            cursor.execute("SELECT COUNT(*) FROM alertas")
            total = cursor.fetchone()[0]
            
            # Por severidad
            cursor.execute("""
                SELECT severidad, COUNT(*) as cantidad 
                FROM alertas 
                GROUP BY severidad
            """)
            por_severidad = dict(cursor.fetchall())
            
            # Top IPs atacantes
            cursor.execute("""
                SELECT ip_origen, COUNT(*) as cantidad 
                FROM alertas 
                WHERE ip_origen IS NOT NULL
                GROUP BY ip_origen 
                ORDER BY cantidad DESC 
                LIMIT 10
            """)
            top_ips = cursor.fetchall()
            
            # Tipos de ataque más comunes
            cursor.execute("""
                SELECT tipo_ataque, COUNT(*) as cantidad 
                FROM alertas 
                GROUP BY tipo_ataque 
                ORDER BY cantidad DESC
            """)
            tipos_ataque = cursor.fetchall()
            
            conn.close()
            
            return {
                'total_alertas': total,
                'por_severidad': por_severidad,
                'top_ips_atacantes': top_ips,
                'tipos_ataque': tipos_ataque
            }
        except Exception as e:
            print(f"❌ Error obteniendo estadísticas: {e}")
            return {}
    
    def exportar_informe(self, formato: str = 'txt') -> str:
        """
        Exporta un informe completo de alertas
        
        Args:
            formato: 'txt', 'json' o 'html'
            
        Devuelve:
            Ruta del archivo generado
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if formato == 'json':
            archivo = os.path.join(config.RUTA_ALERTAS, f"informe_{timestamp}.json")
            with open(archivo, 'w', encoding='utf-8') as f:
                datos = {
                    'generado': datetime.now().isoformat(),
                    'estadisticas': self.obtener_estadisticas_bd(),
                    'alertas': [a.to_dict() for a in self.alertas]
                }
                json.dump(datos, f, indent=2, ensure_ascii=False)
                
        elif formato == 'html':
            archivo = os.path.join(config.RUTA_ALERTAS, f"informe_{timestamp}.html")
            self._generar_html(archivo)
            
        else:  # txt por defecto
            archivo = os.path.join(config.RUTA_ALERTAS, f"informe_{timestamp}.txt")
            with open(archivo, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("      INFORME DE SEGURIDAD - IDS-SIMULA\n")
                f.write(f"      Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 60 + "\n\n")
                
                stats = self.obtener_estadisticas_bd()
                f.write(f"Total de alertas: {stats.get('total_alertas', 0)}\n\n")
                
                f.write("Por severidad:\n")
                for sev, cant in stats.get('por_severidad', {}).items():
                    f.write(f"  - {sev}: {cant}\n")
                
                f.write("\nTop IPs atacantes:\n")
                for ip, cant in stats.get('top_ips_atacantes', []):
                    f.write(f"  - {ip}: {cant} alertas\n")
                
                f.write("\n" + "=" * 60 + "\n")
                f.write("DETALLE DE ALERTAS\n")
                f.write("=" * 60 + "\n")
                
                for alerta in self.alertas:
                    f.write(f"\n[{alerta.severidad.name}] {alerta.tipo_ataque.value}\n")
                    f.write(f"  IP: {alerta.ip_origen}\n")
                    f.write(f"  {alerta.descripcion}\n")
        
        print(f"📄 Informe generado: {archivo}")
        return archivo
    
    def _generar_html(self, archivo: str):
        """Genera un informe en formato HTML"""
        stats = self.obtener_estadisticas_bd()
        
        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Informe IDS-SIMULA - {datetime.now().strftime('%Y-%m-%d')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }}
        h1 {{ color: #00d9ff; }}
        .stats {{ display: flex; gap: 20px; flex-wrap: wrap; }}
        .stat-box {{ background: #16213e; padding: 20px; border-radius: 10px; min-width: 150px; }}
        .stat-value {{ font-size: 2em; color: #00d9ff; }}
        .alerta {{ margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .CRITICA {{ background: #8b0000; border-left: 5px solid #ff0000; }}
        .ALTA {{ background: #8b4000; border-left: 5px solid #ff6600; }}
        .MEDIA {{ background: #8b8b00; border-left: 5px solid #ffff00; }}
        .BAJA {{ background: #006400; border-left: 5px solid #00ff00; }}
        .INFO {{ background: #00008b; border-left: 5px solid #0066ff; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #16213e; }}
    </style>
</head>
<body>
    <h1>🛡️ Informe de Seguridad - IDS-SIMULA</h1>
    <p>Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <h2>📊 Estadísticas</h2>
    <div class="stats">
        <div class="stat-box">
            <div class="stat-value">{stats.get('total_alertas', 0)}</div>
            <div>Total Alertas</div>
        </div>
        <div class="stat-box">
            <div class="stat-value">{stats.get('por_severidad', {}).get('CRITICA', 0)}</div>
            <div>Críticas</div>
        </div>
        <div class="stat-box">
            <div class="stat-value">{stats.get('por_severidad', {}).get('ALTA', 0)}</div>
            <div>Altas</div>
        </div>
    </div>
    
    <h2>🌐 Top IPs Atacantes</h2>
    <table>
        <tr><th>IP</th><th>Alertas</th></tr>
        {''.join(f"<tr><td>{ip}</td><td>{cant}</td></tr>" for ip, cant in stats.get('top_ips_atacantes', []))}
    </table>
    
    <h2>🚨 Alertas Recientes</h2>
    {''.join(f'''
    <div class="alerta {a.severidad.name}">
        <strong>[{a.severidad.name}] {a.tipo_ataque.value}</strong><br>
        🌐 IP: {a.ip_origen or 'Desconocida'}<br>
        📋 {a.descripcion}<br>
        💡 {a.recomendacion}
    </div>
    ''' for a in self.alertas[-20:])}
</body>
</html>"""
        
        with open(archivo, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def marcar_falso_positivo(self, alerta_id: int):
        """Marca una alerta como falso positivo en la BD"""
        try:
            conn = sqlite3.connect(self.ruta_bd)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE alertas SET falso_positivo = 1 WHERE id = ?",
                (alerta_id,)
            )
            conn.commit()
            conn.close()
            print(f"✅ Alerta {alerta_id} marcada como falso positivo")
        except Exception as e:
            print(f"❌ Error: {e}")
