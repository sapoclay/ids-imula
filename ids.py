#!/usr/bin/env python3
"""
══════════════════════════
    IDS-IMULA - Simulador 
══════════════════════════
Este programa monitoriza archivos de log y detecta patrones sospechosos
de ataques informáticos, generando alertas con diferentes niveles de severidad.

Uso (ejecutar siempre desde run_app.py para usar el entorno virtual):
    python3 run_app.py               # Menú interactivo (recomendado)
    
    Opciones adicionales (desde el entorno virtual activado):
    python ids.py --analizar RUTA    # Analizar archivo específico
    python ids.py --ejemplo          # Generar y analizar logs de ejemplo
    python ids.py --ayuda            # Mostrar ayuda

Autor: Proyecto educativo MF0488
"""

import os
import sys
import argparse
from datetime import datetime

# Importar módulos de IDS-IMULA
from config import RUTA_LOGS_EJEMPLO, RUTAS_LOGS_SISTEMA, COLORES, BASE_DIR
from modelos import EstadisticasIDS, Severidad
from lector_logs import LectorLogs, LectorMultiple
from motor_deteccion import MotorDeteccion
from gestor_alertas import GestorAlertas
from generador_logs import generar_logs_ejemplo

# Importar analizador para gráficos (opcional)
try:
    from analizador_logs import AnalizadorLogs, GeneradorGraficos, MATPLOTLIB_DISPONIBLE
    GRAFICOS_DISPONIBLES = MATPLOTLIB_DISPONIBLE
except ImportError:
    GRAFICOS_DISPONIBLES = False
    AnalizadorLogs = None  # type: ignore
    GeneradorGraficos = None  # type: ignore

# Importar nuevos módulos (opcional)
try:
    from monitor_realtime import menu_monitor_realtime
except ImportError:
    def menu_monitor_realtime():
        print(f"\n{COLORES['ALTA']}❌ Módulo de monitorización no disponible{COLORES['RESET']}")
        input("\n⏎ Pulsa Enter para continuar...")

try:
    from enriquecedor_ip import menu_enriquecimiento_ip
except ImportError:
    def menu_enriquecimiento_ip():
        print(f"\n{COLORES['ALTA']}❌ Módulo de enriquecimiento de IPs no disponible{COLORES['RESET']}")
        input("\n⏎ Pulsa Enter para continuar...")

try:
    from ml_detector import menu_machine_learning
except ImportError:
    def menu_machine_learning():
        print(f"\n{COLORES['ALTA']}❌ Módulo de Machine Learning no disponible{COLORES['RESET']}")
        print("   Instala las dependencias: pip install scikit-learn numpy")
        input("\n⏎ Pulsa Enter para continuar...")


def mostrar_banner():
    """Muestra el banner del programa"""
    banner = f"""
{COLORES['NEGRITA']}{COLORES['INFO']}
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ██╗██████╗ ███████╗    ██╗███╗   ███╗██╗   ██╗██╗      █████╗               ║
║   ██║██╔══██╗██╔════╝    ██║████╗ ████║██║   ██║██║     ██╔══██╗              ║
║   ██║██║  ██║███████╗    ██║██╔████╔██║██║   ██║██║     ███████║              ║
║   ██║██║  ██║╚════██║    ██║██║╚██╔╝██║██║   ██║██║     ██╔══██║              ║
║   ██║██████╔╝███████║    ██║██║ ╚═╝ ██║╚██████╔╝███████╗██║  ██║              ║
║   ╚═╝╚═════╝ ╚══════╝    ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝              ║
║                                                                               ║
║                         Seguridad Informática                                 ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
{COLORES['RESET']}"""
    print(banner)


def mostrar_menu_principal():
    """Muestra el menú principal"""
    print(f"""
{COLORES['NEGRITA']}╔═══════════════════════════════════════════════════╗
║               MENÚ PRINCIPAL                      ║
╠═══════════════════════════════════════════════════╣{COLORES['RESET']}
║  1. 📊 Analizar logs de ejemplo (demo)            ║
║  2. 📁 Analizar archivo de log específico         ║
║  3. 🖥️  Analizar logs del sistema                  ║
║  4. 🔎 Buscar en logs                             ║
║  5. 🔧 Ver/modificar reglas de detección          ║
║  6. 💾 Seleccionar/Cargar base de datos           ║
║  7. 📥 Exportar logs a base de datos (.db)        ║
║  8. 📈 Ver estadísticas de la base de datos       ║
║  9. 📄 Generar informe                            ║
║ 10. 🔍 Consultar alertas anteriores               ║
║ 11. ⚙️  Ver/Editar configuración                   ║
║ 12. 🔴 Monitorización en tiempo real              ║
║ 13. 🌍 Enriquecimiento de IPs (geolocalización)   ║
║ 14. 🧠 Machine Learning (detección anomalías)     ║
║ 15. ❓ Ayuda y documentación                      ║
║ 16. 🌐 Abrir repositorio en GitHub                ║
╠═══════════════════════════════════════════════════╣
║  0. 🚪 Salir                                      ║
{COLORES['NEGRITA']}╚═══════════════════════════════════════════════════╝{COLORES['RESET']}
""")


def analizar_logs(rutas: list, gestor: GestorAlertas) -> EstadisticasIDS:
    """
    Analiza una lista de archivos de log
    
    Args:
        rutas: Lista de rutas a archivos de log
        gestor: Gestor de alertas para procesar resultados
        
    Devuelve:
        Estadísticas del análisis
    """
    stats = EstadisticasIDS()
    motor = MotorDeteccion()
    
    # Filtrar archivos existentes
    rutas_validas = [r for r in rutas if os.path.exists(r)]
    
    if not rutas_validas:
        print(f"{COLORES['ALTA']}❌ No se encontraron archivos válidos para analizar{COLORES['RESET']}")
        return stats
    
    print(f"\n{COLORES['INFO']}🔍 Iniciando análisis de {len(rutas_validas)} archivo(s)...{COLORES['RESET']}\n")
    
    for ruta in rutas_validas:
        print(f"  📂 Analizando: {ruta}")
        stats.archivos_analizados.append(ruta)
        
        lector = LectorLogs(ruta)
        
        for evento in lector.leer_logs():
            stats.lineas_procesadas += 1
            stats.eventos_detectados += 1
            
            if evento.ip_origen:
                stats.ips_detectadas.add(evento.ip_origen)
            
            # Analizar evento con el motor de detección
            alertas = motor.analizar_evento(evento)
            
            for alerta in alertas:
                stats.alertas_generadas += 1
                stats.alertas_por_severidad[alerta.severidad.name] += 1
                gestor.procesar_alerta(alerta)
    
    stats.fin_analisis = datetime.now()
    
    return stats


def preguntar_generar_graficos(rutas: list):
    """
    Pregunta al usuario si desea generar gráficos y los genera si acepta
    
    Args:
        rutas: Lista de archivos analizados para generar gráficos
    """
    if not GRAFICOS_DISPONIBLES or AnalizadorLogs is None or GeneradorGraficos is None:
        print(f"\n{COLORES['MEDIA']}💡 Para generar gráficos instala matplotlib: pip install matplotlib{COLORES['RESET']}")
        return
    
    print(f"\n{COLORES['INFO']}📊 ¿Deseas generar gráficos visuales del análisis?{COLORES['RESET']}")
    respuesta = input("   [S/n]: ").strip().lower()
    
    if respuesta in ['', 's', 'si', 'sí', 'y', 'yes']:
        print(f"\n{COLORES['INFO']}📊 Generando visualizaciones...{COLORES['RESET']}")
        
        # Usar el analizador de logs para generar gráficos
        analizador = AnalizadorLogs()  # type: ignore
        total = analizador.cargar_logs(rutas)
        
        if total > 0:
            reporte = analizador.generar_reporte()
            
            # Generar gráficos
            import config
            directorio = os.path.join(config.BASE_DIR, 'reportes')
            generador = GeneradorGraficos(directorio)  # type: ignore
            generador.generar_todos(reporte, analizador.eventos)
            
            print(f"\n{COLORES['BAJA']}✅ Gráficos generados en: {directorio}/{COLORES['RESET']}")
        else:
            print(f"{COLORES['ALTA']}❌ No hay datos suficientes para generar gráficos{COLORES['RESET']}")


def menu_analizar_ejemplo(gestor: GestorAlertas):
    """Genera y analiza logs de ejemplo"""
    print(f"\n{COLORES['INFO']}📝 Generando logs de ejemplo...{COLORES['RESET']}")
    ruta = generar_logs_ejemplo()
    
    rutas = [
        os.path.join(ruta, 'auth.log'),
        os.path.join(ruta, 'access.log'),
        os.path.join(ruta, 'ufw.log'),
    ]
    
    stats = analizar_logs(rutas, gestor)
    print(stats.resumen())
    
    # Ofrecer generar gráficos
    preguntar_generar_graficos(rutas)
    
    input("\n⏎ Presiona Enter para continuar...")


def menu_analizar_archivo(gestor: GestorAlertas):
    """Permite al usuario seleccionar un archivo para analizar"""
    print(f"\n{COLORES['INFO']}📁 ANALIZAR ARCHIVO DE LOG{COLORES['RESET']}")
    print("─" * 40)
    
    ruta = input("Introduce la ruta del archivo: ").strip()
    
    if not ruta:
        print("❌ Ruta vacía")
        return
    
    if not os.path.exists(ruta):
        print(f"❌ El archivo no existe: {ruta}")
        return
    
    rutas = [ruta]
    stats = analizar_logs(rutas, gestor)
    print(stats.resumen())
    
    # Ofrecer generar gráficos
    preguntar_generar_graficos(rutas)
    
    input("\n⏎ Pulsa Intro para continuar...")


def menu_analizar_sistema(gestor: GestorAlertas):
    """Analiza logs del sistema (requiere permisos)"""
    print(f"\n{COLORES['INFO']}🖥️  LOGS DEL SISTEMA DISPONIBLES{COLORES['RESET']}")
    print("─" * 40)
    
    logs_disponibles = []
    for nombre, ruta in RUTAS_LOGS_SISTEMA.items():
        existe = "✅" if os.path.exists(ruta) else "❌"
        accesible = ""
        if os.path.exists(ruta):
            try:
                with open(ruta, 'r') as f:
                    f.read(1)
                accesible = "(accesible)"
            except PermissionError:
                accesible = "(requiere sudo)"
        print(f"  {existe} {nombre}: {ruta} {accesible}")
        if os.path.exists(ruta):
            logs_disponibles.append((nombre, ruta))
    
    if not logs_disponibles:
        print("\n❌ No hay logs del sistema accesibles")
        input("\n⏎ Pulsa Intro para continuar...")
        return
    
    print("\nOpciones:")
    print("  a) Analizar todos los accesibles")
    print("  s) Seleccionar uno específico")
    print("  v) Volver")
    
    opcion = input("\nElige opción: ").strip().lower()
    rutas_analizadas = []
    
    if opcion == 'a':
        rutas_analizadas = [ruta for _, ruta in logs_disponibles]
        stats = analizar_logs(rutas_analizadas, gestor)
        print(stats.resumen())
        # Ofrecer generar gráficos
        preguntar_generar_graficos(rutas_analizadas)
    elif opcion == 's':
        print("\nArchivos disponibles:")
        for i, (nombre, ruta) in enumerate(logs_disponibles, 1):
            print(f"  {i}. {nombre}")
        
        try:
            idx = int(input("\nNúmero de archivo: ")) - 1
            if 0 <= idx < len(logs_disponibles):
                rutas_analizadas = [logs_disponibles[idx][1]]
                stats = analizar_logs(rutas_analizadas, gestor)
                print(stats.resumen())
                # Ofrecer generar gráficos
                preguntar_generar_graficos(rutas_analizadas)
        except ValueError:
            print("❌ Opción inválida")
    
    input("\n⏎ Pulsa Intro para continuar...")


def menu_reglas(motor: MotorDeteccion):
    """Muestra y permite modificar las reglas de detección"""
    while True:
        print(f"\n{COLORES['INFO']}🔧 REGLAS DE DETECCIÓN{COLORES['RESET']}")
        print("═" * 60)
        
        reglas = motor.listar_reglas()
        
        for i, regla in enumerate(reglas, 1):
            estado = "✅" if regla['activa'] else "❌"
            color = COLORES.get(regla['severidad'], '')
            print(f"  {i}. {estado} {color}[{regla['severidad']}]{COLORES['RESET']} {regla['nombre']}")
            print(f"      {regla['descripcion']}")
            print(f"      Umbral: {regla['umbral']} | Intervalo: {regla['intervalo']}s")
            print()
        
        print("─" * 60)
        print(f"{COLORES['NEGRITA']}Opciones:{COLORES['RESET']}")
        print("  [1-9] Seleccionar regla para modificar")
        print("  [A]   Activar/Desactivar una regla")
        print("  [U]   Cambiar umbral de una regla")
        print("  [S]   Cambiar severidad de una regla")
        print("  [0]   Volver al menú principal")
        print()
        
        opcion = input("Selecciona opción: ").strip().upper()
        
        if opcion == '0' or opcion == '':
            break
        elif opcion == 'A':
            _toggle_regla(motor, reglas)
        elif opcion == 'U':
            _cambiar_umbral_regla(motor, reglas)
        elif opcion == 'S':
            _cambiar_severidad_regla(motor, reglas)
        elif opcion.isdigit() and 1 <= int(opcion) <= len(reglas):
            _editar_regla(motor, int(opcion) - 1, reglas)


def _toggle_regla(motor: MotorDeteccion, reglas: list):
    """Activa o desactiva una regla"""
    try:
        num = int(input("  Número de regla a activar/desactivar: ").strip())
        if 1 <= num <= len(reglas):
            indice = num - 1
            regla = motor.obtener_regla_por_indice(indice)
            if regla:
                nuevo_estado = not regla.activa
                motor.modificar_regla_por_indice(indice, 'activa', nuevo_estado)
                estado = "activada" if nuevo_estado else "desactivada"
                print(f"  ✅ Regla '{regla.nombre}' {estado}")
        else:
            print("  ❌ Número de regla inválido")
    except ValueError:
        print("  ❌ Entrada inválida")


def _cambiar_umbral_regla(motor: MotorDeteccion, reglas: list):
    """Cambia el umbral de detección de una regla"""
    try:
        num = int(input("  Número de regla: ").strip())
        if 1 <= num <= len(reglas):
            indice = num - 1
            regla = motor.obtener_regla_por_indice(indice)
            if regla:
                print(f"  Regla: {regla.nombre}")
                print(f"  Umbral actual: {regla.umbral}")
                nuevo = int(input("  Nuevo umbral: ").strip())
                if nuevo > 0:
                    motor.cambiar_umbral_por_indice(indice, nuevo)
                    print(f"  ✅ Umbral cambiado a {nuevo}")
                else:
                    print("  ❌ El umbral debe ser mayor que 0")
        else:
            print("  ❌ Número de regla inválido")
    except ValueError:
        print("  ❌ Entrada inválida")


def _cambiar_severidad_regla(motor: MotorDeteccion, reglas: list):
    """Cambia la severidad de una regla"""
    try:
        num = int(input("  Número de regla: ").strip())
        if 1 <= num <= len(reglas):
            indice = num - 1
            regla = motor.obtener_regla_por_indice(indice)
            if regla:
                print(f"  Regla: {regla.nombre}")
                print(f"  Severidad actual: {regla.severidad.name}")
                print(f"  Opciones: INFO, BAJA, MEDIA, ALTA, CRITICA")
                nueva = input("  Nueva severidad: ").strip().upper()
                if nueva in ['INFO', 'BAJA', 'MEDIA', 'ALTA', 'CRITICA']:
                    motor.cambiar_severidad_por_indice(indice, nueva)
                    print(f"  ✅ Severidad cambiada a {nueva}")
                else:
                    print("  ❌ Severidad inválida")
        else:
            print("  ❌ Número de regla inválido")
    except ValueError:
        print("  ❌ Entrada inválida")


def _editar_regla(motor: MotorDeteccion, indice: int, reglas: list):
    """Menú de edición detallada de una regla"""
    regla = motor.obtener_regla_por_indice(indice)
    if not regla:
        print("  ❌ Regla no encontrada")
        return
    
    while True:
        # Refrescar la regla para ver cambios
        regla_actualizada = motor.obtener_regla_por_indice(indice)
        if not regla_actualizada:
            break
        regla = regla_actualizada
        
        print(f"\n{COLORES['INFO']}📝 EDITANDO: {regla.nombre}{COLORES['RESET']}")
        print("─" * 50)
        estado = "✅ Activa" if regla.activa else "❌ Desactivada"
        print(f"  Estado:       {estado}")
        print(f"  Severidad:    {COLORES.get(regla.severidad.name, '')}{regla.severidad.name}{COLORES['RESET']}")
        print(f"  Umbral:       {regla.umbral} eventos")
        print(f"  Intervalo:    {regla.intervalo} segundos")
        print(f"  Descripción:  {regla.descripcion}")
        print(f"  Categoría:    {regla.categoria}")
        print()
        print("  [1] Activar/Desactivar")
        print("  [2] Cambiar severidad")
        print("  [3] Cambiar umbral")
        print("  [4] Cambiar intervalo")
        print("  [0] Volver")
        
        op = input("\n  Opción: ").strip()
        
        if op == '0':
            break
        elif op == '1':
            motor.modificar_regla_por_indice(indice, 'activa', not regla.activa)
            print(f"  ✅ Estado cambiado")
        elif op == '2':
            print(f"  Opciones: INFO, BAJA, MEDIA, ALTA, CRITICA")
            nueva = input("  Nueva severidad: ").strip().upper()
            if nueva in ['INFO', 'BAJA', 'MEDIA', 'ALTA', 'CRITICA']:
                motor.cambiar_severidad_por_indice(indice, nueva)
                print(f"  ✅ Severidad cambiada a {nueva}")
        elif op == '3':
            try:
                nuevo = int(input(f"  Nuevo umbral (actual: {regla.umbral}): ").strip())
                if nuevo > 0:
                    motor.cambiar_umbral_por_indice(indice, nuevo)
                    print(f"  ✅ Umbral cambiado a {nuevo}")
            except ValueError:
                print("  ❌ Valor inválido")
        elif op == '4':
            try:
                nuevo = int(input(f"  Nuevo intervalo en segundos (actual: {regla.intervalo}): ").strip())
                if nuevo > 0:
                    motor.modificar_regla_por_indice(indice, 'intervalo', nuevo)
                    print(f"  ✅ Intervalo cambiado a {nuevo}s")
            except ValueError:
                print("  ❌ Valor inválido")


def menu_exportar_logs_bd():
    """Permite exportar todos los eventos de un log a una base de datos SQLite"""
    import sqlite3
    
    print(f"\n{COLORES['INFO']}💾 EXPORTAR LOGS A BASE DE DATOS{COLORES['RESET']}")
    print("═" * 60)
    print("""
Esta función permite guardar TODOS los registros de un archivo de log
en una base de datos SQLite (.db), no solo las alertas.

Esto es útil para:
• Consultar logs de forma estructurada con SQL
• Análisis forense posterior
• Búsquedas avanzadas por cualquier campo
• Preservar logs en formato portable
""")
    
    print("─" * 60)
    print(f"  1. Exportar archivo de log específico")
    print(f"  2. Exportar logs de ejemplo")
    print(f"  3. Exportar logs del sistema")
    print(f"  0. Volver")
    
    opcion = input("\n👉 Selecciona opción: ").strip()
    
    if opcion == '0':
        return
    
    rutas = []
    
    if opcion == '1':
        ruta = input("\n📁 Ruta al archivo de log: ").strip()
        ruta = os.path.expanduser(ruta)
        if os.path.exists(ruta):
            rutas = [ruta]
        else:
            print(f"❌ Archivo no encontrado: {ruta}")
            input("\n⏎ Pulsa Intro para continuar...")
            return
    
    elif opcion == '2':
        rutas = [os.path.join(RUTA_LOGS_EJEMPLO, f) 
                 for f in os.listdir(RUTA_LOGS_EJEMPLO) 
                 if f.endswith('.log')]
        if not rutas:
            print("❌ No hay logs de ejemplo. Usa opción 1 para generar primero.")
            input("\n⏎ Pulsa Intro para continuar...")
            return
    
    elif opcion == '3':
        print("\n📋 Logs del sistema disponibles:")
        import config
        for i, (nombre, ruta) in enumerate(config.RUTAS_LOGS_SISTEMA.items(), 1):
            existe = "✅" if os.path.exists(ruta) else "❌"
            print(f"  {i}. {existe} {nombre}: {ruta}")
        
        seleccion = input("\nNúmeros a exportar (ej: 1,3,5 o 'todos'): ").strip()
        
        if seleccion.lower() == 'todos':
            rutas = [r for r in config.RUTAS_LOGS_SISTEMA.values() if os.path.exists(r)]
        else:
            try:
                indices = [int(x.strip()) - 1 for x in seleccion.split(',')]
                nombres = list(config.RUTAS_LOGS_SISTEMA.keys())
                for idx in indices:
                    if 0 <= idx < len(nombres):
                        ruta = config.RUTAS_LOGS_SISTEMA[nombres[idx]]
                        if os.path.exists(ruta):
                            rutas.append(ruta)
            except ValueError:
                print("❌ Selección inválida")
                input("\n⏎ Pulsa Intro para continuar...")
                return
    else:
        print("❌ Opción no válida")
        input("\n⏎ Pulsa Intro para continuar...")
        return
    
    if not rutas:
        print("❌ No hay archivos para exportar")
        input("\n⏎ Pulsa Intro para continuar...")
        return
    
    # Preguntar nombre de la BD de destino
    print(f"\n📂 Se exportarán {len(rutas)} archivo(s)")
    nombre_bd = input("📁 Nombre para la base de datos (sin extensión): ").strip()
    if not nombre_bd:
        nombre_bd = f"logs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    ruta_bd = os.path.join(BASE_DIR, f"{nombre_bd}.db")
    
    # Crear/conectar a la BD
    try:
        conn = sqlite3.connect(ruta_bd)
        cursor = conn.cursor()
        
        # Crear tabla para eventos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS eventos_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                origen TEXT,
                ip_origen TEXT,
                ip_destino TEXT,
                puerto INTEGER,
                usuario TEXT,
                tipo_evento TEXT,
                mensaje TEXT,
                metodo_http TEXT,
                url TEXT,
                codigo_respuesta INTEGER,
                user_agent TEXT,
                linea_original TEXT,
                exportado_en TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Crear índices
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_eventos_timestamp ON eventos_log(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_eventos_ip ON eventos_log(ip_origen)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_eventos_tipo ON eventos_log(tipo_evento)')
        
        conn.commit()
        
        # Procesar cada archivo
        total_eventos = 0
        lector = LectorLogs("")
        
        print(f"\n{COLORES['INFO']}⏳ Exportando...{COLORES['RESET']}")
        
        for ruta in rutas:
            print(f"  📂 Procesando: {os.path.basename(ruta)}")
            lector.ruta_archivo = ruta
            eventos_archivo = 0
            
            for evento in lector.leer_logs():
                # Extraer datos adicionales si existen
                datos = evento.datos_extra or {}
                
                cursor.execute('''
                    INSERT INTO eventos_log 
                    (timestamp, origen, ip_origen, ip_destino, puerto, usuario,
                     tipo_evento, mensaje, metodo_http, url, codigo_respuesta,
                     user_agent, linea_original)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    evento.timestamp.isoformat() if evento.timestamp else None,
                    evento.origen,
                    evento.ip_origen,
                    evento.ip_destino,
                    evento.puerto,
                    evento.usuario,
                    evento.tipo_evento.value if evento.tipo_evento else None,
                    evento.mensaje,
                    datos.get('metodo'),
                    datos.get('url'),
                    datos.get('codigo_respuesta'),
                    datos.get('user_agent'),
                    evento.linea_original[:500] if evento.linea_original else None  # Limitar tamaño
                ))
                
                eventos_archivo += 1
                total_eventos += 1
                
                # Commit cada 1000 registros para eficiencia
                if total_eventos % 1000 == 0:
                    conn.commit()
                    print(f"    ... {total_eventos} eventos exportados")
            
            print(f"    ✅ {eventos_archivo} eventos")
        
        conn.commit()
        conn.close()
        
        # Mostrar resumen
        tamaño = os.path.getsize(ruta_bd) / 1024  # KB
        print(f"\n{COLORES['MEDIA']}{'═' * 60}{COLORES['RESET']}")
        print(f"{COLORES['INFO']}✅ EXPORTACIÓN COMPLETADA{COLORES['RESET']}")
        print(f"{'─' * 60}")
        print(f"  📊 Total eventos exportados: {total_eventos}")
        print(f"  📁 Base de datos: {ruta_bd}")
        print(f"  💾 Tamaño: {tamaño:.1f} KB")
        print(f"\n{COLORES['NEGRITA']}Consultas SQL de ejemplo:{COLORES['RESET']}")
        print(f"  sqlite3 {nombre_bd}.db")
        print(f"  > SELECT * FROM eventos_log WHERE ip_origen = '192.168.1.100';")
        print(f"  > SELECT tipo_evento, COUNT(*) FROM eventos_log GROUP BY tipo_evento;")
        print(f"  > SELECT * FROM eventos_log WHERE url LIKE '%admin%';")
        
    except Exception as e:
        print(f"❌ Error exportando: {e}")
    
    input("\n⏎ Pulsa Intro para continuar...")


def menu_estadisticas(gestor: GestorAlertas):
    """Muestra estadísticas de la base de datos"""
    print(f"\n{COLORES['INFO']}📈 ESTADÍSTICAS DE LA BASE DE DATOS{COLORES['RESET']}")
    print("─" * 60)
    
    stats = gestor.obtener_estadisticas_bd()
    
    if not stats:
        print("❌ No hay datos en la base de datos")
        print("   Ejecuta un análisis primero")
    else:
        print(f"\n📊 Total de alertas registradas: {stats.get('total_alertas', 0)}")
        
        print("\n📉 Por severidad:")
        for sev, cant in stats.get('por_severidad', {}).items():
            color = COLORES.get(sev, '')
            barra = "█" * min(cant, 50)
            print(f"   {color}{sev:10}{COLORES['RESET']} {barra} {cant}")
        
        print("\n🌐 Top 10 IPs atacantes:")
        for ip, cant in stats.get('top_ips_atacantes', [])[:10]:
            print(f"   {ip:20} → {cant} alertas")
        
        print("\n🎯 Tipos de ataque detectados:")
        for tipo, cant in stats.get('tipos_ataque', []):
            print(f"   {tipo:25} → {cant}")
    
    input("\n⏎ Presiona Enter para continuar...")


def menu_generar_informe(gestor: GestorAlertas):
    """Genera un informe en diferentes formatos"""
    print(f"\n{COLORES['INFO']}📄 GENERAR INFORME{COLORES['RESET']}")
    print("─" * 40)
    print("Formatos disponibles:")
    print("  1. TXT (texto plano)")
    print("  2. JSON (procesable)")
    print("  3. HTML (visual)")
    
    opcion = input("\nElige formato (1-3): ").strip()
    
    formatos = {'1': 'txt', '2': 'json', '3': 'html'}
    formato = formatos.get(opcion, 'txt')
    
    archivo = gestor.exportar_informe(formato)
    print(f"\n✅ Informe generado: {archivo}")
    
    input("\n⏎ Pulsa Intro para continuar...")


def menu_consultar_alertas(gestor: GestorAlertas):
    """Consulta alertas anteriores con filtros"""
    print(f"\n{COLORES['INFO']}🔍 CONSULTAR ALERTAS{COLORES['RESET']}")
    print("─" * 40)
    
    print("Filtros (deja en blanco para omitir):")
    severidad = input("  Severidad (INFO/BAJA/MEDIA/ALTA/CRITICA): ").strip().upper() or None
    ip = input("  IP de origen: ").strip() or None
    
    try:
        limite = int(input("  Número máximo de resultados [20]: ").strip() or 20)
    except ValueError:
        limite = 20
    
    alertas = gestor.consultar_alertas(severidad=severidad, ip=ip, limite=limite)
    
    if not alertas:
        print("\n❌ No se encontraron alertas con esos filtros")
    else:
        print(f"\n📋 Mostrando {len(alertas)} alertas:\n")
        for alerta in alertas:
            color = COLORES.get(alerta['severidad'], '')
            print(f"  {color}[{alerta['severidad']}]{COLORES['RESET']} {alerta['tipo_ataque']}")
            print(f"    📅 {alerta['timestamp']}")
            print(f"    🌐 IP: {alerta['ip_origen'] or 'N/A'}")
            print(f"    📝 {alerta['descripcion'][:80]}...")
            print()
    
    input("\n⏎ Presiona Enter para continuar...")


def mostrar_ayuda():
    """Muestra la documentación del sistema"""
    ayuda = f"""
{COLORES['NEGRITA']}╔═══════════════════════════════════════════════════════════════════════════════╗
║                           AYUDA Y DOCUMENTACIÓN                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝{COLORES['RESET']}

{COLORES['INFO']}¿QUÉ ES IDS-IMULA?{COLORES['RESET']}
━━━━━━━━━━━━━━━━━━
IDS-IMULA es un simulador educativo de Sistema de Detección de Intrusos (IDS)
desarrollado como proyecto formativo para el módulo MF0488 de Seguridad 
Informática. Monitoriza archivos de log del sistema en busca de patrones de 
actividad sospechosa o maliciosa, generando alertas clasificadas por severidad.

{COLORES['INFO']}OPCIONES DEL MENÚ PRINCIPAL{COLORES['RESET']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
•  1. Analizar logs de ejemplo   - Genera logs simulados y los analiza (demo)
•  2. Analizar archivo específico - Selecciona un archivo .log para analizar
•  3. Analizar logs del sistema   - Analiza /var/log/auth.log, syslog, etc.
•  4. Buscar en logs              - Busca texto, IPs o patrones en archivos de log
•  5. Ver/modificar reglas        - Gestiona las reglas de detección activas
•  6. Seleccionar base de datos   - Cambia o crea una nueva BD de alertas
•  7. Exportar logs a BD          - Guarda TODOS los eventos de logs en SQLite
•  8. Ver estadísticas            - Consulta estadísticas de la base de datos
•  9. Generar informe             - Exporta informes en TXT, JSON o HTML
• 10. Consultar alertas           - Busca alertas anteriores con filtros
• 11. Ver/Editar configuración    - Modifica umbrales, rutas y patrones
• 12. Ayuda y documentación       - Esta pantalla de ayuda
• 13. Abrir repositorio GitHub    - Abre el repositorio del proyecto en el navegador

{COLORES['INFO']}TIPOS DE ATAQUES DETECTADOS{COLORES['RESET']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━
• 🔐 Fuerza Bruta: Múltiples intentos de login fallidos desde una misma IP
• 🔍 Escaneo de Puertos: Conexiones a múltiples puertos (reconocimiento de red)
• 💉 SQL Injection: Intentos de inyección de código SQL en peticiones web
• 🕷️ XSS: Cross-Site Scripting mediante scripts maliciosos en URLs
• 📂 Path Traversal: Intentos de acceder a directorios superiores (../)
• 🚫 Acceso Sospechoso: Peticiones a rutas sensibles (/admin, /.env, /wp-admin)
• 🌊 DDoS: Demasiadas peticiones desde una IP en un corto período de tiempo
• 🤖 Bots Maliciosos: User-Agents conocidos de herramientas de hacking

{COLORES['INFO']}NIVELES DE SEVERIDAD{COLORES['RESET']}
━━━━━━━━━━━━━━━━━━━━
• ℹ️  INFO:    Eventos informativos, sin riesgo de seguridad
• 🟢 BAJA:    Actividad sospechosa menor, monitorizar
• 🟡 MEDIA:   Posible intento de ataque, investigar
• 🔴 ALTA:    Ataque probable, requiere atención inmediata
• 🟣 CRITICA: Ataque confirmado, tomar acción de contención

{COLORES['INFO']}ARCHIVOS DE LOG SOPORTADOS{COLORES['RESET']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━
• /var/log/auth.log       - Autenticación (SSH, sudo, login)
• /var/log/syslog         - Eventos generales del sistema
• /var/log/apache2/*.log  - Logs de acceso y errores de Apache
• /var/log/nginx/*.log    - Logs de acceso y errores de Nginx
• /var/log/ufw.log        - Firewall UFW (bloqueos, conexiones)
• Archivos personalizados - Cualquier archivo de log en formato estándar

{COLORES['INFO']}USO DESDE LÍNEA DE COMANDOS{COLORES['RESET']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
python3 run_app.py                   # Iniciar menú interactivo (RECOMENDADO)

Opciones adicionales (con el entorno virtual activado):
source .venv/bin/activate            # Activar entorno virtual primero
python ids.py --analizar /ruta/log   # Analizar archivo específico
python ids.py --ejemplo              # Demo con logs de ejemplo
python ids.py --ayuda                # Mostrar esta documentación

{COLORES['INFO']}ESTRUCTURA DEL PROYECTO{COLORES['RESET']}
━━━━━━━━━━━━━━━━━━━━━━━━
• run_app.py           - Lanzador principal (configura entorno virtual)
• ids.py               - Programa principal y menú interactivo
• config.py            - Configuración, umbrales y patrones
• config_defaults.py   - Valores por defecto de configuración
• modelos.py           - Estructuras de datos (Alerta, Evento, etc.)
• lector_logs.py       - Parser de archivos de log multiformato
• motor_deteccion.py   - Motor con reglas y lógica de detección
• gestor_alertas.py    - Almacenamiento en BD y notificaciones
• analizador_logs.py   - Análisis estadístico y generación de gráficos
• generador_logs.py    - Generador de logs de ejemplo para demos

{COLORES['INFO']}CONCEPTOS DE SEGURIDAD (MF0488){COLORES['RESET']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Este proyecto educativo cubre los siguientes conceptos:
• Análisis forense de logs de seguridad
• Detección de patrones de ataque mediante expresiones regulares
• Clasificación y priorización de incidentes por severidad
• Documentación y reporting de incidentes de seguridad
• Almacenamiento estructurado de eventos en bases de datos SQLite
• Generación de informes y visualizaciones estadísticas

{COLORES['INFO']}RECURSOS ADICIONALES{COLORES['RESET']}
━━━━━━━━━━━━━━━━━━━━━
• Repositorio: https://github.com/sapoclay/ids-simula
• Opción 11 del menú para abrir el repositorio en el navegador
"""
    print(ayuda)
    input("\n⏎ Presiona Enter para continuar...")


def abrir_repositorio_github():
    """Abre el repositorio del proyecto en el navegador web predeterminado"""
    import subprocess
    import shutil
    
    url = "https://github.com/sapoclay/ids-simula"
    
    print(f"\n{COLORES['INFO']}🌐 REPOSITORIO DEL PROYECTO{COLORES['RESET']}")
    print("─" * 50)
    print(f"\n  📂 Abriendo: {url}")
    
    abierto = False
    
    # En Linux, intentar navegadores directamente (más confiable que xdg-open)
    if os.name == 'posix':
        # Lista de navegadores a probar en orden de preferencia
        navegadores = [
            ['google-chrome', url],
            ['google-chrome-stable', url],
            ['chromium-browser', url],
            ['chromium', url],
            ['brave-browser', url],
            ['microsoft-edge', url],
            ['opera', url],
            ['sensible-browser', url],
            ['gnome-open', url],
            ['x-www-browser', url],
        ]
        
        for cmd in navegadores:
            if shutil.which(cmd[0]):
                try:
                    # Usar Popen para no bloquear y start_new_session para desvincularlo
                    subprocess.Popen(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True
                    )
                    abierto = True
                    print(f"  ✅ Abierto con: {cmd[0]}")
                    break
                except Exception:
                    continue
        
        # Si ningún navegador funcionó, intentar xdg-open como último recurso
        if not abierto and shutil.which('xdg-open'):
            try:
                resultado = subprocess.run(
                    ['xdg-open', url],
                    capture_output=True,
                    timeout=5
                )
                if resultado.returncode == 0:
                    abierto = True
                    print(f"  ✅ Abierto con: xdg-open")
            except Exception:
                pass
    else:
        # En Windows/Mac usar webbrowser estándar
        import webbrowser
        try:
            webbrowser.open(url)
            abierto = True
            print(f"  ✅ Repositorio abierto en el navegador")
        except Exception:
            pass
    
    if not abierto:
        print(f"  ⚠️  No se pudo abrir el navegador automáticamente")
        print(f"\n  📋 Copia esta URL en tu navegador:")
        print(f"     {COLORES['NEGRITA']}{url}{COLORES['RESET']}")
    
    input("\n⏎ Presiona Enter para continuar...")


def menu_buscar_en_logs():
    """Permite buscar texto, IPs o patrones dentro de archivos de log"""
    import re
    from datetime import datetime
    
    print(f"\n{COLORES['INFO']}🔎 BUSCAR EN LOGS{COLORES['RESET']}")
    print("═" * 60)
    
    # Paso 1: Seleccionar archivo(s) de log
    print(f"\n{COLORES['NEGRITA']}📁 Seleccionar archivo(s) de log:{COLORES['RESET']}")
    print("  1. Logs de ejemplo (logs_ejemplo/)")
    print("  2. Logs del sistema (/var/log/)")
    print("  3. Especificar ruta manualmente")
    print("  0. Volver")
    
    opcion_archivo = input("\n  Opción: ").strip()
    
    archivos_buscar = []
    
    if opcion_archivo == '0':
        return
    elif opcion_archivo == '1':
        # Logs de ejemplo
        if os.path.exists(RUTA_LOGS_EJEMPLO):
            for archivo in os.listdir(RUTA_LOGS_EJEMPLO):
                if archivo.endswith('.log'):
                    archivos_buscar.append(os.path.join(RUTA_LOGS_EJEMPLO, archivo))
        if not archivos_buscar:
            print(f"\n  {COLORES['ALTA']}❌ No hay logs de ejemplo. Genera primero con la opción 1 del menú.{COLORES['RESET']}")
            input("\n⏎ Presiona Enter para continuar...")
            return
    elif opcion_archivo == '2':
        # Logs del sistema
        print(f"\n  {COLORES['INFO']}Logs del sistema disponibles:{COLORES['RESET']}")
        logs_disponibles = []
        for nombre, ruta in RUTAS_LOGS_SISTEMA.items():
            if os.path.exists(ruta):
                try:
                    with open(ruta, 'r') as f:
                        f.read(1)
                    logs_disponibles.append((nombre, ruta))
                    print(f"    {len(logs_disponibles)}. {nombre}: {ruta}")
                except PermissionError:
                    print(f"    ❌ {nombre}: {ruta} (sin permisos)")
        
        if not logs_disponibles:
            print(f"\n  {COLORES['ALTA']}❌ No hay logs del sistema accesibles{COLORES['RESET']}")
            input("\n⏎ Presiona Enter para continuar...")
            return
        
        print(f"    a. Todos los accesibles")
        seleccion = input("\n  Selecciona (número o 'a'): ").strip().lower()
        
        if seleccion == 'a':
            archivos_buscar = [ruta for _, ruta in logs_disponibles]
        else:
            try:
                idx = int(seleccion) - 1
                if 0 <= idx < len(logs_disponibles):
                    archivos_buscar = [logs_disponibles[idx][1]]
            except ValueError:
                pass
    elif opcion_archivo == '3':
        ruta = input("\n  Ruta del archivo: ").strip()
        ruta = os.path.expanduser(ruta)
        if os.path.exists(ruta):
            archivos_buscar = [ruta]
        else:
            print(f"\n  {COLORES['ALTA']}❌ Archivo no encontrado: {ruta}{COLORES['RESET']}")
            input("\n⏎ Presiona Enter para continuar...")
            return
    
    if not archivos_buscar:
        print(f"\n  {COLORES['ALTA']}❌ No se seleccionaron archivos{COLORES['RESET']}")
        input("\n⏎ Presiona Enter para continuar...")
        return
    
    print(f"\n  ✅ Archivos seleccionados: {len(archivos_buscar)}")
    for a in archivos_buscar:
        print(f"     • {a}")
    
    # Paso 2: Tipo de búsqueda
    print(f"\n{COLORES['NEGRITA']}🔍 Tipo de búsqueda:{COLORES['RESET']}")
    print("  1. Texto libre (palabra o frase)")
    print("  2. Dirección IP")
    print("  3. Expresión regular")
    print("  4. Códigos de estado HTTP (4xx, 5xx)")
    print("  5. Intentos de login fallidos")
    print("  6. Palabras clave de ataques")
    
    tipo_busqueda = input("\n  Opción: ").strip()
    
    patron = None
    descripcion_busqueda = ""
    
    if tipo_busqueda == '1':
        texto = input("  Texto a buscar: ").strip()
        if not texto:
            print("  ❌ Texto vacío")
            input("\n⏎ Presiona Enter para continuar...")
            return
        patron = re.escape(texto)
        descripcion_busqueda = f"Texto: '{texto}'"
        
    elif tipo_busqueda == '2':
        ip = input("  IP a buscar (ej: 192.168.1.100 o parcial 192.168.): ").strip()
        if not ip:
            print("  ❌ IP vacía")
            input("\n⏎ Presiona Enter para continuar...")
            return
        patron = re.escape(ip)
        descripcion_busqueda = f"IP: {ip}"
        
    elif tipo_busqueda == '3':
        regex = input("  Expresión regular: ").strip()
        if not regex:
            print("  ❌ Expresión vacía")
            input("\n⏎ Presiona Enter para continuar...")
            return
        try:
            re.compile(regex)
            patron = regex
            descripcion_busqueda = f"Regex: {regex}"
        except re.error as e:
            print(f"  ❌ Expresión regular inválida: {e}")
            input("\n⏎ Presiona Enter para continuar...")
            return
            
    elif tipo_busqueda == '4':
        print("  Opciones: 4xx (errores cliente), 5xx (errores servidor), ambos")
        codigo = input("  Código (4xx/5xx/ambos): ").strip().lower()
        if codigo == '4xx':
            patron = r'\s4[0-9]{2}\s'
            descripcion_busqueda = "Códigos HTTP 4xx"
        elif codigo == '5xx':
            patron = r'\s5[0-9]{2}\s'
            descripcion_busqueda = "Códigos HTTP 5xx"
        else:
            patron = r'\s[45][0-9]{2}\s'
            descripcion_busqueda = "Códigos HTTP 4xx y 5xx"
            
    elif tipo_busqueda == '5':
        patron = r'(Failed password|authentication failure|Invalid user|failed login|FAILED LOGIN|error: PAM)'
        descripcion_busqueda = "Intentos de login fallidos"
        
    elif tipo_busqueda == '6':
        print("  Buscando: SQL injection, XSS, path traversal, scanners...")
        patron = r"(SELECT.*FROM|UNION.*SELECT|<script|\.\.\/|\.\.\\\\|sqlmap|nikto|nmap|dirbuster|' OR |\" OR |admin'--|1=1)"
        descripcion_busqueda = "Palabras clave de ataques"
    else:
        print("  ❌ Opción no válida")
        input("\n⏎ Presiona Enter para continuar...")
        return
    
    # Paso 3: Opciones adicionales
    print(f"\n{COLORES['NEGRITA']}⚙️  Opciones adicionales:{COLORES['RESET']}")
    case_sensitive = input("  ¿Distinguir mayúsculas/minúsculas? [s/N]: ").strip().lower() == 's'
    
    try:
        max_resultados = int(input("  Máximo de resultados [100]: ").strip() or "100")
    except ValueError:
        max_resultados = 100
    
    mostrar_contexto = input("  ¿Mostrar líneas de contexto? [s/N]: ").strip().lower() == 's'
    contexto_lineas = 0
    if mostrar_contexto:
        try:
            contexto_lineas = int(input("  Líneas de contexto antes/después [2]: ").strip() or "2")
        except ValueError:
            contexto_lineas = 2
    
    # Paso 4: Realizar búsqueda
    print(f"\n{COLORES['INFO']}🔍 Buscando: {descripcion_busqueda}{COLORES['RESET']}")
    print("─" * 60)
    
    flags = 0 if case_sensitive else re.IGNORECASE
    regex_compilado = re.compile(patron, flags)
    
    resultados_totales = 0
    resultados_por_archivo = {}
    
    for archivo in archivos_buscar:
        try:
            with open(archivo, 'r', encoding='utf-8', errors='ignore') as f:
                lineas = f.readlines()
            
            coincidencias = []
            for num_linea, linea in enumerate(lineas, 1):
                if regex_compilado.search(linea):
                    coincidencias.append((num_linea, linea.rstrip()))
                    resultados_totales += 1
                    
                    if resultados_totales >= max_resultados:
                        break
            
            if coincidencias:
                resultados_por_archivo[archivo] = (coincidencias, lineas)
                
        except Exception as e:
            print(f"  ⚠️  Error leyendo {archivo}: {e}")
        
        if resultados_totales >= max_resultados:
            break
    
    # Paso 5: Mostrar resultados
    if not resultados_por_archivo:
        print(f"\n  {COLORES['MEDIA']}❌ No se encontraron coincidencias{COLORES['RESET']}")
    else:
        print(f"\n{COLORES['BAJA']}✅ {resultados_totales} coincidencias encontradas:{COLORES['RESET']}\n")
        
        for archivo, (coincidencias, todas_lineas) in resultados_por_archivo.items():
            print(f"  {COLORES['NEGRITA']}📄 {archivo}{COLORES['RESET']} ({len(coincidencias)} coincidencias)")
            print("  " + "─" * 55)
            
            for num_linea, linea in coincidencias[:50]:  # Mostrar máx 50 por archivo
                # Resaltar la coincidencia
                linea_resaltada = regex_compilado.sub(
                    lambda m: f"{COLORES['ALTA']}{m.group()}{COLORES['RESET']}", 
                    linea
                )
                print(f"    {COLORES['INFO']}L{num_linea:>5}:{COLORES['RESET']} {linea_resaltada[:200]}")
                
                # Mostrar contexto si se pidió
                if contexto_lineas > 0:
                    for i in range(max(0, num_linea - contexto_lineas - 1), num_linea - 1):
                        print(f"           {COLORES['RESET']}{todas_lineas[i].rstrip()[:150]}")
                    for i in range(num_linea, min(len(todas_lineas), num_linea + contexto_lineas)):
                        print(f"           {COLORES['RESET']}{todas_lineas[i].rstrip()[:150]}")
                    print()
            
            if len(coincidencias) > 50:
                print(f"    ... y {len(coincidencias) - 50} coincidencias más")
            print()
        
        # Preguntar si exportar
        exportar = input(f"\n  ¿Exportar resultados a archivo? [s/N]: ").strip().lower()
        if exportar == 's':
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            nombre_export = f"busqueda_{timestamp}.txt"
            ruta_export = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reportes', nombre_export)
            
            os.makedirs(os.path.dirname(ruta_export), exist_ok=True)
            
            with open(ruta_export, 'w', encoding='utf-8') as f:
                f.write(f"Búsqueda: {descripcion_busqueda}\n")
                f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total coincidencias: {resultados_totales}\n")
                f.write("=" * 60 + "\n\n")
                
                for archivo, (coincidencias, _) in resultados_por_archivo.items():
                    f.write(f"Archivo: {archivo}\n")
                    f.write("-" * 40 + "\n")
                    for num_linea, linea in coincidencias:
                        f.write(f"L{num_linea}: {linea}\n")
                    f.write("\n")
            
            print(f"  ✅ Resultados exportados a: {ruta_export}")
    
    input("\n⏎ Presiona Enter para continuar...")


def menu_cargar_bd(gestor: GestorAlertas):
    """Permite cargar otra base de datos"""
    print(f"\n{COLORES['INFO']}💾 CARGAR BASE DE DATOS{COLORES['RESET']}")
    print("─" * 60)
    print(f"\n📂 Base de datos actual: {COLORES['NEGRITA']}{gestor.obtener_ruta_bd()}{COLORES['RESET']}")
    
    print(f"\n{COLORES['INFO']}Opciones:{COLORES['RESET']}")
    print("  1. Seleccionar/Cargar archivo .db existente")
    print("  2. Crear nueva base de datos")
    print("  3. Restaurar base de datos por defecto")
    print("  0. Volver")
    
    opcion = input("\n👉 Selecciona una opción: ").strip()
    
    if opcion == '1':
        ruta = input("\n📁 Introduce la ruta al archivo .db: ").strip()
        if ruta:
            # Expandir ~ y rutas relativas
            ruta = os.path.expanduser(ruta)
            if not os.path.isabs(ruta):
                ruta = os.path.join(os.getcwd(), ruta)
            gestor.cambiar_base_datos(ruta)
    
    elif opcion == '2':
        nombre = input("\n📝 Nombre para la nueva BD (sin extensión): ").strip()
        if nombre:
            from config import BASE_DIR
            nueva_ruta = os.path.join(BASE_DIR, f"{nombre}.db")
            if os.path.exists(nueva_ruta):
                confirmar = input(f"⚠️  El archivo ya existe. ¿Sobrescribir? [s/N]: ").strip().lower()
                if confirmar != 's':
                    print("Operación cancelada")
                    input("\n⏎ Pulsa Intro para continuar...")
                    return
                os.remove(nueva_ruta)
            gestor.ruta_bd = nueva_ruta
            gestor._inicializar_bd()
            print(f"✅ Nueva base de datos creada: {nueva_ruta}")
    
    elif opcion == '3':
        from config import RUTA_BD
        gestor.ruta_bd = RUTA_BD
        gestor._inicializar_bd()
        print(f"✅ Restaurada base de datos por defecto: {RUTA_BD}")
    
    input("\n⏎ Pulsa Intro para continuar...")


def menu_configuracion():
    """Muestra y permite editar la configuración del sistema"""
    import config
    import config_defaults
    
    while True:
        print(f"\n{COLORES['INFO']}⚙️  CONFIGURACIÓN DE IDS-IMULA{COLORES['RESET']}")
        print("═" * 60)
        
        print(f"\n{COLORES['NEGRITA']}📁 RUTAS DEL SISTEMA{COLORES['RESET']}")
        print(f"   Base del proyecto: {config.BASE_DIR}")
        print(f"   Logs de ejemplo:   {config.RUTA_LOGS_EJEMPLO}")
        print(f"   Alertas:           {config.RUTA_ALERTAS}")
        print(f"   Base de datos:     {config.RUTA_BD}")
        
        print(f"\n{COLORES['NEGRITA']}📋 LOGS DEL SISTEMA CONFIGURADOS{COLORES['RESET']}")
        for nombre, ruta in config.RUTAS_LOGS_SISTEMA.items():
            existe = "✅" if os.path.exists(ruta) else "❌"
            print(f"   {existe} {nombre:15} → {ruta}")
        
        print(f"\n{COLORES['NEGRITA']}🎯 UMBRALES DE DETECCIÓN{COLORES['RESET']}")
        for nombre, valor in config.UMBRALES.items():
            print(f"   {nombre:30} → {valor}")
        
        print(f"\n{COLORES['NEGRITA']}🎨 COLORES (terminal){COLORES['RESET']}")
        for nivel in ['INFO', 'BAJA', 'MEDIA', 'ALTA', 'CRITICA']:
            color = config.COLORES.get(nivel, '')
            print(f"   {color}■ {nivel}{COLORES['RESET']}")
        
        print("\n" + "─" * 60)
        print(f"{COLORES['NEGRITA']}Opciones:{COLORES['RESET']}")
        print("  1. Modificar umbrales de detección")
        print("  2. Añadir/quitar ruta de log del sistema")
        print("  3. Ver/Modificar patrones de ataque (SQLi/XSS)")
        print("  4. Ver/Modificar User-Agents sospechosos")
        print("  5. Ver/Modificar rutas web sospechosas")
        print(f"  6. {COLORES['ALTA']}🔄 Restaurar valores por defecto{COLORES['RESET']}")
        print("  0. Volver al menú principal")
        
        opcion = input("\n👉 Selecciona una opción: ").strip()
        
        if opcion == '0':
            break
        elif opcion == '1':
            _editar_umbrales(config)
        elif opcion == '2':
            _editar_rutas_logs(config)
        elif opcion == '3':
            _editar_patrones_ataque(config)
        elif opcion == '4':
            _editar_user_agents(config)
        elif opcion == '5':
            _editar_rutas_sospechosas(config)
        elif opcion == '6':
            _restaurar_valores_defecto(config, config_defaults)


def _guardar_config(config):
    """Guarda la configuración actual en el archivo config.py"""
    import re
    
    config_path = os.path.join(config.BASE_DIR, 'config.py')
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            contenido = f.read()
        
        # Actualizar UMBRALES
        patron_umbrales = r"(UMBRALES\s*=\s*\{)[^}]+(\})"
        nuevo_umbrales = "UMBRALES = {\n"
        for nombre, valor in config.UMBRALES.items():
            nuevo_umbrales += f"    '{nombre}': {valor},\n"
        nuevo_umbrales += "}"
        contenido = re.sub(patron_umbrales, nuevo_umbrales, contenido, flags=re.DOTALL)
        
        # Actualizar RUTAS_LOGS_SISTEMA
        patron_rutas = r"(RUTAS_LOGS_SISTEMA\s*=\s*\{)[^}]+(\})"
        nuevo_rutas = "RUTAS_LOGS_SISTEMA = {\n"
        for nombre, ruta in config.RUTAS_LOGS_SISTEMA.items():
            nuevo_rutas += f"    '{nombre}': '{ruta}',\n"
        nuevo_rutas += "}"
        contenido = re.sub(patron_rutas, nuevo_rutas, contenido, flags=re.DOTALL)
        
        # Actualizar USER_AGENTS_SOSPECHOSOS
        patron_ua = r"USER_AGENTS_SOSPECHOSOS\s*=\s*\[[^\]]+\]"
        nuevo_ua = "USER_AGENTS_SOSPECHOSOS = [\n"
        for ua in config.USER_AGENTS_SOSPECHOSOS:
            nuevo_ua += f"    '{ua}',\n"
        nuevo_ua += "]"
        contenido = re.sub(patron_ua, nuevo_ua, contenido, flags=re.DOTALL)
        
        # Actualizar RUTAS_SOSPECHOSAS
        patron_rutas_sosp = r"RUTAS_SOSPECHOSAS\s*=\s*\[[^\]]+\]"
        nuevo_rutas_sosp = "RUTAS_SOSPECHOSAS = [\n"
        for ruta in config.RUTAS_SOSPECHOSAS:
            nuevo_rutas_sosp += f"    '{ruta}',\n"
        nuevo_rutas_sosp += "]"
        contenido = re.sub(patron_rutas_sosp, nuevo_rutas_sosp, contenido, flags=re.DOTALL)
        
        # Actualizar PATRONES_SQL_INJECTION
        patron_sql = r"PATRONES_SQL_INJECTION\s*=\s*\[[^\]]+\]"
        nuevo_sql = "PATRONES_SQL_INJECTION = [\n"
        for patron in config.PATRONES_SQL_INJECTION:
            # Escapar comillas simples en los patrones
            patron_escapado = patron.replace("'", "\\'")
            nuevo_sql += f"    '{patron_escapado}',\n"
        nuevo_sql += "]"
        contenido = re.sub(patron_sql, nuevo_sql, contenido, flags=re.DOTALL)
        
        with open(config_path, 'w', encoding='utf-8') as f:
            f.write(contenido)
        
        return True
    except Exception as e:
        print(f"  ❌ Error al guardar: {e}")
        return False


def _editar_umbrales(config):
    """Permite editar los umbrales de detección"""
    print(f"\n{COLORES['INFO']}🎯 EDITAR UMBRALES{COLORES['RESET']}")
    print("─" * 40)
    
    umbrales_lista = list(config.UMBRALES.items())
    for i, (nombre, valor) in enumerate(umbrales_lista, 1):
        print(f"  {i}. {nombre}: {valor}")
    
    print("  0. Volver")
    
    try:
        opcion = input("\n  Selecciona umbral a modificar: ").strip()
        if opcion == '0':
            return
        
        idx = int(opcion) - 1
        if 0 <= idx < len(umbrales_lista):
            nombre, valor_actual = umbrales_lista[idx]
            nuevo = input(f"  Nuevo valor para '{nombre}' (actual: {valor_actual}): ").strip()
            if nuevo.isdigit():
                config.UMBRALES[nombre] = int(nuevo)
                
                # Preguntar si guardar
                guardar = input("  ¿Guardar cambio permanentemente? (s/n): ").strip().lower()
                if guardar == 's':
                    if _guardar_config(config):
                        print(f"  ✅ Umbral '{nombre}' cambiado a {nuevo} (guardado)")
                    else:
                        print(f"  ⚠️  Umbral cambiado solo para esta sesión")
                else:
                    print(f"  ✅ Umbral '{nombre}' cambiado a {nuevo} (solo esta sesión)")
            else:
                print("  ❌ Valor inválido")
    except (ValueError, IndexError):
        print("  ❌ Opción inválida")
    
    input("\n⏎ Pulsa Intro para continuar...")


def _editar_rutas_logs(config):
    """Permite añadir o quitar rutas de logs"""
    print(f"\n{COLORES['INFO']}📋 EDITAR RUTAS DE LOGS{COLORES['RESET']}")
    print("─" * 40)
    
    print("  1. Añadir nueva ruta de log")
    print("  2. Eliminar ruta de log")
    print("  0. Volver")
    
    opcion = input("\n  Selecciona opción: ").strip()
    
    if opcion == '1':
        nombre = input("  Nombre identificador (ej: 'mi_app'): ").strip()
        ruta = input("  Ruta al archivo de log: ").strip()
        if nombre and ruta:
            ruta = os.path.expanduser(ruta)
            config.RUTAS_LOGS_SISTEMA[nombre] = ruta
            existe = "✅ existe" if os.path.exists(ruta) else "❌ no existe"
            print(f"  ✅ Añadido: {nombre} → {ruta} ({existe})")
            
            guardar = input("  ¿Guardar cambio permanentemente? (s/n): ").strip().lower()
            if guardar == 's':
                if _guardar_config(config):
                    print(f"  ✅ Cambio guardado en config.py")
                else:
                    print(f"  ⚠️  Cambio solo para esta sesión")
    
    elif opcion == '2':
        print("\n  Rutas actuales:")
        rutas_lista = list(config.RUTAS_LOGS_SISTEMA.keys())
        for i, nombre in enumerate(rutas_lista, 1):
            print(f"    {i}. {nombre}")
        
        try:
            idx = int(input("  Número a eliminar: ").strip()) - 1
            if 0 <= idx < len(rutas_lista):
                nombre = rutas_lista[idx]
                del config.RUTAS_LOGS_SISTEMA[nombre]
                print(f"  ✅ Eliminado: {nombre}")
                
                guardar = input("  ¿Guardar cambio permanentemente? (s/n): ").strip().lower()
                if guardar == 's':
                    if _guardar_config(config):
                        print(f"  ✅ Cambio guardado en config.py")
                    else:
                        print(f"  ⚠️  Cambio solo para esta sesión")
        except (ValueError, IndexError):
            print("  ❌ Opción inválida")
    
    input("\n⏎ Pulsa Intro para continuar...")


def _editar_patrones_ataque(config):
    """Permite ver y modificar los patrones de SQL Injection/XSS"""
    while True:
        print(f"\n{COLORES['INFO']}🔍 PATRONES DE ATAQUE (SQL Injection/XSS){COLORES['RESET']}")
        print("─" * 50)
        
        for i, patron in enumerate(config.PATRONES_SQL_INJECTION, 1):
            print(f"  {i:2}. {patron}")
        
        print("\n" + "─" * 50)
        print("  a. Añadir nuevo patrón")
        print("  e. Eliminar patrón")
        print("  0. Volver")
        
        opcion = input("\n  Selecciona opción: ").strip().lower()
        
        if opcion == '0':
            break
        elif opcion == 'a':
            nuevo = input("  Introduce el nuevo patrón: ").strip()
            if nuevo:
                if nuevo not in config.PATRONES_SQL_INJECTION:
                    config.PATRONES_SQL_INJECTION.append(nuevo)
                    print(f"  ✅ Patrón añadido: {nuevo}")
                    
                    guardar = input("  ¿Guardar cambio permanentemente? (s/n): ").strip().lower()
                    if guardar == 's':
                        if _guardar_config(config):
                            print(f"  ✅ Cambio guardado en config.py")
                        else:
                            print(f"  ⚠️  Cambio solo para esta sesión")
                else:
                    print(f"  ⚠️  El patrón ya existe")
        elif opcion == 'e':
            try:
                idx = int(input("  Número del patrón a eliminar: ").strip()) - 1
                if 0 <= idx < len(config.PATRONES_SQL_INJECTION):
                    eliminado = config.PATRONES_SQL_INJECTION.pop(idx)
                    print(f"  ✅ Patrón eliminado: {eliminado}")
                    
                    guardar = input("  ¿Guardar cambio permanentemente? (s/n): ").strip().lower()
                    if guardar == 's':
                        if _guardar_config(config):
                            print(f"  ✅ Cambio guardado en config.py")
                        else:
                            print(f"  ⚠️  Cambio solo para esta sesión")
                else:
                    print("  ❌ Número inválido")
            except ValueError:
                print("  ❌ Debes introducir un número")


def _editar_user_agents(config):
    """Permite ver y modificar los User-Agents sospechosos"""
    while True:
        print(f"\n{COLORES['INFO']}🤖 USER-AGENTS SOSPECHOSOS{COLORES['RESET']}")
        print("─" * 40)
        
        for i, ua in enumerate(config.USER_AGENTS_SOSPECHOSOS, 1):
            print(f"  {i:2}. {ua}")
        
        print("\n" + "─" * 40)
        print("  a. Añadir nuevo User-Agent")
        print("  e. Eliminar User-Agent")
        print("  0. Volver")
        
        opcion = input("\n  Selecciona opción: ").strip().lower()
        
        if opcion == '0':
            break
        elif opcion == 'a':
            nuevo = input("  Introduce el nuevo User-Agent: ").strip()
            if nuevo:
                if nuevo.lower() not in [ua.lower() for ua in config.USER_AGENTS_SOSPECHOSOS]:
                    config.USER_AGENTS_SOSPECHOSOS.append(nuevo)
                    print(f"  ✅ User-Agent añadido: {nuevo}")
                    
                    guardar = input("  ¿Guardar cambio permanentemente? (s/n): ").strip().lower()
                    if guardar == 's':
                        if _guardar_config(config):
                            print(f"  ✅ Cambio guardado en config.py")
                        else:
                            print(f"  ⚠️  Cambio solo para esta sesión")
                else:
                    print(f"  ⚠️  El User-Agent ya existe")
        elif opcion == 'e':
            try:
                idx = int(input("  Número del User-Agent a eliminar: ").strip()) - 1
                if 0 <= idx < len(config.USER_AGENTS_SOSPECHOSOS):
                    eliminado = config.USER_AGENTS_SOSPECHOSOS.pop(idx)
                    print(f"  ✅ User-Agent eliminado: {eliminado}")
                    
                    guardar = input("  ¿Guardar cambio permanentemente? (s/n): ").strip().lower()
                    if guardar == 's':
                        if _guardar_config(config):
                            print(f"  ✅ Cambio guardado en config.py")
                        else:
                            print(f"  ⚠️  Cambio solo para esta sesión")
                else:
                    print("  ❌ Número inválido")
            except ValueError:
                print("  ❌ Debes introducir un número")


def _editar_rutas_sospechosas(config):
    """Permite ver y modificar las rutas web sospechosas"""
    while True:
        print(f"\n{COLORES['INFO']}🚫 RUTAS WEB SOSPECHOSAS{COLORES['RESET']}")
        print("─" * 40)
        
        for i, ruta in enumerate(config.RUTAS_SOSPECHOSAS, 1):
            print(f"  {i:2}. {ruta}")
        
        print("\n" + "─" * 40)
        print("  a. Añadir nueva ruta sospechosa")
        print("  e. Eliminar ruta sospechosa")
        print("  0. Volver")
        
        opcion = input("\n  Selecciona opción: ").strip().lower()
        
        if opcion == '0':
            break
        elif opcion == 'a':
            nueva = input("  Introduce la nueva ruta (ej: /backup, /.htaccess): ").strip()
            if nueva:
                if nueva not in config.RUTAS_SOSPECHOSAS:
                    config.RUTAS_SOSPECHOSAS.append(nueva)
                    print(f"  ✅ Ruta añadida: {nueva}")
                    
                    guardar = input("  ¿Guardar cambio permanentemente? (s/n): ").strip().lower()
                    if guardar == 's':
                        if _guardar_config(config):
                            print(f"  ✅ Cambio guardado en config.py")
                        else:
                            print(f"  ⚠️  Cambio solo para esta sesión")
                else:
                    print(f"  ⚠️  La ruta ya existe")
        elif opcion == 'e':
            try:
                idx = int(input("  Número de la ruta a eliminar: ").strip()) - 1
                if 0 <= idx < len(config.RUTAS_SOSPECHOSAS):
                    eliminada = config.RUTAS_SOSPECHOSAS.pop(idx)
                    print(f"  ✅ Ruta eliminada: {eliminada}")
                    
                    guardar = input("  ¿Guardar cambio permanentemente? (s/n): ").strip().lower()
                    if guardar == 's':
                        if _guardar_config(config):
                            print(f"  ✅ Cambio guardado en config.py")
                        else:
                            print(f"  ⚠️  Cambio solo para esta sesión")
                else:
                    print("  ❌ Número inválido")
            except ValueError:
                print("  ❌ Debes introducir un número")


def _restaurar_valores_defecto(config, config_defaults):
    """Restaura la configuración a valores por defecto"""
    print(f"\n{COLORES['ALTA']}🔄 RESTAURAR VALORES POR DEFECTO{COLORES['RESET']}")
    print("─" * 50)
    print(f"\n{COLORES['NEGRITA']}⚠️  Esta acción restaurará:{COLORES['RESET']}")
    print("   • Umbrales de detección")
    print("   • Rutas de logs del sistema")
    print("   • User-Agents sospechosos")
    print("   • Rutas web sospechosas")
    print("   • Patrones de SQL Injection")
    
    print(f"\n{COLORES['ALTA']}Los cambios personalizados se perderán.{COLORES['RESET']}")
    
    confirmar = input("\n  ¿Estás seguro? Escribe 'RESTAURAR' para confirmar: ").strip()
    
    if confirmar == 'RESTAURAR':
        # Restaurar valores en memoria
        config.UMBRALES.clear()
        config.UMBRALES.update(config_defaults.UMBRALES_DEFAULT.copy())
        
        config.RUTAS_LOGS_SISTEMA.clear()
        config.RUTAS_LOGS_SISTEMA.update(config_defaults.RUTAS_LOGS_SISTEMA_DEFAULT.copy())
        
        config.USER_AGENTS_SOSPECHOSOS.clear()
        config.USER_AGENTS_SOSPECHOSOS.extend(config_defaults.USER_AGENTS_SOSPECHOSOS_DEFAULT.copy())
        
        config.RUTAS_SOSPECHOSAS.clear()
        config.RUTAS_SOSPECHOSAS.extend(config_defaults.RUTAS_SOSPECHOSAS_DEFAULT.copy())
        
        config.PATRONES_SQL_INJECTION.clear()
        config.PATRONES_SQL_INJECTION.extend(config_defaults.PATRONES_SQL_INJECTION_DEFAULT.copy())
        
        # Guardar en archivo
        if _guardar_config(config):
            print(f"\n  {COLORES['BAJA']}✅ Configuración restaurada y guardada correctamente{COLORES['RESET']}")
        else:
            print(f"\n  ⚠️  Valores restaurados solo para esta sesión")
    else:
        print("\n  ❌ Operación cancelada")
    
    input("\n⏎ Pulsa Intro para continuar...")


def main():
    """Función principal del programa"""
    parser = argparse.ArgumentParser(
        description='IDS-IMULA - Simulador de Sistema de Detección de Intrusos'
    )
    parser.add_argument('--analizar', '-a', type=str, 
                        help='Ruta del archivo de log a analizar')
    parser.add_argument('--ejemplo', '-e', action='store_true',
                        help='Generar y analizar logs de ejemplo')
    parser.add_argument('--ayuda', action='store_true',
                        help='Mostrar documentación completa')
    
    args = parser.parse_args()
    
    # Inicializar gestor de alertas y motor de detección
    gestor = GestorAlertas()
    motor = MotorDeteccion()
    
    # Modo línea de comandos
    if args.ayuda:
        mostrar_banner()
        mostrar_ayuda()
        return
    
    if args.ejemplo:
        mostrar_banner()
        menu_analizar_ejemplo(gestor)
        return
    
    if args.analizar:
        mostrar_banner()
        stats = analizar_logs([args.analizar], gestor)
        print(stats.resumen())
        return
    
    # Modo interactivo
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        mostrar_banner()
        mostrar_menu_principal()
        
        opcion = input("👉 Selecciona una opción: ").strip()
        
        if opcion == '1':
            menu_analizar_ejemplo(gestor)
        elif opcion == '2':
            menu_analizar_archivo(gestor)
        elif opcion == '3':
            menu_analizar_sistema(gestor)
        elif opcion == '4':
            menu_buscar_en_logs()
        elif opcion == '5':
            menu_reglas(motor)
        elif opcion == '6':
            menu_cargar_bd(gestor)
        elif opcion == '7':
            menu_exportar_logs_bd()
        elif opcion == '8':
            menu_estadisticas(gestor)
        elif opcion == '9':
            menu_generar_informe(gestor)
        elif opcion == '10':
            menu_consultar_alertas(gestor)
        elif opcion == '11':
            menu_configuracion()
        elif opcion == '12':
            menu_monitor_realtime()
        elif opcion == '13':
            menu_enriquecimiento_ip()
        elif opcion == '14':
            menu_machine_learning()
        elif opcion == '15':
            mostrar_ayuda()
        elif opcion == '16':
            abrir_repositorio_github()
        elif opcion == '0':
            print(f"\n{COLORES['INFO']}👋 ¡Hasta pronto! Mantén tus sistemas seguros.{COLORES['RESET']}\n")
            break
        else:
            print("❌ Opción no válida")
            input("\n⏎ Pulsa Intro para continuar...")


if __name__ == '__main__':
    main()
