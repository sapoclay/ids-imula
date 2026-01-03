# 🛡️ IDS-IMULA

**Simulador de Sistema de Detección de Intrusos**  
*MF0488 - Gestión de incidentes de seguridad informática*

---

## ¿Qué es IDS-IMULA?

IDS-IMULA es un conjunto de herramientas educativas para aprender seguridad informática:

### 🚀 Archivos principales
| Archivo | Descripción |
|---------|-------------|
| **run_app.py** | Lanzador principal - configura el entorno virtual automáticamente |
| **ids.py** | Programa principal con menú interactivo de 12 opciones |

### 🔍 Módulos de análisis y detección
| Archivo | Descripción |
|---------|-------------|
| **motor_deteccion.py** | Motor con reglas de detección de ataques (fuerza bruta, SQL injection, XSS, etc.) |
| **lector_logs.py** | Parser multiformato de archivos de log (auth.log, access.log, syslog, CSV, JSON) |
| **analizador_logs.py** | Analizador estadístico con generación de gráficos visuales |
| **gestor_alertas.py** | Gestiona alertas, las almacena en BD SQLite y genera notificaciones |

### ⚙️ Configuración
| Archivo | Descripción |
|---------|-------------|
| **config.py** | Configuración principal: umbrales, patrones, rutas de logs |
| **config_defaults.py** | Valores por defecto para restaurar configuración |
| **modelos.py** | Estructuras de datos: Alerta, Evento, Severidad, EstadísticasIDS |

### 🧪 Generadores de logs de prueba
| Archivo | Descripción |
|---------|-------------|
| **generador_logs.py** | Genera logs de ejemplo con ataques simulados |
| **generador_logs_multiformat.py** | Genera logs en formatos CSV, JSON y JSONL |

### 📦 Otros archivos
| Archivo | Descripción |
|---------|-------------|
| **mensaje_salida.py** | Mensaje de despedida al cerrar la aplicación |
| **requirements.txt** | Dependencias del proyecto (matplotlib) |

### 📁 Directorios generados
| Directorio | Contenido |
|------------|-----------|
| **logs_ejemplo/** | Logs de prueba generados (auth.log, access.log, ufw.log) |
| **alertas/** | Alertas exportadas en formato TXT y JSON |
| **reportes/** | Informes, gráficos PNG y resultados de búsquedas |
| **.venv/** | Entorno virtual de Python (se crea automáticamente) |

---

## Instalación rápida

```bash
# 1. Ir al directorio del proyecto
cd /var/www/html/Python/Sistema-deteccion-intrusos

# 2. Ejecutar el programa (crea el entorno virtual automáticamente)
python3 run_app.py
```

> **Nota:** `run_app.py` crea automáticamente el entorno virtual `.venv` e instala las dependencias necesarias en la primera ejecución.

---

## 🔧 Herramienta 1: Detector de Intrusos (ids.py)

### ¿Qué hace?
Lee archivos de log, busca patrones de ataques y genera alertas cuando detecta actividad sospechosa.

### Ejemplos de uso

#### Ejecutar en modo interactivo
```bash
python3 run_app.py
```
Aparecerá un menú con opciones:
```
╔═══════════════════════════════════════════════════╗
║               MENÚ PRINCIPAL                      ║
╠═══════════════════════════════════════════════════╣
║  1. 📊 Analizar logs de ejemplo (demo)            ║
║  2. 📁 Analizar archivo de log específico         ║
║  3. 🖥️  Analizar logs del sistema                 ║
║  4. 🔧 Ver/modificar reglas de detección          ║
║  5. 📈 Ver estadísticas de la base de datos       ║
║  6. 📄 Generar informe                            ║
║  7. 🔍 Consultar alertas anteriores               ║
║  8. 💾 Seleccionar/Cargar base de datos           ║
║  9. ⚙️  Ver/Editar configuración                  ║
║ 10. ❓ Ayuda y documentación                      ║
║ 11. 🌐 Abrir repositorio en GitHub                ║
║ 12. 🔎 Buscar en logs                             ║
║  0. 🚪 Salir                                      ║
╚═══════════════════════════════════════════════════╝
```

#### Generar logs de prueba con ataques simulados
```bash
python3 run_app.py
# Seleccionar opción 1
```
Esto crea archivos en `logs_ejemplo/` con ataques como:
- Intentos de login fallidos
- SQL Injection
- Escaneo de puertos
- Path Traversal

#### Analizar logs del sistema real
```bash
# Primero activar el entorno virtual
source .venv/bin/activate
python ids.py --analizar /var/log/auth.log
```
Ejemplo de salida:
```
🔍 Analizando: /var/log/auth.log
📊 Eventos procesados: 1,859
🚨 Alertas generadas: 12

ALERTAS DETECTADAS:
[ALTA] Posible ataque de fuerza bruta desde 192.168.1.100
[MEDIA] Usuario inválido 'admin' desde 10.0.0.5
```

#### Generar gráficos visuales
Después de cualquier análisis (demo, archivo o sistema), el programa pregunta:
```
📊 ¿Deseas generar gráficos visuales del análisis?
   [S/n]: s

📊 Generando visualizaciones...
✅ Gráficos generados en: reportes/
```
Los gráficos incluyen:
- Dashboard completo
- Distribución por categoría
- Timeline de eventos
- Actividad por hora
- Top IPs atacantes

#### Ver estadísticas del análisis
```bash
python3 run_app.py
# Seleccionar opción 5
```
Muestra:
```
📊 ESTADÍSTICAS IDS-SIMULA
═══════════════════════════════════
Total eventos analizados: 5,234
Total alertas generadas: 47

Por severidad:
  CRÍTICA: 3
  ALTA: 15
  MEDIA: 22
  BAJA: 7

Top IPs atacantes:
  192.168.1.100 → 23 alertas
  10.0.0.50     → 12 alertas
```

#### Abrir repositorio en GitHub
```bash
python3 run_app.py
# Seleccionar opción 11
```
Abre automáticamente el repositorio del proyecto en el navegador web predeterminado del sistema:
```
🌐 REPOSITORIO DEL PROYECTO
──────────────────────────────────────────────────

  📂 Abriendo: https://github.com/sapoclay/ids-simula
  ✅ Repositorio abierto en el navegador predeterminado
```

#### Buscar en logs
```bash
python3 run_app.py
# Seleccionar opción 12
```
Permite realizar búsquedas avanzadas dentro de los archivos de log:

**Tipos de búsqueda disponibles:**
- **Texto libre**: Buscar cualquier palabra o frase
- **Dirección IP**: Buscar por IP completa o parcial
- **Expresión regular**: Búsquedas avanzadas con regex
- **Códigos HTTP**: Filtrar errores 4xx y 5xx
- **Logins fallidos**: Detectar intentos de autenticación fallidos
- **Palabras clave de ataques**: SQL injection, XSS, scanners, etc.

**Opciones adicionales:**
- Distinguir mayúsculas/minúsculas
- Límite de resultados
- Mostrar líneas de contexto
- Exportar resultados a archivo

Ejemplo de salida:
```
🔍 Buscando: IP: 192.168.1.100
────────────────────────────────────────────────────────────

✅ 15 coincidencias encontradas:

  📄 logs_ejemplo/auth.log (8 coincidencias)
  ───────────────────────────────────────────────────────
    L   42: Jan  2 10:15:23 server sshd: Failed password for root from 192.168.1.100
    L   58: Jan  2 10:15:45 server sshd: Failed password for admin from 192.168.1.100
```

---

## 📊 Herramienta 2: Analizador de Logs (analizador_logs.py)

### ¿Qué hace?
Clasifica eventos de seguridad en categorías y genera reportes con gráficos visuales.

### Ejemplos de uso

#### Analizar logs de ejemplo
```bash
python3 analizador_logs.py logs_ejemplo/auth.log logs_ejemplo/access.log
```
Salida:
```
📂 Cargando logs...
  📂 Cargando: logs_ejemplo/auth.log
     ✅ 92 eventos
  📂 Cargando: logs_ejemplo/access.log
     ✅ 198 eventos

✅ Total eventos cargados: 290

══════════════════════════════════════════════════════════════════════
            📊 REPORTE DE ANÁLISIS DE LOGS DE SEGURIDAD
══════════════════════════════════════════════════════════════════════

📊 Eventos por categoría:
   exito              211 ( 72.8%) ████████████████████████████████████
   fallo               42 ( 14.5%) ███████
   informativo         20 (  6.9%) ███
   intrusion           17 (  5.9%) ██

🌐 Top 10 IPs más activas:
   45.33.32.156         → 100 eventos
   192.168.1.30         → 46 eventos
   192.168.1.10         → 37 eventos

🚨 Eventos críticos/intrusiones: 17
   [2026-01-02 18:19:20] 🚨 Herramienta de ataque detectada
      IP: 45.33.32.156
   [2026-01-02 18:26:20] ⚠️ Posible intento de SQL Injection
      IP: 45.33.32.156

📊 Generando visualizaciones...
   📈 reportes/categorias.png
   📈 reportes/timeline.png
   📈 reportes/horas.png
   📈 reportes/top_ips.png
   📈 reportes/dashboard.png
```

#### Analizar logs reales del sistema
```bash
# Logs de autenticación
python3 analizador_logs.py /var/log/auth.log

# Logs de Apache
python3 analizador_logs.py /var/log/apache2/access.log

# Múltiples archivos
python3 analizador_logs.py /var/log/auth.log /var/log/syslog
```

#### Analizar archivos CSV o JSON
```bash
# Archivo CSV con logs
python3 analizador_logs.py eventos.csv

# Archivo JSON
python3 analizador_logs.py logs.json
```

### Gráficos generados

Los gráficos se guardan en la carpeta `reportes/`:

| Archivo | Descripción |
|---------|-------------|
| `dashboard.png` | Panel con todas las métricas juntas |
| `categorias.png` | Gráfico circular por categoría |
| `timeline.png` | Eventos por día |
| `horas.png` | Distribución por hora del día |
| `top_ips.png` | IPs más activas |

---

## 🧪 Herramienta 3: Generador de Logs (generador_logs.py)

### ¿Qué hace?
Crea archivos de log con ataques simulados para practicar.

### Ejemplo de uso

```bash
python3 generador_logs.py
```
Salida:
```
🔧 Generando logs de ejemplo...

📁 Creando: logs_ejemplo/auth.log
   ✅ 50 eventos de autenticación SSH
   ✅ 15 intentos de fuerza bruta simulados

📁 Creando: logs_ejemplo/access.log
   ✅ 100 peticiones web normales
   ✅ 20 intentos de SQL Injection
   ✅ 10 intentos de XSS

📁 Creando: logs_ejemplo/ufw.log
   ✅ 30 conexiones bloqueadas por firewall
```

---

## 🧪 Herramienta 4: Generador Multiformato (generador_logs_multiformat.py)

### ¿Qué hace?
Genera logs en formatos CSV, JSON y JSONL para probar el analizador.

### Ejemplo de uso

```bash
python3 generador_logs_multiformat.py
```
Crea:
- `logs_ejemplo/logs_seguridad.csv`
- `logs_ejemplo/logs_seguridad.json`
- `logs_ejemplo/logs_seguridad.jsonl`

---

## 📁 Estructura del proyecto

```
IDS-SIMULA/
│
├── run_app.py              # Lanzador que configura el entorno virtual
├── ids.py                  # Detector de intrusos (menú interactivo)
├── analizador_logs.py      # Analizador con gráficos
├── config.py               # Configuración de umbrales
├── config_defaults.py      # Valores por defecto de configuración
├── modelos.py              # Clases de datos
├── lector_logs.py          # Lee diferentes formatos de log
├── motor_deteccion.py      # Reglas de detección de ataques
├── gestor_alertas.py       # Guarda alertas en ficheros y BD
├── generador_logs.py       # Genera logs de prueba
├── generador_logs_multiformat.py  # Genera CSV/JSON
├── mensaje_salida.py       # Mensaje de despedida
│
├── logs_ejemplo/           # Logs de prueba generados
│   ├── auth.log
│   ├── access.log
│   └── ufw.log
│
├── alertas/                # Alertas guardadas
│   ├── alertas_2026-01-02.txt
│   └── alertas_2026-01-02.json
│
├── reportes/               # Gráficos y reportes JSON
│   ├── dashboard.png
│   ├── categorias.png
│   └── reporte_*.json
│
└── ids_simula.db           # Base de datos SQLite
```

---

## 🔍 Ataques que detecta IDS-SIMULA

| Ataque | Ejemplo en log | Severidad |
|--------|----------------|-----------|
| **Fuerza bruta** | Muchos "Failed password" desde una IP | ALTA |
| **SQL Injection** | `' OR 1=1 --` en URL | CRÍTICA |
| **XSS** | `<script>alert('xss')</script>` en parámetros | ALTA |
| **Path Traversal** | `../../etc/passwd` | ALTA |
| **Escaneo de puertos** | Conexiones a muchos puertos diferentes | MEDIA |
| **Herramientas de ataque** | User-Agent: `sqlmap`, `nikto`, `nmap` | CRÍTICA |

---

## ⚙️ Configuración

Edita `config.py` para cambiar los umbrales de detección:

```python
# Cuántos intentos fallidos antes de alertar
UMBRAL_FUERZA_BRUTA = 5

# Máximo de conexiones por IP
CONEXIONES_MAXIMAS_IP = 100

# Puertos escaneados para detectar escaneo
UMBRAL_ESCANEO_PUERTOS = 10
```

---

## 💾 Dónde se guardan los datos

| Tipo | Ubicación | Formato |
|------|-----------|---------|
| Alertas texto | `alertas/alertas_FECHA.txt` | Texto plano |
| Alertas JSON | `alertas/alertas_FECHA.json` | JSON |
| Base de datos | `ids_simula.db` | SQLite |
| Reportes | `reportes/reporte_*.json` | JSON |
| Gráficos | `reportes/*.png` | Imágenes PNG |

---

## 🐍 Uso desde código Python

### Ejemplo: Usar IDS-SIMULA desde tu propio script

```python
from lector_logs import LectorLogs
from motor_deteccion import MotorDeteccion
from gestor_alertas import GestorAlertas

# Crear los componentes
lector = LectorLogs('/var/log/auth.log')
motor = MotorDeteccion()
gestor = GestorAlertas()

# Leer y analizar cada evento
for evento in lector.leer_logs():
    alertas = motor.analizar_evento(evento)
    for alerta in alertas:
        print(f"🚨 {alerta.severidad}: {alerta.descripcion}")
        gestor.procesar_alerta(alerta)

# Mostrar resumen
print(motor.obtener_resumen_alertas())
```

### Ejemplo: Usar el analizador desde código

```python
from analizador_logs import AnalizadorLogs, GeneradorGraficos

# Crear analizador
analizador = AnalizadorLogs()

# Cargar logs
analizador.cargar_logs(['/var/log/auth.log', '/var/log/syslog'])

# Generar reporte
reporte = analizador.generar_reporte()
analizador.imprimir_reporte(reporte)

# Generar gráficos
graficos = GeneradorGraficos('mis_reportes')
graficos.generar_todos(reporte, analizador.eventos)
```

---

## 🔗 Enlaces útiles

| Recurso | Enlace |
|---------|--------|
| **Repositorio GitHub** | https://github.com/sapoclay/ids-simula |
| **Ayuda integrada** | Opción 10 del menú principal |
| **Abrir en navegador** | Opción 11 del menú principal |

---

## 🤝 Contribución

Este es un proyecto educativo para echar un rato. Sugerencias de mejora:

1. Añadir más reglas de detección
2. Implementar monitorización en tiempo real
3. Crear dashboard web con Flask
4. Añadir notificaciones por email
5. Integración con SIEM

## 📜 Licencia

Proyecto educativo para la gestión de incidentes de seguridad - IDS-IMULA

---
