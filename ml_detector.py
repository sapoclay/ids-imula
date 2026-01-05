#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
    IDS-IMULA - Detector de Anomalías con Machine Learning - MF0488 
═══════════════════════════════════════════════════════════════════════════════

Módulo de detección de anomalías usando Machine Learning:
- Detección de anomalías sin supervisión (sin patrones predefinidos)
- Aprendizaje de tráfico "normal" (baseline)
- Alertas cuando se detectan desviaciones significativas
- Modelos: Isolation Forest, One-Class SVM, LOF
"""

import os
import sys
import json
import pickle
import warnings
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from collections import defaultdict, Counter
from enum import Enum

from config import COLORES, BASE_DIR
from modelos import Severidad, Alerta, TipoEvento

# Eliminar warnings de sklearn
warnings.filterwarnings('ignore')

# ═══════════════════════════════════════════════════════════════════════════════
# VERIFICACIÓN DE DEPENDENCIAS
# ══════════════════════════════════

ML_DISPONIBLE = False
NUMPY_DISPONIBLE = False

try:
    import numpy as np
    NUMPY_DISPONIBLE = True
except ImportError:
    np = None  # type: ignore

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.cluster import DBSCAN
    ML_DISPONIBLE = True
except ImportError:
    IsolationForest = None  # type: ignore
    OneClassSVM = None  # type: ignore
    LocalOutlierFactor = None  # type: ignore
    StandardScaler = None  # type: ignore
    LabelEncoder = None  # type: ignore
    DBSCAN = None  # type: ignore


# ════════════════════════════════════════════════
# CONFIGURACIÓN
# ═══════════════════════════════════════════════════════════════════════════════

MODELOS_DIR = os.path.join(BASE_DIR, 'modelos_ml')
MODELO_DEFAULT = os.path.join(MODELOS_DIR, 'modelo_baseline.pkl')


class TipoModelo(Enum):
    """Tipos de modelos de ML disponibles"""
    ISOLATION_FOREST = "isolation_forest"
    ONE_CLASS_SVM = "one_class_svm"
    LOF = "local_outlier_factor"
    DBSCAN = "dbscan"


@dataclass
class ConfiguracionML:
    """Configuración del detector de ML"""
    tipo_modelo: TipoModelo = TipoModelo.ISOLATION_FOREST
    contamination: float = 0.1          # % esperado de anomalías (0.01-0.5)
    n_estimators: int = 100             # Número de árboles (Isolation Forest)
    umbral_anomalia: float = -0.5       # Score por debajo = anomalía
    ventana_tiempo_minutos: int = 5     # Ventana para agregar eventos
    min_muestras_entrenamiento: int = 100  # Muestras mínimas para entrenar


# ═══════════════════════════════════════════════════════════════════════════════
# EXTRACTOR DE CARACTERÍSTICAS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class CaracteristicasEvento:
    """Características extraídas de un evento para ML"""
    hora_del_dia: int = 0               # 0-23
    dia_semana: int = 0                 # 0-6
    longitud_linea: int = 0
    num_digitos: int = 0
    num_caracteres_especiales: int = 0
    tiene_ip: int = 0
    tiene_error: int = 0
    tiene_failed: int = 0
    tiene_success: int = 0
    codigo_respuesta: int = 0           # Para logs web
    metodo_http: int = 0                # GET=1, POST=2, etc.
    longitud_url: int = 0
    profundidad_url: int = 0            # Número de / en la URL
    tiene_parametros: int = 0
    eventos_por_ip_minuto: int = 0
    
    def to_array(self) -> List[float]:
        """Convierte a array numérico para ML"""
        return [
            self.hora_del_dia,
            self.dia_semana,
            self.longitud_linea,
            self.num_digitos,
            self.num_caracteres_especiales,
            self.tiene_ip,
            self.tiene_error,
            self.tiene_failed,
            self.tiene_success,
            self.codigo_respuesta,
            self.metodo_http,
            self.longitud_url,
            self.profundidad_url,
            self.tiene_parametros,
            self.eventos_por_ip_minuto,
        ]


class ExtractorCaracteristicas:
    """
    Extrae características de eventos/líneas de log para ML
    """
    
    def __init__(self):
        self.contadores_ip: Dict[str, List[datetime]] = defaultdict(list)
        self.metodos_http = {'GET': 1, 'POST': 2, 'PUT': 3, 'DELETE': 4, 
                             'HEAD': 5, 'OPTIONS': 6, 'PATCH': 7}
    
    def _limpiar_contadores_antiguos(self, ventana_minutos: int = 5):
        """Limpia contadores de IPs más antiguos que la ventana"""
        ahora = datetime.now()
        limite = ahora - timedelta(minutes=ventana_minutos)
        
        for ip in list(self.contadores_ip.keys()):
            self.contadores_ip[ip] = [
                t for t in self.contadores_ip[ip] if t > limite
            ]
            if not self.contadores_ip[ip]:
                del self.contadores_ip[ip]
    
    def _extraer_ip(self, linea: str) -> Optional[str]:
        """Extrae la primera IP de una línea"""
        import re
        match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', linea)
        return match.group(1) if match else None
    
    def _extraer_codigo_respuesta(self, linea: str) -> int:
        """Extrae código de respuesta HTTP"""
        import re
        # Buscar patrón de código HTTP (200, 404, 500, etc.)
        match = re.search(r'\s([1-5]\d{2})\s', linea)
        return int(match.group(1)) if match else 0
    
    def _extraer_metodo_http(self, linea: str) -> int:
        """Extrae método HTTP"""
        for metodo, codigo in self.metodos_http.items():
            if metodo in linea.upper():
                return codigo
        return 0
    
    def _extraer_url(self, linea: str) -> str:
        """Extrae URL de la línea"""
        import re
        # Buscar patrón de URL en logs de acceso
        match = re.search(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s"]+)', linea)
        return match.group(1) if match else ""
    
    def extraer(self, linea: str, timestamp: Optional[datetime] = None) -> CaracteristicasEvento:
        """
        Extrae características de una línea de log
        
        Args:
            linea: Línea de log a analizar
            timestamp: Timestamp del evento (o datetime.now())
        
        Returns:
            CaracteristicasEvento con los valores extraídos
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        linea_lower = linea.lower()
        ip = self._extraer_ip(linea)
        url = self._extraer_url(linea)
        
        # Registrar IP para conteo por minuto
        if ip:
            self.contadores_ip[ip].append(timestamp)
            self._limpiar_contadores_antiguos()
        
        # Contar caracteres especiales
        caracteres_especiales = sum(1 for c in linea if not c.isalnum() and not c.isspace())
        
        caract = CaracteristicasEvento(
            hora_del_dia=timestamp.hour,
            dia_semana=timestamp.weekday(),
            longitud_linea=len(linea),
            num_digitos=sum(1 for c in linea if c.isdigit()),
            num_caracteres_especiales=caracteres_especiales,
            tiene_ip=1 if ip else 0,
            tiene_error=1 if 'error' in linea_lower else 0,
            tiene_failed=1 if 'fail' in linea_lower or 'invalid' in linea_lower else 0,
            tiene_success=1 if 'success' in linea_lower or 'accepted' in linea_lower else 0,
            codigo_respuesta=self._extraer_codigo_respuesta(linea),
            metodo_http=self._extraer_metodo_http(linea),
            longitud_url=len(url),
            profundidad_url=url.count('/'),
            tiene_parametros=1 if '?' in url or '=' in url else 0,
            eventos_por_ip_minuto=len(self.contadores_ip.get(ip, [])) if ip else 0,
        )
        
        return caract


# ═══════════════════════════════════════════════════════════════════════════════
# DETECTOR DE ANOMALÍAS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ResultadoAnomalia:
    """Resultado de la detección de anomalía"""
    linea: str
    es_anomalia: bool
    score: float                    # Negativo = más anómalo
    confianza: float               # 0-1, probabilidad de ser anomalía
    caracteristicas: CaracteristicasEvento
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_alerta(self) -> Optional[Alerta]:
        """Convierte a alerta si es anomalía"""
        if not self.es_anomalia:
            return None
        
        # Determinar severidad basada en score
        if self.score < -0.8:
            severidad = Severidad.CRITICA
        elif self.score < -0.6:
            severidad = Severidad.ALTA
        elif self.score < -0.4:
            severidad = Severidad.MEDIA
        else:
            severidad = Severidad.BAJA
        
        return Alerta(
            timestamp=self.timestamp,
            severidad=severidad,
            tipo_ataque=TipoEvento.ACCESO_SOSPECHOSO,
            descripcion=f"Comportamiento anómalo detectado por ML (score: {self.score:.3f}, confianza: {self.confianza:.1%})",
            regla_activada="ml_anomaly_detection",
            recomendacion="Revisar el evento manualmente para determinar si es un ataque o comportamiento legítimo inusual",
        )


class DetectorAnomalias:
    """
    Detector de anomalías basado en Machine Learning
    """
    
    def __init__(self, config: Optional[ConfiguracionML] = None):
        """
        Inicializa el detector
        
        Args:
            config: Configuración del detector
        """
        if not ML_DISPONIBLE:
            raise ImportError(
                "scikit-learn no está instalado. "
                "Ejecuta: pip install scikit-learn numpy"
            )
        
        self.config = config or ConfiguracionML()
        self.extractor = ExtractorCaracteristicas()
        self.scaler: Any = StandardScaler() if StandardScaler else None
        self.modelo: Any = None
        self._entrenado = False
        self._muestras_entrenamiento: List[List[float]] = []
        
        # Crear directorio de modelos
        os.makedirs(MODELOS_DIR, exist_ok=True)
    
    def _crear_modelo(self) -> Any:
        """Crea el modelo según la configuración"""
        if not ML_DISPONIBLE or IsolationForest is None:
            raise ImportError("scikit-learn no está instalado")
            
        if self.config.tipo_modelo == TipoModelo.ISOLATION_FOREST:
            return IsolationForest(  # type: ignore
                n_estimators=self.config.n_estimators,
                contamination=self.config.contamination,
                random_state=42,
                n_jobs=-1,
            )
        elif self.config.tipo_modelo == TipoModelo.ONE_CLASS_SVM and OneClassSVM is not None:
            return OneClassSVM(  # type: ignore
                kernel='rbf',
                gamma='auto',
                nu=self.config.contamination,
            )
        elif self.config.tipo_modelo == TipoModelo.LOF and LocalOutlierFactor is not None:
            return LocalOutlierFactor(  # type: ignore
                n_neighbors=20,
                contamination=self.config.contamination,
                novelty=True,
            )
        elif self.config.tipo_modelo == TipoModelo.DBSCAN and DBSCAN is not None:
            return DBSCAN(eps=0.5, min_samples=5)  # type: ignore
        else:
            return IsolationForest(  # type: ignore
                n_estimators=100,
                contamination=0.1,
                random_state=42,
            )
    
    def agregar_muestra_entrenamiento(self, linea: str, timestamp: Optional[datetime] = None):
        """
        Agrega una muestra para entrenamiento del baseline
        
        Args:
            linea: Línea de log de tráfico "normal"
            timestamp: Timestamp del evento
        """
        caract = self.extractor.extraer(linea, timestamp)
        self._muestras_entrenamiento.append(caract.to_array())
    
    def entrenar(self, lineas: Optional[List[str]] = None, mostrar_progreso: bool = True) -> bool:
        """
        Entrena el modelo con el baseline de tráfico normal
        
        Args:
            lineas: Lista de líneas de log normales (opcional si ya hay muestras)
            mostrar_progreso: Mostrar progreso del entrenamiento
        
        Returns:
            True si el entrenamiento fue exitoso
        """
        # Agregar líneas si se proporcionaron
        if lineas:
            if mostrar_progreso:
                print(f"\n{COLORES['INFO']}📊 Extrayendo características de {len(lineas)} líneas...{COLORES['RESET']}")
            
            for i, linea in enumerate(lineas):
                self.agregar_muestra_entrenamiento(linea)
                if mostrar_progreso and (i + 1) % 100 == 0:
                    print(f"\r  Procesadas: {i + 1}/{len(lineas)}", end='')
            
            if mostrar_progreso:
                print()
        
        # Verificar mínimo de muestras
        if len(self._muestras_entrenamiento) < self.config.min_muestras_entrenamiento:
            print(f"\n{COLORES['MEDIA']}⚠️  Se necesitan al menos {self.config.min_muestras_entrenamiento} "
                  f"muestras (hay {len(self._muestras_entrenamiento)}){COLORES['RESET']}")
            return False
        
        if mostrar_progreso:
            print(f"\n{COLORES['INFO']}🧠 Entrenando modelo {self.config.tipo_modelo.value}...{COLORES['RESET']}")
        
        try:
            if np is None:
                raise ImportError("numpy no está instalado")
                
            # Convertir a numpy array
            X = np.array(self._muestras_entrenamiento)  # type: ignore
            
            # Escalar características
            X_scaled = self.scaler.fit_transform(X)
            
            # Crear y entrenar modelo
            self.modelo = self._crear_modelo()
            self.modelo.fit(X_scaled)
            
            self._entrenado = True
            
            if mostrar_progreso:
                print(f"{COLORES['INFO']}✅ Modelo entrenado con {len(X)} muestras{COLORES['RESET']}")
            
            return True
            
        except Exception as e:
            print(f"\n{COLORES['ALTA']}❌ Error en entrenamiento: {e}{COLORES['RESET']}")
            return False
    
    def detectar(self, linea: str, timestamp: Optional[datetime] = None) -> ResultadoAnomalia:
        """
        Detecta si una línea es anómala
        
        Args:
            linea: Línea de log a analizar
            timestamp: Timestamp del evento
        
        Devuelve:
            ResultadoAnomalia con los resultados
        """
        if not self._entrenado:
            raise RuntimeError("El modelo no está entrenado. Llama a entrenar() primero.")
        
        if np is None:
            raise ImportError("numpy no está instalado")
        
        timestamp = timestamp or datetime.now()
        caract = self.extractor.extraer(linea, timestamp)
        
        # Preparar datos
        X = np.array([caract.to_array()])  # type: ignore
        X_scaled = self.scaler.transform(X)
        
        # Obtener predicción y score
        prediccion = self.modelo.predict(X_scaled)[0]
        
        # Obtener score de anomalía
        if hasattr(self.modelo, 'decision_function'):
            score = self.modelo.decision_function(X_scaled)[0]
        elif hasattr(self.modelo, 'score_samples'):
            score = self.modelo.score_samples(X_scaled)[0]
        else:
            score = -1 if prediccion == -1 else 1
        
        # Calcular confianza (normalizar score a 0-1)
        # Scores más negativos = más anómalo
        confianza = max(0, min(1, (1 - score) / 2))
        
        es_anomalia = prediccion == -1 or score < self.config.umbral_anomalia
        
        return ResultadoAnomalia(
            linea=linea,
            es_anomalia=es_anomalia,
            score=float(score),
            confianza=float(confianza),
            caracteristicas=caract,
            timestamp=timestamp,
        )
    
    def detectar_multiples(self, lineas: List[str], 
                          mostrar_progreso: bool = True) -> List[ResultadoAnomalia]:
        """
        Detecta anomalías en múltiples líneas
        
        Args:
            lineas: Lista de líneas a analizar
            mostrar_progreso: Mostrar progreso
        
        Returns:
            Lista de ResultadoAnomalia
        """
        resultados = []
        total = len(lineas)
        
        if mostrar_progreso:
            print(f"\n{COLORES['INFO']}🔍 Analizando {total} líneas...{COLORES['RESET']}")
        
        for i, linea in enumerate(lineas):
            try:
                resultado = self.detectar(linea)
                resultados.append(resultado)
                
                if mostrar_progreso and (i + 1) % 100 == 0:
                    anomalias = sum(1 for r in resultados if r.es_anomalia)
                    print(f"\r  Procesadas: {i + 1}/{total} | Anomalías: {anomalias}", end='')
                    
            except Exception:
                pass
        
        if mostrar_progreso:
            print()
        
        return resultados
    
    def guardar_modelo(self, ruta: Optional[str] = None):
        """
        Guarda el modelo entrenado
        
        Args:
            ruta: Ruta donde guardar (por defecto: modelos_ml/modelo_baseline.pkl)
        """
        ruta = ruta or MODELO_DEFAULT
        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        
        datos = {
            'modelo': self.modelo,
            'scaler': self.scaler,
            'config': asdict(self.config),
            'tipo_modelo': self.config.tipo_modelo.value,
            'fecha_entrenamiento': datetime.now().isoformat(),
            'num_muestras': len(self._muestras_entrenamiento),
        }
        
        with open(ruta, 'wb') as f:
            pickle.dump(datos, f)
        
        print(f"{COLORES['INFO']}💾 Modelo guardado en: {ruta}{COLORES['RESET']}")
    
    def cargar_modelo(self, ruta: Optional[str] = None) -> bool:
        """
        Carga un modelo guardado
        
        Args:
            ruta: Ruta del modelo (por defecto: modelos_ml/modelo_baseline.pkl)
        
        Returns:
            True si se cargó correctamente
        """
        ruta = ruta or MODELO_DEFAULT
        
        if not os.path.exists(ruta):
            print(f"{COLORES['ALTA']}❌ Modelo no encontrado: {ruta}{COLORES['RESET']}")
            return False
        
        try:
            with open(ruta, 'rb') as f:
                datos = pickle.load(f)
            
            self.modelo = datos['modelo']
            self.scaler = datos['scaler']
            self._entrenado = True
            
            print(f"{COLORES['INFO']}✅ Modelo cargado: {ruta}{COLORES['RESET']}")
            print(f"   Tipo: {datos.get('tipo_modelo', 'desconocido')}")
            print(f"   Fecha entrenamiento: {datos.get('fecha_entrenamiento', 'desconocida')}")
            print(f"   Muestras de entrenamiento: {datos.get('num_muestras', 'desconocido')}")
            
            return True
            
        except Exception as e:
            print(f"{COLORES['ALTA']}❌ Error cargando modelo: {e}{COLORES['RESET']}")
            return False
    
    def generar_reporte(self, resultados: List[ResultadoAnomalia], 
                        ruta_salida: Optional[str] = None) -> str:
        """
        Genera un reporte de detección de anomalías
        
        Args:
            resultados: Lista de resultados de detectar_multiples
            ruta_salida: Ruta opcional para guardar el reporte
        
        Returns:
            Contenido del reporte
        """
        anomalias = [r for r in resultados if r.es_anomalia]
        
        lineas = []
        lineas.append("=" * 70)
        lineas.append("  🧠 REPORTE DE DETECCIÓN DE ANOMALÍAS - ML")
        lineas.append(f"  Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lineas.append("=" * 70)
        
        lineas.append(f"\n  📊 ESTADÍSTICAS:")
        lineas.append(f"     • Total líneas analizadas: {len(resultados)}")
        lineas.append(f"     • Anomalías detectadas: {len(anomalias)}")
        lineas.append(f"     • Tasa de anomalías: {len(anomalias)/len(resultados)*100:.2f}%")
        
        if anomalias:
            lineas.append(f"\n     • Score promedio anomalías: {sum(a.score for a in anomalias)/len(anomalias):.3f}")
            lineas.append(f"     • Confianza promedio: {sum(a.confianza for a in anomalias)/len(anomalias):.1%}")
        
        # Distribución por severidad
        if anomalias:
            lineas.append(f"\n  ⚠️  DISTRIBUCIÓN POR SEVERIDAD:")
            severidades = Counter()
            for a in anomalias:
                alerta = a.to_alerta()
                if alerta:
                    severidades[alerta.severidad.name] += 1
            
            for sev in ['CRITICA', 'ALTA', 'MEDIA', 'BAJA']:
                count = severidades.get(sev, 0)
                if count > 0:
                    lineas.append(f"     • {sev}: {count}")
        
        # Top anomalías más graves
        if anomalias:
            lineas.append(f"\n  🔴 TOP 10 ANOMALÍAS MÁS GRAVES:")
            top_anomalias = sorted(anomalias, key=lambda x: x.score)[:10]
            
            for i, a in enumerate(top_anomalias, 1):
                lineas.append(f"\n  [{i}] Score: {a.score:.3f} | Confianza: {a.confianza:.1%}")
                lineas.append(f"      {a.linea[:100]}{'...' if len(a.linea) > 100 else ''}")
        
        lineas.append("\n" + "=" * 70)
        
        reporte = '\n'.join(lineas)
        
        if ruta_salida:
            os.makedirs(os.path.dirname(ruta_salida), exist_ok=True)
            with open(ruta_salida, 'w', encoding='utf-8') as f:
                f.write(reporte)
            print(f"\n{COLORES['INFO']}📄 Reporte guardado en: {ruta_salida}{COLORES['RESET']}")
        
        return reporte


# ═══════════════════════════════════════════════════════════════════════════════
# INTERFAZ DE MENÚ
# ═══════════════════════════════════════════════════════════════════════════════

def menu_machine_learning():
    """Menú interactivo para Machine Learning"""
    
    if not ML_DISPONIBLE:
        print(f"""
{COLORES['ALTA']}╔═══════════════════════════════════════════════════════════════════╗
║  ❌ MACHINE LEARNING NO DISPONIBLE                                 ║
╠═══════════════════════════════════════════════════════════════════╣
║  Faltan dependencias de Python. Instálalas con:                   ║
║                                                                   ║
║    pip install scikit-learn numpy                                 ║
║                                                                   ║
║  O ejecuta: python3 run_app.py para que se instalen               ║
║  automáticamente.                                                 ║
╚═══════════════════════════════════════════════════════════════════╝{COLORES['RESET']}
""")
        return
    
    detector = None
    
    while True:
        modelo_estado = "✅ Cargado" if detector and detector._entrenado else "❌ No cargado"
        
        print(f"""
{COLORES['NEGRITA']}╔═══════════════════════════════════════════════════╗
║       🧠 MACHINE LEARNING - DETECCIÓN ANOMALÍAS   ║
╠═══════════════════════════════════════════════════╣{COLORES['RESET']}
║  Estado modelo: {modelo_estado:<28}     ║
╠═══════════════════════════════════════════════════╣
║  1. 📚 Entrenar modelo con logs normales          ║
║  2. 🔍 Analizar archivo buscando anomalías        ║
║  3. 💾 Guardar modelo entrenado                   ║
║  4. 📂 Cargar modelo guardado                     ║
║  5. ⚙️  Configurar parámetros de ML                ║
║  6. ❓ Ayuda sobre Machine Learning               ║
║  0. ↩️  Volver al menú principal                   ║
{COLORES['NEGRITA']}╚═══════════════════════════════════════════════════╝{COLORES['RESET']}
""")
        
        opcion = input("  Selecciona una opción: ").strip()
        
        if opcion == '1':
            # Entrenar modelo
            ruta = input("\n  Ruta del archivo de logs normales (baseline): ").strip()
            if not ruta:
                # Usar logs de ejemplo si existen
                from config import RUTA_LOGS_EJEMPLO
                ruta = os.path.join(RUTA_LOGS_EJEMPLO, 'access.log')
            
            if os.path.exists(ruta):
                print(f"\n{COLORES['INFO']}  Cargando logs de: {ruta}{COLORES['RESET']}")
                
                with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                    lineas = [l.strip() for l in f.readlines() if l.strip()]
                
                print(f"  Líneas cargadas: {len(lineas)}")
                
                detector = DetectorAnomalias()
                if detector.entrenar(lineas):
                    print(f"\n{COLORES['INFO']}  ✅ Modelo listo para detectar anomalías{COLORES['RESET']}")
                else:
                    detector = None
            else:
                print(f"\n{COLORES['ALTA']}  ❌ Archivo no encontrado{COLORES['RESET']}")
        
        elif opcion == '2':
            # Analizar archivo
            if not detector or not detector._entrenado:
                print(f"\n{COLORES['ALTA']}  ❌ Primero entrena o carga un modelo{COLORES['RESET']}")
            else:
                ruta = input("\n  Ruta del archivo a analizar: ").strip()
                
                if os.path.exists(ruta):
                    with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                        lineas = [l.strip() for l in f.readlines() if l.strip()]
                    
                    resultados = detector.detectar_multiples(lineas)
                    
                    anomalias = [r for r in resultados if r.es_anomalia]
                    print(f"\n{COLORES['INFO']}  📊 Resultados:{COLORES['RESET']}")
                    print(f"     Total analizadas: {len(resultados)}")
                    print(f"     Anomalías detectadas: {len(anomalias)}")
                    
                    if anomalias:
                        print(f"\n  🔴 Anomalías más graves:")
                        for a in sorted(anomalias, key=lambda x: x.score)[:5]:
                            print(f"     Score: {a.score:.3f} - {a.linea[:60]}...")
                        
                        # Guardar reporte
                        ruta_reporte = os.path.join(
                            BASE_DIR, 'reportes', 
                            f'anomalias_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
                        )
                        detector.generar_reporte(resultados, ruta_reporte)
                else:
                    print(f"\n{COLORES['ALTA']}  ❌ Archivo no encontrado{COLORES['RESET']}")
        
        elif opcion == '3':
            # Guardar modelo
            if detector and detector._entrenado:
                detector.guardar_modelo()
            else:
                print(f"\n{COLORES['ALTA']}  ❌ No hay modelo entrenado para guardar{COLORES['RESET']}")
        
        elif opcion == '4':
            # Cargar modelo
            detector = DetectorAnomalias()
            if not detector.cargar_modelo():
                detector = None
        
        elif opcion == '5':
            # Configuración
            print(f"""
  {COLORES['INFO']}⚙️  PARÁMETROS ACTUALES:{COLORES['RESET']}
  
  • Tipo de modelo: Isolation Forest
  • Contamination: 0.1 (10% de datos anómalos esperados)
  • Número de estimadores: 100
  • Umbral de anomalía: -0.5
  
  Para modificar, edita la clase ConfiguracionML en ml_detector.py
""")
        
        elif opcion == '6':
            # Ayuda
            print(f"""
{COLORES['INFO']}╔═══════════════════════════════════════════════════════════════════╗
║  ❓ AYUDA - MACHINE LEARNING                                       ║
╠═══════════════════════════════════════════════════════════════════╣{COLORES['RESET']}
║                                                                   ║
║  🧠 ¿QUÉ ES LA DETECCIÓN DE ANOMALÍAS?                            ║
║  ─────────────────────────────────────                            ║
║  El sistema aprende qué es "tráfico normal" analizando logs       ║
║  legítimos. Después, detecta automáticamente comportamientos      ║
║  que se desvían de ese patrón normal.                             ║
║                                                                   ║
║  📚 ¿CÓMO ENTRENAR EL MODELO?                                     ║
║  ─────────────────────────────                                    ║
║  1. Obtén logs de un período SIN ataques (tráfico limpio)         ║
║  2. Usa la opción 1 para entrenar con esos logs                   ║
║  3. Guarda el modelo entrenado (opción 3)                         ║
║                                                                   ║
║  🔍 ¿CÓMO DETECTAR ANOMALÍAS?                                     ║
║  ───────────────────────────                                      ║
║  1. Carga un modelo entrenado (opción 4)                          ║
║  2. Analiza nuevos logs (opción 2)                                ║
║  3. Revisa el reporte generado                                    ║
║                                                                   ║
║  ⚠️  IMPORTANTE:                                                   ║
║  El ML complementa las reglas, no las sustituye. Puede detectar   ║
║  ataques nuevos (0-day) que las reglas no conocen.               ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
""")
        
        elif opcion == '0':
            break
        
        input("\n  Pulsa Enter para continuar...")


if __name__ == "__main__":
    menu_machine_learning()
