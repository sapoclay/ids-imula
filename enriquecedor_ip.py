#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
    IDS-IMULA - Enriquecedor de IPs - MF0488
═══════════════════════════════════════════════════════════════════════════════

Módulo para enriquecer información de direcciones IP:
- Geolocalización (país, ciudad, coordenadas)
- Consulta de listas negras (AbuseIPDB, blacklists)
- Información Whois (propietario, ASN)
- Puntuación de reputación
"""

import os
import re
import json
import socket
import sqlite3
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass, field, asdict
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

from config import COLORES, BASE_DIR


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ═══════════════════════════════════════════════════════════════════════════════

# APIs gratuitas (algunas requieren registro para API key)
APIS_CONFIG = {
    'ipapi': {
        'url': 'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query',
        'requiere_key': False,
        'limite_por_minuto': 45,
    },
    'ipinfo': {
        'url': 'https://ipinfo.io/{ip}/json',
        'requiere_key': False,  # Tiene límite gratuito
        'limite_por_minuto': 50,
    },
    'abuseipdb': {
        'url': 'https://api.abuseipdb.com/api/v2/check',
        'requiere_key': True,
        'key_env': 'ABUSEIPDB_API_KEY',
    },
}

# Ruta de caché para resultados
CACHE_DIR = os.path.join(BASE_DIR, 'cache_ip')
CACHE_DB = os.path.join(CACHE_DIR, 'ip_cache.db')
CACHE_EXPIRACION_HORAS = 24


# ═══════════════════════════════════════════════════════════════════════════════
# MODELOS DE DATOS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class GeolocalizacionIP:
    """Información de geolocalización de una IP"""
    ip: str
    pais: str = "Desconocido"
    codigo_pais: str = "??"
    region: str = ""
    ciudad: str = ""
    codigo_postal: str = ""
    latitud: float = 0.0
    longitud: float = 0.0
    zona_horaria: str = ""
    isp: str = ""
    organizacion: str = ""
    asn: str = ""
    
    def __str__(self):
        bandera = self._obtener_bandera()
        ubicacion = f"{self.ciudad}, {self.region}" if self.ciudad else self.region
        return f"{bandera} {self.pais} ({ubicacion}) - {self.isp}"
    
    def _obtener_bandera(self) -> str:
        """Convierte código de país a emoji de bandera"""
        if self.codigo_pais and len(self.codigo_pais) == 2:
            return ''.join(chr(ord(c) + 127397) for c in self.codigo_pais.upper())
        return "🌐"


@dataclass
class ReputacionIP:
    """Información de reputación de una IP"""
    ip: str
    es_maliciosa: bool = False
    puntuacion_abuso: int = 0  # 0-100, mayor = peor
    reportes_totales: int = 0
    ultimo_reporte: Optional[datetime] = None
    categorias_abuso: List[str] = field(default_factory=list)
    en_blacklist: bool = False
    blacklists: List[str] = field(default_factory=list)
    
    @property
    def nivel_riesgo(self) -> str:
        """Determina el nivel de riesgo basado en la puntuación"""
        if self.puntuacion_abuso >= 80 or self.en_blacklist:
            return "CRÍTICO"
        elif self.puntuacion_abuso >= 50:
            return "ALTO"
        elif self.puntuacion_abuso >= 25:
            return "MEDIO"
        elif self.puntuacion_abuso > 0:
            return "BAJO"
        return "LIMPIO"
    
    @property
    def color_riesgo(self) -> str:
        """Color para mostrar en terminal"""
        niveles = {
            "CRÍTICO": COLORES['CRITICA'],
            "ALTO": COLORES['ALTA'],
            "MEDIO": COLORES['MEDIA'],
            "BAJO": COLORES['BAJA'],
            "LIMPIO": COLORES['INFO'],
        }
        return niveles.get(self.nivel_riesgo, COLORES['RESET'])


@dataclass
class WhoisIP:
    """Información Whois de una IP"""
    ip: str
    propietario: str = ""
    organizacion: str = ""
    asn: str = ""
    asn_nombre: str = ""
    rango_red: str = ""
    pais_registro: str = ""
    fecha_registro: str = ""
    contacto_abuso: str = ""


@dataclass
class InformacionIP:
    """Información completa enriquecida de una IP"""
    ip: str
    es_privada: bool = False
    es_reservada: bool = False
    geolocalizacion: Optional[GeolocalizacionIP] = None
    reputacion: Optional[ReputacionIP] = None
    whois: Optional[WhoisIP] = None
    dns_inverso: str = ""
    timestamp_consulta: datetime = field(default_factory=datetime.now)
    
    def resumen(self) -> str:
        """Genera un resumen de la información"""
        lineas = [f"\n{'═'*60}"]
        lineas.append(f"  📍 IP: {self.ip}")
        lineas.append(f"{'═'*60}")
        
        if self.es_privada:
            lineas.append("  ℹ️  IP Privada (red local)")
            return '\n'.join(lineas)
        
        if self.es_reservada:
            lineas.append("  ℹ️  IP Reservada/Especial")
            return '\n'.join(lineas)
        
        if self.dns_inverso:
            lineas.append(f"  🔗 DNS Inverso: {self.dns_inverso}")
        
        if self.geolocalizacion:
            geo = self.geolocalizacion
            lineas.append(f"\n  🌍 GEOLOCALIZACIÓN:")
            lineas.append(f"     País: {geo._obtener_bandera()} {geo.pais} ({geo.codigo_pais})")
            if geo.ciudad or geo.region:
                lineas.append(f"     Ubicación: {geo.ciudad}, {geo.region}")
            if geo.latitud and geo.longitud:
                lineas.append(f"     Coordenadas: {geo.latitud}, {geo.longitud}")
            if geo.isp:
                lineas.append(f"     ISP: {geo.isp}")
            if geo.organizacion:
                lineas.append(f"     Organización: {geo.organizacion}")
            if geo.asn:
                lineas.append(f"     ASN: {geo.asn}")
        
        if self.reputacion:
            rep = self.reputacion
            color = rep.color_riesgo
            reset = COLORES['RESET']
            lineas.append(f"\n  🛡️  REPUTACIÓN:")
            lineas.append(f"     Nivel de riesgo: {color}{rep.nivel_riesgo}{reset}")
            lineas.append(f"     Puntuación abuso: {rep.puntuacion_abuso}/100")
            lineas.append(f"     Reportes totales: {rep.reportes_totales}")
            if rep.en_blacklist:
                lineas.append(f"     ⚠️  En blacklists: {', '.join(rep.blacklists)}")
            if rep.categorias_abuso:
                lineas.append(f"     Categorías: {', '.join(rep.categorias_abuso[:5])}")
        
        if self.whois:
            w = self.whois
            lineas.append(f"\n  📋 WHOIS:")
            if w.propietario:
                lineas.append(f"     Propietario: {w.propietario}")
            if w.organizacion:
                lineas.append(f"     Organización: {w.organizacion}")
            if w.asn:
                lineas.append(f"     ASN: {w.asn} ({w.asn_nombre})")
            if w.rango_red:
                lineas.append(f"     Rango: {w.rango_red}")
            if w.contacto_abuso:
                lineas.append(f"     Contacto abuso: {w.contacto_abuso}")
        
        lineas.append(f"\n{'═'*60}")
        return '\n'.join(lineas)


# ═══════════════════════════════════════════════════════════════════════════════
# CACHÉ DE RESULTADOS
# ═══════════════════════════════════════════════════════════════════════════════

class CacheIP:
    """Caché en SQLite para almacenar resultados de consultas IP"""
    
    def __init__(self, ruta_db: str = CACHE_DB):
        self.ruta_db = ruta_db
        os.makedirs(os.path.dirname(ruta_db), exist_ok=True)
        self._inicializar_db()
    
    def _inicializar_db(self):
        """Crea las tablas de caché"""
        conn = sqlite3.connect(self.ruta_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cache_ip (
                ip TEXT PRIMARY KEY,
                datos_json TEXT,
                timestamp TEXT,
                expira TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def obtener(self, ip: str) -> Optional[Dict]:
        """Obtiene datos de la caché si no han expirado"""
        conn = sqlite3.connect(self.ruta_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT datos_json, expira FROM cache_ip WHERE ip = ?
        ''', (ip,))
        
        resultado = cursor.fetchone()
        conn.close()
        
        if resultado:
            datos_json, expira = resultado
            if datetime.fromisoformat(expira) > datetime.now():
                return json.loads(datos_json)
        
        return None
    
    def guardar(self, ip: str, datos: Dict, horas_expiracion: int = CACHE_EXPIRACION_HORAS):
        """Guarda datos en la caché"""
        conn = sqlite3.connect(self.ruta_db)
        cursor = conn.cursor()
        
        ahora = datetime.now()
        expira = ahora + timedelta(hours=horas_expiracion)
        
        cursor.execute('''
            INSERT OR REPLACE INTO cache_ip (ip, datos_json, timestamp, expira)
            VALUES (?, ?, ?, ?)
        ''', (ip, json.dumps(datos), ahora.isoformat(), expira.isoformat()))
        
        conn.commit()
        conn.close()
    
    def limpiar_expirados(self):
        """Elimina entradas expiradas"""
        conn = sqlite3.connect(self.ruta_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            DELETE FROM cache_ip WHERE expira < ?
        ''', (datetime.now().isoformat(),))
        
        eliminados = cursor.rowcount
        conn.commit()
        conn.close()
        
        return eliminados


# ═══════════════════════════════════════════════════════════════════════════════
# ENRIQUECEDOR DE IPs
# ═══════════════════════════════════════════════════════════════════════════════

class EnriquecedorIP:
    """
    Clase principal para enriquecer información de direcciones IP
    """
    
    def __init__(self, usar_cache: bool = True, timeout: int = 5):
        """
        Inicializa el enriquecedor
        
        Args:
            usar_cache: Si True, usa caché para evitar consultas repetidas
            timeout: Timeout en segundos para las peticiones HTTP
        """
        self.usar_cache = usar_cache
        self.timeout = timeout
        self.cache = CacheIP() if usar_cache else None
        
        # APIs keys desde variables de entorno
        self.abuseipdb_key = os.environ.get('ABUSEIPDB_API_KEY', '')
    
    def es_ip_valida(self, ip: str) -> bool:
        """Verifica si una IP es válida"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def es_ip_privada(self, ip: str) -> bool:
        """Verifica si es una IP privada"""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
    
    def es_ip_reservada(self, ip: str) -> bool:
        """Verifica si es una IP reservada (loopback, multicast, etc.)"""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_loopback or addr.is_multicast or addr.is_reserved
        except ValueError:
            return False
    
    def obtener_dns_inverso(self, ip: str) -> str:
        """Obtiene el hostname mediante DNS inverso"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return ""
    
    def _hacer_peticion(self, url: str, headers: Optional[Dict] = None) -> Optional[Dict]:
        """Realiza una petición HTTP y devuelve JSON"""
        try:
            req = Request(url, headers=headers or {})
            with urlopen(req, timeout=self.timeout) as response:
                return json.loads(response.read().decode('utf-8'))
        except (URLError, HTTPError, json.JSONDecodeError, Exception) as e:
            return None
    
    def obtener_geolocalizacion(self, ip: str) -> Optional[GeolocalizacionIP]:
        """
        Obtiene información de geolocalización de una IP
        Usa ip-api.com (gratuito, sin API key)
        """
        if self.es_ip_privada(ip) or self.es_ip_reservada(ip):
            return GeolocalizacionIP(ip=ip, pais="Red Local/Reservada")
        
        # Verificar caché
        if self.cache:
            cached = self.cache.obtener(f"geo_{ip}")
            if cached:
                return GeolocalizacionIP(**cached)
        
        # Consultar API
        url = APIS_CONFIG['ipapi']['url'].format(ip=ip)
        datos = self._hacer_peticion(url)
        
        if datos and datos.get('status') == 'success':
            geo = GeolocalizacionIP(
                ip=ip,
                pais=datos.get('country', 'Desconocido'),
                codigo_pais=datos.get('countryCode', '??'),
                region=datos.get('regionName', ''),
                ciudad=datos.get('city', ''),
                codigo_postal=datos.get('zip', ''),
                latitud=datos.get('lat', 0.0),
                longitud=datos.get('lon', 0.0),
                zona_horaria=datos.get('timezone', ''),
                isp=datos.get('isp', ''),
                organizacion=datos.get('org', ''),
                asn=datos.get('as', ''),
            )
            
            # Guardar en caché
            if self.cache:
                self.cache.guardar(f"geo_{ip}", asdict(geo))
            
            return geo
        
        return None
    
    def obtener_reputacion(self, ip: str) -> Optional[ReputacionIP]:
        """
        Obtiene información de reputación de una IP
        Usa múltiples fuentes incluyendo AbuseIPDB si hay API key
        """
        if self.es_ip_privada(ip) or self.es_ip_reservada(ip):
            return ReputacionIP(ip=ip, puntuacion_abuso=0)
        
        # Verificar caché
        if self.cache:
            cached = self.cache.obtener(f"rep_{ip}")
            if cached:
                rep = ReputacionIP(**cached)
                if cached.get('ultimo_reporte'):
                    rep.ultimo_reporte = datetime.fromisoformat(cached['ultimo_reporte'])
                return rep
        
        reputacion = ReputacionIP(ip=ip)
        
        # Consultar AbuseIPDB si hay API key
        if self.abuseipdb_key:
            headers = {
                'Key': self.abuseipdb_key,
                'Accept': 'application/json',
            }
            url = f"{APIS_CONFIG['abuseipdb']['url']}?ipAddress={ip}&maxAgeInDays=90"
            datos = self._hacer_peticion(url, headers)
            
            if datos and 'data' in datos:
                d = datos['data']
                reputacion.puntuacion_abuso = d.get('abuseConfidenceScore', 0)
                reputacion.reportes_totales = d.get('totalReports', 0)
                reputacion.es_maliciosa = reputacion.puntuacion_abuso >= 50
                
                if d.get('lastReportedAt'):
                    try:
                        reputacion.ultimo_reporte = datetime.fromisoformat(
                            d['lastReportedAt'].replace('Z', '+00:00')
                        )
                    except:
                        pass
        
        # Consulta básica de blacklists conocidas (simulado sin API externa)
        reputacion.blacklists = self._verificar_blacklists_dns(ip)
        reputacion.en_blacklist = len(reputacion.blacklists) > 0
        
        # Guardar en caché
        if self.cache:
            datos_cache = asdict(reputacion)
            if reputacion.ultimo_reporte:
                datos_cache['ultimo_reporte'] = reputacion.ultimo_reporte.isoformat()
            self.cache.guardar(f"rep_{ip}", datos_cache)
        
        return reputacion
    
    def _verificar_blacklists_dns(self, ip: str) -> List[str]:
        """
        Verifica blacklists basadas en DNS (DNSBL)
        Este método es gratuito y no requiere API keys
        """
        blacklists = [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'dnsbl.sorbs.net',
        ]
        
        encontradas = []
        octetos = ip.split('.')
        
        if len(octetos) != 4:
            return encontradas
        
        ip_reversa = '.'.join(reversed(octetos))
        
        for bl in blacklists:
            try:
                query = f"{ip_reversa}.{bl}"
                socket.gethostbyname(query)
                # Si resuelve, está en la blacklist
                encontradas.append(bl)
            except socket.gaierror:
                # No está en esta blacklist
                pass
            except Exception:
                pass
        
        return encontradas
    
    def obtener_whois_basico(self, ip: str) -> Optional[WhoisIP]:
        """
        Obtiene información Whois básica
        Usa los datos de geolocalización como fuente
        """
        if self.es_ip_privada(ip) or self.es_ip_reservada(ip):
            return WhoisIP(ip=ip, propietario="Red Local")
        
        # Usar datos de geolocalización para Whois básico
        geo = self.obtener_geolocalizacion(ip)
        
        if geo:
            return WhoisIP(
                ip=ip,
                organizacion=geo.organizacion,
                asn=geo.asn.split()[0] if geo.asn else "",
                asn_nombre=' '.join(geo.asn.split()[1:]) if geo.asn else "",
                pais_registro=geo.codigo_pais,
            )
        
        return None
    
    def enriquecer_ip(self, ip: str, incluir_geo: bool = True, 
                      incluir_reputacion: bool = True,
                      incluir_whois: bool = True,
                      incluir_dns: bool = True) -> InformacionIP:
        """
        Enriquece una IP con toda la información disponible
        
        Args:
            ip: Dirección IP a enriquecer
            incluir_geo: Incluir geolocalización
            incluir_reputacion: Incluir reputación
            incluir_whois: Incluir Whois
            incluir_dns: Incluir DNS inverso
        
        Returns:
            InformacionIP con todos los datos disponibles
        """
        info = InformacionIP(
            ip=ip,
            es_privada=self.es_ip_privada(ip),
            es_reservada=self.es_ip_reservada(ip),
        )
        
        # Si es privada o reservada, no consultamos APIs externas
        if info.es_privada or info.es_reservada:
            return info
        
        # Obtener DNS inverso
        if incluir_dns:
            info.dns_inverso = self.obtener_dns_inverso(ip)
        
        # Obtener geolocalización
        if incluir_geo:
            info.geolocalizacion = self.obtener_geolocalizacion(ip)
        
        # Obtener reputación
        if incluir_reputacion:
            info.reputacion = self.obtener_reputacion(ip)
        
        # Obtener Whois
        if incluir_whois:
            info.whois = self.obtener_whois_basico(ip)
        
        return info
    
    def enriquecer_multiples(self, ips: List[str], max_workers: int = 5,
                             mostrar_progreso: bool = True) -> Dict[str, InformacionIP]:
        """
        Enriquece múltiples IPs en paralelo
        
        Args:
            ips: Lista de IPs a enriquecer
            max_workers: Número máximo de hilos
            mostrar_progreso: Mostrar barra de progreso
        
        Returns:
            Diccionario IP -> InformacionIP
        """
        # Filtrar IPs únicas y válidas
        ips_unicas = list(set(ip for ip in ips if self.es_ip_valida(ip)))
        resultados = {}
        
        if not ips_unicas:
            return resultados
        
        total = len(ips_unicas)
        procesadas = 0
        
        print(f"\n{COLORES['INFO']}🔍 Enriqueciendo {total} IPs únicas...{COLORES['RESET']}\n")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futuros = {
                executor.submit(self.enriquecer_ip, ip): ip 
                for ip in ips_unicas
            }
            
            for futuro in as_completed(futuros):
                ip = futuros[futuro]
                try:
                    resultados[ip] = futuro.result()
                    procesadas += 1
                    
                    if mostrar_progreso:
                        porcentaje = (procesadas / total) * 100
                        barra = '█' * int(porcentaje / 5) + '░' * (20 - int(porcentaje / 5))
                        print(f"\r  [{barra}] {porcentaje:.0f}% ({procesadas}/{total})", end='')
                        
                except Exception as e:
                    resultados[ip] = InformacionIP(ip=ip)
        
        if mostrar_progreso:
            print()  # Nueva línea después de la barra de progreso
        
        return resultados
    
    def generar_reporte_ips(self, resultados: Dict[str, InformacionIP], 
                            ruta_salida: Optional[str] = None) -> str:
        """
        Genera un reporte de las IPs analizadas
        
        Args:
            resultados: Diccionario de resultados de enriquecer_multiples
            ruta_salida: Ruta opcional para guardar el reporte
        
        Returns:
            Contenido del reporte
        """
        lineas = []
        lineas.append("=" * 70)
        lineas.append("  📊 REPORTE DE ANÁLISIS DE IPs - IDS-IMULA")
        lineas.append(f"  Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lineas.append(f"  Total IPs analizadas: {len(resultados)}")
        lineas.append("=" * 70)
        
        # Estadísticas
        maliciosas = sum(1 for r in resultados.values() 
                        if r.reputacion and r.reputacion.es_maliciosa)
        en_blacklist = sum(1 for r in resultados.values() 
                          if r.reputacion and r.reputacion.en_blacklist)
        privadas = sum(1 for r in resultados.values() if r.es_privada)
        
        lineas.append(f"\n  📈 ESTADÍSTICAS:")
        lineas.append(f"     • IPs públicas: {len(resultados) - privadas}")
        lineas.append(f"     • IPs privadas/locales: {privadas}")
        lineas.append(f"     • IPs maliciosas detectadas: {maliciosas}")
        lineas.append(f"     • IPs en blacklists: {en_blacklist}")
        
        # Países
        paises = {}
        for r in resultados.values():
            if r.geolocalizacion and not r.es_privada:
                pais = r.geolocalizacion.pais
                paises[pais] = paises.get(pais, 0) + 1
        
        if paises:
            lineas.append(f"\n  🌍 IPs POR PAÍS:")
            for pais, count in sorted(paises.items(), key=lambda x: -x[1])[:10]:
                lineas.append(f"     • {pais}: {count}")
        
        # IPs más peligrosas
        peligrosas = sorted(
            [r for r in resultados.values() if r.reputacion and r.reputacion.puntuacion_abuso > 0],
            key=lambda x: x.reputacion.puntuacion_abuso if x.reputacion else 0,
            reverse=True
        )[:10]
        
        if peligrosas:
            lineas.append(f"\n  ⚠️  TOP 10 IPs MÁS PELIGROSAS:")
            for r in peligrosas:
                pais = r.geolocalizacion.codigo_pais if r.geolocalizacion else "??"
                bandera = r.geolocalizacion._obtener_bandera() if r.geolocalizacion else "🌐"
                if r.reputacion:
                    lineas.append(
                        f"     • {r.ip} - Score: {r.reputacion.puntuacion_abuso}/100 "
                        f"- {bandera} {pais} - Reportes: {r.reputacion.reportes_totales}"
                    )
        
        lineas.append("\n" + "=" * 70)
        
        # Detalles de cada IP
        lineas.append("\n  📋 DETALLE POR IP:\n")
        
        for ip, info in sorted(resultados.items(), 
                              key=lambda x: x[1].reputacion.puntuacion_abuso if x[1].reputacion else 0,
                              reverse=True):
            if info.es_privada or info.es_reservada:
                continue
            
            geo = info.geolocalizacion
            rep = info.reputacion
            
            pais = geo.pais if geo else "?"
            bandera = geo._obtener_bandera() if geo else "🌐"
            score = rep.puntuacion_abuso if rep else 0
            riesgo = rep.nivel_riesgo if rep else "?"
            
            lineas.append(f"  {ip}")
            lineas.append(f"    └─ {bandera} {pais} | Riesgo: {riesgo} ({score}/100)")
            if geo and geo.isp:
                lineas.append(f"       ISP: {geo.isp}")
            lineas.append("")
        
        reporte = '\n'.join(lineas)
        
        # Guardar si se especificó ruta
        if ruta_salida:
            os.makedirs(os.path.dirname(ruta_salida), exist_ok=True)
            with open(ruta_salida, 'w', encoding='utf-8') as f:
                f.write(reporte)
            print(f"\n{COLORES['INFO']}📄 Reporte guardado en: {ruta_salida}{COLORES['RESET']}")
        
        return reporte


# ═══════════════════════════════════════════════════════════════════════════════
# FUNCIÓN AUXILIAR PARA EXTRAER IPs DE TEXTO
# ═══════════════════════════════════════════════════════════════════════════════

def extraer_ips_de_texto(texto: str) -> List[str]:
    """
    Extrae todas las direcciones IP de un texto
    
    Args:
        texto: Texto donde buscar IPs
    
    Returns:
        Lista de IPs encontradas (únicas)
    """
    patron_ip = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(patron_ip, texto)
    
    # Filtrar IPs válidas
    ips_validas = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
            ips_validas.append(ip)
        except ValueError:
            pass
    
    return list(set(ips_validas))


def extraer_ips_de_archivo(ruta: str) -> List[str]:
    """
    Extrae todas las IPs de un archivo
    
    Args:
        ruta: Ruta al archivo
    
    Returns:
        Lista de IPs encontradas
    """
    try:
        with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
            return extraer_ips_de_texto(f.read())
    except Exception:
        return []


# ═══════════════════════════════════════════════════════════════════════════════
# INTERFAZ DE LÍNEA DE COMANDOS
# ═══════════════════════════════════════════════════════════════════════════════

def menu_enriquecimiento_ip():
    """Menú interactivo para enriquecimiento de IPs"""
    enriquecedor = EnriquecedorIP()
    
    while True:
        print(f"""
{COLORES['NEGRITA']}╔═══════════════════════════════════════════════════╗
║         🌐 ENRIQUECIMIENTO DE IPs                 ║
╠═══════════════════════════════════════════════════╣{COLORES['RESET']}
║  1. 🔍 Analizar una IP específica                 ║
║  2. 📋 Analizar lista de IPs (archivo)            ║
║  3. 📊 Ver estadísticas de caché                  ║
║  4. 🧹 Limpiar caché expirada                     ║
║  0. ↩️  Volver al menú principal                   ║
{COLORES['NEGRITA']}╚═══════════════════════════════════════════════════╝{COLORES['RESET']}
""")
        
        opcion = input("  Selecciona una opción: ").strip()
        
        if opcion == '1':
            ip = input("\n  Introduce la IP a analizar: ").strip()
            if enriquecedor.es_ip_valida(ip):
                print(f"\n{COLORES['INFO']}  Analizando {ip}...{COLORES['RESET']}")
                info = enriquecedor.enriquecer_ip(ip)
                print(info.resumen())
            else:
                print(f"\n{COLORES['ALTA']}  ❌ IP no válida{COLORES['RESET']}")
        
        elif opcion == '2':
            ruta = input("\n  Ruta del archivo con IPs o logs: ").strip()
            if os.path.exists(ruta):
                ips = extraer_ips_de_archivo(ruta)
                if ips:
                    print(f"\n  Encontradas {len(ips)} IPs únicas")
                    resultados = enriquecedor.enriquecer_multiples(ips)
                    
                    # Mostrar resumen
                    ruta_reporte = os.path.join(BASE_DIR, 'reportes', 
                                                f'ips_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt')
                    enriquecedor.generar_reporte_ips(resultados, ruta_reporte)
                else:
                    print(f"\n{COLORES['MEDIA']}  ⚠️  No se encontraron IPs en el archivo{COLORES['RESET']}")
            else:
                print(f"\n{COLORES['ALTA']}  ❌ Archivo no encontrado{COLORES['RESET']}")
        
        elif opcion == '3':
            if enriquecedor.cache:
                conn = sqlite3.connect(enriquecedor.cache.ruta_db)
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM cache_ip')
                total = cursor.fetchone()[0]
                conn.close()
                print(f"\n  📊 Entradas en caché: {total}")
                print(f"  📁 Ubicación: {enriquecedor.cache.ruta_db}")
        
        elif opcion == '4':
            if enriquecedor.cache:
                eliminados = enriquecedor.cache.limpiar_expirados()
                print(f"\n  🧹 Eliminadas {eliminados} entradas expiradas")
        
        elif opcion == '0':
            break
        
        input("\n  Pulsa Intro para continuar...")


if __name__ == "__main__":
    menu_enriquecimiento_ip()
