"""
IDS-SIMULA - Generador de logs en múltiples formatos
Crea archivos CSV, JSON y texto para pruebas del analizador
"""

import os
import csv
import json
import random
from datetime import datetime, timedelta


def generar_logs_multiformat(directorio: str = "logs_ejemplo"):
    """Genera logs de ejemplo en CSV, JSON y texto"""
    
    os.makedirs(directorio, exist_ok=True)
    
    # Datos de ejemplo
    ips_normales = ['192.168.1.10', '192.168.1.20', '192.168.1.30', '10.0.0.5']
    ips_atacantes = ['45.33.32.156', '185.220.101.45', '103.75.201.4']
    usuarios = ['admin', 'root', 'user1', 'guest', 'test']
    
    eventos = []
    fecha_base = datetime.now()
    
    # Generar eventos variados
    for i in range(200):
        tiempo = fecha_base - timedelta(minutes=random.randint(1, 1440))
        
        # 70% tráfico normal
        if random.random() < 0.7:
            tipo = random.choice([
                ('exito', 'Accepted password', random.choice(ips_normales), random.choice(['user1', 'admin'])),
                ('exito', 'session opened', random.choice(ips_normales), random.choice(usuarios)),
                ('info', 'CRON session', '127.0.0.1', 'root'),
            ])
        else:
            # 30% eventos de seguridad
            tipo = random.choice([
                ('fallo', 'Failed password', random.choice(ips_atacantes), random.choice(usuarios)),
                ('fallo', 'Invalid user administrator', random.choice(ips_atacantes), 'administrator'),
                ('fallo', 'authentication failure', random.choice(ips_atacantes), 'root'),
                ('intrusion', "GET /api?id=1' OR '1'='1 HTTP/1.1", random.choice(ips_atacantes), None),
                ('intrusion', "GET /../../../etc/passwd HTTP/1.1", random.choice(ips_atacantes), None),
                ('sospechoso', 'GET /admin HTTP/1.1', random.choice(ips_atacantes), None),
            ])
        
        eventos.append({
            'timestamp': tiempo.isoformat(),
            'categoria': tipo[0],
            'mensaje': tipo[1],
            'ip': tipo[2],
            'usuario': tipo[3],
            'raw': f"{tiempo.strftime('%Y-%m-%dT%H:%M:%S')} server sshd[{random.randint(1000,9999)}]: {tipo[1]} from {tipo[2]}"
        })
    
    # Ordenar por tiempo
    eventos.sort(key=lambda x: x['timestamp'])
    
    # ===== GUARDAR CSV =====
    csv_path = os.path.join(directorio, 'logs_seguridad.csv')
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['timestamp', 'categoria', 'mensaje', 'ip', 'usuario', 'raw'])
        writer.writeheader()
        writer.writerows(eventos)
    print(f"✅ CSV generado: {csv_path} ({len(eventos)} eventos)")
    
    # ===== GUARDAR JSON =====
    json_path = os.path.join(directorio, 'logs_seguridad.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(eventos, f, indent=2, ensure_ascii=False)
    print(f"✅ JSON generado: {json_path}")
    
    # ===== GUARDAR JSONL (una línea por evento) =====
    jsonl_path = os.path.join(directorio, 'logs_seguridad.jsonl')
    with open(jsonl_path, 'w', encoding='utf-8') as f:
        for evento in eventos:
            f.write(json.dumps(evento, ensure_ascii=False) + '\n')
    print(f"✅ JSONL generado: {jsonl_path}")
    
    return directorio


if __name__ == '__main__':
    generar_logs_multiformat()
