#!/usr/bin/env python3
"""
IDS-SIMULA - Mensaje de Salida
Muestra un mensaje personalizado al cerrar la aplicación.
"""


def imprimir_mensaje_salida():
    """Imprime el mensaje de despedida de IDS-IMULA"""
    mensaje = """

╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   👋 ¡Gracias por usar IDS-IMULA!                                            ║
║                                                                               ║
║   📚 Proyecto - MF0488                                                        ║
║      Gestión de incidentes de seguridad informática                           ║
║                                                                               ║
║   🛡️  Recuerda: La seguridad es un proceso continuo                           ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
    print(mensaje)


if __name__ == '__main__':
    imprimir_mensaje_salida()
