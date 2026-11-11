"""
inventario-red — Escáner de redes locales e industriales
========================================================

Herramienta en Python puro (sin Nmap) para descubrir equipos activos
en redes de oficina y planta (OT), clasificarlos por tipo, detectar
riesgos de seguridad y exportar los resultados a Excel/CSV.

.. code-block:: python

    from src.scanner import escanear, expandir_rangos
    from src.detector import clasificar_equipos, analizar_red

    ips = expandir_rangos(["192.168.1.0/24"])
    equipos = escanear(ips)
    clasificar_equipos(equipos)
    analisis = analizar_red(equipos)
"""
from __future__ import annotations

__version__ = "2.0.0"
__author__ = "Juan Sebastián Ortiz Quintero"

from .scanner import Equipo, escanear, expandir_rangos
from .detector import clasificar_equipo, clasificar_equipos, analizar_red, generar_resumen
from .constants import PUERTOS, FABRICANTES

__all__ = [
    "__version__",
    "__author__",
    "Equipo",
    "escanear",
    "expandir_rangos",
    "clasificar_equipo",
    "clasificar_equipos",
    "analizar_red",
    "generar_resumen",
    "PUERTOS",
    "FABRICANTES",
]
