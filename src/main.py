#!/usr/bin/env python3
"""
main.py — Interfaz de línea de comandos (CLI)
==============================================

Punto de entrada principal de ``inventario-red``. Acepta rangos de red
en notación CIDR, rango o IP individual, ejecuta el escaneo en
paralelo y exporta los resultados a Excel, CSV y/o JSON.

Uso::

    python -m src.main 192.168.1.0/24
    python -m src.main 192.168.1.0/24 10.0.0.0/28 -o inventario.xlsx --csv
    python -m src.main 192.168.1.10-192.168.1.60 --hilos 128 --json

Autor: Juan Sebastián Ortiz Quintero
"""
from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime

from .detector import analizar_red, clasificar_equipos
from .constants import PUERTOS
from .exporter import VERSION, exportar_csv, exportar_excel, exportar_json
from .scanner import Equipo, escanear, expandir_rangos

# ---------------------------------------------------------------- colores ANSI

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
ROJO = "\033[31m"
VERDE = "\033[32m"
AMARILLO = "\033[33m"
AZUL = "\033[34m"
CYAN = "\033[36m"
BLANCO = "\033[97m"

BANNER = f"""{AZUL}{BOLD}
╔══════════════════════════════════════════════════════════════╗
║  {BLANCO}inventario-red v{VERSION}{AZUL}                                       ║
║  {DIM}Escáner de redes locales e industriales — Sin Nmap{RESET}{AZUL}{BOLD}        ║
╚══════════════════════════════════════════════════════════════╝{RESET}
"""


# ---------------------------------------------------------------- utilidades

def color_tipo(tipo: str) -> str:
    """Devuelve el tipo de equipo coloreado según su categoría."""
    t = tipo.lower()
    if "industrial" in t or "plc" in t:
        return f"{AMARILLO}{tipo}{RESET}"
    if "cámara" in t or "nvr" in t:
        return f"{ROJO}{tipo}{RESET}"
    if "impresora" in t:
        return f"{CYAN}{tipo}{RESET}"
    if "servidor" in t or "base de datos" in t:
        return f"{VERDE}{tipo}{RESET}"
    if "red" in t or "router" in t or "switch" in t:
        return f"{AZUL}{tipo}{RESET}"
    return tipo


def color_puertos(servicios: str) -> str:
    """Resalta puertos inseguros en rojo."""
    if not servicios or servicios == "-":
        return f"{DIM}-{RESET}"
    partes: list[str] = []
    for fragmento in servicios.split(", "):
        if "Telnet" in fragmento or "FTP" in fragmento:
            partes.append(f"{ROJO}{BOLD}{fragmento}{RESET}")
        elif "Siemens" in fragmento or "Modbus" in fragmento or "EtherNet/IP" in fragmento:
            partes.append(f"{AMARILLO}{fragmento}{RESET}")
        else:
            partes.append(fragmento)
    return ", ".join(partes)


def imprimir_tabla(equipos: list[Equipo]) -> None:
    """Imprime una tabla formateada con colores ANSI en la terminal."""
    # Línea separadora
    sep = f"{DIM}{'─' * 120}{RESET}"

    print(f"\n{sep}")
    print(
        f"  {BOLD}{'IP':<17}{'Nombre':<26}{'MAC':<20}"
        f"{'Tipo':<28}{'Latencia':<10}Puertos{RESET}"
    )
    print(sep)

    for e in equipos:
        nombre = (e.nombre or "-")[:25]
        mac = (e.mac or "-")[:18]
        lat = f"{e.latencia_ms:.0f} ms" if e.latencia_ms is not None else "-"
        tipo_col = color_tipo(e.tipo)
        puertos_col = color_puertos(e.servicios)
        print(
            f"  {e.ip:<17}{nombre:<26}{mac:<20}"
            f"{tipo_col:<39}{lat:<10}{puertos_col}"
        )

    print(sep)


def imprimir_resumen(
    equipos: list[Equipo],
    duracion: float,
    rangos: list[str],
    analisis: dict | None = None,
) -> None:
    """Imprime el resumen final del escaneo."""
    print(f"\n{BOLD}{'═' * 60}{RESET}")
    print(f"  {BOLD}📊 Resumen del escaneo{RESET}")
    print(f"  {DIM}Rangos: {', '.join(rangos)}{RESET}")
    print(f"  {DIM}Duración: {duracion:.1f} s{RESET}")
    print(f"{'═' * 60}")

    # Conteo por tipo
    conteo: dict[str, int] = {}
    for e in equipos:
        conteo[e.tipo] = conteo.get(e.tipo, 0) + 1

    print(f"\n  {BOLD}Equipos encontrados: {len(equipos)}{RESET}\n")
    for tipo, n in sorted(conteo.items(), key=lambda x: -x[1]):
        barra = "█" * min(n, 30)
        print(f"    {color_tipo(tipo):<39} {n:>3}  {AZUL}{barra}{RESET}")

    # Alertas rápidas
    inseguros = [e for e in equipos if {21, 23} & set(e.puertos)]
    if inseguros:
        print(f"\n  {ROJO}{BOLD}⚠️  {len(inseguros)} equipo(s) con Telnet/FTP abierto:{RESET}")
        for e in inseguros:
            print(f"    {ROJO}• {e.ip} ({e.nombre or '-'}){RESET}")

    industriales = [e for e in equipos if {102, 502, 44818} & set(e.puertos)]
    if industriales:
        print(f"\n  {AMARILLO}{BOLD}🏭 {len(industriales)} equipo(s) industriales (OT):{RESET}")
        for e in industriales:
            print(f"    {AMARILLO}• {e.ip} — {e.tipo}{RESET}")

    # Análisis de riesgos
    if analisis:
        estado = analisis.get("estado", "Sin datos")
        if "Crítico" in estado or "🔴" in estado:
            color = ROJO
        elif "Precaución" in estado or "🟡" in estado:
            color = AMARILLO
        else:
            color = VERDE
        print(f"\n  {BOLD}Estado de la red: {color}{estado}{RESET}")

        for riesgo in analisis.get("riesgos", []):
            print(f"    {ROJO}▸ {riesgo}{RESET}")
        for rec in analisis.get("recomendaciones", []):
            print(f"    {CYAN}💡 {rec}{RESET}")

    print()


# ---------------------------------------------------------------- CLI

def crear_parser() -> argparse.ArgumentParser:
    """Construye el parser de argumentos de la CLI."""
    ap = argparse.ArgumentParser(
        prog="inventario-red",
        description=(
            "Escáner de redes locales e industriales (OT). "
            "Descubre equipos, identifica su tipo probable y exporta "
            "los resultados a Excel, CSV o JSON — sin necesidad de Nmap."
        ),
        epilog=(
            "Ejemplos:\n"
            "  python -m src.main 192.168.1.0/24\n"
            "  python -m src.main 10.0.0.0/24 --hilos 128 --csv --json\n"
            "  python -m src.main 192.168.1.10-192.168.1.50 -o mi_red.xlsx\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "rangos", nargs="+",
        help="Rangos de red: CIDR (192.168.1.0/24), rango (inicio-fin) o IP individual",
    )
    ap.add_argument(
        "-o", "--salida",
        default=f"inventario_{datetime.now():%Y%m%d_%H%M}.xlsx",
        help="Archivo Excel de salida (por defecto: inventario_FECHA.xlsx)",
    )
    ap.add_argument(
        "--csv", action="store_true",
        help="Exportar también en formato CSV (separador ;)",
    )
    ap.add_argument(
        "--json", action="store_true",
        help="Exportar también en formato JSON (para APIs o dashboards)",
    )
    ap.add_argument(
        "--hilos", type=int, default=64, metavar="N",
        help="Cantidad de hilos simultáneos para ping (por defecto: 64)",
    )
    ap.add_argument(
        "--timeout", type=int, default=800, metavar="MS",
        help="Tiempo de espera por equipo en milisegundos (por defecto: 800)",
    )
    ap.add_argument(
        "--puertos", metavar="LISTA",
        help="Lista de puertos separada por comas (por defecto: lista interna OT+IT)",
    )
    ap.add_argument(
        "--sin-analisis", action="store_true",
        help="Omitir el análisis de riesgos y recomendaciones",
    )
    ap.add_argument(
        "--version", action="version",
        version=f"%(prog)s v{VERSION}",
    )
    return ap


def main() -> int:
    """Punto de entrada principal de la CLI."""
    print(BANNER)

    ap = crear_parser()
    args = ap.parse_args()

    # Validar y expandir rangos
    try:
        ips = expandir_rangos(args.rangos)
    except ValueError as e:
        print(f"{ROJO}Error: Rango inválido — {e}{RESET}", file=sys.stderr)
        return 2

    if not ips:
        print(f"{ROJO}Error: No se encontraron direcciones IP en los rangos dados.{RESET}", file=sys.stderr)
        return 2

    if len(ips) > 4096:
        print(
            f"{AMARILLO}Advertencia: El rango tiene {len(ips)} direcciones. "
            f"Considere dividirlo en subredes de /20 o menos.{RESET}",
            file=sys.stderr,
        )
        return 2

    # Preparar lista de puertos
    if args.puertos:
        try:
            puertos = sorted(int(p.strip()) for p in args.puertos.split(","))
        except ValueError:
            print(f"{ROJO}Error: Lista de puertos inválida.{RESET}", file=sys.stderr)
            return 2
        for p in puertos:
            PUERTOS.setdefault(p, "")
    else:
        puertos = sorted(PUERTOS)

    # Ejecutar escaneo
    print(f"  {BOLD}Objetivo:{RESET} {', '.join(args.rangos)}")
    print(f"  {BOLD}Direcciones:{RESET} {len(ips)}  |  {BOLD}Hilos:{RESET} {args.hilos}  |  {BOLD}Timeout:{RESET} {args.timeout} ms")
    print(f"  {BOLD}Puertos:{RESET} {len(puertos)}\n")

    inicio = time.perf_counter()
    equipos = escanear(ips, args.hilos, args.timeout, puertos)
    duracion = time.perf_counter() - inicio

    if not equipos:
        print(f"\n{AMARILLO}No se encontraron equipos activos en los rangos dados.{RESET}")
        return 0

    # Clasificar tipo de equipo
    equipos = clasificar_equipos(equipos)

    # Análisis de riesgos
    analisis = None
    if not args.sin_analisis:
        analisis = analizar_red(equipos)

    # Mostrar resultados en consola
    imprimir_tabla(equipos)
    imprimir_resumen(equipos, duracion, args.rangos, analisis)

    # Exportar a Excel
    try:
        exportar_excel(equipos, args.salida, args.rangos, analisis)
        print(f"  {VERDE}✓ Excel:{RESET} {args.salida}")
    except ImportError:
        print(
            f"  {AMARILLO}⚠ openpyxl no está instalado "
            f"(pip install openpyxl); guardando solo CSV.{RESET}"
        )
        args.csv = True

    # Exportar a CSV
    if args.csv:
        ruta_csv = args.salida.rsplit(".", 1)[0] + ".csv"
        exportar_csv(equipos, ruta_csv)
        print(f"  {VERDE}✓ CSV:{RESET}   {ruta_csv}")

    # Exportar a JSON
    if args.json:
        ruta_json = args.salida.rsplit(".", 1)[0] + ".json"
        exportar_json(equipos, ruta_json, args.rangos, analisis)
        print(f"  {VERDE}✓ JSON:{RESET}  {ruta_json}")

    print(
        f"\n  {BOLD}{len(equipos)} equipos descubiertos en {duracion:.1f} s{RESET}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
