#!/usr/bin/env python3
"""
exporter.py — Módulo de exportación de resultados
==================================================

Genera reportes en Excel (.xlsx), CSV y JSON a partir de los equipos
descubiertos durante el escaneo de red. El Excel incluye hojas de
equipos, resumen estadístico y análisis de riesgos.

Autor: Juan Sebastián Ortiz Quintero
"""
from __future__ import annotations

import csv
import json
from datetime import datetime
from typing import TYPE_CHECKING, Any, Generator

if TYPE_CHECKING:
    from .scanner import Equipo

from .constants import PUERTOS

# ---------------------------------------------------------------- constantes

COLUMNAS = [
    "IP", "Nombre", "MAC", "Fabricante",
    "Tipo probable", "Latencia (ms)", "Puertos abiertos",
]

VERSION = "2.0.0"


# ---------------------------------------------------------------- generadores

def filas(equipos: list[Equipo]) -> Generator[list[Any], None, None]:
    """Produce una fila por equipo con los valores de cada columna."""
    for e in equipos:
        yield [
            e.ip,
            e.nombre or "-",
            e.mac or "-",
            e.fabricante or "-",
            e.tipo,
            e.latencia_ms,
            e.servicios or "-",
        ]


# ---------------------------------------------------------------- CSV

def exportar_csv(equipos: list[Equipo], ruta: str) -> None:
    """Exporta los equipos a CSV con separador de punto y coma y BOM UTF-8."""
    with open(ruta, "w", newline="", encoding="utf-8-sig") as f:
        escritor = csv.writer(f, delimiter=";")
        escritor.writerow(COLUMNAS)
        escritor.writerows(filas(equipos))


# ---------------------------------------------------------------- JSON

def exportar_json(
    equipos: list[Equipo],
    ruta: str,
    rangos: list[str] | None = None,
    analisis: dict[str, Any] | None = None,
) -> None:
    """Exporta los equipos a JSON para integración con APIs o dashboards."""
    datos: dict[str, Any] = {
        "metadata": {
            "herramienta": "inventario-red",
            "version": VERSION,
            "fecha": datetime.now().isoformat(),
            "rangos_escaneados": rangos or [],
            "total_equipos": len(equipos),
        },
        "equipos": [
            {
                "ip": e.ip,
                "nombre": e.nombre or None,
                "mac": e.mac or None,
                "fabricante": e.fabricante or None,
                "tipo": e.tipo,
                "latencia_ms": e.latencia_ms,
                "puertos": e.puertos,
                "servicios": e.servicios or None,
            }
            for e in equipos
        ],
    }
    if analisis:
        datos["analisis"] = analisis

    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(datos, f, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------- Excel

def exportar_excel(
    equipos: list[Equipo],
    ruta: str,
    rangos: list[str],
    analisis: dict[str, Any] | None = None,
) -> None:
    """
    Genera un libro Excel profesional con hasta tres hojas:

    - **Equipos**: tabla completa con formato condicional para puertos
      inseguros (Telnet/FTP en rojo, protocolos industriales en naranja).
    - **Resumen**: metadatos del escaneo, conteo por tipo de equipo y
      listado de alertas de seguridad.
    - **Análisis** (opcional): estado de salud de la red, riesgos
      detectados y recomendaciones de mejora.
    """
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.table import Table, TableStyleInfo

    wb = Workbook()

    # ---- colores y estilos reutilizables ----
    fuente_titulo = Font(name="Calibri", size=14, bold=True, color="1F4E79")
    fuente_subtitulo = Font(name="Calibri", size=11, bold=True, color="2E75B6")
    fuente_cabecera = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    relleno_cabecera = PatternFill("solid", fgColor="2E75B6")
    relleno_alerta_rojo = PatternFill("solid", fgColor="FDE2E1")
    relleno_alerta_naranja = PatternFill("solid", fgColor="FFF2CC")
    relleno_ok = PatternFill("solid", fgColor="E2EFDA")
    relleno_riesgo = PatternFill("solid", fgColor="FCE4EC")
    borde_fino = Border(
        left=Side(style="thin", color="D9D9D9"),
        right=Side(style="thin", color="D9D9D9"),
        top=Side(style="thin", color="D9D9D9"),
        bottom=Side(style="thin", color="D9D9D9"),
    )
    alineacion = Alignment(vertical="top", wrap_text=True)

    # =================================================================
    # HOJA 1 — Equipos
    # =================================================================
    ws = wb.active
    ws.title = "Equipos"
    ws.sheet_properties.tabColor = "2E75B6"

    # Cabeceras
    ws.append(COLUMNAS)
    for celda in ws[1]:
        celda.font = fuente_cabecera
        celda.fill = relleno_cabecera
        celda.alignment = Alignment(horizontal="center", vertical="center")

    # Datos
    for fila_datos in filas(equipos):
        ws.append(fila_datos)

    # Tabla con formato
    if equipos:
        ref_tabla = f"A1:{get_column_letter(len(COLUMNAS))}{len(equipos) + 1}"
        tabla = Table(displayName="Equipos", ref=ref_tabla)
        tabla.tableStyleInfo = TableStyleInfo(
            name="TableStyleMedium2", showRowStripes=True,
        )
        ws.add_table(tabla)

    # Anchos de columna
    anchos = [16, 30, 19, 22, 28, 14, 60]
    for i, ancho in enumerate(anchos, 1):
        ws.column_dimensions[get_column_letter(i)].width = ancho

    ws.freeze_panes = "A2"

    # Formato condicional: resaltar puertos inseguros y protocolos OT
    for fila in ws.iter_rows(min_row=2, max_row=ws.max_row):
        texto_puertos = str(fila[6].value or "")
        # Telnet / FTP → rojo
        if "Telnet" in texto_puertos or "FTP" in texto_puertos:
            fila[6].fill = relleno_alerta_rojo
        # Protocolos industriales → naranja
        elif any(proto in texto_puertos for proto in ("Siemens", "Modbus", "EtherNet/IP")):
            fila[6].fill = relleno_alerta_naranja
        for celda in fila:
            celda.border = borde_fino
            celda.alignment = alineacion

    # =================================================================
    # HOJA 2 — Resumen
    # =================================================================
    rs = wb.create_sheet("Resumen")
    rs.sheet_properties.tabColor = "70AD47"

    rs["A1"] = "📊 Inventario de Red — Resumen"
    rs["A1"].font = fuente_titulo
    rs.merge_cells("A1:B1")
    rs.append([])

    # Metadatos
    meta = [
        ("Fecha del escaneo", datetime.now().strftime("%Y-%m-%d %H:%M")),
        ("Rangos escaneados", ", ".join(rangos)),
        ("Total equipos encontrados", len(equipos)),
        ("Herramienta", f"inventario-red v{VERSION}"),
    ]
    for etiqueta, valor in meta:
        rs.append([etiqueta, valor])
        rs.cell(rs.max_row, 1).font = Font(bold=True)

    rs.append([])

    # Conteo por tipo
    rs.append(["Tipo de equipo", "Cantidad"])
    rs.cell(rs.max_row, 1).font = fuente_subtitulo
    rs.cell(rs.max_row, 2).font = fuente_subtitulo

    conteo: dict[str, int] = {}
    for e in equipos:
        conteo[e.tipo] = conteo.get(e.tipo, 0) + 1
    for tipo, n in sorted(conteo.items(), key=lambda x: -x[1]):
        rs.append([tipo, n])

    # Alertas de seguridad
    inseguros = [e.ip for e in equipos if {21, 23} & set(e.puertos)]
    if inseguros:
        rs.append([])
        rs.append(["⚠️ Equipos con FTP/Telnet abiertos", ", ".join(inseguros)])
        rs.cell(rs.max_row, 1).font = Font(bold=True, color="B3261E")
        rs.cell(rs.max_row, 1).fill = relleno_riesgo

    industriales = [e.ip for e in equipos if {102, 502, 44818} & set(e.puertos)]
    if industriales:
        rs.append([])
        rs.append(["🏭 Equipos industriales detectados", ", ".join(industriales)])
        rs.cell(rs.max_row, 1).font = Font(bold=True, color="E65100")
        rs.cell(rs.max_row, 1).fill = relleno_alerta_naranja

    rs.column_dimensions["A"].width = 44
    rs.column_dimensions["B"].width = 55
    for fila in rs.iter_rows():
        for c in fila:
            c.alignment = alineacion

    # =================================================================
    # HOJA 3 — Análisis (si se proporcionó)
    # =================================================================
    if analisis:
        an = wb.create_sheet("Análisis")
        an.sheet_properties.tabColor = "ED7D31"

        an["A1"] = "🛡️ Análisis de Seguridad de la Red"
        an["A1"].font = fuente_titulo
        an.merge_cells("A1:B1")
        an.append([])

        # Estado general
        estado = analisis.get("estado", "Sin datos")
        an.append(["Estado general de la red", estado])
        celda_estado = an.cell(an.max_row, 2)
        celda_estado.font = Font(size=12, bold=True)
        if "Crítico" in estado or "🔴" in estado:
            celda_estado.fill = relleno_alerta_rojo
        elif "Precaución" in estado or "🟡" in estado:
            celda_estado.fill = relleno_alerta_naranja
        else:
            celda_estado.fill = relleno_ok
        an.cell(an.max_row, 1).font = Font(bold=True)

        an.append([])

        # Riesgos
        riesgos = analisis.get("riesgos", [])
        if riesgos:
            an.append(["🚨 Riesgos detectados", ""])
            an.cell(an.max_row, 1).font = fuente_subtitulo
            for riesgo in riesgos:
                an.append(["", riesgo])
                an.cell(an.max_row, 2).fill = relleno_riesgo
        else:
            an.append(["✅ No se detectaron riesgos críticos", ""])
            an.cell(an.max_row, 1).font = fuente_subtitulo
            an.cell(an.max_row, 1).fill = relleno_ok

        an.append([])

        # Recomendaciones
        recomendaciones = analisis.get("recomendaciones", [])
        if recomendaciones:
            an.append(["💡 Recomendaciones de mejora", ""])
            an.cell(an.max_row, 1).font = fuente_subtitulo
            for i, rec in enumerate(recomendaciones, 1):
                an.append([f"  {i}.", rec])

        an.column_dimensions["A"].width = 44
        an.column_dimensions["B"].width = 80
        for fila in an.iter_rows():
            for c in fila:
                c.alignment = alineacion

    wb.save(ruta)
