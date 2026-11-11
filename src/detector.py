"""
detector.py — Clasificación de equipos y análisis de riesgos
=============================================================

Heurísticas para determinar el tipo probable de cada dispositivo
detectado en la red (PLC, servidor, impresora, cámara, etc.) y
funciones de análisis de seguridad que generan alertas y
recomendaciones automáticas.

Uso interno:
    from src.detector import clasificar_equipo, analizar_red, generar_resumen
"""
from __future__ import annotations

from .constants import PUERTOS, PUERTOS_INDUSTRIALES, PUERTOS_INSEGUROS
from .scanner import Equipo

__all__ = [
    "clasificar_equipo",
    "clasificar_equipos",
    "analizar_red",
    "generar_resumen",
]


# ---------------------------------------------------------------- clasificación

def clasificar_equipo(equipo: Equipo) -> str:
    """Determina el tipo probable de un equipo según puertos y fabricante.

    Aplica heurísticas ordenadas por especificidad (los tipos más
    distintivos se evalúan primero) para evitar falsos positivos.

    Args:
        equipo: Instancia de :class:`~scanner.Equipo` con puertos y
                fabricante ya completados.

    Returns:
        Cadena descriptiva del tipo de equipo.
    """
    p = set(equipo.puertos)
    f = equipo.fabricante.lower()

    # --- Industrial / OT ---
    if p & PUERTOS_INDUSTRIALES or any(
        x in f for x in ("siemens", "rockwell", "schneider", "abb", "yokogawa",
                          "emerson", "phoenix", "hms industrial")
    ):
        if 502 in p:
            return "PLC / dispositivo Modbus"
        if 102 in p:
            return "PLC Siemens (S7)"
        if 44818 in p or 2222 in p:
            return "PLC Allen-Bradley (EtherNet/IP)"
        if 4840 in p:
            return "Servidor OPC UA"
        if 47808 in p:
            return "Controlador BACnet (HVAC)"
        return "Equipo industrial (OT)"

    # --- Videovigilancia ---
    if p & {554, 8000, 37777, 34567} or any(
        x in f for x in ("hikvision", "dahua", "axis", "xmeye")
    ):
        if 37777 in p or "dahua" in f:
            return "Cámara / NVR Dahua"
        if 8000 in p or "hikvision" in f:
            return "Cámara / NVR Hikvision"
        if "axis" in f:
            return "Cámara Axis"
        return "Cámara / NVR"

    # --- Impresoras ---
    if p & {9100, 515, 631} or any(
        x in f for x in ("epson", "brother", "ricoh", "xerox", "impresora")
    ):
        return "Impresora"

    # --- Virtualización ---
    if any(x in f for x in ("vmware", "virtualbox", "hyper-v", "qemu")):
        if p & {1433, 3306, 5432}:
            return "Máquina virtual (servidor BD)"
        return "Máquina virtual"

    # --- Raspberry Pi / embebido ---
    if "raspberry" in f:
        return "Raspberry Pi / embebido"

    # --- Servidores de base de datos ---
    if p & {1433, 3306, 5432, 6379, 27017}:
        dbs = []
        if 1433 in p:
            dbs.append("SQL Server")
        if 3306 in p:
            dbs.append("MySQL")
        if 5432 in p:
            dbs.append("PostgreSQL")
        if 6379 in p:
            dbs.append("Redis")
        if 27017 in p:
            dbs.append("MongoDB")
        return f"Servidor de base de datos ({', '.join(dbs)})"

    # --- Equipos de red gestionables ---
    if any(x in f for x in ("cisco", "juniper", "aruba", "arista", "ruckus",
                              "ubiquiti", "mikrotik", "tp-link", "fortinet",
                              "palo alto")):
        if any(x in f for x in ("fortinet", "palo alto")):
            return "Firewall / UTM"
        if "ubiquiti" in f or "ruckus" in f or "aruba" in f:
            return "Access Point / controlador Wi-Fi"
        return "Switch / Router gestionable"

    # --- Switch/Router por puertos (sin marca conocida) ---
    if p >= {22, 80, 443} and not p & {135, 445, 3389}:
        if 161 in p:
            return "Switch / Router gestionable"
        return "Equipo con interfaz web (posible switch)"

    # --- Servidor Windows ---
    if 445 in p and 3389 in p:
        if 135 in p and p & {80, 443}:
            return "Servidor Windows"
        return "Servidor / PC Windows (con RDP)"

    # --- PC Windows ---
    if p & {445, 135}:
        return "PC Windows"

    # --- Servidor Linux ---
    if 22 in p and not p & {445, 135, 3389}:
        if p & {80, 443}:
            return "Servidor Linux (web)"
        if 25 in p or 143 in p or 993 in p:
            return "Servidor Linux (correo)"
        return "Servidor / equipo Linux"

    # --- Docker / Proxmox ---
    if 2375 in p:
        return "Docker host"
    if 8006 in p:
        return "Proxmox VE"

    # --- VNC ---
    if 5900 in p:
        return "Equipo con VNC"

    # --- Equipo con interfaz web genérica ---
    if p & {80, 443, 8080, 8443}:
        return "Equipo con interfaz web"

    # --- Dispositivo Apple ---
    if "apple" in f:
        return "Dispositivo Apple"

    return "Desconocido"


def clasificar_equipos(equipos: list[Equipo]) -> list[Equipo]:
    """Clasifica todos los equipos de una lista, asignando el campo ``tipo``.

    Args:
        equipos: Lista de equipos ya escaneados.

    Returns:
        La misma lista (mutada in-place) con el campo ``tipo`` actualizado.
    """
    for eq in equipos:
        eq.tipo = clasificar_equipo(eq)
    return equipos


# ---------------------------------------------------------------- análisis de riesgos

def analizar_red(equipos: list[Equipo]) -> dict:
    """Analiza los resultados de un escaneo para detectar riesgos y emitir
    recomendaciones de seguridad.

    Evalúa:
        - Puertos inseguros (Telnet, FTP) abiertos.
        - Equipos sin nombre DNS (puntos ciegos de auditoría).
        - Presencia de dispositivos industriales (OT) en la red.
        - Concentración excesiva de servicios críticos.

    Args:
        equipos: Lista de :class:`~scanner.Equipo` con puertos y tipo
                 ya asignados.

    Returns:
        Diccionario con las claves:
            - ``estado`` (str): Resumen de salud (``"Saludable"``,
              ``"Precaución"`` o ``"Crítico"``).
            - ``riesgos`` (list[str]): Descripciones de riesgos detectados.
            - ``recomendaciones`` (list[str]): Acciones sugeridas.
            - ``metricas`` (dict): Contadores numéricos del análisis.
    """
    total = len(equipos)
    if total == 0:
        return {
            "estado": "Sin datos",
            "riesgos": [],
            "recomendaciones": [],
            "metricas": {"total": 0},
        }

    riesgos: list[str] = []
    recomendaciones: list[str] = []

    # 1. Puertos inseguros (Telnet / FTP / SMTP abierto / POP3 / IMAP)
    con_inseguros: list[str] = []
    for eq in equipos:
        encontrados = set(eq.puertos) & PUERTOS_INSEGUROS
        if encontrados:
            nombres = ", ".join(
                f"{p} ({PUERTOS.get(p, '')})" for p in sorted(encontrados)
            )
            con_inseguros.append(f"{eq.ip} → {nombres}")

    if con_inseguros:
        riesgos.append(
            f"⚠️  {len(con_inseguros)} equipo(s) con puertos inseguros "
            f"(texto plano): {', '.join(eq.split(' →')[0] for eq in con_inseguros)}"
        )
        recomendaciones.append(
            "Desactiva servicios legacy como Telnet y FTP. Usa SSH/SFTP "
            "como alternativas cifradas para mitigar la captura de "
            "credenciales en la red."
        )

    # 2. Equipos sin nombre DNS
    sin_nombre = [eq for eq in equipos if not eq.nombre]
    if sin_nombre:
        porcentaje = (len(sin_nombre) / total) * 100
        if porcentaje > 20:
            riesgos.append(
                f"🔍 El {porcentaje:.0f}% de los equipos ({len(sin_nombre)}/{total}) "
                f"no tienen nombre DNS inverso."
            )
            recomendaciones.append(
                "Implementa registros PTR en tu servidor DNS local para "
                "identificar rápidamente los equipos y evitar puntos "
                "ciegos de auditoría."
            )

    # 3. Dispositivos industriales (OT)
    equipos_ot = [
        eq for eq in equipos
        if set(eq.puertos) & PUERTOS_INDUSTRIALES or "industrial" in eq.tipo.lower()
        or "plc" in eq.tipo.lower() or "modbus" in eq.tipo.lower()
    ]
    if equipos_ot:
        ips_ot = ", ".join(eq.ip for eq in equipos_ot)
        riesgos.append(
            f"🏭 Se detectaron {len(equipos_ot)} dispositivo(s) industrial(es) "
            f"(OT): {ips_ot}"
        )
        recomendaciones.append(
            "Segmentación industrial: los PLCs y equipos OT deben estar "
            "en una VLAN aislada del tráfico de oficina. Considera "
            "implementar un firewall industrial entre las zonas IT y OT "
            "(modelo Purdue / IEC 62443)."
        )

    # 4. Servidores de base de datos expuestos
    bds_expuestas = [
        eq for eq in equipos
        if set(eq.puertos) & {1433, 3306, 5432, 6379, 27017}
    ]
    if len(bds_expuestas) > 0:
        sin_cifrado = [
            eq for eq in bds_expuestas
            if not (set(eq.puertos) & {443, 8443})
        ]
        if sin_cifrado:
            recomendaciones.append(
                f"Se encontraron {len(sin_cifrado)} servidor(es) de base de "
                f"datos accesibles por red. Restringe el acceso a IPs "
                f"autorizadas mediante firewall y usa conexiones cifradas (TLS)."
            )

    # 5. Docker API expuesto
    docker_expuesto = [eq for eq in equipos if 2375 in eq.puertos]
    if docker_expuesto:
        riesgos.append(
            f"🐳 {len(docker_expuesto)} equipo(s) con Docker API (puerto 2375) "
            f"expuesto sin TLS. Esto permite ejecución remota de contenedores."
        )
        recomendaciones.append(
            "Desactiva el Docker API remoto o configúralo con TLS mutuo "
            "(puerto 2376). El puerto 2375 sin cifrar es un vector de "
            "ataque crítico."
        )

    # Determinar estado general
    if len(riesgos) >= 3:
        estado = "Crítico 🔴"
    elif len(riesgos) >= 1:
        estado = "Precaución 🟡"
    else:
        estado = "Saludable 🟢"

    # Recomendaciones generales si no hay alertas específicas
    if not recomendaciones:
        recomendaciones.append(
            "No se detectaron riesgos críticos. Mantén un escaneo "
            "periódico (semanal) para detectar cambios no autorizados."
        )

    return {
        "estado": estado,
        "riesgos": riesgos,
        "recomendaciones": recomendaciones,
        "metricas": {
            "total": total,
            "con_puertos_inseguros": len(con_inseguros),
            "sin_nombre_dns": len(sin_nombre),
            "equipos_ot": len(equipos_ot),
            "bds_expuestas": len(bds_expuestas),
        },
    }


# ---------------------------------------------------------------- resumen

def generar_resumen(equipos: list[Equipo]) -> dict:
    """Genera un resumen estadístico del inventario escaneado.

    Args:
        equipos: Lista de equipos clasificados.

    Returns:
        Diccionario con:
            - ``total`` (int): Cantidad de equipos encontrados.
            - ``por_tipo`` (dict[str, int]): Conteo por tipo de equipo.
            - ``por_fabricante`` (dict[str, int]): Conteo por fabricante.
            - ``con_inseguros`` (list[str]): IPs con puertos inseguros.
            - ``sin_nombre`` (list[str]): IPs sin resolución DNS.
            - ``rango_latencia`` (tuple[float, float]): Mín y máx de latencia.
    """
    por_tipo: dict[str, int] = {}
    por_fabricante: dict[str, int] = {}
    con_inseguros: list[str] = []
    sin_nombre: list[str] = []
    latencias: list[float] = []

    for eq in equipos:
        # Conteo por tipo
        por_tipo[eq.tipo] = por_tipo.get(eq.tipo, 0) + 1

        # Conteo por fabricante
        fab = eq.fabricante or "(desconocido)"
        por_fabricante[fab] = por_fabricante.get(fab, 0) + 1

        # Puertos inseguros
        if set(eq.puertos) & PUERTOS_INSEGUROS:
            con_inseguros.append(eq.ip)

        # Sin nombre
        if not eq.nombre:
            sin_nombre.append(eq.ip)

        # Latencia
        if eq.latencia_ms is not None:
            latencias.append(eq.latencia_ms)

    # Ordenar por cantidad descendente
    por_tipo = dict(sorted(por_tipo.items(), key=lambda x: -x[1]))
    por_fabricante = dict(sorted(por_fabricante.items(), key=lambda x: -x[1]))

    return {
        "total": len(equipos),
        "por_tipo": por_tipo,
        "por_fabricante": por_fabricante,
        "con_inseguros": con_inseguros,
        "sin_nombre": sin_nombre,
        "rango_latencia": (
            (min(latencias), max(latencias)) if latencias else (0.0, 0.0)
        ),
    }
