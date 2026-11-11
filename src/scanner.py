"""
scanner.py — Motor de escaneo de red
=====================================

Descubre equipos activos en una red local mediante ICMP ping o sondeo
TCP, resuelve nombres DNS, lee la tabla ARP del sistema y escanea
puertos abiertos. Funciona en Windows y Linux sin dependencias externas
como Nmap.

Uso interno:
    from src.scanner import escanear, expandir_rangos, Equipo
"""
from __future__ import annotations

import ipaddress
import platform
import re
import shutil
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable

from .constants import FABRICANTES, PUERTOS

__all__ = [
    "Equipo",
    "escanear",
    "expandir_rangos",
    "ping",
    "sondeo_tcp",
    "puerto_abierto",
    "nombre_dns",
    "tabla_arp",
    "fabricante_por_mac",
]

ES_WINDOWS: bool = platform.system().lower() == "windows"
HAY_PING: bool = shutil.which("ping") is not None


# ---------------------------------------------------------------- modelo
@dataclass
class Equipo:
    """Representa un dispositivo detectado en la red.

    Atributos:
        ip:          Dirección IPv4 del equipo.
        nombre:      Nombre DNS inverso (vacío si no resolvió).
        mac:         Dirección MAC en formato ``AA:BB:CC:DD:EE:FF``.
        fabricante:  Nombre del fabricante deducido del prefijo OUI.
        latencia_ms: Latencia del ping o sondeo TCP, en milisegundos.
        puertos:     Lista de puertos TCP abiertos encontrados.
        tipo:        Tipo de equipo (asignado por el módulo detector).
    """

    ip: str
    nombre: str = ""
    mac: str = ""
    fabricante: str = ""
    latencia_ms: float | None = None
    puertos: list[int] = field(default_factory=list)
    tipo: str = "Desconocido"

    @property
    def servicios(self) -> str:
        """Cadena legible de puertos abiertos con sus etiquetas."""
        return ", ".join(
            f"{p} {PUERTOS.get(p, '')}" for p in sorted(self.puertos)
        )


# ---------------------------------------------------------------- descubrimiento

def sondeo_tcp(ip: str, timeout_ms: int) -> float | None:
    """Alternativa al ping cuando ICMP está bloqueado.

    Intenta conectar a puertos comunes; si alguno acepta o rechaza
    la conexión, el equipo está encendido.

    Args:
        ip:         Dirección IPv4 a sondear.
        timeout_ms: Tiempo máximo de espera total, en milisegundos.

    Returns:
        Latencia en ms si el equipo respondió, ``None`` en caso contrario.
    """
    inicio = time.perf_counter()
    puertos_rapidos = (445, 80, 443, 22, 135, 3389, 554, 102, 502)
    timeout_por_puerto = max(0.05, (timeout_ms / 1000) / len(puertos_rapidos))

    for p in puertos_rapidos:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout_por_puerto)
                resultado = s.connect_ex((ip, p))
                # 0 = abierto, 111/10061 = rechazado (el equipo existe)
                if resultado in (0, 111, 10061):
                    return round((time.perf_counter() - inicio) * 1000, 1)
        except OSError:
            continue
    return None


def ping(ip: str, timeout_ms: int) -> float | None:
    """Envía un ping ICMP al equipo y devuelve la latencia.

    Si el comando ``ping`` no está disponible, recurre a :func:`sondeo_tcp`.
    Funciona tanto en Windows como en Linux.

    Args:
        ip:         Dirección IPv4.
        timeout_ms: Tiempo máximo de espera, en milisegundos.

    Returns:
        Latencia en ms, o ``None`` si el equipo no respondió.
    """
    if not HAY_PING:
        return sondeo_tcp(ip, timeout_ms)

    if ES_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]

    inicio = time.perf_counter()
    try:
        r = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout_ms / 1000 + 2,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    if r.returncode != 0 or "TTL=" not in r.stdout.upper():
        return None

    m = re.search(r"(?:time|tiempo)[=<]\s*([\d.,]+)\s*ms", r.stdout, re.IGNORECASE)
    if m:
        return float(m.group(1).replace(",", "."))
    return round((time.perf_counter() - inicio) * 1000, 1)


def puerto_abierto(ip: str, puerto: int, timeout: float) -> bool:
    """Verifica si un puerto TCP está abierto.

    Args:
        ip:      Dirección IPv4.
        puerto:  Número de puerto TCP.
        timeout: Tiempo de espera en segundos.

    Returns:
        ``True`` si el puerto aceptó la conexión.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, puerto)) == 0
    except OSError:
        return False


def nombre_dns(ip: str) -> str:
    """Intenta resolver el nombre DNS inverso de una dirección IP.

    Returns:
        Nombre de host, o cadena vacía si no se pudo resolver.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def tabla_arp() -> dict[str, str]:
    """Lee la tabla ARP del sistema operativo.

    Funciona en Windows (``arp -a``) y Linux (``ip neigh``).

    Returns:
        Diccionario ``{dirección_ip: dirección_mac}``.
        Las MACs se normalizan a mayúsculas con separador ``:``.
    """
    macs: dict[str, str] = {}
    try:
        if ES_WINDOWS:
            salida = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True
            ).stdout
        else:
            salida = subprocess.run(
                ["ip", "neigh"], capture_output=True, text=True
            ).stdout
    except FileNotFoundError:
        return macs

    patron = re.compile(
        r"(\d+\.\d+\.\d+\.\d+)\D+?(([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})"
    )
    for linea in salida.splitlines():
        m = patron.search(linea)
        if m:
            macs[m.group(1)] = m.group(2).replace("-", ":").upper()
    return macs


def fabricante_por_mac(mac: str) -> str:
    """Busca el fabricante a partir del prefijo OUI de la dirección MAC.

    Args:
        mac: Dirección MAC en formato ``AA:BB:CC:DD:EE:FF``.

    Returns:
        Nombre del fabricante, o cadena vacía si no está en la base.
    """
    if not mac or len(mac) < 8:
        return ""
    return FABRICANTES.get(mac[:8].upper(), "")


# ---------------------------------------------------------------- rangos

def expandir_rangos(rangos: list[str]) -> list[str]:
    """Convierte notaciones de red a una lista plana de IPs.

    Formatos aceptados:
        - CIDR:  ``192.168.1.0/24``
        - Rango: ``192.168.1.10-192.168.1.50``
        - IP individual: ``10.0.0.5``

    Args:
        rangos: Lista de cadenas con las notaciones a expandir.

    Returns:
        Lista de direcciones IPv4 como cadenas, sin duplicados.

    Raises:
        ValueError: Si alguna notación es inválida.
    """
    ips: list[str] = []
    for r in rangos:
        r = r.strip()
        if "-" in r:
            partes = r.split("-", 1)
            a = ipaddress.IPv4Address(partes[0].strip())
            b = ipaddress.IPv4Address(partes[1].strip())
            if b < a:
                a, b = b, a
            ips += [str(ipaddress.IPv4Address(i)) for i in range(int(a), int(b) + 1)]
        elif "/" in r:
            red = ipaddress.IPv4Network(r, strict=False)
            hosts = list(red.hosts()) or [red.network_address]
            ips += [str(h) for h in hosts]
        else:
            ips.append(str(ipaddress.IPv4Address(r)))
    return list(dict.fromkeys(ips))  # sin duplicados, preserva orden


# ---------------------------------------------------------------- escaneo

ProgressCallback = Callable[[int, int, int], None]
"""Firma del callback de progreso: (revisadas, total, encontradas)."""


def escanear(
    ips: list[str],
    hilos: int = 64,
    timeout_ms: int = 800,
    puertos: list[int] | None = None,
    callback: ProgressCallback | None = None,
) -> list[Equipo]:
    """Ejecuta un escaneo completo de las direcciones indicadas.

    Fases:
        1. Descubrimiento: ping/sondeo TCP en paralelo.
        2. Detalle: puertos abiertos y nombre DNS de cada equipo vivo.
        3. Enriquecimiento: MAC y fabricante desde la tabla ARP.

    Args:
        ips:        Lista de direcciones IPv4 a escanear.
        hilos:      Cantidad de hilos concurrentes para el ping.
        timeout_ms: Tiempo de espera por equipo, en milisegundos.
        puertos:    Puertos TCP a revisar. Si es ``None``, usa la lista
                    predeterminada de :data:`constants.PUERTOS`.
        callback:   Función opcional para reportar progreso durante la
                    fase de descubrimiento. Recibe ``(revisadas, total,
                    encontradas)``.

    Returns:
        Lista de :class:`Equipo` ordenada por IP.
    """
    if puertos is None:
        puertos = sorted(PUERTOS.keys())

    vivos: list[Equipo] = []
    total = len(ips)

    # Fase 1: Descubrimiento
    with ThreadPoolExecutor(max_workers=hilos) as ex:
        futuros = {ex.submit(ping, ip, timeout_ms): ip for ip in ips}
        for n, fut in enumerate(as_completed(futuros), 1):
            lat = fut.result()
            if lat is not None:
                vivos.append(Equipo(ip=futuros[fut], latencia_ms=lat))
            if callback and (n % 25 == 0 or n == total):
                callback(n, total, len(vivos))

    if not vivos:
        return vivos

    # Fase 2: Detalle (puertos + DNS)
    timeout_s = max(0.3, timeout_ms / 1000 / 2)

    def detallar(eq: Equipo) -> Equipo:
        eq.nombre = nombre_dns(eq.ip)
        eq.puertos = [p for p in puertos if puerto_abierto(eq.ip, p, timeout_s)]
        return eq

    with ThreadPoolExecutor(max_workers=min(hilos, 32)) as ex:
        list(ex.map(detallar, vivos))

    # Fase 3: Enriquecimiento ARP
    arp = tabla_arp()
    for eq in vivos:
        eq.mac = arp.get(eq.ip, "")
        eq.fabricante = fabricante_por_mac(eq.mac)

    vivos.sort(key=lambda e: ipaddress.IPv4Address(e.ip))
    return vivos
