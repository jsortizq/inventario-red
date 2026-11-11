"""
constants.py — Constantes compartidas del escáner de red
========================================================

Mapas de puertos conocidos y prefijos OUI de fabricantes para
la identificación de equipos en redes de oficina e industriales.
"""
from __future__ import annotations

__all__ = ["PUERTOS", "FABRICANTES", "PUERTOS_INSEGUROS", "PUERTOS_INDUSTRIALES"]

# ---------------------------------------------------------------- puertos
# Puertos TCP que revelan el tipo de equipo en una red de oficina o planta.
# Clave: número de puerto → valor: etiqueta legible.

PUERTOS: dict[int, str] = {
    # Servicios generales
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    135:   "RPC",
    139:   "NetBIOS",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    993:   "IMAPS",
    995:   "POP3S",
    # Bases de datos
    1433:  "SQL Server",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    6379:  "Redis",
    27017: "MongoDB",
    # Administración remota
    3389:  "Escritorio remoto (RDP)",
    5900:  "VNC",
    8080:  "HTTP alterno",
    8443:  "HTTPS alterno",
    # Impresoras
    9100:  "Impresora (RAW/JetDirect)",
    515:   "LPD (impresora)",
    631:   "IPP (CUPS)",
    # Cámaras y videovigilancia
    554:   "RTSP (cámara)",
    8000:  "Hikvision HTTP",
    37777: "Dahua",
    34567: "XMEye / genérica",
    # Protocolos industriales (OT)
    102:   "Siemens S7 (ISO-TSAP)",
    502:   "Modbus TCP",
    44818: "EtherNet/IP (Allen-Bradley)",
    2222:  "EtherNet/IP (implícito)",
    4840:  "OPC UA",
    20000: "DNP3",
    47808: "BACnet",
    # Virtualización / contenedores
    2375:  "Docker API",
    8006:  "Proxmox",
    # Monitoreo
    161:   "SNMP",
    10050: "Zabbix Agent",
}

# Subconjuntos útiles para análisis de riesgo
PUERTOS_INSEGUROS: set[int] = {21, 23, 25, 110, 143}
PUERTOS_INDUSTRIALES: set[int] = {102, 502, 44818, 2222, 4840, 20000, 47808}

# ---------------------------------------------------------------- fabricantes
# Prefijos OUI (primeros 3 octetos de la MAC) → fabricante.
# Lista curada para cubrir lo más frecuente en PYMEs y entornos industriales.

FABRICANTES: dict[str, str] = {
    # --- Intel / genérico PC ---
    "00:1B:21": "Intel",
    "3C:97:0E": "Intel",
    "A4:BF:01": "Intel",
    "68:05:CA": "Intel",
    # --- HP / HPE ---
    "3C:52:82": "HP",
    "00:1E:0B": "HP (impresora)",
    "B4:B5:2F": "HP Enterprise",
    "94:57:A5": "HP Enterprise",
    "D4:C9:EF": "HP Enterprise",
    # --- Dell ---
    "D4:BE:D9": "Dell",
    "F8:BC:12": "Dell",
    "00:14:22": "Dell",
    "18:66:DA": "Dell",
    "F0:1F:AF": "Dell",
    # --- Lenovo ---
    "E8:6A:64": "Lenovo",
    "50:7B:9D": "Lenovo",
    "98:FA:9B": "Lenovo",
    "00:06:1B": "Lenovo (servidor)",
    # --- Apple ---
    "3C:22:FB": "Apple",
    "A8:5C:2C": "Apple",
    "F0:18:98": "Apple",
    "AC:DE:48": "Apple",
    "14:7D:DA": "Apple",
    # --- Samsung ---
    "00:21:19": "Samsung",
    "E4:7C:F9": "Samsung",
    "BC:72:B1": "Samsung",
    # --- Cisco ---
    "00:1A:A1": "Cisco",
    "00:1E:F7": "Cisco",
    "00:26:0B": "Cisco",
    "58:97:1E": "Cisco",
    "F4:CF:E2": "Cisco",
    "00:1B:D5": "Cisco (Meraki)",
    "0C:8D:DB": "Cisco (Meraki)",
    # --- Juniper ---
    "00:05:85": "Juniper",
    "88:E0:F3": "Juniper",
    # --- Fortinet ---
    "00:09:0F": "Fortinet",
    "70:4C:A5": "Fortinet",
    "90:6C:AC": "Fortinet",
    # --- Palo Alto ---
    "00:1B:17": "Palo Alto Networks",
    "08:66:1F": "Palo Alto Networks",
    # --- Ubiquiti ---
    "24:5A:4C": "Ubiquiti",
    "FC:EC:DA": "Ubiquiti",
    "B4:FB:E4": "Ubiquiti",
    "78:8A:20": "Ubiquiti",
    # --- MikroTik ---
    "4C:5E:0C": "MikroTik",
    "00:0C:42": "MikroTik",
    "D4:CA:6D": "MikroTik",
    "6C:3B:6B": "MikroTik",
    # --- TP-Link ---
    "F4:F2:6D": "TP-Link",
    "50:C7:BF": "TP-Link",
    "EC:08:6B": "TP-Link",
    "30:DE:4B": "TP-Link",
    # --- Huawei ---
    "00:E0:FC": "Huawei",
    "48:46:FB": "Huawei",
    "AC:CF:85": "Huawei",
    "88:28:B3": "Huawei",
    # --- ZTE ---
    "00:19:CB": "ZTE",
    "54:22:F8": "ZTE",
    "C8:64:C7": "ZTE",
    # --- Aruba / HP Aruba ---
    "00:0B:86": "Aruba Networks",
    "24:DE:C6": "Aruba Networks",
    "D8:C7:C8": "Aruba Networks",
    # --- Impresoras ---
    "00:26:AB": "Epson",
    "00:00:48": "Epson",
    "00:80:77": "Brother",
    "00:00:74": "Ricoh",
    "00:00:AA": "Xerox",
    "00:15:99": "Samsung (impresora)",
    # --- Cámaras / Videovigilancia ---
    "BC:AD:28": "Hikvision",
    "44:19:B6": "Hikvision",
    "C0:56:E3": "Hikvision",
    "3C:EF:8C": "Dahua",
    "E0:50:8B": "Dahua",
    "A0:BD:1D": "Dahua",
    "00:0E:A6": "Axis (cámara)",
    "AC:CC:8E": "Axis (cámara)",
    # --- Industrial / OT ---
    "00:1C:06": "Siemens",
    "00:0E:8C": "Siemens",
    "00:1F:F8": "Siemens",
    "00:00:BC": "Rockwell Automation",
    "00:80:F4": "Schneider Electric",
    "00:60:35": "ABB",
    "00:80:2D": "Yokogawa",
    "00:C0:AA": "Emerson / Fisher-Rosemount",
    "00:A0:45": "Phoenix Contact",
    "00:30:11": "HMS Industrial Networks",
    # --- Virtualización ---
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "08:00:27": "VirtualBox",
    "00:15:5D": "Hyper-V",
    "52:54:00": "QEMU/KVM",
    # --- Raspberry Pi ---
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    # --- Otros ---
    "70:85:C2": "ASRock",
    "00:1A:3F": "Arista",
    "50:6B:4B": "Ruckus Wireless",
}
