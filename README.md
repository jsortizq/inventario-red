<p align="center">
  <h1 align="center">🛡️ Inventario de Red / Network Inventory Scanner</h1>
  <p align="center">
    Escáner de redes locales e industriales (OT) sin dependencias externas como Nmap.<br>
    <em>Local & industrial (OT) network scanner — no Nmap required.</em>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue" alt="Platform">
  <img src="https://img.shields.io/github/last-commit/jsortizq/inventario-red" alt="Last commit">
  <img src="https://img.shields.io/badge/Nmap-no%20requerido-orange" alt="No Nmap">
</p>

---

## Tabla de Contenidos

- [Características](#características)
- [Arquitectura](#arquitectura)
- [Instalación](#instalación)
- [Uso](#uso)
- [Parámetros CLI](#parámetros-cli)
- [Ejemplo de salida](#ejemplo-de-salida)
- [Uso Responsable / Ciberseguridad OT](#️-uso-responsable--ciberseguridad-ot)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Contribuir](#contribuir)
- [Licencia](#licencia)
- [English](#english)

---

## Características

- **Escaneo multihilo** — Descubrimiento masivo con pings en paralelo (configurable hasta 256 hilos).
- **Detección de puertos de oficina e industriales** — Identifica servicios como SSH, RDP, SMB, SQL Server, y protocolos OT: Siemens S7 (puerto 102), Modbus TCP (502), EtherNet/IP Allen-Bradley (44818).
- **Clasificación automática de equipos** — Heurísticas para detectar PLCs, cámaras IP (Hikvision/Dahua RTSP), impresoras, servidores, routers y equipos de red.
- **Identificación de fabricantes** — Lookup OUI (MAC → fabricante) con base de datos integrada de Siemens, Rockwell, Schneider, Hikvision, Dahua, Ubiquiti, MikroTik y más.
- **Análisis de riesgos automático** — Detecta puertos inseguros (FTP/Telnet), equipos sin DNS inverso, PLCs expuestos, y genera recomendaciones de seguridad.
- **Exportación flexible** — Excel (.xlsx con hojas de Equipos y Resumen estilizadas), CSV y JSON.
- **Sin dependencias externas** — Python puro con sockets TCP; no necesita Nmap, Masscan ni permisos de root.
- **Multiplataforma** — Windows y Linux. Adaptación automática de comandos ping y lectura ARP.

---

## Arquitectura

```
┌─────────────────────────────────────────────────────┐
│                    src/main.py                      │
│              CLI (argparse) + orquestador            │
└──────────┬──────────┬──────────┬────────────────────┘
           │          │          │
     ┌─────▼────┐ ┌───▼────┐ ┌──▼───────┐ ┌──────────┐
     │scanner.py│ │detector│ │exporter  │ │analyzer  │
     │          │ │  .py   │ │  .py     │ │  .py     │
     │ Ping     │ │ OUI    │ │ Excel    │ │ Riesgos  │
     │ TCP probe│ │ Puertos│ │ CSV      │ │ Consejos │
     │ ARP      │ │ Clasif.│ │ JSON     │ │ Métricas │
     └──────────┘ └────────┘ └──────────┘ └──────────┘
```

---

## Instalación

```bash
# Clonar el repositorio
git clone https://github.com/jsortizq/inventario-red.git
cd inventario-red

# Crear entorno virtual (recomendado)
python -m venv venv
source venv/bin/activate    # Linux
venv\Scripts\activate       # Windows

# Instalar dependencias
pip install -r requirements.txt

# (Opcional) Instalar como paquete
pip install -e .
```

### Requisitos

- Python 3.9 o superior
- `openpyxl` (para exportación Excel)
- Sin necesidad de Nmap, libpcap ni permisos de administrador para el escaneo básico

---

## Uso

```bash
# Escaneo básico de una subred /24
python -m src.main 192.168.1.0/24

# Múltiples rangos con exportación a Excel y CSV
python -m src.main 192.168.1.0/24 10.0.0.0/28 -o inventario.xlsx --csv

# Rango específico con más hilos
python -m src.main 192.168.1.10-192.168.1.60 --hilos 128

# Red industrial con timeout alto y exportación JSON
python -m src.main 10.10.5.0/24 --timeout 2000 --hilos 16 --json

# Si se instaló como paquete
inventario-red 192.168.1.0/24
```

---

## Parámetros CLI

| Parámetro | Corto | Tipo | Por defecto | Descripción |
|-----------|-------|------|-------------|-------------|
| `rangos` | — | posicional | *requerido* | CIDR (`192.168.1.0/24`), rango (`10.0.0.1-10.0.0.50`) o IP suelta |
| `--salida` | `-o` | `str` | `inventario_YYYYMMDD_HHMM.xlsx` | Archivo Excel de salida |
| `--csv` | — | flag | `false` | Exportar también en CSV (delimitador `;`) |
| `--json` | — | flag | `false` | Exportar también en JSON |
| `--hilos` | — | `int` | `64` | Hilos simultáneos para ping. ⚠️ Reducir a 8-16 en redes OT |
| `--timeout` | — | `int` | `800` | Timeout de respuesta en milisegundos |
| `--puertos` | — | `str` | lista interna | Puertos a escanear, separados por comas (ej: `22,80,443,502`) |
| `--sin-analisis` | — | flag | `false` | Omitir el análisis de riesgos y recomendaciones |

### Puertos escaneados por defecto

| Puerto | Servicio | Contexto |
|--------|----------|----------|
| 21 | FTP | ⚠️ Texto claro — riesgo |
| 22 | SSH | Acceso seguro |
| 23 | Telnet | ⚠️ Texto claro — riesgo |
| 80 / 443 | HTTP / HTTPS | Interfaz web |
| 102 | Siemens S7 (ISO-TSAP) | 🏭 Industrial |
| 135 / 139 / 445 | RPC / NetBIOS / SMB | Windows |
| 502 | Modbus TCP | 🏭 Industrial |
| 554 | RTSP | 📹 Cámaras |
| 1433 / 3306 | SQL Server / MySQL | Base de datos |
| 3389 | RDP | Escritorio remoto |
| 8000 | Hikvision HTTP | 📹 Cámaras |
| 9100 | RAW Printing | 🖨️ Impresoras |
| 37777 | Dahua | 📹 Cámaras |
| 44818 | EtherNet/IP | 🏭 Allen-Bradley |

---

## Ejemplo de salida

```
$ python -m src.main 192.168.1.0/24

Buscando equipos en 254 direcciones...
  254/254 revisadas, 12 encendidas
Revisando puertos y nombres de 12 equipos...

IP              Nombre                      Tipo probable               Puertos
192.168.1.1     router-gateway              Red (router / AP / switch)  80,443
192.168.1.10    srv-sql-01                  Servidor de base de datos   135,445,1433,3389
192.168.1.15    -                           PC Windows                  135,445
192.168.1.20    impresora-recepcion         Impresora                   80,9100
192.168.1.50    plc-linea1-siemens          PLC / equipo industrial     80,102
192.168.1.51    plc-embalaje                PLC / equipo industrial     502
192.168.1.100   camara-patio                Cámara / NVR                80,554,8000
192.168.1.101   nvr-bodega                  Cámara / NVR                80,37777

─── Análisis de riesgos ───
Estado: Precaución 🟡
⚠️  2 equipos con puertos Telnet (23) o FTP (21) abiertos
🔍  33.3% de equipos sin resolución DNS inversa
🏭  2 PLCs detectados — verificar segmentación VLAN

Excel: inventario_20261111_1530.xlsx
CSV:   inventario_20261111_1530.csv
12 equipos en 8.3 s
```

---

## ⚠️ Uso Responsable / Ciberseguridad OT

> **Esta herramienta es para uso autorizado exclusivamente.** Escanear redes sin permiso del propietario puede violar leyes locales e internacionales.

### Precauciones para redes industriales (OT/ICS/SCADA)

| Riesgo | Mitigación |
|--------|------------|
| Los PLCs industriales pueden fallar ante escaneos agresivos | Reducir hilos a `--hilos 8` y aumentar timeout a `--timeout 3000` |
| Protocolos como Modbus TCP y S7 no tienen autenticación | No conectar jamás una red OT a Internet sin firewall industrial |
| Un escaneo de puertos puede interrumpir procesos de producción | Coordinar con el ingeniero de planta y realizar fuera de horas productivas |
| Las cámaras y NVRs pueden rebootearse bajo carga de red | Escanear sistemas de CCTV en horarios de bajo tráfico |

### Mejores prácticas

1. **Obtener autorización por escrito** antes de escanear cualquier red.
2. **Documentar** la fecha, hora, rangos escaneados y responsable del escaneo.
3. **Nunca escanear** redes de producción industrial sin la supervisión del responsable OT.
4. **Usar los resultados** para mejorar la postura de seguridad, no para explotación.
5. **Cumplir** con las regulaciones locales de ciberseguridad y protección de datos.

---

## Estructura del proyecto

```
inventario-red/
├── src/
│   ├── __init__.py           # Paquete principal
│   ├── main.py               # CLI con argparse + orquestador
│   ├── scanner.py            # Ping paralelo, sondeo TCP, tabla ARP
│   ├── detector.py           # Heurísticas de clasificación + OUI lookup
│   ├── exporter.py           # Generación Excel/CSV/JSON
│   └── analyzer.py           # Análisis de riesgos y recomendaciones
├── tests/
│   ├── __init__.py
│   └── test_scanner.py       # Tests unitarios
├── .github/
│   └── workflows/
│       └── python-lint.yml   # CI: lint + type check + tests
├── requirements.txt          # Dependencias de producción
├── requirements-dev.txt      # Dependencias de desarrollo
├── setup.py                  # Instalación como paquete
├── CONTRIBUTING.md           # Guía de contribución
├── LICENSE                   # MIT
└── README.md
```

---

## Contribuir

¡Las contribuciones son bienvenidas! Consulta [CONTRIBUTING.md](CONTRIBUTING.md) para la guía completa.

Áreas donde se necesita ayuda:
- Ampliar la base de datos OUI de fabricantes
- Agregar detección de más protocolos industriales (BACnet, PROFINET, DNP3)
- Dashboard interactivo con Streamlit
- Soporte para IPv6
- Integración con bases de datos de vulnerabilidades (CVE)

---

## Licencia

Este proyecto está bajo la [Licencia MIT](LICENSE).

---

<a name="english"></a>

# 🇬🇧 English

## Network Inventory Scanner

A pure-Python CLI tool for scanning local and industrial (OT) networks to inventory all active devices — without requiring Nmap, root privileges, or external dependencies.

### Features

- **Multi-threaded scanning** — Parallel ping discovery with configurable thread count (up to 256).
- **Office & industrial port detection** — Identifies services like SSH, RDP, SMB, SQL Server, plus OT protocols: Siemens S7 (port 102), Modbus TCP (502), EtherNet/IP Allen-Bradley (44818).
- **Automatic device classification** — Heuristics to detect PLCs, IP cameras (Hikvision/Dahua RTSP), printers, servers, routers and network equipment.
- **Manufacturer identification** — OUI lookup (MAC → manufacturer) with built-in database covering Siemens, Rockwell, Schneider, Hikvision, Dahua, Ubiquiti, MikroTik and more.
- **Automated risk analysis** — Detects insecure ports (FTP/Telnet), devices without reverse DNS, exposed PLCs, and generates security recommendations.
- **Flexible export** — Excel (.xlsx with styled Equipment and Summary sheets), CSV and JSON.
- **No external dependencies** — Pure Python with TCP sockets; no Nmap, Masscan or root permissions needed.
- **Cross-platform** — Windows and Linux. Auto-adapts ping commands and ARP table reading.

### Installation

```bash
git clone https://github.com/jsortizq/inventario-red.git
cd inventario-red
python -m venv venv
source venv/bin/activate    # Linux
pip install -r requirements.txt
```

### Usage

```bash
# Basic /24 subnet scan
python -m src.main 192.168.1.0/24

# Multiple ranges with Excel + CSV export
python -m src.main 192.168.1.0/24 10.0.0.0/28 -o inventory.xlsx --csv

# Industrial network with higher timeout
python -m src.main 10.10.5.0/24 --timeout 2000 --hilos 16 --json
```

### CLI Parameters

| Parameter | Short | Type | Default | Description |
|-----------|-------|------|---------|-------------|
| `rangos` | — | positional | *required* | CIDR (`192.168.1.0/24`), range (`10.0.0.1-10.0.0.50`) or single IP |
| `--salida` | `-o` | `str` | `inventario_YYYYMMDD_HHMM.xlsx` | Output Excel file |
| `--csv` | — | flag | `false` | Also export as CSV (`;` delimiter) |
| `--json` | — | flag | `false` | Also export as JSON |
| `--hilos` | — | `int` | `64` | Concurrent ping threads. ⚠️ Reduce to 8-16 for OT networks |
| `--timeout` | — | `int` | `800` | Response timeout in milliseconds |
| `--puertos` | — | `str` | built-in list | Comma-separated ports to scan (e.g. `22,80,443,502`) |
| `--sin-analisis` | — | flag | `false` | Skip risk analysis and recommendations |

### ⚠️ Responsible Use / OT Cybersecurity

> **This tool is for authorized use only.** Scanning networks without owner permission may violate local and international laws.

**Industrial network precautions:**
- Industrial PLCs may crash under aggressive scanning — use `--hilos 8 --timeout 3000`.
- Protocols like Modbus TCP and S7 lack authentication — never expose OT networks to the internet.
- Port scanning can disrupt production processes — coordinate with the plant engineer and scan outside production hours.
- Always obtain **written authorization** before scanning any network.

### License

[MIT License](LICENSE) — Juan Sebastian Ortiz Quintero, 2026.
