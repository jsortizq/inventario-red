# Inventario de red

Herramienta en Python que recorre una red local y arma el inventario de equipos en Excel: IP, nombre, MAC, fabricante, puertos abiertos y **tipo de equipo probable** (PC, servidor, impresora, cámara, PLC, equipo de red).

Sirve para el levantamiento inicial cuando se recibe una red sin documentación, para auditorías y para detectar equipos nuevos o servicios inseguros expuestos.

## Qué detecta

- Equipos encendidos (ping en paralelo, rápido aun en un /24)
- Nombre por DNS inverso
- MAC y fabricante (tabla ARP del sistema)
- Puertos de oficina **y de planta**: SMB, RDP, SQL Server, impresoras, cámaras (RTSP, Hikvision, Dahua) y protocolos industriales (Siemens S7, Modbus TCP, EtherNet/IP)
- Alertas cuando hay **FTP o Telnet** abiertos

## Ejemplo de salida

```
Buscando equipos en 254 direcciones...
  254/254 revisadas, 23 encendidas
Revisando puertos y nombres de 23 equipos...

IP              Nombre                      Tipo probable               Puertos
192.168.1.1     router.local                Red (router / AP / switch)  22,80,443
192.168.1.10    SRV-ARCHIVOS                Servidor / PC Windows       135,139,445,3389
192.168.1.12    SRV-SQL                     Servidor de base de datos   135,445,1433,3389
192.168.1.40    -                           Impresora                   80,443,9100
192.168.1.64    -                           Cámara / NVR                80,554,8000
192.168.1.120   -                           PLC / equipo industrial     80,102

Excel: inventario_20261023_1530.xlsx
23 equipos en 9.4 s
```

El Excel trae dos hojas: **Equipos** (tabla con filtros) y **Resumen** (conteo por tipo y alertas).

## Instalación

```bash
pip install -r requirements.txt
```

Python 3.9 o superior. Funciona en Windows y Linux, sin instalar Nmap.

## Uso

```bash
# Una red completa
python inventario_red.py 192.168.1.0/24

# Varios rangos, con CSV además del Excel
python inventario_red.py 192.168.1.0/24 192.168.10.1-192.168.10.50 -o planta.xlsx --csv

# Solo algunos puertos y más hilos
python inventario_red.py 10.0.0.0/24 --puertos 102,502,44818 --hilos 128
```

| Opción | Por defecto | Descripción |
|---|---|---|
| `-o`, `--salida` | `inventario_<fecha>.xlsx` | Archivo de salida |
| `--csv` | no | Exporta también a CSV (separador `;`, abre directo en Excel) |
| `--hilos` | 64 | Pings simultáneos |
| `--timeout` | 800 | Espera en milisegundos |
| `--puertos` | lista interna | Puertos a revisar, separados por coma |

## Uso responsable

Escanee únicamente redes que administra o para las que tiene autorización escrita. En redes de planta, coordine con producción: algunos PLC antiguos no toleran bien muchas conexiones seguidas; en ese caso use `--hilos 8`.

---
Juan Sebastián Ortiz Quintero · Ingeniero en Mecatrónica · [Industrias Ortiz](https://jsortizq.github.io)
