"""Tests unitarios para los módulos del escáner de red."""
import pytest

from src.scanner import expandir_rangos, fabricante_por_mac, Equipo
from src.detector import clasificar_equipo
from src.constants import FABRICANTES


# ───────────────────────────── expandir_rangos ─────────────────────────────


class TestExpandirRangos:
    """Pruebas de expansión de rangos de IP."""

    def test_cidr_24(self):
        """Un /24 debe producir 254 hosts (sin red ni broadcast)."""
        ips = expandir_rangos(["192.168.1.0/24"])
        assert len(ips) == 254
        assert "192.168.1.1" in ips
        assert "192.168.1.254" in ips
        assert "192.168.1.0" not in ips    # dirección de red
        assert "192.168.1.255" not in ips  # broadcast

    def test_cidr_28(self):
        """Un /28 debe producir 14 hosts."""
        ips = expandir_rangos(["10.0.0.0/28"])
        assert len(ips) == 14

    def test_rango_inicio_fin(self):
        """Un rango con guión genera IPs consecutivas."""
        ips = expandir_rangos(["192.168.1.10-192.168.1.15"])
        assert len(ips) == 6
        assert ips[0] == "192.168.1.10"
        assert ips[-1] == "192.168.1.15"

    def test_rango_invertido(self):
        """Si el inicio es mayor al fin, se invierte automáticamente."""
        ips = expandir_rangos(["192.168.1.15-192.168.1.10"])
        assert len(ips) == 6
        assert ips[0] == "192.168.1.10"

    def test_ip_suelta(self):
        """Una IP sola devuelve una lista con un elemento."""
        ips = expandir_rangos(["10.0.0.5"])
        assert ips == ["10.0.0.5"]

    def test_multiples_rangos(self):
        """Varios rangos se combinan sin duplicados."""
        ips = expandir_rangos(["192.168.1.1", "192.168.1.1", "10.0.0.1"])
        assert len(ips) == 2  # sin duplicados

    def test_rango_invalido(self):
        """Un rango inválido lanza ValueError."""
        with pytest.raises(ValueError):
            expandir_rangos(["999.999.999.999"])


# ───────────────────────────── fabricante ─────────────────────────────


class TestFabricante:
    """Pruebas de lookup OUI de fabricantes."""

    def test_fabricante_conocido_siemens(self):
        """MAC con prefijo Siemens se identifica correctamente."""
        assert fabricante_por_mac("00:1C:06:AA:BB:CC") == "Siemens"

    def test_fabricante_conocido_hikvision(self):
        """MAC con prefijo Hikvision se identifica."""
        assert fabricante_por_mac("BC:AD:28:11:22:33") == "Hikvision"

    def test_fabricante_conocido_mikrotik(self):
        """MAC con prefijo MikroTik se identifica."""
        assert fabricante_por_mac("4C:5E:0C:AA:BB:CC") == "MikroTik"

    def test_fabricante_desconocido(self):
        """MAC con prefijo no registrado devuelve cadena vacía."""
        assert fabricante_por_mac("FF:FF:FF:AA:BB:CC") == ""

    def test_fabricante_mac_vacia(self):
        """MAC vacía devuelve cadena vacía sin error."""
        assert fabricante_por_mac("") == ""


# ───────────────────────────── clasificación de equipo ─────────────────────────────


class TestClasificacionEquipo:
    """Pruebas de heurísticas de clasificación por puertos y fabricante."""

    def test_tipo_plc_por_puerto_s7(self):
        """Puerto 102 (Siemens S7) clasifica como PLC."""
        eq = Equipo(ip="10.0.0.1", puertos=[80, 102])
        tipo = clasificar_equipo(eq)
        assert "PLC" in tipo or "industrial" in tipo.lower() or "Siemens" in tipo

    def test_tipo_plc_por_puerto_modbus(self):
        """Puerto 502 (Modbus TCP) clasifica como PLC."""
        eq = Equipo(ip="10.0.0.2", puertos=[502])
        tipo = clasificar_equipo(eq)
        assert "PLC" in tipo or "industrial" in tipo.lower() or "Modbus" in tipo

    def test_tipo_plc_por_fabricante(self):
        """Fabricante Rockwell clasifica como PLC."""
        eq = Equipo(ip="10.0.0.3", fabricante="Rockwell Automation", puertos=[80])
        tipo = clasificar_equipo(eq)
        assert "PLC" in tipo or "industrial" in tipo.lower() or "Allen" in tipo

    def test_tipo_camara_rtsp(self):
        """Puerto 554 (RTSP) clasifica como cámara."""
        eq = Equipo(ip="10.0.0.4", puertos=[80, 554, 8000])
        tipo = clasificar_equipo(eq)
        assert "mara" in tipo or "NVR" in tipo

    def test_tipo_camara_dahua(self):
        """Puerto 37777 (Dahua) clasifica como cámara."""
        eq = Equipo(ip="10.0.0.5", puertos=[80, 37777])
        tipo = clasificar_equipo(eq)
        assert "mara" in tipo or "NVR" in tipo or "Dahua" in tipo

    def test_tipo_impresora(self):
        """Puerto 9100 (RAW) clasifica como impresora."""
        eq = Equipo(ip="10.0.0.6", puertos=[80, 9100])
        tipo = clasificar_equipo(eq)
        assert "mpresora" in tipo or "Printer" in tipo

    def test_tipo_servidor_db(self):
        """Puerto 1433 (SQL Server) clasifica como servidor de BD."""
        eq = Equipo(ip="10.0.0.7", puertos=[135, 445, 1433])
        tipo = clasificar_equipo(eq)
        assert "base de datos" in tipo.lower() or "servidor" in tipo.lower() or "SQL" in tipo

    def test_tipo_pc_windows(self):
        """Puertos 135+445 sin RDP clasifica como PC Windows."""
        eq = Equipo(ip="10.0.0.8", puertos=[135, 445])
        tipo = clasificar_equipo(eq)
        assert "Windows" in tipo

    def test_tipo_linux(self):
        """Puerto 22 sin SMB clasifica como Linux."""
        eq = Equipo(ip="10.0.0.9", puertos=[22])
        tipo = clasificar_equipo(eq)
        assert "Linux" in tipo or "red" in tipo

    def test_tipo_desconocido(self):
        """Sin puertos reveladores clasifica como desconocido."""
        eq = Equipo(ip="10.0.0.10", puertos=[])
        tipo = clasificar_equipo(eq)
        assert tipo == "Desconocido"
