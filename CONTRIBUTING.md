# Contribuir / Contributing

¡Gracias por tu interés en mejorar este proyecto! A continuación encontrarás la guía para contribuir.

*Thank you for your interest in improving this project! Below you'll find the contribution guide.*

---

## Cómo contribuir / How to contribute

### 1. Fork y clone

```bash
# Fork el repositorio desde GitHub, luego:
git clone https://github.com/TU_USUARIO/inventario-red.git
cd inventario-red
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

### 2. Crear una rama / Create a branch

Usa un nombre descriptivo con prefijo según el tipo de cambio:

```bash
git checkout -b feat/deteccion-bacnet       # Nueva funcionalidad
git checkout -b fix/timeout-windows         # Corrección de bug
git checkout -b docs/mejorar-readme         # Documentación
git checkout -b refactor/separar-arp        # Refactorización
```

### 3. Estilo de código / Code style

- **Type hints**: Todas las funciones deben tener anotaciones de tipos.
- **Docstrings**: En español, usando formato triple comillas.
- **Formato**: Seguimos PEP 8 con líneas de máximo 100 caracteres.
- **Nombres**: Variables y funciones en `snake_case` (español permitido: `equipos_vivos`, `tabla_arp`).

```python
def escanear_puerto(ip: str, puerto: int, timeout: float) -> bool:
    """Verifica si un puerto TCP está abierto en la IP indicada."""
    ...
```

### 4. Ejecutar validaciones / Run checks

Antes de hacer commit, asegúrate de que todo pase:

```bash
# Lint
flake8 src/ tests/ --max-line-length=100

# Type checking
mypy src/ --ignore-missing-imports

# Tests
pytest tests/ -v
```

### 5. Commit y Pull Request

```bash
git add .
git commit -m "feat: agregar detección de protocolo BACnet (puerto 47808)"
git push origin feat/deteccion-bacnet
```

Luego abre un **Pull Request** en GitHub con:
- Descripción clara de los cambios
- Referencia al issue si aplica (`Closes #12`)
- Screenshots o salida de consola si es relevante

---

## Áreas de contribución prioritarias

| Área | Descripción |
|------|-------------|
| **Protocolos OT** | BACnet (47808), PROFINET, DNP3, OPC UA (4840) |
| **Base OUI** | Ampliar `FABRICANTES` con más prefijos MAC de equipos industriales |
| **Dashboard** | Interfaz gráfica con Streamlit para visualización interactiva |
| **IPv6** | Soporte para escaneo de redes IPv6 |
| **Tests** | Aumentar cobertura de tests unitarios |
| **Internacionalización** | Traducción de la CLI a inglés (output bilingüe) |

---

## Código de conducta / Code of Conduct

Este proyecto se adhiere al [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Al participar, te comprometes a mantener un ambiente respetuoso y colaborativo.

### Uso ético

Este proyecto es una herramienta de **auditoría y levantamiento de inventario**. No aceptamos contribuciones que:
- Faciliten el escaneo no autorizado de redes
- Agreguen capacidades ofensivas o de explotación
- Comprometan la seguridad de sistemas industriales

---

## Preguntas / Questions

¿Tienes dudas? Abre un [issue](https://github.com/jsortizq/inventario-red/issues) o contacta al autor.

*Have questions? Open an [issue](https://github.com/jsortizq/inventario-red/issues) or reach out to the author.*
