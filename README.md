# 🔐 Pwned-PassChecker

![CI](https://github.com/technssoluciones-dev/Pwned-PassChecker/actions/workflows/ci.yml/badge.svg)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![HIBP](https://img.shields.io/badge/API-Have%20I%20Been%20Pwned-orange)](https://haveibeenpwned.com/API/v3)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](Dockerfile)

Verificador de contraseñas comprometidas contra la base de datos de **Have I Been Pwned (HIBP)**, usando el protocolo **k-Anonymity** — la contraseña completa nunca sale de tu máquina, solo se envían los primeros 5 caracteres de su hash SHA-1. Disponible como CLI y como servicio web con interfaz propia.

---

## 🌐 Demo en vivo

**[pwned-passchecker.onrender.com](https://pwned-passchecker.onrender.com)**

Interfaz web con verificador de contraseñas (visualización del hash k-Anonymity en tiempo real) y generador seguro — construida sobre el mismo motor de este repo, sin duplicar lógica.

> ⚠️ Corre en el plan free de Render: si nadie lo visita en 15 minutos el servidor "duerme", y la primera carga puede tardar 30-50 segundos en despertar. Las siguientes cargas son instantáneas.

---

## 🎬 Demo del CLI

![Demo](assets/demo.gif)

---

## ✨ Características

| Feature | Descripción |
|---|---|
| 🔒 k-Anonymity | Solo se envían los primeros 5 chars del hash SHA-1 — la contraseña real nunca viaja por red |
| 🔄 Retry automático | Reintentos con backoff ante errores de red o rate-limit de la API |
| 📂 Verificación masiva | Procesa listas completas de contraseñas desde archivo |
| 📄 Reportes | Exporta resultados en JSON o CSV |
| 🎲 Generador seguro | Usa el módulo `secrets` (criptográficamente seguro, no `random`) |
| 🌐 Web + CLI | Mismo motor expuesto como interfaz de línea de comandos y como API/UI web |
| 🐳 Docker ready | Imágenes separadas para CLI y para el servicio web |
| ✅ Tests incluidos | Suite con pytest + mocks, corriendo en CI |

---

## 📋 Requisitos

- Python **3.10+**
- pip

---

## 🚀 Instalación

```bash
git clone https://github.com/technssoluciones-dev/Pwned-PassChecker.git
cd Pwned-PassChecker

pip install -r requirements.txt
pip install -e .
```

> **Windows:** si el comando `pwned-checker` no se reconoce tras instalar, es porque la carpeta `Scripts` de Python no está en tu PATH. Usa `python -m pwned_checker check -i` como alternativa, o agrega esa carpeta al PATH (la ruta aparece en el aviso de `pip install`) y reabre la terminal.

---

## 📖 Uso del CLI

### Verificar contraseña (modo interactivo)

```bash
pwned-checker check -i
# → Solicita la contraseña sin mostrarla en pantalla
```

### Verificar lista de contraseñas

```bash
pwned-checker check -f sample_passwords.txt
pwned-checker check -f mis_claves.txt -o reports/resultado.json
pwned-checker check -f mis_claves.txt -o reports/resultado.csv
```

### Generar contraseñas seguras

```bash
pwned-checker generate                              # 1 contraseña de 14 chars (default)
pwned-checker generate -n 5 -l 20                    # 5 contraseñas de 20 chars
pwned-checker generate -n 3 --no-symbols --no-ambiguous
```

### Scripts heredados (compatibilidad)

```bash
python pwned_checker.py -i
python pwned_checker.py -f sample_passwords.txt -o reporte.json
python password_generator.py -l 18 -n 3
```

---

## 🐳 Docker

### CLI

```bash
docker build -t pwned-checker .

docker run --rm -it pwned-checker check -i

docker run --rm -it \
  -v $(pwd)/reports:/home/appuser/app/reports \
  -v $(pwd)/sample_passwords.txt:/home/appuser/app/sample_passwords.txt:ro \
  pwned-checker check -f sample_passwords.txt -o reports/result.json
```

### Servicio web

```bash
docker build -f Dockerfile.web -t pwned-passchecker-web .
docker run -p 8000:8000 pwned-passchecker-web
# → http://localhost:8000
```

---

## 🧪 Testing

```bash
pytest tests/ -v
pytest tests/ --cov=src/pwned_checker --cov-report=term-missing

make test
make test-cov
```

---

## ⚙️ Configuración

```bash
cp .env.example .env
```

| Variable | Default | Descripción |
|---|---|---|
| `HIBP_TIMEOUT` | `10` | Timeout HTTP en segundos |
| `HIBP_RETRIES` | `3` | Reintentos ante error |
| `LOG_LEVEL` | `WARNING` | Nivel de log (`DEBUG`/`INFO`/`WARNING`) |
| `LOG_FILE` | `` | Archivo de log (vacío = solo consola) |
| `DEFAULT_PWD_LENGTH` | `14` | Longitud default del generador |
| `REPORTS_DIR` | `reports` | Directorio para reportes |

---

## 🏗️ Arquitectura

```
src/pwned_checker/
├── __init__.py     ← versión y metadatos
├── config.py       ← configuración centralizada (.env)
├── logger.py       ← logging estructurado
├── checker.py      ← lógica HIBP con retry y k-Anonymity
├── generator.py    ← generador criptográfico
└── cli.py          ← interfaz CLI unificada (entry point)

web/
├── main.py         ← wrapper FastAPI (reutiliza checker.py y generator.py sin modificarlos)
└── static/
    └── index.html  ← UI del verificador y generador
```

El servicio web **no reimplementa la lógica de negocio**: importa directamente `checker.py` y `generator.py` del paquete CLI, exponiéndolos vía HTTP. Esto evita duplicación y garantiza que ambas interfaces (CLI y web) se comporten de forma idéntica.

---

## 🔒 Privacidad y Seguridad

- La contraseña **nunca** sale de tu máquina completa — el protocolo k-Anonymity de HIBP solo requiere los primeros 5 caracteres del hash SHA-1
- Los reportes enmascaran contraseñas por defecto (`mi***...`)
- Usa `--expose-passwords` solo en entornos privados y seguros
- El generador usa `secrets` del módulo estándar (CSPRNG), no `random`

---

## 📄 Licencia

MIT © 2026 [technssoluciones-dev](https://github.com/technssoluciones-dev)
