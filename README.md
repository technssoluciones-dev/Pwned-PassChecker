# ðŸ” Pwned PassChecker v2.0

![CI](https://github.com/technssoluciones-dev/Pwned-PassChecker/actions/workflows/ci.yml/badge.svg)

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![HIBP](https://img.shields.io/badge/API-Have%20I%20Been%20Pwned-orange)](https://haveibeenpwned.com/API/v3)

Verificador de contraseÃ±as filtradas con **Have I Been Pwned (HIBP)** usando **k-Anonymity** â€” nunca se envÃ­a la contraseÃ±a completa a la API. Incluye generador criptogrÃ¡ficamente seguro.

---

## âœ¨ CaracterÃ­sticas

| Feature | DescripciÃ³n |
|---|---|
| ðŸ”’ k-Anonymity | Solo se envÃ­an los primeros 5 chars del hash SHA-1 |
| ðŸ”„ Retry automÃ¡tico | Reintentos con backoff ante errores de red o rate-limit |
| ðŸ“‚ VerificaciÃ³n masiva | Procesa listas de contraseÃ±as desde archivo |
| ðŸ“„ Reportes | Exporta resultados en JSON o CSV |
| ðŸŽ² Generador seguro | Usa `secrets` (criptogrÃ¡ficamente seguro) |
| ðŸ³ Docker ready | Imagen lista para contenedores |
| âœ… Tests incluidos | Suite con pytest + mocks |

---

## ðŸ“‹ Requisitos

- Python **3.10+**
- pip

---

## ðŸš€ InstalaciÃ³n

```bash
git clone https://github.com/technssoluciones-dev/Pwned-PassChecker.git
cd Pwned-PassChecker

# InstalaciÃ³n rÃ¡pida
python actualizacion_proyecto.py

# O manualmente:
pip install -r requirements.txt
pip install -e .
```

---

## ðŸ“– Uso

### Verificar contraseÃ±a (modo interactivo)

```bash
pwned-checker check -i
# â†’ Solicita contraseÃ±a sin mostrarla en pantalla
```

### Verificar lista de contraseÃ±as

```bash
pwned-checker check -f sample_passwords.txt
pwned-checker check -f mis_claves.txt -o reports/resultado.json
pwned-checker check -f mis_claves.txt -o reports/resultado.csv
```

### Generar contraseÃ±as seguras

```bash
# Una contraseÃ±a de 14 caracteres (default)
pwned-checker generate

# 5 contraseÃ±as de 20 caracteres
pwned-checker generate -n 5 -l 20

# Sin sÃ­mbolos, sin ambigÃ¼edades (0,O,l,1â€¦)
pwned-checker generate -n 3 --no-symbols --no-ambiguous
```

### Scripts heredados (compatibilidad)

```bash
python pwned_checker.py -i
python pwned_checker.py -f sample_passwords.txt -o reporte.json
python password_generator.py -l 18 -n 3
```

---

## ðŸ³ Docker

```bash
# Construir imagen
docker build -t pwned-checker .

# Verificar interactivamente
docker run --rm -it pwned-checker check -i

# Verificar archivo y guardar reporte en ./reports/
docker run --rm -it \
  -v $(pwd)/reports:/home/appuser/app/reports \
  -v $(pwd)/sample_passwords.txt:/home/appuser/app/sample_passwords.txt:ro \
  pwned-checker check -f sample_passwords.txt -o reports/result.json
```

---

## ðŸ§ª Testing

```bash
# Tests bÃ¡sicos
pytest tests/ -v

# Con cobertura
pytest tests/ --cov=src/pwned_checker --cov-report=term-missing

# Con Make
make test
make test-cov
```

---

## âš™ï¸ ConfiguraciÃ³n

Copia `.env.example` a `.env` y ajusta segÃºn necesites:

```bash
cp .env.example .env
```

Variables disponibles:

| Variable | Default | DescripciÃ³n |
|---|---|---|
| `HIBP_TIMEOUT` | `10` | Timeout HTTP en segundos |
| `HIBP_RETRIES` | `3` | Reintentos ante error |
| `LOG_LEVEL` | `WARNING` | Nivel de log (`DEBUG`/`INFO`/`WARNING`) |
| `LOG_FILE` | `` | Archivo de log (vacÃ­o = solo consola) |
| `DEFAULT_PWD_LENGTH` | `14` | Longitud default del generador |
| `REPORTS_DIR` | `reports` | Directorio para reportes |

---

## ðŸ—ï¸ Arquitectura

```
src/pwned_checker/
â”œâ”€â”€ __init__.py     â† versiÃ³n y metadatos
â”œâ”€â”€ config.py       â† configuraciÃ³n centralizada (.env)
â”œâ”€â”€ logger.py       â† logging estructurado
â”œâ”€â”€ checker.py      â† lÃ³gica HIBP con retry y k-Anonymity
â”œâ”€â”€ generator.py    â† generador criptogrÃ¡fico
â””â”€â”€ cli.py          â† interfaz CLI unificada (entry point)
```

---

## ðŸ”’ Privacidad y Seguridad

- La contraseÃ±a **nunca** sale de tu mÃ¡quina completa
- Solo se envÃ­an los **primeros 5 caracteres** del hash SHA-1
- Los reportes enmascaran passwords por defecto (`mi***...`)
- Usa `--expose-passwords` solo en entornos privados y seguros
- El generador usa `secrets` del mÃ³dulo estÃ¡ndar (CSPRNG)

---

## ðŸ“„ Licencia

MIT Â© 2026 [technssoluciones-dev](https://github.com/technssoluciones-dev)

