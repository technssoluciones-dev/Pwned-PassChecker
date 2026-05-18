# Changelog

Todos los cambios notables de este proyecto se documentan en este archivo.
Formato basado en [Keep a Changelog](https://keepachangelog.com/es/1.0.0/).
Este proyecto sigue [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] — 2026-05-18

### Agregado
- Arquitectura modular bajo `src/pwned_checker/` (config, logger, checker, generator, cli)
- CLI unificado con subcomandos `check` y `generate` vía `pwned-checker`
- Verificación por lotes desde archivo con soporte de comentarios (`#`)
- Reportes exportables en JSON y CSV con flag `--expose-passwords`
- Generador criptográficamente seguro usando `secrets` con opciones avanzadas (`--no-ambiguous`, `--no-upper`, etc.)
- Retry automático con backoff exponencial ante rate-limit (HTTP 429) y errores de red
- Padding HIBP habilitado (`Add-Padding: true`) para mayor privacidad
- Docker multi-stage con usuario no-root (`appuser`)
- `docker-compose.yml` con perfil `dev` para hot-reload y tests
- Suite de tests con mocks de red (sin dependencia de conexión real en CI)
- Cobertura de tests para checker, generator y edge cases
- `actualizacion_proyecto.py` — script de inicialización y validación automática
- `pyproject.toml` con `[project.optional-dependencies]` para herramientas dev
- `Makefile` con targets: `install`, `install-dev`, `test`, `test-cov`, `lint`, `typecheck`, `format`, `clean`, `docker-build`, `docker-run`

### Cambiado
- Refactor completo desde script monolítico a arquitectura por capas
- `password_generator.py` y `pwned_checker.py` convertidos en scripts de compatibilidad
- Configuración centralizada vía `.env` con `python-dotenv`
- Logging estructurado a stderr para no contaminar stdout del CLI

### Seguridad
- k-Anonymity: solo los primeros 5 chars del hash SHA-1 se envían a HIBP
- Passwords enmascaradas por defecto en todos los reportes y salidas
- `secrets` en lugar de `random` para generación de contraseñas

---

## [1.0.0] — 2025-xx-xx

### Agregado
- Script inicial `pwned_checker.py` con verificación via HIBP
- Generador básico en `password_generator.py`
