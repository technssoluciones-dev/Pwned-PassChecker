# ─── Pwned-PassChecker — Makefile ─────────────────────────────────────────────
.DEFAULT_GOAL := help
PYTHON        := python3
PIP           := pip3
PACKAGE       := pwned-checker
SRC           := src/pwned_checker

.PHONY: help install install-dev test test-cov lint typecheck format clean docker-build docker-run

help:  ## Muestra esta ayuda
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

install:  ## Instala dependencias de producción
	$(PIP) install -r requirements.txt
	$(PIP) install -e .

install-dev:  ## Instala dependencias de desarrollo
	$(PIP) install -r requirements-dev.txt
	$(PIP) install -e .

test:  ## Ejecuta tests
	pytest tests/ -v

test-cov:  ## Ejecuta tests con reporte de cobertura
	pytest tests/ --cov=$(SRC) --cov-report=term-missing --cov-report=html

lint:  ## Linting con ruff
	ruff check src/ tests/

format:  ## Formateo automático con ruff
	ruff format src/ tests/

typecheck:  ## Verificación de tipos con mypy
	mypy src/

clean:  ## Limpia archivos temporales
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .coverage htmlcov dist build *.egg-info

docker-build:  ## Construye imagen Docker
	docker build -t pwned-checker:latest .

docker-run:  ## Corre el CLI dentro de Docker
	docker run --rm -it -v $(PWD)/reports:/home/appuser/app/reports pwned-checker:latest

check-interactive:  ## Verificación interactiva rápida
	pwned-checker check -i

generate:  ## Genera 5 contraseñas de ejemplo
	pwned-checker generate -n 5 -l 16

check-sample:  ## Verifica sample_passwords.txt y guarda reporte
	pwned-checker check -f sample_passwords.txt -o reports/sample_report.json
