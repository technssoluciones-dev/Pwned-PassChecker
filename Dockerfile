# ── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# ── Final stage ───────────────────────────────────────────────────────────────
FROM python:3.12-slim

# Usuario no-root por seguridad
RUN useradd --create-home --shell /bin/bash appuser
WORKDIR /home/appuser/app

# Copiar dependencias instaladas
COPY --from=builder /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=builder /usr/local/bin            /usr/local/bin

# Copiar código fuente
COPY src/     src/
COPY pyproject.toml .
COPY README.md .
COPY LICENSE  .
COPY sample_passwords.txt .

# Instalar paquete en modo editable (o usar pip install .)
RUN pip install --no-cache-dir -e .

# Directorio para reportes
RUN mkdir -p reports && chown appuser:appuser reports

USER appuser

# Variables de entorno por defecto
ENV PYTHONUNBUFFERED=1 \
    LOG_LEVEL=WARNING \
    REPORTS_DIR=/home/appuser/app/reports

ENTRYPOINT ["pwned-checker"]
CMD ["--help"]
