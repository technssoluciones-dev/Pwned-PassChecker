"""
Configuración centralizada via variables de entorno / .env
"""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()  # carga .env si existe

@dataclass
class Config:
    # HIBP API
    hibp_api_url: str    = field(default_factory=lambda: os.getenv("HIBP_API_URL", "https://api.pwnedpasswords.com/range"))
    hibp_timeout: int    = field(default_factory=lambda: int(os.getenv("HIBP_TIMEOUT", "10")))
    hibp_retries: int    = field(default_factory=lambda: int(os.getenv("HIBP_RETRIES", "3")))
    hibp_user_agent: str = field(default_factory=lambda: os.getenv("HIBP_USER_AGENT", "pwned-checker/2.0 (github.com/technssoluciones-dev/Pwned-PassChecker)"))

    # Logging
    log_level: str  = field(default_factory=lambda: os.getenv("LOG_LEVEL", "WARNING"))
    log_file: str   = field(default_factory=lambda: os.getenv("LOG_FILE", ""))

    # Generador
    default_length: int = field(default_factory=lambda: int(os.getenv("DEFAULT_PWD_LENGTH", "14")))

    # Reportes
    reports_dir: str = field(default_factory=lambda: os.getenv("REPORTS_DIR", "reports"))


config = Config()
