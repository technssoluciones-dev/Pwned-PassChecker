"""
Módulo de verificación HIBP con k-Anonymity, retry y rate-limit handling.
"""
from __future__ import annotations

import hashlib
import time
from enum import Enum

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import config
from .logger import logger


# ── Tipos de resultado ─────────────────────────────────────────────────────
class CheckStatus(str, Enum):
    SAFE       = "safe"
    VULNERABLE = "vulnerable"
    ERROR      = "error"


class CheckResult:
    __slots__ = ("password", "breach_count", "status", "masked")

    def __init__(self, password: str, breach_count: int, status: CheckStatus) -> None:
        self.password     = password
        self.breach_count = breach_count
        self.status       = status
        self.masked = password[:2] + "*" * (len(password) - 2) if len(password) > 2 else "**"

    def to_dict(self) -> dict:
        return {
            "password_masked": self.masked,
            "breach_count":    self.breach_count,
            "status":          self.status.value,
        }

    def to_dict_with_password(self) -> dict:
        d = self.to_dict()
        d["password"] = self.password
        return d


def _build_session() -> requests.Session:
    session = requests.Session()
    retry   = Retry(
        total            = config.hibp_retries,
        backoff_factor   = 1.0,
        status_forcelist = [429, 500, 502, 503, 504],
        allowed_methods  = ["GET"],
        raise_on_status  = False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent":  config.hibp_user_agent,
        "Add-Padding": "true",
    })
    return session


_SESSION: requests.Session | None = None


def _get_session() -> requests.Session:
    global _SESSION
    if _SESSION is None:
        _SESSION = _build_session()
    return _SESSION


def hash_password(password: str) -> str:
    """Retorna hash SHA-1 en mayúsculas."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def check_breach(password: str) -> CheckResult:
    """
    Verifica si la contraseña aparece en filtraciones conocidas via HIBP.
    Implementa k-Anonymity: solo se envian los primeros 5 caracteres del hash.

    Returns:
        CheckResult con status SAFE, VULNERABLE o ERROR.
    """
    # FIX: tratar passwords vacias o de solo espacios como ERROR
    if not password or not password.strip():
        logger.warning("Se intento verificar una contrasena vacia o de solo espacios.")
        return CheckResult(password, 0, CheckStatus.ERROR)

    sha1   = hash_password(password)
    prefix = sha1[:5]
    suffix = sha1[5:]
    url    = f"{config.hibp_api_url}/{prefix}"

    logger.debug("Consultando HIBP para prefijo %s (password enmascarada)", prefix)

    try:
        resp = _get_session().get(url, timeout=config.hibp_timeout)

        if resp.status_code == 429:
            wait = int(resp.headers.get("Retry-After", 5))
            logger.warning("Rate limit HIBP. Esperando %ds.", wait)
            time.sleep(wait)
            resp = _get_session().get(url, timeout=config.hibp_timeout)

        resp.raise_for_status()

        for line in resp.text.splitlines():
            parts = line.split(":")
            if len(parts) != 2:
                continue
            line_suffix, count_str = parts
            if line_suffix.strip() == suffix:
                count = int(count_str.strip())
                logger.info("Contrasena encontrada en %d filtraciones.", count)
                return CheckResult(password, count, CheckStatus.VULNERABLE)

        logger.info("Contrasena no encontrada en filtraciones.")
        return CheckResult(password, 0, CheckStatus.SAFE)

    except requests.exceptions.ConnectionError as exc:
        logger.error("Error de conexion con HIBP: %s", exc)
        return CheckResult(password, -1, CheckStatus.ERROR)
    except requests.exceptions.Timeout as exc:
        logger.error("Timeout al conectar con HIBP: %s", exc)
        return CheckResult(password, -1, CheckStatus.ERROR)
    except requests.exceptions.RequestException as exc:
        logger.error("Error HTTP inesperado: %s", exc)
        return CheckResult(password, -1, CheckStatus.ERROR)


def check_passwords_from_list(passwords: list[str]) -> list[CheckResult]:
    """
    Verifica una lista de contrasenas.
    Se omiten strings vacios y de solo espacios.
    """
    return [check_breach(pwd) for pwd in passwords if pwd and pwd.strip()]
