"""
Generador de contraseñas criptográficamente seguro usando `secrets`.
"""
from __future__ import annotations

import secrets
import string
from dataclasses import dataclass

from .config import config
from .logger import logger


@dataclass
class GeneratorOptions:
    length:      int  = 0        # 0 = usar config.default_length
    use_digits:  bool = True
    use_symbols: bool = True
    use_upper:   bool = True
    use_lower:   bool = True
    exclude_ambiguous: bool = False   # excluir 0,O,l,1,I,|

    def __post_init__(self) -> None:
        if self.length == 0:
            self.length = config.default_length
        if self.length < 8:
            logger.warning("Longitud %d < 8, usando 8.", self.length)
            self.length = 8


AMBIGUOUS = set("0Ol1I|`")


def _build_alphabet(opts: GeneratorOptions) -> str:
    parts: list[str] = []
    if opts.use_upper:
        parts.append(string.ascii_uppercase)
    if opts.use_lower:
        parts.append(string.ascii_lowercase)
    if opts.use_digits:
        parts.append(string.digits)
    if opts.use_symbols:
        parts.append(string.punctuation)

    alphabet = "".join(parts)
    if not alphabet:
        raise ValueError("El alfabeto no puede estar vacío. Activa al menos un conjunto de caracteres.")

    if opts.exclude_ambiguous:
        alphabet = "".join(c for c in alphabet if c not in AMBIGUOUS)

    return alphabet


def _satisfies(password: str, opts: GeneratorOptions) -> bool:
    """Verifica que la contraseña cumple todos los requisitos de composición."""
    if opts.use_upper and not any(c.isupper() for c in password):
        return False
    if opts.use_lower and not any(c.islower() for c in password):
        return False
    if opts.use_digits and not any(c.isdigit() for c in password):
        return False
    return not (opts.use_symbols and not any(c in string.punctuation for c in password))


def generate_password(opts: GeneratorOptions | None = None) -> str:
    """
    Genera una contraseña aleatoria criptográficamente segura.

    Args:
        opts: Opciones de generación. Si None, usa valores por defecto.

    Returns:
        Contraseña generada como string.
    """
    if opts is None:
        opts = GeneratorOptions()

    alphabet = _build_alphabet(opts)

    # Límite de intentos para evitar bucle infinito en configuraciones extremas
    max_attempts = 10_000
    for attempt in range(max_attempts):
        password = "".join(secrets.choice(alphabet) for _ in range(opts.length))
        if _satisfies(password, opts):
            logger.debug("Contraseña generada en %d intento(s).", attempt + 1)
            return password

    raise RuntimeError(
        f"No se pudo generar contraseña válida en {max_attempts} intentos. "
        "Verifica que la longitud y los conjuntos de caracteres sean compatibles."
    )


def generate_multiple(count: int, opts: GeneratorOptions | None = None) -> list[str]:
    """Genera `count` contraseñas con las mismas opciones."""
    return [generate_password(opts) for _ in range(count)]
