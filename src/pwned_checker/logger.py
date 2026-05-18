"""
Logging estructurado para pwned_checker.
"""
from __future__ import annotations
import logging
import sys
from .config import config


def setup_logger(name: str = "pwned_checker") -> logging.Logger:
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger  # evitar duplicar handlers

    level = getattr(logging, config.log_level.upper(), logging.WARNING)
    logger.setLevel(level)

    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Handler consola (stderr para no contaminar stdout del CLI)
    ch = logging.StreamHandler(sys.stderr)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # Handler archivo (opcional)
    if config.log_file:
        fh = logging.FileHandler(config.log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


logger = setup_logger()
