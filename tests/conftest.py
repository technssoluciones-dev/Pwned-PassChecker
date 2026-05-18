"""
conftest.py — Fixtures compartidos para toda la suite de tests.

Fixtures disponibles:
  - mock_hibp_response(text, status_code): factory para respuestas HTTP mock
  - mock_hibp_session: inyecta sesión mockeada en checker._get_session
  - vulnerable_response: respuesta mock con contraseña "password" como vulnerable
  - safe_response: respuesta mock sin coincidencias (contraseña segura)
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


# ─── Factories ────────────────────────────────────────────────────────────────

def make_mock_response(text: str, status_code: int = 200) -> MagicMock:
    """Factory para respuestas HTTP mock reutilizable."""
    mock = MagicMock()
    mock.status_code = status_code
    mock.text = text
    mock.raise_for_status = MagicMock()
    mock.headers = {}
    return mock


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_hibp_session(monkeypatch):
    """
    Inyecta un mock de sesión HTTP en checker._get_session.
    Evita cualquier llamada real a la red en CI.

    Uso:
        def test_algo(mock_hibp_session):
            mock_hibp_session.get.return_value = make_mock_response("SUFFIX:42")
    """
    import pwned_checker.checker as checker_module

    mock_session = MagicMock()
    monkeypatch.setattr(checker_module, "_SESSION", None)
    monkeypatch.setattr(checker_module, "_get_session", lambda: mock_session)
    return mock_session


@pytest.fixture
def vulnerable_response():
    """Respuesta HIBP mock que indica 'password' como vulnerable (12345 filtraciones)."""
    from pwned_checker.checker import hash_password
    sha1   = hash_password("password")
    suffix = sha1[5:]
    body   = f"AAAAAA:99\n{suffix}:12345\nBBBBBB:1\n"
    return make_mock_response(body)


@pytest.fixture
def safe_response():
    """Respuesta HIBP mock sin coincidencias (contraseña segura)."""
    return make_mock_response("AAAAA:1\nBBBBB:2\n")