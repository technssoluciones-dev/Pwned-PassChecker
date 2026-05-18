"""
Tests para pwned_checker.checker
Usa mocks para no depender de la red en CI.
"""
from __future__ import annotations

import sys
import os
import pytest
import requests
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pwned_checker.checker import (
    CheckStatus,
    CheckResult,
    hash_password,
    check_breach,
    check_passwords_from_list,
)


# Helper local (evita import circular de tests.conftest en entornos sin pip install -e .)
def make_mock_response(text: str, status_code: int = 200) -> MagicMock:
    mock = MagicMock()
    mock.status_code = status_code
    mock.text = text
    mock.raise_for_status = MagicMock()
    mock.headers = {}
    return mock


class TestHashPassword:
    def test_known_hash(self):
        expected = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        assert hash_password("password") == expected

    def test_always_uppercase(self):
        result = hash_password("test")
        assert result == result.upper()

    def test_empty_string_known_hash(self):
        assert hash_password("") == "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"

    def test_different_passwords_produce_different_hashes(self):
        assert hash_password("abc") != hash_password("ABC")


class TestCheckBreach:
    def test_vulnerable_password(self):
        sha1   = hash_password("password")
        suffix = sha1[5:]
        body   = f"AAAAAA:99\n{suffix}:12345\nBBBBBB:1\n"

        with patch("pwned_checker.checker._get_session") as mock_get_session:
            mock_get_session.return_value = MagicMock(
                get=MagicMock(return_value=make_mock_response(body))
            )
            result = check_breach("password")

        assert result.status       == CheckStatus.VULNERABLE
        assert result.breach_count == 12345

    def test_safe_password(self):
        body = "AAAAA:1\nBBBBB:2\n"
        with patch("pwned_checker.checker._get_session") as mock_get_session:
            mock_get_session.return_value = MagicMock(
                get=MagicMock(return_value=make_mock_response(body))
            )
            result = check_breach("Contr4senya!MuyRara#XyZ99abc")

        assert result.status       == CheckStatus.SAFE
        assert result.breach_count == 0

    def test_connection_error_returns_error_status(self):
        with patch("pwned_checker.checker._get_session") as mock_get_session:
            mock_get_session.return_value = MagicMock(
                get=MagicMock(side_effect=requests.exceptions.ConnectionError("sin red"))
            )
            result = check_breach("cualquiera")
        assert result.status == CheckStatus.ERROR

    def test_timeout_returns_error_status(self):
        with patch("pwned_checker.checker._get_session") as mock_get_session:
            mock_get_session.return_value = MagicMock(
                get=MagicMock(side_effect=requests.exceptions.Timeout("timeout"))
            )
            result = check_breach("otrapassword")
        assert result.status == CheckStatus.ERROR

    def test_empty_password_returns_error(self):
        result = check_breach("")
        assert result.status == CheckStatus.ERROR

    def test_whitespace_only_password_returns_error(self):
        result = check_breach("   ")
        assert result.status == CheckStatus.ERROR

    def test_rate_limit_response_triggers_retry(self):
        sha1   = hash_password("password")
        suffix = sha1[5:]
        body   = f"{suffix}:1\n"

        rate_limit_resp = make_mock_response("", status_code=429)
        rate_limit_resp.headers = {"Retry-After": "0"}
        success_resp    = make_mock_response(body, status_code=200)

        with patch("pwned_checker.checker._get_session") as mock_get_session, \
             patch("pwned_checker.checker.time.sleep"):
            mock_session = MagicMock()
            mock_session.get.side_effect = [rate_limit_resp, success_resp]
            mock_get_session.return_value = mock_session
            result = check_breach("password")

        assert result.status == CheckStatus.VULNERABLE


class TestCheckResult:
    def test_masking_hides_password(self):
        result = CheckResult("mysecret", 0, CheckStatus.SAFE)
        assert "mysecret" not in result.masked
        assert result.masked.startswith("my")

    def test_masking_short_password(self):
        result = CheckResult("ab", 0, CheckStatus.SAFE)
        assert result.masked == "**"

    def test_to_dict_does_not_expose_password(self):
        result = CheckResult("topsecret", 5, CheckStatus.VULNERABLE)
        d = result.to_dict()
        assert "topsecret" not in str(d)
        assert "password_masked" in d
        assert "status" in d
        assert "breach_count" in d

    def test_to_dict_with_password_exposes_it(self):
        result = CheckResult("topsecret", 5, CheckStatus.VULNERABLE)
        d = result.to_dict_with_password()
        assert d["password"] == "topsecret"

    def test_status_values(self):
        assert CheckStatus.SAFE.value       == "safe"
        assert CheckStatus.VULNERABLE.value == "vulnerable"
        assert CheckStatus.ERROR.value      == "error"


class TestCheckPasswordsFromList:
    def test_empty_list_returns_empty(self):
        results = check_passwords_from_list([])
        assert results == []

    def test_filters_empty_strings(self):
        """Strings vacios y de solo espacios se omiten — no llegan a la API."""
        # FIX: check_passwords_from_list ahora filtra `if pwd and pwd.strip()`
        results = check_passwords_from_list(["", "  ", ""])
        assert results == []

    def test_filters_mixed_valid_and_empty(self):
        body = "AAAAA:1\n"
        with patch("pwned_checker.checker._get_session") as mock_get_session:
            mock_get_session.return_value = MagicMock(
                get=MagicMock(return_value=make_mock_response(body))
            )
            results = check_passwords_from_list(["", "valid_password", "  "])

        assert len(results) == 1
        assert results[0].status in (CheckStatus.SAFE, CheckStatus.VULNERABLE)
