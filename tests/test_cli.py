"""
Tests para pwned_checker.cli

Cubre:
  - cmd_check modo interactivo
  - cmd_check modo archivo
  - cmd_generate con distintas opciones
  - _save_report (JSON y CSV)
  - build_parser (subcomandos y flags)
  - Códigos de salida (0 = seguro, 1 = vulnerable o error de argumento)
"""
from __future__ import annotations

import csv
import json
import sys
import os
import argparse
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pwned_checker.checker import CheckResult, CheckStatus
from pwned_checker.cli import (
    _print_result,
    _save_report,
    build_parser,
    cmd_check,
    cmd_generate,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def make_result(password: str, status: CheckStatus, count: int = 0) -> CheckResult:
    return CheckResult(password, count, status)


def make_namespace(**kwargs) -> argparse.Namespace:
    """Crea un Namespace con defaults sensatos para cmd_check."""
    defaults = {
        "interactive": False,
        "file": None,
        "output": None,
        "expose_passwords": False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def make_gen_namespace(**kwargs) -> argparse.Namespace:
    """Crea un Namespace con defaults sensatos para cmd_generate."""
    defaults = {
        "length": 14,
        "number": 1,
        "no_digits": False,
        "no_symbols": False,
        "no_upper": False,
        "no_lower": False,
        "no_ambiguous": False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ─── Tests: _print_result ────────────────────────────────────────────────────

class TestPrintResult:
    def test_vulnerable_output(self, capsys):
        r = make_result("password", CheckStatus.VULNERABLE, 12345)
        _print_result(r)
        out = capsys.readouterr().out
        assert "VULNERABLE" in out
        assert "12,345" in out

    def test_safe_output(self, capsys):
        r = make_result("SafePass!", CheckStatus.SAFE)
        _print_result(r)
        out = capsys.readouterr().out
        assert "SEGURA" in out

    def test_error_output(self, capsys):
        r = make_result("x", CheckStatus.ERROR)
        _print_result(r)
        out = capsys.readouterr().out
        assert "ERROR" in out

    def test_with_index(self, capsys):
        r = make_result("abc123", CheckStatus.SAFE)
        _print_result(r, index=3)
        out = capsys.readouterr().out
        assert "[3]" in out

    def test_without_index(self, capsys):
        r = make_result("abc123", CheckStatus.SAFE)
        _print_result(r, index=None)
        out = capsys.readouterr().out
        assert "[" not in out


# ─── Tests: _save_report ─────────────────────────────────────────────────────

class TestSaveReport:
    def test_saves_json(self, tmp_path, capsys):
        results = [
            make_result("pass1", CheckStatus.SAFE),
            make_result("pass2", CheckStatus.VULNERABLE, 100),
        ]
        out_file = tmp_path / "result.json"
        _save_report(results, str(out_file))
        assert out_file.exists()
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert len(data) == 2
        assert data[0]["status"] == "safe"
        assert data[1]["status"] == "vulnerable"
        # Por defecto no expone passwords
        assert "password" not in data[0]

    def test_saves_csv(self, tmp_path):
        results = [make_result("abc", CheckStatus.SAFE)]
        out_file = tmp_path / "result.csv"
        _save_report(results, str(out_file))
        assert out_file.exists()
        rows = list(csv.DictReader(out_file.open(encoding="utf-8")))
        assert len(rows) == 1
        assert rows[0]["status"] == "safe"

    def test_json_with_expose_passwords(self, tmp_path):
        results = [make_result("mysecret", CheckStatus.VULNERABLE, 5)]
        out_file = tmp_path / "exposed.json"
        _save_report(results, str(out_file), expose_passwords=True)
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert data[0]["password"] == "mysecret"

    def test_unsupported_format_prints_warning(self, tmp_path, capsys):
        results = [make_result("x", CheckStatus.SAFE)]
        out_file = tmp_path / "result.xml"
        _save_report(results, str(out_file))
        err = capsys.readouterr().err
        assert "no soportado" in err.lower() or "soportado" in err

    def test_creates_parent_directory(self, tmp_path):
        results = [make_result("x", CheckStatus.SAFE)]
        nested = tmp_path / "subdir" / "deep" / "result.json"
        _save_report(results, str(nested))
        assert nested.exists()

    def test_empty_results_csv_does_nothing(self, tmp_path):
        out_file = tmp_path / "empty.csv"
        _save_report([], str(out_file))
        # No debe crear archivo si no hay filas
        assert not out_file.exists()


# ─── Tests: cmd_check (modo interactivo) ─────────────────────────────────────

class TestCmdCheckInteractive:
    def test_interactive_safe_password(self, capsys):
        safe_result = make_result("SafePass!", CheckStatus.SAFE)
        args = make_namespace(interactive=True)

        with patch("pwned_checker.cli.getpass.getpass", return_value="SafePass!"), \
             patch("pwned_checker.cli.check_breach", return_value=safe_result):
            code = cmd_check(args)

        assert code == 0
        out = capsys.readouterr().out
        assert "SEGURA" in out

    def test_interactive_vulnerable_password_returns_exit_1(self, capsys):
        vuln_result = make_result("password", CheckStatus.VULNERABLE, 999)
        args = make_namespace(interactive=True)

        with patch("pwned_checker.cli.getpass.getpass", return_value="password"), \
             patch("pwned_checker.cli.check_breach", return_value=vuln_result):
            code = cmd_check(args)

        assert code == 1

    def test_interactive_error_returns_exit_0(self, capsys):
        """ERROR no se considera vulnerable — exit 0."""
        err_result = make_result("x", CheckStatus.ERROR)
        args = make_namespace(interactive=True)

        with patch("pwned_checker.cli.getpass.getpass", return_value="x"), \
             patch("pwned_checker.cli.check_breach", return_value=err_result):
            code = cmd_check(args)

        assert code == 0


# ─── Tests: cmd_check (modo archivo) ─────────────────────────────────────────

class TestCmdCheckFile:
    def test_file_not_found_returns_exit_1(self, tmp_path, capsys):
        args = make_namespace(file=str(tmp_path / "no_existe.txt"))
        code = cmd_check(args)
        assert code == 1
        err = capsys.readouterr().err
        assert "no encontrado" in err.lower()

    def test_empty_file_returns_exit_1(self, tmp_path, capsys):
        empty = tmp_path / "empty.txt"
        empty.write_text("# solo comentarios\n\n   \n", encoding="utf-8")
        args = make_namespace(file=str(empty))
        code = cmd_check(args)
        assert code == 1

    def test_file_with_safe_passwords_returns_exit_0(self, tmp_path, capsys):
        pwd_file = tmp_path / "passwords.txt"
        pwd_file.write_text("SafePass1!\nAnotherSafe2@\n", encoding="utf-8")

        safe = make_result("SafePass1!", CheckStatus.SAFE)
        safe2 = make_result("AnotherSafe2@", CheckStatus.SAFE)

        args = make_namespace(file=str(pwd_file))
        with patch("pwned_checker.cli.check_passwords_from_list", return_value=[safe, safe2]):
            code = cmd_check(args)

        assert code == 0

    def test_file_with_vulnerable_password_returns_exit_1(self, tmp_path, capsys):
        pwd_file = tmp_path / "passwords.txt"
        pwd_file.write_text("password\n", encoding="utf-8")

        vuln = make_result("password", CheckStatus.VULNERABLE, 12345)
        args = make_namespace(file=str(pwd_file))

        with patch("pwned_checker.cli.check_passwords_from_list", return_value=[vuln]):
            code = cmd_check(args)

        assert code == 1

    def test_file_skips_comment_lines(self, tmp_path):
        pwd_file = tmp_path / "passwords.txt"
        pwd_file.write_text("# esto es un comentario\nrealpassword\n", encoding="utf-8")

        safe = make_result("realpassword", CheckStatus.SAFE)
        args = make_namespace(file=str(pwd_file))

        with patch("pwned_checker.cli.check_passwords_from_list", return_value=[safe]) as mock_check:
            cmd_check(args)
            # Solo debe pasar "realpassword", no el comentario
            called_with = mock_check.call_args[0][0]
            assert "# esto es un comentario" not in called_with
            assert "realpassword" in called_with

    def test_file_with_output_report(self, tmp_path, capsys):
        pwd_file = tmp_path / "passwords.txt"
        pwd_file.write_text("pass1\n", encoding="utf-8")
        out_file = tmp_path / "report.json"

        safe = make_result("pass1", CheckStatus.SAFE)
        args = make_namespace(file=str(pwd_file), output=str(out_file))

        with patch("pwned_checker.cli.check_passwords_from_list", return_value=[safe]):
            cmd_check(args)

        assert out_file.exists()

    def test_summary_shows_counts(self, tmp_path, capsys):
        pwd_file = tmp_path / "passwords.txt"
        pwd_file.write_text("p1\np2\np3\n", encoding="utf-8")

        results = [
            make_result("p1", CheckStatus.VULNERABLE, 1),
            make_result("p2", CheckStatus.SAFE),
            make_result("p3", CheckStatus.ERROR),
        ]
        args = make_namespace(file=str(pwd_file))

        with patch("pwned_checker.cli.check_passwords_from_list", return_value=results):
            cmd_check(args)

        out = capsys.readouterr().out
        assert "1" in out   # vulnerable
        assert "RESUMEN" in out


# ─── Tests: cmd_generate ─────────────────────────────────────────────────────

class TestCmdGenerate:
    def test_generate_single_password(self, capsys):
        args = make_gen_namespace(number=1, length=16)
        code = cmd_generate(args)
        assert code == 0
        out = capsys.readouterr().out.strip()
        assert len(out) == 16

    def test_generate_multiple_passwords(self, capsys):
        args = make_gen_namespace(number=5, length=12)
        code = cmd_generate(args)
        assert code == 0
        lines = [l for l in capsys.readouterr().out.strip().splitlines() if l]
        assert len(lines) == 5

    def test_generate_no_digits(self, capsys):
        args = make_gen_namespace(number=10, length=20, no_digits=True, no_symbols=True)
        cmd_generate(args)
        out = capsys.readouterr().out
        passwords = [l.strip() for l in out.strip().splitlines() if l]
        for pwd in passwords:
            assert not any(c.isdigit() for c in pwd)

    def test_generate_no_symbols(self, capsys):
        import string
        args = make_gen_namespace(number=10, length=20, no_symbols=True)
        cmd_generate(args)
        out = capsys.readouterr().out
        passwords = [l.strip() for l in out.strip().splitlines() if l]
        for pwd in passwords:
            assert not any(c in string.punctuation for c in pwd)

    def test_generate_returns_exit_0(self):
        args = make_gen_namespace()
        code = cmd_generate(args)
        assert code == 0

    def test_generate_numbered_output_for_multiple(self, capsys):
        args = make_gen_namespace(number=3, length=10)
        cmd_generate(args)
        out = capsys.readouterr().out
        # Debe mostrar numeración cuando number > 1
        assert "1:" in out or "  1:" in out


# ─── Tests: build_parser ─────────────────────────────────────────────────────

class TestBuildParser:
    def test_parser_creates_successfully(self):
        parser = build_parser()
        assert parser is not None

    def test_check_subcommand_exists(self):
        parser = build_parser()
        args = parser.parse_args(["check", "-i"])
        assert args.command == "check"
        assert args.interactive is True

    def test_generate_subcommand_exists(self):
        parser = build_parser()
        args = parser.parse_args(["generate"])
        assert args.command == "generate"

    def test_check_file_flag(self):
        parser = build_parser()
        args = parser.parse_args(["check", "-f", "passwords.txt"])
        assert args.file == "passwords.txt"

    def test_check_output_flag(self):
        parser = build_parser()
        args = parser.parse_args(["check", "-f", "f.txt", "-o", "out.json"])
        assert args.output == "out.json"

    def test_check_expose_passwords_flag(self):
        parser = build_parser()
        args = parser.parse_args(["check", "-f", "f.txt", "--expose-passwords"])
        assert args.expose_passwords is True

    def test_generate_length_flag(self):
        parser = build_parser()
        args = parser.parse_args(["generate", "-l", "20"])
        assert args.length == 20

    def test_generate_number_flag(self):
        parser = build_parser()
        args = parser.parse_args(["generate", "-n", "5"])
        assert args.number == 5

    def test_generate_no_ambiguous_flag(self):
        parser = build_parser()
        args = parser.parse_args(["generate", "--no-ambiguous"])
        assert args.no_ambiguous is True

    def test_check_requires_mode(self):
        """Sin -i ni -f debe fallar."""
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["check"])

    def test_check_mutual_exclusion(self):
        """No se puede usar -i y -f juntos."""
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["check", "-i", "-f", "file.txt"])

    def test_version_flag(self):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0
