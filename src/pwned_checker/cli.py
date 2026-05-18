#!/usr/bin/env python3
"""
CLI unificado para Pwned-PassChecker.
Combina verificador + generador en una sola interfaz.
"""
from __future__ import annotations

import argparse
import csv
import getpass
import json
import sys
import textwrap
from pathlib import Path

from . import __version__
from .checker import CheckResult, CheckStatus, check_breach, check_passwords_from_list
from .config  import config
from .generator import GeneratorOptions, generate_multiple, generate_password


# ─── Helpers de presentación ──────────────────────────────────────────────

def _print_result(result: CheckResult, index: int | None = None) -> None:
    prefix = f"[{index}] " if index is not None else ""
    if result.status == CheckStatus.VULNERABLE:
        print(f"{prefix}❌ VULNERABLE — aparece en {result.breach_count:,} filtraciones → {result.masked}")
    elif result.status == CheckStatus.SAFE:
        print(f"{prefix}✅ SEGURA — no encontrada en filtraciones → {result.masked}")
    else:
        print(f"{prefix}⚠️  ERROR — no se pudo verificar → {result.masked}")


def _save_report(results: list[CheckResult], output_path: str, expose_passwords: bool = False) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    to_dict = (lambda r: r.to_dict_with_password()) if expose_passwords else (lambda r: r.to_dict())

    ext = path.suffix.lower()
    if ext == ".json":
        with path.open("w", encoding="utf-8") as f:
            json.dump([to_dict(r) for r in results], f, indent=2, ensure_ascii=False)
        print(f"\n📄 Reporte JSON guardado en: {path}")

    elif ext == ".csv":
        rows = [to_dict(r) for r in results]
        if not rows:
            return
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        print(f"\n📄 Reporte CSV guardado en: {path}")

    else:
        print(f"⚠️  Formato no soportado: {ext}. Usa .json o .csv", file=sys.stderr)


# ─── Sub-comandos ─────────────────────────────────────────────────────────

def cmd_check(args: argparse.Namespace) -> int:
    """Verifica una o varias contraseñas contra HIBP."""
    results: list[CheckResult] = []

    if args.interactive:
        print("🔒 Pwned PassChecker — Verificación interactiva")
        pwd = getpass.getpass("Contraseña a verificar: ")
        result = check_breach(pwd)
        _print_result(result)
        results = [result]

    elif args.file:
        fpath = Path(args.file)
        if not fpath.is_file():
            print(f"❌ Archivo no encontrado: {args.file}", file=sys.stderr)
            return 1

        raw_lines = fpath.read_text(encoding="utf-8").splitlines()
        passwords = [l.strip() for l in raw_lines if l.strip() and not l.startswith("#")]

        if not passwords:
            print("⚠️  El archivo no contiene contraseñas válidas.", file=sys.stderr)
            return 1

        print(f"🔍 Verificando {len(passwords)} contraseña(s)...\n")
        results = check_passwords_from_list(passwords)

        for i, r in enumerate(results, 1):
            _print_result(r, index=i)

        vulnerable = sum(1 for r in results if r.status == CheckStatus.VULNERABLE)
        safe       = sum(1 for r in results if r.status == CheckStatus.SAFE)
        errors     = sum(1 for r in results if r.status == CheckStatus.ERROR)

        print(f"\n{'─'*50}")
        print(f"📊 RESUMEN  →  ❌ Vulnerables: {vulnerable}  ✅ Seguras: {safe}  ⚠️  Errores: {errors}")

    if args.output and results:
        _save_report(results, args.output, expose_passwords=args.expose_passwords)

    # Código de salida: 1 si hay vulnerables (útil para CI/scripts)
    has_vulnerable = any(r.status == CheckStatus.VULNERABLE for r in results)
    return 1 if has_vulnerable else 0


def cmd_generate(args: argparse.Namespace) -> int:
    """Genera contraseñas seguras."""
    opts = GeneratorOptions(
        length             = args.length,
        use_digits         = not args.no_digits,
        use_symbols        = not args.no_symbols,
        use_upper          = not args.no_upper,
        use_lower          = not args.no_lower,
        exclude_ambiguous  = args.no_ambiguous,
    )
    passwords = generate_multiple(args.number, opts)
    for i, pwd in enumerate(passwords, 1):
        if args.number > 1:
            print(f"{i:>3}:  {pwd}")
        else:
            print(pwd)
    return 0


# ─── Parser principal ─────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwned-checker",
        description="🔐 Pwned PassChecker — Verifica y genera contraseñas seguras",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Ejemplos:
              Verificar interactivamente:
                pwned-checker check -i

              Verificar archivo con reporte JSON:
                pwned-checker check -f sample_passwords.txt -o reports/result.json

              Generar 5 contraseñas de 20 caracteres:
                pwned-checker generate -n 5 -l 20

              Generar sin símbolos ni ambigüedades:
                pwned-checker generate --no-symbols --no-ambiguous
        """),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", metavar="COMANDO")
    sub.required = True

    # ── check ──────────────────────────────────────────────────────────────
    p_check = sub.add_parser("check", help="Verifica contraseñas contra HIBP")
    mode    = p_check.add_mutually_exclusive_group(required=True)
    mode.add_argument("-i", "--interactive", action="store_true",
                      help="Modo interactivo (una contraseña oculta)")
    mode.add_argument("-f", "--file", metavar="ARCHIVO",
                      help="Archivo con contraseñas (una por línea)")
    p_check.add_argument("-o", "--output", metavar="REPORTE",
                         help="Guardar reporte (ej: reports/result.json o .csv)")
    p_check.add_argument("--expose-passwords", action="store_true",
                         help="Incluir contraseñas reales en el reporte (¡úsalo con cuidado!)")
    p_check.set_defaults(func=cmd_check)

    # ── generate ───────────────────────────────────────────────────────────
    p_gen = sub.add_parser("generate", help="Genera contraseñas seguras")
    p_gen.add_argument("-l", "--length",  type=int, default=config.default_length,
                       help=f"Longitud (mínimo 8, default: {config.default_length})")
    p_gen.add_argument("-n", "--number",  type=int, default=1,
                       help="Cantidad de contraseñas a generar (default: 1)")
    p_gen.add_argument("--no-digits",     action="store_true", help="Sin números")
    p_gen.add_argument("--no-symbols",    action="store_true", help="Sin símbolos")
    p_gen.add_argument("--no-upper",      action="store_true", help="Sin mayúsculas")
    p_gen.add_argument("--no-lower",      action="store_true", help="Sin minúsculas")
    p_gen.add_argument("--no-ambiguous",  action="store_true",
                       help="Excluir caracteres ambiguos (0,O,l,1,I,|)")
    p_gen.set_defaults(func=cmd_generate)

    return parser


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()