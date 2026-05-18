#!/usr/bin/env python3
"""
Pwned PassChecker — Script de compatibilidad.
Este archivo conserva la API original para usuarios que lo usan directamente.
Para el CLI completo: pwned-checker check -i / -f archivo.txt
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

# Re-exportar para compatibilidad total con scripts externos
from pwned_checker.checker import hash_password, check_breach  # noqa: F401
from pwned_checker.cli import build_parser


def interactive_check():
    import getpass
    from pwned_checker.checker import CheckStatus
    print("\U0001F512 Verificador de contraseñas vulneradas")
    pwd = getpass.getpass("Introduce la contraseña a verificar: ")
    result = check_breach(pwd)
    if result.status == CheckStatus.ERROR:
        print("⚠️  No se pudo realizar la verificación. Revisa tu conexión.")
    elif result.status == CheckStatus.VULNERABLE:
        print(f"❌ ¡Contraseña VULNERABLE! Apareció en {result.breach_count:,} filtraciones.")
        print("   Por favor, cámbiala inmediatamente.")
    else:
        print("✅ ¡Contraseña segura! No se encontró en brechas conocidas.")


def check_from_file(filepath, output_report=None):
    from pathlib import Path
    import json, csv
    from pwned_checker.checker import CheckStatus, check_passwords_from_list

    try:
        lines = Path(filepath).read_text(encoding="utf-8").splitlines()
        passwords = [l.strip() for l in lines if l.strip()]
    except FileNotFoundError:
        print(f"❌ Archivo no encontrado: {filepath}")
        return

    if not passwords:
        print("El archivo no contiene contraseñas válidas.")
        return

    results = []
    print(f"\U0001F50D Verificando {len(passwords)} contraseñas...\n")
    all_results = check_passwords_from_list(passwords)

    for idx, result in enumerate(all_results, 1):
        display = result.masked
        if result.status == CheckStatus.VULNERABLE:
            print(f"[{idx}/{len(passwords)}] {display} → ❌ VULNERABLE ({result.breach_count:,} filtraciones)")
        elif result.status == CheckStatus.SAFE:
            print(f"[{idx}/{len(passwords)}] {display} → ✅ SEGURA")
        else:
            print(f"[{idx}/{len(passwords)}] {display} → ⚠️  ERROR")
        results.append(result.to_dict_with_password())

    vulnerable = sum(1 for r in all_results if r.status == CheckStatus.VULNERABLE)
    safe       = sum(1 for r in all_results if r.status == CheckStatus.SAFE)
    errors     = sum(1 for r in all_results if r.status == CheckStatus.ERROR)
    print(f"\n{'='*40}")
    print(f"📊 RESUMEN: Vulnerables: {vulnerable}, Seguras: {safe}, Errores: {errors}")

    if output_report:
        out = Path(output_report)
        if out.suffix.lower() == ".json":
            with out.open("w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"📄 Reporte JSON guardado en {output_report}")
        elif out.suffix.lower() == ".csv":
            with out.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
                writer.writeheader()
                writer.writerows(results)
            print(f"📄 Reporte CSV guardado en {output_report}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Comprueba si una o varias contraseñas han sido filtradas (HIBP)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--interactive", action="store_true", help="Modo interactivo")
    group.add_argument("-f", "--file", help="Archivo con contraseñas")
    parser.add_argument("-o", "--output", help="Guardar reporte (ej: report.json o report.csv)")
    args = parser.parse_args()

    if args.interactive:
        interactive_check()
    elif args.file:
        check_from_file(args.file, args.output)


if __name__ == "__main__":
    main()
