#!/usr/bin/env python3
"""
Generador de contraseñas seguras — Script de compatibilidad.
Para el CLI completo: pwned-checker generate -n 5 -l 20
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from pwned_checker.generator import GeneratorOptions, generate_password


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generador de contraseñas seguras")
    parser.add_argument("-l", "--length",     type=int, default=14, help="Longitud (mínimo 8, default 14)")
    parser.add_argument("--no-digits",        action="store_true",  help="Excluir números")
    parser.add_argument("--no-symbols",       action="store_true",  help="Excluir símbolos")
    parser.add_argument("-n", "--number",     type=int, default=1,  help="Cantidad de contraseñas")
    args = parser.parse_args()

    opts = GeneratorOptions(
        length      = args.length,
        use_digits  = not args.no_digits,
        use_symbols = not args.no_symbols,
    )
    for i in range(args.number):
        pwd = generate_password(opts)
        print(f"{i+1}: {pwd}" if args.number > 1 else pwd)


if __name__ == "__main__":
    main()
