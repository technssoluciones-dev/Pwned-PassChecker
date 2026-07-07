"""
Tests para pwned_checker.generator
"""
from __future__ import annotations

import os
import string
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pwned_checker.generator import (
    AMBIGUOUS,
    GeneratorOptions,
    generate_multiple,
    generate_password,
)


class TestGeneratorOptions:
    def test_minimum_length_enforced(self):
        opts = GeneratorOptions(length=3)
        assert opts.length == 8

    def test_zero_length_uses_default(self):
        opts = GeneratorOptions(length=0)
        assert opts.length >= 8


class TestGeneratePassword:
    def test_correct_length(self):
        pwd = generate_password(GeneratorOptions(length=16))
        assert len(pwd) == 16

    def test_has_upper(self):
        for _ in range(20):
            pwd = generate_password(GeneratorOptions(length=12, use_digits=False, use_symbols=False))
            assert any(c.isupper() for c in pwd)

    def test_has_lower(self):
        for _ in range(20):
            pwd = generate_password(GeneratorOptions(length=12, use_digits=False, use_symbols=False))
            assert any(c.islower() for c in pwd)

    def test_has_digits_when_enabled(self):
        for _ in range(20):
            pwd = generate_password(GeneratorOptions(length=12, use_digits=True, use_symbols=False))
            assert any(c.isdigit() for c in pwd)

    def test_no_digits_when_disabled(self):
        for _ in range(20):
            pwd = generate_password(GeneratorOptions(length=12, use_digits=False, use_symbols=False))
            assert not any(c.isdigit() for c in pwd)

    def test_has_symbols_when_enabled(self):
        for _ in range(20):
            pwd = generate_password(GeneratorOptions(length=12, use_digits=True, use_symbols=True))
            assert any(c in string.punctuation for c in pwd)

    def test_no_ambiguous_when_excluded(self):
        for _ in range(50):
            pwd = generate_password(GeneratorOptions(length=20, exclude_ambiguous=True))
            assert not any(c in AMBIGUOUS for c in pwd)

    def test_empty_alphabet_raises(self):
        opts = GeneratorOptions(
            length=12, use_digits=False, use_symbols=False,
            use_upper=False, use_lower=False
        )
        with pytest.raises(ValueError):
            generate_password(opts)


class TestGenerateMultiple:
    def test_returns_correct_count(self):
        passwords = generate_multiple(5)
        assert len(passwords) == 5

    def test_all_unique(self):
        passwords = generate_multiple(20, GeneratorOptions(length=16))
        # Estadísticamente imposible que 20 contraseñas de 16 chars sean iguales
        assert len(set(passwords)) == 20
