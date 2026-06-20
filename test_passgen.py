"""
Tests for passgen.py
Run: python -m pytest tests/ -v
"""

import sys
import os
import string
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import passgen as pg


# ─────────────────────────────────────────────────────────────────────────────
#  generate_password
# ─────────────────────────────────────────────────────────────────────────────

class TestGeneratePassword:

    def test_default_length_is_16(self):
        pw = pg.generate_password()
        assert len(pw) == 16

    def test_custom_length(self):
        for length in [8, 20, 32, 64]:
            assert len(pg.generate_password(length=length)) == length

    def test_contains_lowercase_when_enabled(self):
        # With enough attempts, a lowercase char should always appear
        pw = pg.generate_password(length=32, use_lower=True, use_upper=False,
                                   use_digits=False, use_symbols=False)
        assert any(c in string.ascii_lowercase for c in pw)

    def test_contains_uppercase_when_enabled(self):
        pw = pg.generate_password(length=32, use_lower=False, use_upper=True,
                                   use_digits=False, use_symbols=False)
        assert any(c in string.ascii_uppercase for c in pw)

    def test_contains_digits_when_enabled(self):
        pw = pg.generate_password(length=32, use_lower=False, use_upper=False,
                                   use_digits=True, use_symbols=False)
        assert any(c in string.digits for c in pw)

    def test_contains_symbols_when_enabled(self):
        pw = pg.generate_password(length=32, use_lower=False, use_upper=False,
                                   use_digits=False, use_symbols=True)
        assert any(c in pg.SYMBOLS for c in pw)

    def test_no_symbols_excludes_them(self):
        for _ in range(10):
            pw = pg.generate_password(length=20, use_symbols=False)
            assert not any(c in pg.SYMBOLS for c in pw)

    def test_no_ambiguous_excludes_ambiguous_chars(self):
        for _ in range(50):
            pw = pg.generate_password(length=20, no_ambiguous=True)
            assert not any(c in pg.AMBIGUOUS for c in pw)

    def test_all_types_disabled_raises_value_error(self):
        with pytest.raises(ValueError, match="At least one"):
            pg.generate_password(use_lower=False, use_upper=False,
                                  use_digits=False, use_symbols=False)

    def test_length_below_4_raises_value_error(self):
        with pytest.raises(ValueError, match="at least 4"):
            pg.generate_password(length=3)

    def test_guaranteed_one_of_each_type(self):
        """With all types on, all 4 character types must appear."""
        # Run multiple times to account for randomness
        for _ in range(20):
            pw = pg.generate_password(length=16)
            assert any(c in string.ascii_lowercase for c in pw), "Missing lowercase"
            assert any(c in string.ascii_uppercase for c in pw), "Missing uppercase"
            assert any(c in string.digits          for c in pw), "Missing digit"
            assert any(c in pg.SYMBOLS             for c in pw), "Missing symbol"

    def test_passwords_are_unique(self):
        """Two calls should never return the same password (statistically near-certain)."""
        passwords = {pg.generate_password() for _ in range(20)}
        assert len(passwords) == 20


# ─────────────────────────────────────────────────────────────────────────────
#  generate_pin
# ─────────────────────────────────────────────────────────────────────────────

class TestGeneratePin:

    def test_default_length_is_6(self):
        assert len(pg.generate_pin()) == 6

    def test_custom_length(self):
        assert len(pg.generate_pin(4)) == 4
        assert len(pg.generate_pin(8)) == 8

    def test_only_digits(self):
        for _ in range(10):
            pin = pg.generate_pin(8)
            assert pin.isdigit()

    def test_length_below_4_raises(self):
        with pytest.raises(ValueError, match="at least 4"):
            pg.generate_pin(3)


# ─────────────────────────────────────────────────────────────────────────────
#  generate_passphrase
# ─────────────────────────────────────────────────────────────────────────────

class TestGeneratePassphrase:

    def test_default_word_count(self):
        phrase = pg.generate_passphrase(words=4, add_number=False)
        assert len(phrase.split("-")) == 4

    def test_custom_word_count(self):
        phrase = pg.generate_passphrase(words=6, add_number=False)
        assert len(phrase.split("-")) == 6

    def test_capitalize_option(self):
        phrase = pg.generate_passphrase(capitalize=True, add_number=False)
        for word in phrase.split("-"):
            assert word[0].isupper()

    def test_no_capitalize(self):
        phrase = pg.generate_passphrase(capitalize=False, add_number=False)
        for word in phrase.split("-"):
            assert word[0].islower()

    def test_add_number_appends_numeric_segment(self):
        phrase = pg.generate_passphrase(words=3, add_number=True)
        parts = phrase.split("-")
        assert parts[-1].isdigit()

    def test_custom_separator(self):
        phrase = pg.generate_passphrase(words=3, separator=".", add_number=False)
        assert "." in phrase
        assert len(phrase.split(".")) == 3


# ─────────────────────────────────────────────────────────────────────────────
#  score_password
# ─────────────────────────────────────────────────────────────────────────────

class TestScorePassword:

    def test_very_weak_short_password(self):
        result = pg.score_password("abc")
        assert result["label"] == "Very Weak"

    def test_weak_common_password(self):
        result = pg.score_password("abc123")
        assert result["label"] in ("Very Weak", "Weak", "Fair")

    def test_strong_long_complex_password(self):
        result = pg.score_password("X9$mK#vP2@nL8qR!dZ&w")
        assert result["label"] in ("Strong", "Very Strong")

    def test_entropy_increases_with_length(self):
        short  = pg.score_password("aB1!")
        longer = pg.score_password("aB1!aB1!aB1!aB1!")
        assert longer["entropy"] > short["entropy"]

    def test_detects_lowercase(self):
        result = pg.score_password("abcdef")
        assert result["has_lower"] is True
        assert result["has_upper"] is False

    def test_detects_uppercase(self):
        result = pg.score_password("ABCDEF")
        assert result["has_upper"] is True

    def test_detects_digits(self):
        result = pg.score_password("123456")
        assert result["has_digit"] is True

    def test_detects_symbols(self):
        result = pg.score_password("!@#$%^")
        assert result["has_symbol"] is True

    def test_result_has_all_required_keys(self):
        result = pg.score_password("TestPass123!")
        for key in ["password", "length", "entropy", "pool_size",
                    "score", "label", "color"]:
            assert key in result

    def test_entropy_is_positive(self):
        result = pg.score_password("Hello123!")
        assert result["entropy"] > 0


# ─────────────────────────────────────────────────────────────────────────────
#  build_charset
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildCharset:

    def test_returns_pool_and_required(self):
        pool, required = pg.build_charset()
        assert isinstance(pool, str)
        assert isinstance(required, list)

    def test_pool_contains_lowercase_when_enabled(self):
        pool, _ = pg.build_charset(use_lower=True, use_upper=False,
                                    use_digits=False, use_symbols=False)
        assert any(c in string.ascii_lowercase for c in pool)

    def test_pool_excludes_uppercase_when_disabled(self):
        pool, _ = pg.build_charset(use_lower=True, use_upper=False,
                                    use_digits=False, use_symbols=False)
        assert not any(c in string.ascii_uppercase for c in pool)

    def test_no_ambiguous_removes_ambiguous_chars(self):
        pool, _ = pg.build_charset(no_ambiguous=True)
        for c in pg.AMBIGUOUS:
            assert c not in pool

    def test_all_disabled_raises(self):
        with pytest.raises(ValueError):
            pg.build_charset(use_lower=False, use_upper=False,
                              use_digits=False, use_symbols=False)
