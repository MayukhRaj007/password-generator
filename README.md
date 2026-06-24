# Password Generator

![Language](https://img.shields.io/badge/language-Python-3776AB?logo=python)  ![License](https://img.shields.io/badge/license-MIT-green)  ![Status](https://img.shields.io/badge/status-active-brightgreen)  ![Security](https://img.shields.io/badge/security-cryptographically_secure-red)

A secure command-line password generator using Python's `secrets` module — the cryptographically safe standard for generating passwords, tokens, and keys.

## Features

- Cryptographically secure generation via `secrets.SystemRandom` (not `random`)
- Composable character sets — toggle lowercase, uppercase, digits, symbols
- Exclude visually ambiguous characters (`0/O/l/1/I`) for easier reading
- Batch mode — generate many passwords at once
- PIN generator
- Memorable word passphrase generator
- Entropy-based strength checker (real math, not arbitrary rules)
- Optional clipboard copy with `--copy`

## Usage

```bash
# Default — 16-char password with all character types
python passgen.py

# Custom length
python passgen.py --length 32

# No symbols (letters + digits only)
python passgen.py --no-symbols

# Exclude ambiguous characters
python passgen.py --no-ambiguous

# Generate 10 passwords at once
python passgen.py --batch 10

# Numeric PIN
python passgen.py --pin 6

# Memorable passphrase
python passgen.py --phrase
python passgen.py --phrase --words 5 --separator _

# Check strength of an existing password
python passgen.py --check "MyP@ssw0rd"

# Copy first result to clipboard
python passgen.py --copy
```

## Example output

```
  Password : &d|YAb,69H<MhfCm
  Length   : 16 characters
  Entropy  : 103.4 bits
  Pool     : 88 unique characters

  Strength : ✅ Very Strong
  [████████████████████]

  Contains : ✅ lowercase  ✅ uppercase  ✅ digits  ✅ symbols
```

## Why `secrets` and not `random`?

Python's `random` module uses a predictable algorithm (Mersenne Twister). Given enough outputs, an attacker can reconstruct its internal state and predict future values. `secrets` draws from your OS's cryptographically secure random source (`/dev/urandom` on Linux/macOS, `CryptGenRandom` on Windows) — the same source used by TLS and SSH key generation.

**Rule:** `random` → simulations, games. `secrets` → passwords, tokens, API keys. Always.

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/password-generator.git
cd password-generator

# Optional — only needed for --copy clipboard support
pip install pyperclip
```

No external dependencies required for core functionality.

## Running tests

```bash
pip install pytest
python -m pytest tests/ -v
```

## Project structure

```
password-generator/
├── passgen.py           # Main CLI application
├── requirements.txt     # Optional dependencies
├── tests/
│   └── test_passgen.py  # 37 unit tests
└── README.md
```

## What I learned

- `secrets` vs `random` — why cryptographic randomness matters
- Composable character set design with guaranteed character-type coverage
- Entropy calculation: `bits = length × log₂(pool_size)`
- `argparse` mutually exclusive groups
- Defensive coding for edge cases (length < 4, all types disabled)
- Grouping tests into classes with `pytest`

## Tech stack

- Python 3.8+
- `secrets` (stdlib) — cryptographic randomness
- `string` (stdlib) — character set constants
- `argparse` (stdlib) — CLI argument parsing
- `pyperclip` (optional) — clipboard support

---

Part of my [50 GitHub Projects](https://github.com/YOUR_USERNAME) portfolio challenge.
