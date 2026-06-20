"""
Secure Password Generator
─────────────────────────
Uses Python's `secrets` module — cryptographically secure, safe for real passwords.

Usage examples:
  python passgen.py                        # 16-char password, all character types
  python passgen.py --length 24            # 24 characters
  python passgen.py --no-symbols           # letters + digits only
  python passgen.py --no-ambiguous         # exclude 0/O/l/1/I (easy to misread)
  python passgen.py --batch 5              # generate 5 passwords at once
  python passgen.py --pin 6               # numeric PIN
  python passgen.py --phrase              # memorable word-based passphrase
  python passgen.py --check "MyP@ssw0rd" # score an existing password
  python passgen.py --copy                # copy result to clipboard
"""

import argparse
import math
import secrets
import string
import sys

# ── Try clipboard support (optional dependency) ───────────────────────────────
try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
#  Character sets
# ─────────────────────────────────────────────────────────────────────────────

LOWERCASE   = string.ascii_lowercase          # a-z
UPPERCASE   = string.ascii_uppercase          # A-Z
DIGITS      = string.digits                   # 0-9
SYMBOLS     = "!@#$%^&*()-_=+[]{}|;:,.<>?"   # curated — avoids shell-tricky chars
AMBIGUOUS   = set("0Ol1I")                    # visually confusable characters

# Word list for passphrases (kept short — real tools use EFF wordlist)
WORD_LIST = [
    "apple", "brave", "cloud", "dance", "eagle", "flame", "grace", "honor",
    "ivory", "jungle", "karma", "lemon", "maple", "noble", "ocean", "pixel",
    "quest", "river", "stone", "tiger", "ultra", "vivid", "waltz", "xenon",
    "yacht", "zebra", "amber", "blaze", "crisp", "dusty", "ember", "frost",
    "gleam", "haven", "inlet", "jewel", "knack", "lunar", "minor", "north",
    "onset", "prism", "quirk", "radar", "swift", "thorn", "umbra", "vault",
    "wheat", "xylem", "yearn", "zonal", "acute", "bench", "cedar", "delta",
]


# ─────────────────────────────────────────────────────────────────────────────
#  Core password builders
# ─────────────────────────────────────────────────────────────────────────────

def build_charset(use_lower=True, use_upper=True, use_digits=True,
                  use_symbols=True, no_ambiguous=False):
    """
    Assemble a character pool from enabled options.
    Returns (charset_string, list_of_required_chars).

    The 'required' list ensures at least one char from each enabled group
    appears in the final password — guaranteed by the caller.
    """
    pool     = ""
    required = []

    if use_lower:
        chars = LOWERCASE
        if no_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS)
        pool += chars
        required.append(secrets.choice(chars))

    if use_upper:
        chars = UPPERCASE
        if no_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS)
        pool += chars
        required.append(secrets.choice(chars))

    if use_digits:
        chars = DIGITS
        if no_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS)
        pool += chars
        required.append(secrets.choice(chars))

    if use_symbols:
        pool += SYMBOLS
        required.append(secrets.choice(SYMBOLS))

    if not pool:
        raise ValueError("At least one character type must be enabled.")

    return pool, required


def generate_password(length=16, use_lower=True, use_upper=True,
                      use_digits=True, use_symbols=True, no_ambiguous=False):
    """
    Generate a single secure password.

    Strategy:
      1. Pick one char from each required group (guarantees diversity)
      2. Fill remaining slots from the full pool
      3. Shuffle with secrets.SystemRandom (cryptographically secure)
    """
    if length < 4:
        raise ValueError("Password length must be at least 4.")

    pool, required = build_charset(
        use_lower, use_upper, use_digits, use_symbols, no_ambiguous
    )

    # If required chars alone exceed length, truncate required list
    required = required[:length]

    # Fill the rest
    rng = secrets.SystemRandom()
    remaining = [secrets.choice(pool) for _ in range(length - len(required))]

    # Combine and shuffle — shuffle is the key step that removes positional bias
    password_chars = required + remaining
    rng.shuffle(password_chars)

    return "".join(password_chars)


def generate_pin(length=6):
    """Generate a numeric-only PIN."""
    if length < 4:
        raise ValueError("PIN length must be at least 4.")
    return "".join(secrets.choice(DIGITS) for _ in range(length))


def generate_passphrase(words=4, separator="-", capitalize=True, add_number=True):
    """
    Generate a memorable word-based passphrase.
    e.g.  Maple-River-Frost-Eagle-7
    """
    chosen = [secrets.choice(WORD_LIST) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    phrase = separator.join(chosen)
    if add_number:
        phrase += separator + str(secrets.randbelow(90) + 10)  # 10–99
    return phrase


# ─────────────────────────────────────────────────────────────────────────────
#  Strength checker
# ─────────────────────────────────────────────────────────────────────────────

def score_password(password):
    """
    Return a dict with entropy estimate, score (0-100), and a label.

    Entropy = log2(pool_size ^ length)
    This is the real measure used by security tools — not silly rules like
    "must contain a symbol".
    """
    has_lower   = any(c in LOWERCASE for c in password)
    has_upper   = any(c in UPPERCASE for c in password)
    has_digit   = any(c in DIGITS    for c in password)
    has_symbol  = any(c in SYMBOLS   for c in password)

    pool_size = 0
    if has_lower:   pool_size += 26
    if has_upper:   pool_size += 26
    if has_digit:   pool_size += 10
    if has_symbol:  pool_size += len(SYMBOLS)

    pool_size = max(pool_size, 1)
    entropy   = len(password) * math.log2(pool_size)

    # Score out of 100 based on entropy thresholds
    if entropy < 28:
        label, score, color = "Very Weak",  10, "🔴"
    elif entropy < 36:
        label, score, color = "Weak",       30, "🟠"
    elif entropy < 60:
        label, score, color = "Fair",       55, "🟡"
    elif entropy < 80:
        label, score, color = "Strong",     80, "🟢"
    else:
        label, score, color = "Very Strong", 100, "✅"

    return {
        "password":   password,
        "length":     len(password),
        "entropy":    round(entropy, 1),
        "pool_size":  pool_size,
        "score":      score,
        "label":      label,
        "color":      color,
        "has_lower":  has_lower,
        "has_upper":  has_upper,
        "has_digit":  has_digit,
        "has_symbol": has_symbol,
    }


def print_strength_report(result):
    bar_filled = round(result["score"] / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)

    print(f"""
  Password : {result['password']}
  Length   : {result['length']} characters
  Entropy  : {result['entropy']} bits
  Pool     : {result['pool_size']} unique characters

  Strength : {result['color']} {result['label']}
  [{bar}]

  Contains : {'✅' if result['has_lower'] else '❌'} lowercase  \
{'✅' if result['has_upper'] else '❌'} uppercase  \
{'✅' if result['has_digit'] else '❌'} digits  \
{'✅' if result['has_symbol'] else '❌'} symbols
""")


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="passgen",
        description="Generate cryptographically secure passwords",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python passgen.py                   # 16-char default\n"
            "  python passgen.py --length 32        # 32 characters\n"
            "  python passgen.py --no-symbols       # no special chars\n"
            "  python passgen.py --no-ambiguous     # exclude 0/O/l/1/I\n"
            "  python passgen.py --batch 10         # 10 passwords\n"
            "  python passgen.py --pin 4            # 4-digit PIN\n"
            "  python passgen.py --phrase           # word passphrase\n"
            "  python passgen.py --check 'abc123'   # score a password\n"
        ),
    )

    # Mode group — only one of these at a time
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--pin",    type=int, metavar="LENGTH",
                      help="Generate a numeric PIN of given length")
    mode.add_argument("--phrase", action="store_true",
                      help="Generate a memorable word passphrase")
    mode.add_argument("--check",  metavar="PASSWORD",
                      help="Check the strength of an existing password")

    # Standard password options
    parser.add_argument("--length",       "-l", type=int, default=16,
                        help="Password length (default: 16)")
    parser.add_argument("--batch",        "-b", type=int, default=1,
                        help="Number of passwords to generate (default: 1)")
    parser.add_argument("--no-symbols",   action="store_true",
                        help="Exclude symbols")
    parser.add_argument("--no-lower",     action="store_true",
                        help="Exclude lowercase letters")
    parser.add_argument("--no-upper",     action="store_true",
                        help="Exclude uppercase letters")
    parser.add_argument("--no-digits",    action="store_true",
                        help="Exclude digits")
    parser.add_argument("--no-ambiguous", action="store_true",
                        help="Exclude visually ambiguous chars (0/O/l/1/I)")

    # Passphrase options
    parser.add_argument("--words",     type=int, default=4,
                        help="Number of words in passphrase (default: 4)")
    parser.add_argument("--separator", default="-",
                        help="Separator between words (default: -)")

    # Output
    parser.add_argument("--copy", "-c", action="store_true",
                        help="Copy result to clipboard")
    parser.add_argument("--no-strength", action="store_true",
                        help="Skip strength report (just print password)")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # ── Mode: check existing password ────────────────────────────────────────
    if args.check:
        result = score_password(args.check)
        print_strength_report(result)
        return

    # ── Mode: PIN ────────────────────────────────────────────────────────────
    if args.pin:
        for _ in range(args.batch):
            pin = generate_pin(args.pin)
            print(pin)
        return

    # ── Mode: Passphrase ─────────────────────────────────────────────────────
    if args.phrase:
        for _ in range(args.batch):
            phrase = generate_passphrase(words=args.words, separator=args.separator)
            print(phrase)
        return

    # ── Mode: Standard password ──────────────────────────────────────────────
    passwords = []
    for _ in range(args.batch):
        try:
            pw = generate_password(
                length      = args.length,
                use_lower   = not args.no_lower,
                use_upper   = not args.no_upper,
                use_digits  = not args.no_digits,
                use_symbols = not args.no_symbols,
                no_ambiguous= args.no_ambiguous,
            )
        except ValueError as e:
            print(f"❌ Error: {e}")
            sys.exit(1)
        passwords.append(pw)

    # Print results
    if args.batch > 1:
        for i, pw in enumerate(passwords, 1):
            print(f"  {i:>2}. {pw}")
    else:
        pw = passwords[0]
        if args.no_strength:
            print(pw)
        else:
            result = score_password(pw)
            print_strength_report(result)

    # Clipboard (copies the first password)
    if args.copy:
        if CLIPBOARD_AVAILABLE:
            pyperclip.copy(passwords[0])
            print("  📋 Copied to clipboard!")
        else:
            print("  ⚠️  Clipboard unavailable. Install pyperclip: pip install pyperclip")


if __name__ == "__main__":
    main()
