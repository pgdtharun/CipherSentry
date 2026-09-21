"""
Detection rules for common cryptographic misuse patterns in Python source code.

Each rule is defined here as data (ID, title, severity, remediation). The
AST-walking logic that actually finds these patterns lives in scanner.py.
Keeping them separate means you can review or tune the rule text without
touching the traversal code.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str  # "HIGH", "MEDIUM", "LOW"
    remediation: str


HARDCODED_SECRET = Rule(
    rule_id="CM001",
    title="Hardcoded cryptographic secret",
    severity="HIGH",
    remediation=(
        "Load secrets from environment variables, a secrets manager, or a "
        "config file excluded from version control -- never as a literal in source."
    ),
)

WEAK_CIPHER_MODE_ECB = Rule(
    rule_id="CM002",
    title="ECB cipher mode",
    severity="HIGH",
    remediation=(
        "ECB mode leaks patterns in the plaintext (identical blocks encrypt to "
        "identical ciphertext). Use an authenticated mode such as AES-GCM."
    ),
)

WEAK_HASH = Rule(
    rule_id="CM003",
    title="Weak hash algorithm (MD5/SHA-1)",
    severity="MEDIUM",
    remediation=(
        "MD5 and SHA-1 are broken for collision resistance. Use SHA-256 or "
        "better for integrity checks; use a password-hashing function "
        "(bcrypt, scrypt, Argon2) for passwords -- never a bare hash."
    ),
)

INSECURE_RANDOM = Rule(
    rule_id="CM004",
    title="Non-cryptographic RNG used for a security-sensitive value",
    severity="MEDIUM",
    remediation=(
        "The 'random' module is not cryptographically secure. Use the "
        "'secrets' module or os.urandom() for keys, tokens, and nonces."
    ),
)

WEAK_CIPHER_ALGORITHM = Rule(
    rule_id="CM005",
    title="Deprecated or weak cipher algorithm",
    severity="HIGH",
    remediation=(
        "DES, 3DES, RC4, and Blowfish are deprecated or have known "
        "weaknesses. Use AES-256-GCM for new symmetric encryption."
    ),
)

PARSE_ERROR = Rule(
    rule_id="CM000",
    title="File failed to parse",
    severity="LOW",
    remediation="Fix the syntax error and re-scan.",
)

WEAK_KEY_SIZE = Rule(
    rule_id="CM006",
    title="Weak key size for asymmetric encryption",
    severity="HIGH",
    remediation=(
        "The key size doesn't meet the minimum requirement. "
        "The minimum required key size is RSA 2048 bits; ECC is a modern alternative."
    ),
)


RULES = [
    HARDCODED_SECRET,
    WEAK_CIPHER_MODE_ECB,
    WEAK_HASH,
    INSECURE_RANDOM,
    WEAK_CIPHER_ALGORITHM,
    WEAK_KEY_SIZE,
]













