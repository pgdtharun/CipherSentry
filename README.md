# CipherSentry

A static analysis tool that flags common cryptographic misuse patterns in Python source code
No third-party dependencies required to run it.

## Why this exists

This started as a scoped-down trial of a "crypto misuse detector" idea I was
considering for my final-year project. Building a small, working version
first — rather than just proposing the idea — let me test whether static
pattern-matching on an AST was actually a reasonable approach before
committing a full year to a larger version of it.

## What it catches

| ID | Check | Severity |
|----|-------|----------|
| CM001 | Hardcoded cryptographic secret (key/password/token/etc. assigned a literal) | HIGH |
| CM002 | ECB cipher mode | HIGH |
| CM003 | Weak hash algorithm (MD5 / SHA-1) | MEDIUM |
| CM004 | Non-cryptographic RNG (`random`) used for a security-sensitive value | MEDIUM |
| CM005 | Deprecated/weak cipher (DES, 3DES, RC4, Blowfish) | HIGH |
| CM006 | Weak key size for asymmetric encryption (RSA/DSA < 2048 bits) | HIGH |


## Install

```bash
git clone https://github.com/pgdtharun/CipherSentry.git
cd CipherSentry
pip install -e .
```

## Usage

```bash
cipher-sentry path/to/file_or_directory
cipher-sentry . --min-severity HIGH
cipher-sentry . --json > findings.json
```

Or without installing:

```bash
python -m crypto_misuse_scanner.cli samples/vulnerable/bad_crypto.py
```

### Example output

Running it against `samples/vulnerable/bad_crypto.py` (a deliberately
vulnerable file included in this repo for demo purposes):

```
[HIGH] CM005 Deprecated or weak cipher algorithm
  samples/vulnerable/bad_crypto.py:9
  > from Crypto.Cipher import AES, DES
  Imports 'DES'. DES (56-bit key) is trivially brute-forced.
  Fix: DES, 3DES, RC4, and Blowfish are deprecated or have known weaknesses. Use AES-256-GCM for new symmetric encryption.

[HIGH] CM001 Hardcoded cryptographic secret
  samples/vulnerable/bad_crypto.py:12
  > SECRET_KEY = "s3cr3t-signing-key-2024"
  Variable 'SECRET_KEY' is assigned a literal value directly in source.
  Fix: Load secrets from environment variables, a secrets manager, or a config file excluded from version control -- never as a literal in source.

[HIGH] CM002 ECB cipher mode
  samples/vulnerable/bad_crypto.py:18
  > cipher = AES.new(SECRET_KEY.encode().ljust(32, b"0"), AES.MODE_ECB)
  Cipher constructed with AES.MODE_ECB.
  Fix: ECB mode leaks patterns in the plaintext (identical blocks encrypt to identical ciphertext). Use an authenticated mode such as AES-GCM.

[MEDIUM] CM003 Weak hash algorithm (MD5/SHA-1)
  samples/vulnerable/bad_crypto.py:24
  > return hashlib.md5(password.encode()).hexdigest()
  Calls hashlib.md5(...).
  Fix: MD5 and SHA-1 are broken for collision resistance. Use SHA-256 or better for integrity checks; use a password-hashing function (bcrypt, scrypt, Argon2) for passwords -- never a bare hash.

[MEDIUM] CM004 Non-cryptographic RNG used for a security-sensitive value
  samples/vulnerable/bad_crypto.py:29
  > session_token = random.randint(100000, 999999)
  random.randint(...) result assigned to 'session_token'.
  Fix: The 'random' module is not cryptographically secure. Use the 'secrets' module or os.urandom() for keys, tokens, and nonces.

Summary: 5 HIGH, 2 MEDIUM, 0 LOW  (7 total)
```

Running it against `samples/safe/good_crypto.py` (correct usage of AES-GCM,
`secrets`, environment-based key loading, and SHA-256 for integrity rather
than passwords) produces zero findings — confirming the rules don't fire on
legitimate code.

## How it works

1. Parse the target file into a Python AST with `ast.parse` — the code is
   never executed.
2. Walk the tree once with `MisuseVisitor` (a subclass of `ast.NodeVisitor`).
   Each `visit_*` method hooks into one kind of node — `Import`, `Assign`,
   `Call` — and checks it against a rule.
3. Each match becomes a `Finding` (file, line, rule, explanation), which
   `cli.py` prints or serializes as JSON.

This is **pattern matching on syntax, not dataflow analysis**: it doesn't
trace whether a hardcoded value actually reaches a cipher constructor several
lines later, it flags the pattern directly at the point it appears. That
keeps the tool fast and dependency-free, at the cost of missing anything
that requires tracking a value across multiple statements.

## Known limitations

- **Heuristic, not proof.** A hash named `md5` used for a non-security
  checksum (e.g. a cache key) will still be flagged — the fix suggestion is
  there for you to judge, not an automatic verdict.
- **No cross-function tracing.** If a secret is passed as a function
  parameter rather than a literal in the same scope, it won't be caught.
- **No dataflow/taint analysis.** Unlike tools such as Bandit or Semgrep,
  this doesn't build a full control-flow graph — it's intentionally a
  narrower, from-scratch prototype.

## Tests

```bash
pip install -r requirements-dev.txt
pytest tests/
```

## Possible extensions

- Detect IV/nonce reuse across multiple calls (needs lightweight dataflow)
- Flag insufficient key sizes for RSA/DH key generation
- Pre-commit hook integration
- Support for JavaScript/TypeScript crypto APIs

## License

MIT — see [LICENSE](LICENSE).
