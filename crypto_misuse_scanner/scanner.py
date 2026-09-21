"""
AST-based visitor that walks a parsed Python file looking for the crypto
misuse patterns defined in rules.py, plus the driver that runs it across
a file or a whole directory tree.

How it works, at a glance:
  1. Parse the source into a Python AST (ast.parse) -- no execution involved.
  2. Walk the tree once with MisuseVisitor, a subclass of ast.NodeVisitor.
     Each visit_* method below hooks into one kind of AST node (Import,
     Assign, Call, ...) and checks it against a rule.
  3. Each match becomes a Finding with the file, line number, rule, and a
     one-line explanation, which cli.py then prints or serializes as JSON.

This is static analysis, not dataflow analysis: it doesn't trace whether a
hardcoded value actually reaches a cipher constructor, it flags the pattern
directly (e.g. "a variable named like a secret was assigned a literal").
That keeps it fast and dependency-free, at the cost of some false positives
on unusual code -- see the README for known limitations.
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .rules import (
    HARDCODED_SECRET,
    WEAK_CIPHER_MODE_ECB,
    WEAK_HASH,
    INSECURE_RANDOM,
    WEAK_CIPHER_ALGORITHM,
    PARSE_ERROR,
    Rule,
    WEAK_KEY_SIZE,
)

WEAK_HASH_NAMES = {"md5", "sha1"}

WEAK_CIPHER_MODULES = {
    "DES": "DES (56-bit key) is trivially brute-forced.",
    "DES3": "3DES is deprecated (NIST disallows it after 2023).",
    "ARC4": "RC4 has multiple known biases and is deprecated.",
    "Blowfish": "Blowfish's 64-bit block size is vulnerable to birthday attacks (SWEET32).",
}

MIN_SECRET_LITERAL_LEN = 4  # ignore trivially short / placeholder-ish literals

SECRET_KEYWORDS = {
    "secret", "password", "passwd", "pwd", "key", "iv", "nonce",
    "salt", "token", "apikey", "privatekey", "credential", "credentials",
}

_CAMEL_BOUNDARY_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"


def _split_identifier(name: str) -> List[str]:
    """
    Split a snake_case or camelCase identifier into lowercase word parts.

    e.g. "SECRET_KEY" -> ["secret", "key"]
         "sessionToken" -> ["session", "token"]
         "give_up" -> ["give", "up"]   (correctly NOT matching "iv")
    """
    parts: List[str] = []
    for chunk in name.split("_"):
        if not chunk:
            continue
        current = chunk[0]
        for ch in chunk[1:]:
            if ch.isupper() and current and current[-1] in _CAMEL_BOUNDARY_CHARS:
                parts.append(current.lower())
                current = ch
            else:
                current += ch
        parts.append(current.lower())
    return parts


def _looks_like_secret_name(name: Optional[str]) -> bool:
    if not name:
        return False
    words = set(_split_identifier(name))
    return bool(words & SECRET_KEYWORDS)


@dataclass
class Finding:
    file: str
    line: int
    rule: Rule
    detail: str
    snippet: str

    def format(self, use_color: bool = True) -> str:
        colors = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}
        reset = "\033[0m" if use_color else ""
        color = colors.get(self.rule.severity, "") if use_color else ""
        return (
            f"{color}[{self.rule.severity}] {self.rule.rule_id} "
            f"{self.rule.title}{reset}\n"
            f"  {self.file}:{self.line}\n"
            f"  > {self.snippet}\n"
            f"  {self.detail}\n"
            f"  Fix: {self.rule.remediation}\n"
        )


class MisuseVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, source_lines: List[str]):
        self.filename = filename
        self.source_lines = source_lines
        self.findings: List[Finding] = []
        self._imports_random_module = False  # tracks 'import random'

    def _snippet(self, node: ast.AST) -> str:
        try:
            return self.source_lines[node.lineno - 1].strip()
        except (IndexError, AttributeError):
            return ""

    def _add(self, node: ast.AST, rule: Rule, detail: str) -> None:
        self.findings.append(
            Finding(
                file=self.filename,
                line=getattr(node, "lineno", 0),
                rule=rule,
                detail=detail,
                snippet=self._snippet(node),
            )
        )

    # ---- imports ---------------------------------------------------
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name == "random":
                self._imports_random_module = True
            for module_name, reason in WEAK_CIPHER_MODULES.items():
                if alias.name.endswith(module_name):
                    self._add(node, WEAK_CIPHER_ALGORITHM, f"Imports '{alias.name}'. {reason}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        for alias in node.names:
            if alias.name in WEAK_CIPHER_MODULES:
                reason = WEAK_CIPHER_MODULES[alias.name]
                self._add(node, WEAK_CIPHER_ALGORITHM, f"Imports '{alias.name}'. {reason}")
        self.generic_visit(node)

    # ---- assignments (hardcoded secrets) ----------------------------
    def visit_Assign(self, node: ast.Assign):
        value = node.value
        is_literal = isinstance(value, ast.Constant) and isinstance(value.value, (str, bytes))
        if is_literal and len(value.value) >= MIN_SECRET_LITERAL_LEN:
            for target in node.targets:
                name = self._target_name(target)
                if _looks_like_secret_name(name):
                    self._add(
                        node, HARDCODED_SECRET,
                        f"Variable '{name}' is assigned a literal value directly in source.",
                    )
        self.generic_visit(node)

    @staticmethod
    def _target_name(target: ast.AST) -> Optional[str]:
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            return target.attr
        return None

    # ---- calls: ECB mode, weak hash, insecure random, secret kwargs --
    def visit_Call(self, node: ast.Call):
        func = node.func
        full_name = self._dotted_name(func)

        # ECB mode passed as a positional/keyword arg, e.g. AES.new(key, AES.MODE_ECB)
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            arg_name = self._dotted_name(arg)
            if arg_name and arg_name.endswith("MODE_ECB"):
                self._add(node, WEAK_CIPHER_MODE_ECB, f"Cipher constructed with {arg_name}.")
        # ECB mode via the `cryptography` library, e.g. modes.ECB(iv)
        if full_name == "modes.ECB":
            self._add(node, WEAK_CIPHER_MODE_ECB, f"Cipher mode set via {full_name}(...).")

        # Weak hash: hashlib.md5(...)/hashlib.sha1(...), or bare md5(...)/sha1(...)
        if isinstance(func, ast.Attribute) and func.attr in WEAK_HASH_NAMES:
            self._add(node, WEAK_HASH, f"Calls {full_name}(...).")
        elif isinstance(func, ast.Name) and func.id in WEAK_HASH_NAMES:
            self._add(node, WEAK_HASH, f"Calls {func.id}(...) (imported directly from hashlib).")

        # Insecure RNG: random.<fn>(...) whose result feeds a security-named variable
        if (
            self._imports_random_module
            and isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "random"
        ):
            parent_name = getattr(node, "_assign_target", None)
            if _looks_like_secret_name(parent_name):
                self._add(
                    node, INSECURE_RANDOM,
                    f"random.{func.attr}(...) result assigned to '{parent_name}'.",
                )

        # Hardcoded secret passed directly as a keyword, e.g. AES.new(key=b"...")
        for kw in node.keywords:
            if kw.arg and _looks_like_secret_name(kw.arg):
                if (
                    isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, (str, bytes))
                    and len(kw.value.value) >= MIN_SECRET_LITERAL_LEN
                ):
                    self._add(
                        node, HARDCODED_SECRET,
                        f"Argument '{kw.arg}' passed a literal value directly.",
                    )
        # --- weak key size (CM006) ---
        if full_name and "generate" in full_name:
            key_size = None
            for kw in node.keywords:
                if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                    key_size = kw.value.value
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
                    key_size = arg.value
            if key_size is not None and key_size < 2048:
                self._add(node, WEAK_KEY_SIZE, f"Key generated with {key_size}-bit size.")            
        self.generic_visit(node)

    @staticmethod
    def _dotted_name(node: Optional[ast.AST]) -> Optional[str]:
        if isinstance(node, ast.Attribute):
            base = MisuseVisitor._dotted_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Name):
            return node.id
        return None


def _annotate_assign_targets(tree: ast.AST) -> None:
    """
    Pre-pass: tag each Call node inside an Assign's value with the target
    variable name, so visit_Call can check 'random.random() assigned to
    session_token' without a second full traversal.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            name = MisuseVisitor._target_name(node.targets[0])
            for sub in ast.walk(node.value):
                if isinstance(sub, ast.Call):
                    sub._assign_target = name  # type: ignore[attr-defined]


def scan_file(path: Path) -> List[Finding]:
    source = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as e:
        return [
            Finding(
                file=str(path), line=e.lineno or 0,
                rule=PARSE_ERROR, detail=str(e), snippet="",
            )
        ]
    _annotate_assign_targets(tree)
    visitor = MisuseVisitor(str(path), source.splitlines())
    visitor.visit(tree)
    return visitor.findings


def scan_path(target: Path) -> List[Finding]:
    findings: List[Finding] = []
    files = [target] if target.is_file() else sorted(target.rglob("*.py"))
    for f in files:
        findings.extend(scan_file(f))
    return findings
