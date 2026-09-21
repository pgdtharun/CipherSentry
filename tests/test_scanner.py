"""
Tests for the misuse scanner.

Run with: pytest
"""

from pathlib import Path

from crypto_misuse_scanner.scanner import scan_path, _looks_like_secret_name

SAMPLES = Path(__file__).parent.parent / "samples"


def _rule_ids(findings):
    return {f.rule.rule_id for f in findings}


def test_vulnerable_sample_triggers_all_rules():
    findings = scan_path(SAMPLES / "vulnerable" / "bad_crypto.py")
    ids = _rule_ids(findings)
    assert "CM001" in ids  # hardcoded secret
    assert "CM002" in ids  # ECB mode
    assert "CM003" in ids  # weak hash
    assert "CM004" in ids  # insecure random
    assert "CM005" in ids  # weak cipher (DES)
    assert "CM006" in ids  # weak RSA/DSA key size


def test_safe_sample_triggers_nothing():
    findings = scan_path(SAMPLES / "safe" / "good_crypto.py")
    assert findings == []


def test_scan_directory_covers_both_files():
    findings = scan_path(SAMPLES)
    files_scanned = {f.file for f in findings}
    assert any("bad_crypto.py" in f for f in files_scanned)


def test_secret_name_matcher_handles_snake_case():
    assert _looks_like_secret_name("SECRET_KEY")
    assert _looks_like_secret_name("api_key")
    assert _looks_like_secret_name("session_token")


def test_secret_name_matcher_handles_camel_case():
    assert _looks_like_secret_name("sessionToken")
    assert _looks_like_secret_name("apiKey")


def test_secret_name_matcher_avoids_false_positives():
    # "iv" as a whole word should match, but words that merely CONTAIN
    # "iv" as a substring (give, live, drive) must not.
    assert _looks_like_secret_name("iv")
    assert not _looks_like_secret_name("give_up")
    assert not _looks_like_secret_name("live_data")
    assert not _looks_like_secret_name("drive_path")


def test_secret_name_matcher_ignores_unrelated_names():
    assert not _looks_like_secret_name("username")
    assert not _looks_like_secret_name("counter")
    assert not _looks_like_secret_name(None)
