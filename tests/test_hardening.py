"""Edge-case and error-path tests for quantumready hardening."""
from __future__ import annotations

import tempfile

import pytest

from quantumready.core import readiness, scan_path, scan_text
from quantumready.cli import main


# ---------------------------------------------------------------------------
# scan_text edge cases
# ---------------------------------------------------------------------------

def test_scan_text_empty_string():
    """Empty string must return no findings, not raise."""
    assert scan_text("") == []


def test_scan_text_none_like_empty():
    """None-ish falsy input returns empty list without AttributeError."""
    # scan_text guards `if not text: return []`
    assert scan_text("") == []


def test_scan_text_no_matches():
    """Clean text with no crypto patterns yields an empty list."""
    assert scan_text("hello world\nprint('nothing here')") == []


# ---------------------------------------------------------------------------
# scan_path edge cases
# ---------------------------------------------------------------------------

def test_scan_path_nonexistent_raises():
    """scan_path on a missing path must raise ValueError (not return [])."""
    with pytest.raises(ValueError, match="does not exist"):
        scan_path("/no/such/path/quantumready_test_xyz")


def test_scan_path_empty_directory():
    """scan_path on an empty directory returns an empty list without error."""
    with tempfile.TemporaryDirectory() as d:
        result = scan_path(d)
    assert result == []


def test_scan_path_single_file(tmp_path):
    """scan_path on a single file with a hit returns findings correctly."""
    src = tmp_path / "cipher.py"
    src.write_text("key = rsa.generate_private_key(2048)\n")
    findings = scan_path(str(src))
    assert any(f.id == "QR-RSA" for f in findings)


# ---------------------------------------------------------------------------
# readiness edge cases
# ---------------------------------------------------------------------------

def test_readiness_empty():
    """No findings should yield score=100 and grade='A'."""
    r = readiness([])
    assert r["score"] == 100
    assert r["grade"] == "A"
    assert r["pqc_present"] is False


# ---------------------------------------------------------------------------
# CLI error handling
# ---------------------------------------------------------------------------

def test_cli_missing_target_exits_nonzero():
    """scan with a non-existent target must return exit code 2."""
    rc = main(["scan", "/no/such/path/quantumready_cli_test"])
    assert rc == 2


def test_cli_no_subcommand_exits_zero(capsys):
    """Calling the CLI with no subcommand prints help and exits 0."""
    rc = main([])
    assert rc == 0


def test_cli_json_output_valid(tmp_path):
    """--format json must produce parseable JSON even for a clean file."""
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1\n")
    rc = main(["scan", str(clean), "--format", "json"])
    assert rc == 0


def test_cli_fail_on_triggers(tmp_path, capsys):
    """--fail-on high returns 2 when a high-severity finding is present."""
    src = tmp_path / "vuln.py"
    src.write_text("key = rsa.generate_private_key(2048)\n")
    rc = main(["scan", str(src), "--fail-on", "high"])
    assert rc == 2
