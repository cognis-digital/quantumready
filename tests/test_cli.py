"""End-to-end CLI tests (`quantumready.cli.main`). Offline, stdlib only.

Feed-dependent paths point COGNIS_FEEDS_CACHE at the committed trimmed fixtures
and pass --offline, so nothing touches the network.
"""
import json
from pathlib import Path

import pytest

from quantumready.cli import main

FIX = Path(__file__).resolve().parent / "fixtures" / "feeds-cache"


@pytest.fixture(autouse=True)
def _offline_cache(monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(FIX))
    import importlib
    import quantumready.datafeeds as df
    importlib.reload(df)
    yield


# --------------------------------------------------------------------------- #
# top-level / help / version
# --------------------------------------------------------------------------- #
def test_no_args_prints_help_rc0(capsys):
    rc = main([])
    assert rc == 0
    assert "quantumready" in capsys.readouterr().out.lower()


def test_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert "quantumready" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# scan: formats
# --------------------------------------------------------------------------- #
def test_scan_table_format(capsys, tmp_path):
    src = tmp_path / "s.py"
    src.write_text("k = rsa.generate_private_key(2048)\ncurve=secp256k1\n")
    rc = main(["scan", str(src)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "QR-RSA" in out
    assert "PQC readiness:" in out


def test_scan_json_format(capsys, tmp_path):
    src = tmp_path / "s.py"
    src.write_text("k = rsa.generate_private_key(2048)\n")
    rc = main(["scan", str(src), "--format", "json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["tool"] == "quantumready"
    assert any(f["id"] == "QR-RSA" for f in doc["findings"])


def test_scan_sarif_format(capsys, tmp_path):
    src = tmp_path / "s.py"
    src.write_text("rsa_1024\n")
    rc = main(["scan", str(src), "--format", "sarif"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"]


# --------------------------------------------------------------------------- #
# scan: --fail-on exit codes
# --------------------------------------------------------------------------- #
def test_fail_on_high_returns_2(tmp_path):
    src = tmp_path / "s.conf"
    src.write_text("ssh-rsa AAAA\n")
    assert main(["scan", str(src), "--fail-on", "high"]) == 2


def test_fail_on_critical_not_triggered_by_high(tmp_path):
    src = tmp_path / "s.conf"
    src.write_text("ssh-rsa AAAA\n")  # high, not critical
    assert main(["scan", str(src), "--fail-on", "critical"]) == 0


def test_fail_on_critical_triggered(tmp_path):
    src = tmp_path / "s.conf"
    src.write_text("rsa_512 weak\n")
    assert main(["scan", str(src), "--fail-on", "critical"]) == 2


def test_no_fail_on_returns_0_even_with_findings(tmp_path):
    src = tmp_path / "s.conf"
    src.write_text("rsa_512 weak\n")
    assert main(["scan", str(src)]) == 0


def test_clean_scan_fail_on_high_returns_0(tmp_path):
    src = tmp_path / "clean.txt"
    src.write_text("only ml-kem here\n")
    assert main(["scan", str(src), "--fail-on", "high"]) == 0


# --------------------------------------------------------------------------- #
# feeds subcommands (offline)
# --------------------------------------------------------------------------- #
def test_feeds_no_subcommand_prints_help(capsys):
    rc = main(["feeds"])
    assert rc == 0
    assert "feeds" in capsys.readouterr().out.lower()


def test_feeds_list_shows_two_feeds(capsys):
    rc = main(["feeds", "list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "cisa-kev" in out and "nvd-cve" in out


def test_feeds_get_offline(capsys):
    rc = main(["feeds", "get", "cisa-kev", "--offline"])
    assert rc == 0
    assert "vulnerabilities" in capsys.readouterr().out


def test_feeds_get_rejects_unknown_feed():
    with pytest.raises(SystemExit):
        # argparse choices restrict to RELEVANT_FEEDS
        main(["feeds", "get", "opensky-states", "--offline"])


# --------------------------------------------------------------------------- #
# scan --enrich (offline)
# --------------------------------------------------------------------------- #
def test_scan_enrich_json_offline(capsys, tmp_path):
    src = tmp_path / "svc.py"
    src.write_text("k = rsa.generate_private_key(2048)\ncurve=secp256k1\n")
    rc = main(["scan", str(src), "--format", "json", "--enrich", "--offline"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert "enrichment" in doc
    assert doc["enrichment"]["offline"] is True
    assert doc["enrichment"]["summary"]["total_priority_cves"] >= 1


def test_scan_enrich_table_offline(capsys, tmp_path):
    src = tmp_path / "svc.py"
    src.write_text("k = rsa.generate_private_key(2048)\n")
    rc = main(["scan", str(src), "--enrich", "--offline"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CISA-KEV" in out or "Actively-exploited" in out
