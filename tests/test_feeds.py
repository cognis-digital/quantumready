"""Offline tests for the CISA-KEV / NVD feed enrichment.

NO NETWORK: COGNIS_FEEDS_CACHE points at the committed trimmed fixtures and every
feed call uses offline=True, so the suite is hermetic and CI-safe.
"""
import json
from pathlib import Path

import pytest

FIX = Path(__file__).resolve().parent / "fixtures" / "feeds-cache"


@pytest.fixture(autouse=True)
def _offline_cache(monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(FIX))
    # drop any import-time cached module state
    import importlib
    import quantumready.datafeeds as df
    importlib.reload(df)
    yield


def _expected_ids():
    return set(json.loads((FIX / "_expected.json").read_text())["crypto_kev_ids"])


def test_fixtures_present():
    assert (FIX / "cisa-kev.data").exists()
    assert (FIX / "nvd-cve.data").exists()
    assert _expected_ids(), "fixture must contain at least one KEV-listed crypto CVE"


def test_only_relevant_feeds_allowed():
    from quantumready import feeds as fm
    assert fm.RELEVANT_FEEDS == ["cisa-kev", "nvd-cve"]
    with pytest.raises(ValueError):
        fm.feed_get("opensky-states", offline=True)  # not wired into this tool


def test_kev_index_offline():
    from quantumready import feeds as fm
    idx = fm.kev_index(offline=True)
    assert idx and all(k == k.upper() for k in idx)
    assert _expected_ids() <= set(idx)  # the crypto CVEs are in the KEV fixture


def test_offline_get_no_network():
    from quantumready import feeds as fm
    kev = fm.feed_get("cisa-kev", offline=True)
    assert kev["vulnerabilities"]
    nvd = fm.feed_get("nvd-cve", offline=True)
    assert nvd["vulnerabilities"]


def test_enrichment_flags_known_exploited_offline():
    """The core enrichment: a codebase using RSA/ECC -> the actively-exploited
    (KEV) CVEs for those families, served entirely from cache."""
    from quantumready.core import scan_text
    from quantumready import feeds as fm

    # crypto the scanner will flag as quantum-vulnerable, across several families
    findings = scan_text(
        "import rsa\nk = rsa.generate_private_key(2048)\n"
        "curve = secp256k1  # ECDSA\n"
        "kex = diffie-hellman group14\n"
    )
    fam_ids = {f.id for f in findings}
    assert "QR-RSA" in fam_ids and "QR-ECC" in fam_ids and "QR-DH" in fam_ids

    report = fm.enrich_findings(findings, offline=True)
    assert report["offline"] is True
    assert report["feeds"] == ["cisa-kev", "nvd-cve"]
    # at least one detected family resolved KEV-listed (actively-exploited) CVEs
    assert report["summary"]["total_priority_cves"] >= 1
    pr_ids = {h["id"] for h in report["priority"]}
    assert pr_ids & _expected_ids(), "enrichment must surface the known KEV crypto CVE"
    for h in report["priority"]:
        assert h["known_exploited"] is True
        assert h["family"] in report["summary"]["families_detected"]


def test_enrichment_empty_when_no_vuln_crypto():
    """PQC-only code (ML-KEM) detects no quantum-vulnerable family -> no priority CVEs."""
    from quantumready.core import scan_text
    from quantumready import feeds as fm

    findings = scan_text("use ML-KEM (x25519mlkem768) and ML-DSA only\n")
    report = fm.enrich_findings(findings, offline=True)
    assert report["summary"]["total_priority_cves"] == 0


def test_cli_feeds_get_offline(capsys, monkeypatch):
    from quantumready.cli import main
    rc = main(["feeds", "get", "cisa-kev", "--offline"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "vulnerabilities" in out


def test_cli_feeds_list(capsys):
    from quantumready.cli import main
    rc = main(["feeds", "list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "cisa-kev" in out and "nvd-cve" in out


def test_cli_scan_enrich_offline_json(capsys, tmp_path):
    from quantumready.cli import main
    src = tmp_path / "svc.py"
    src.write_text("k = rsa.generate_private_key(2048)\ncurve=secp256k1\n")
    rc = main(["scan", str(src), "--format", "json", "--enrich", "--offline"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert "enrichment" in data
    assert data["enrichment"]["summary"]["total_priority_cves"] >= 1
