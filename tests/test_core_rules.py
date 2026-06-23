"""Exhaustive behavior tests for the detection rules and readiness scoring.

Every rule id is exercised positively, key false-positives are pinned negatively,
and the readiness grade boundaries (A/B/C/D/F) are checked at their thresholds.
All offline, stdlib only.
"""
import json

import pytest

from quantumready.core import (
    RULES,
    Finding,
    readiness,
    scan_path,
    scan_text,
    to_json,
    TOOL_NAME,
    TOOL_VERSION,
)


def ids(findings):
    return {f.id for f in findings}


# --------------------------------------------------------------------------- #
# rule table integrity
# --------------------------------------------------------------------------- #
def test_rule_table_has_eight_unique_rules():
    rule_ids = [r[0] for r in RULES]
    assert len(rule_ids) == 8
    assert len(set(rule_ids)) == 8


def test_every_rule_has_label_and_recommendation():
    for rid, sev, rx, label, rec in RULES:
        assert rid.startswith("QR-")
        assert sev in {"critical", "high", "medium", "low", "info"}
        assert label and isinstance(label, str)
        assert rec and isinstance(rec, str)


def test_tool_identity_constants():
    assert TOOL_NAME == "quantumready"
    assert TOOL_VERSION.count(".") == 2  # semver-ish


# --------------------------------------------------------------------------- #
# positive detections — one per rule id
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "text,expected_id",
    [
        ("key = rsa.generate_private_key(2048)", "QR-RSA"),
        ("openssl genrsa -out key.pem 2048", "QR-RSA"),
        ("authorized_keys: ssh-rsa AAAAB3", "QR-RSA"),
        ("padding = PKCS1", "QR-RSA"),
        ("curve = secp256k1", "QR-ECC"),
        ("name = prime256v1", "QR-ECC"),
        ("sig = ed25519", "QR-ECC"),
        ("kex = x25519", "QR-ECC"),
        ("KexAlgorithms diffie-hellman-group14-sha256", "QR-DH"),
        ("ssl_dhparam /etc/dhparam.pem", "QR-DH"),
        ("group = ffdhe", "QR-DH"),
        ("HostKey uses dsa key", "QR-DSA"),
        ("cert signed with DSS", "QR-DSA"),
        ("rsa_1024 legacy modulus", "QR-WEAKRSA"),
        ("RSA 512 bit key", "QR-WEAKRSA"),
        ("cipher TLS_RSA enabled", "QR-TLS"),
        ("cipher kRSA only", "QR-TLS"),
        ("kem = x25519mlkem768", "QR-GOODKEM"),
        ("using kyber kem", "QR-GOODKEM"),
        ("signature = ml-dsa-65", "QR-GOODSIG"),
        ("root uses sphincs+", "QR-GOODSIG"),
    ],
)
def test_rule_fires(text, expected_id):
    assert expected_id in ids(scan_text(text))


# --------------------------------------------------------------------------- #
# negative cases / false-positive guards
# --------------------------------------------------------------------------- #
def test_ml_dsa_does_not_trip_legacy_dsa():
    f = scan_text("ml-dsa-87 and slh-dsa-shake-256s")
    assert "QR-DSA" not in ids(f)
    assert "QR-GOODSIG" in ids(f)


def test_ecdsa_is_ecc_not_dsa():
    f = scan_text("alg = ecdsa-with-SHA384")
    assert "QR-ECC" in ids(f)
    assert "QR-DSA" not in ids(f)


def test_clean_text_no_findings():
    assert scan_text("the quick brown fox jumps over the lazy dog") == []


def test_empty_text_no_findings():
    assert scan_text("") == []


def test_strong_rsa_not_weak():
    f = scan_text("rsa 4096 bit key")
    assert "QR-WEAKRSA" not in ids(f)


# --------------------------------------------------------------------------- #
# Finding shape + line numbers
# --------------------------------------------------------------------------- #
def test_finding_is_dataclass_with_fields():
    f = scan_text("genrsa")[0]
    assert isinstance(f, Finding)
    for attr in ("id", "severity", "label", "where", "line", "match", "recommend"):
        assert hasattr(f, attr)


def test_line_numbers_are_one_based_and_correct():
    text = "line one clean\nkey = rsa.generate_private_key(2048)\nclean again"
    f = scan_text(text)
    rsa = [x for x in f if x.id == "QR-RSA"]
    assert rsa and rsa[0].line == 2


def test_match_truncated_to_60_chars():
    for f in scan_text("ssh-rsa " + "A" * 200):
        assert len(f.match) <= 60


def test_path_propagates_into_where():
    f = scan_text("genrsa", path="config/server.conf")
    assert f[0].where == "config/server.conf"


def test_multiple_rules_on_one_line():
    f = scan_text("rsa.generate_private_key with secp256k1 and diffie-hellman")
    assert {"QR-RSA", "QR-ECC", "QR-DH"} <= ids(f)


# --------------------------------------------------------------------------- #
# readiness scoring + grade boundaries
# --------------------------------------------------------------------------- #
def _fake(severity, n=1):
    return [Finding("QR-X", severity, "l", "w", 1, "m", "r") for _ in range(n)]


def test_readiness_clean_is_A_100():
    r = readiness([])
    assert r["score"] == 100 and r["grade"] == "A"
    assert r["pqc_present"] is False


def test_readiness_info_only_is_A_and_pqc_present():
    r = readiness(_fake("info", 3))
    assert r["grade"] == "A"
    assert r["pqc_present"] is True


def test_readiness_severity_counts_sum():
    findings = _fake("critical", 2) + _fake("high", 1) + _fake("low", 4)
    r = readiness(findings)
    assert r["severity_counts"]["critical"] == 2
    assert r["severity_counts"]["high"] == 1
    assert r["severity_counts"]["low"] == 4


def test_readiness_one_critical_drops_grade():
    # 1 critical -> vuln 4 -> score 100-12 = 88 -> B
    r = readiness(_fake("critical", 1))
    assert r["score"] == 88
    assert r["grade"] == "B"


def test_readiness_score_floor_zero():
    r = readiness(_fake("critical", 50))
    assert r["score"] == 0
    assert r["grade"] == "F"


@pytest.mark.parametrize(
    "highs,expected_grade",
    [(0, "A"), (2, "B"), (5, "C"), (10, "D"), (20, "F")],
)
def test_grade_bands_via_high_findings(highs, expected_grade):
    # each high = vuln 2 -> score = 100 - highs*6
    r = readiness(_fake("high", highs))
    assert r["grade"] == expected_grade


# --------------------------------------------------------------------------- #
# JSON serialization
# --------------------------------------------------------------------------- #
def test_to_json_round_trips_and_has_sections():
    f = scan_text("genrsa\nsecp256k1")
    doc = json.loads(to_json(f))
    assert doc["tool"] == "quantumready"
    assert isinstance(doc["findings"], list) and len(doc["findings"]) >= 2
    assert "readiness" in doc
    assert set(doc["findings"][0]) == {
        "id", "severity", "label", "where", "line", "match", "recommend"
    }


def test_to_json_empty_findings():
    doc = json.loads(to_json([]))
    assert doc["findings"] == []
    assert doc["readiness"]["grade"] == "A"


# --------------------------------------------------------------------------- #
# scan_path on the filesystem
# --------------------------------------------------------------------------- #
def test_scan_path_single_file(tmp_path):
    p = tmp_path / "svc.py"
    p.write_text("k = rsa.generate_private_key(2048)\n")
    f = scan_path(str(p))
    assert "QR-RSA" in ids(f)


def test_scan_path_recurses_directory(tmp_path):
    (tmp_path / "a.conf").write_text("ssl dhparam /x\n")
    sub = tmp_path / "nested"
    sub.mkdir()
    (sub / "b.py").write_text("curve = secp256r1\n")
    f = scan_path(str(tmp_path))
    assert {"QR-DH", "QR-ECC"} <= ids(f)


def test_scan_path_skips_unreadable_gracefully(tmp_path):
    # a directory entry that isn't a normal text file should not crash the walk
    (tmp_path / "ok.py").write_text("genrsa\n")
    (tmp_path / "binary.bin").write_bytes(bytes(range(256)))
    f = scan_path(str(tmp_path))  # must not raise
    assert "QR-RSA" in ids(f)
