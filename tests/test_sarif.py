"""Tests for SARIF 2.1.0 export and the QR-DSA PQC false-positive fix."""
import json

from quantumready.core import scan_text, to_sarif, RULES


def test_sarif_shape_and_version():
    f = scan_text("key = rsa.generate_private_key(2048)\nuse secp256k1")
    doc = json.loads(to_sarif(f))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "quantumready"
    # one rule per distinct rule id
    assert {r["id"] for r in driver["rules"]} == {rid for rid, *_ in RULES}


def test_sarif_results_have_locations_and_levels():
    f = scan_text("rsa_1024 used here")  # critical
    doc = json.loads(to_sarif(f))
    res = doc["runs"][0]["results"]
    assert res, "expected at least one result"
    r0 = res[0]
    assert r0["ruleId"] == "QR-WEAKRSA"
    assert r0["level"] == "error"           # critical -> error
    loc = r0["locations"][0]["physicalLocation"]
    assert loc["region"]["startLine"] >= 1
    assert loc["artifactLocation"]["uri"]   # has a path


def test_sarif_ruleindex_in_bounds():
    f = scan_text("ecdsa secp256r1\ndiffie-hellman group")
    doc = json.loads(to_sarif(f))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    for r in doc["runs"][0]["results"]:
        assert 0 <= r["ruleIndex"] < len(rules)
        assert rules[r["ruleIndex"]]["id"] == r["ruleId"]


def test_sarif_empty_findings_is_valid():
    doc = json.loads(to_sarif([]))
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"]  # rules still declared


def test_mldsa_not_flagged_as_legacy_dsa():
    # QR-DSA must not fire on PQC ml-dsa/slh-dsa; QR-GOODSIG should.
    f = scan_text("signature = ml-dsa-65\nroot = slh-dsa-sha2-128s")
    ids = {x.id for x in f}
    assert "QR-DSA" not in ids
    assert "QR-GOODSIG" in ids


def test_legacy_dsa_still_flagged():
    f = scan_text("host_key = dsa\ncert uses DSS")
    assert "QR-DSA" in {x.id for x in f}


def test_ecdsa_not_double_flagged_as_dsa():
    f = scan_text("ecdsa-with-SHA256")
    ids = {x.id for x in f}
    assert "QR-ECC" in ids and "QR-DSA" not in ids
