"""Every demo input must actually produce its intended scanner output."""
from pathlib import Path

import pytest

from quantumready.core import scan_path, readiness

DEMOS = Path(__file__).resolve().parent.parent / "demos"

# (demo input file, expectation)
#   "findings" -> at least one finding
#   "critical" -> at least one critical finding
#   "pqc-A"    -> PQC recognized and grade A
CASES = [
    ("01-basic/sample.py", "findings"),
    ("02-tls-nginx/nginx.conf", "findings"),
    ("03-openssh-config/sshd_config", "findings"),
    ("04-python-pki/token_service.py", "findings"),
    ("05-weak-rsa-legacy/legacy_device.conf", "critical"),
    ("06-pqc-hybrid-ready/tls_policy.yaml", "pqc-A"),
    ("07-java-keystore/application.properties", "findings"),
    ("08-x509-inventory/cert_inventory.csv", "critical"),
    ("09-vpn-ipsec/ipsec.conf", "findings"),
    ("10-ci-gate/crypto_helpers.go", "findings"),
]


@pytest.mark.parametrize("rel,expect", CASES)
def test_demo_fires(rel, expect):
    target = DEMOS / rel
    assert target.exists(), f"missing demo input {rel}"
    f = scan_path(str(target))
    r = readiness(f)
    if expect == "findings":
        assert len(f) >= 1
    elif expect == "critical":
        assert r["severity_counts"]["critical"] >= 1
    elif expect == "pqc-A":
        assert r["pqc_present"] and r["grade"] == "A"


@pytest.mark.parametrize("rel,_e", CASES)
def test_every_demo_has_scenario(rel, _e):
    assert (DEMOS / rel).parent.joinpath("SCENARIO.md").exists()
