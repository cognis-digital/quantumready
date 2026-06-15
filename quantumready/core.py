"""quantumready core — find quantum-vulnerable crypto, map to NIST PQC replacements.

Scans source, configs, and cert/algorithm strings for RSA/ECC/DH/DSA usage that a
cryptographically-relevant quantum computer (CRQC) breaks, and recommends the NIST
PQC standards: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205). Pure stdlib.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass

TOOL_NAME = "quantumready"
TOOL_VERSION = "1.0.0"

# (id, severity, regex, label, pqc_recommendation)
RULES = [
    (
        "QR-RSA",
        "high",
        r"(?i)\b(rsa\.generate_private_key|RSA\.generate|genrsa|PKCS1|rsa_pkcs1|ssh-rsa)\b",
        "RSA (key exchange/signature) — broken by Shor's algorithm",
        "Migrate KEM→ML-KEM (FIPS 203); signatures→ML-DSA (FIPS 204)."
        " Use hybrid during transition.",
    ),
    (
        "QR-ECC",
        "high",
        r"(?i)\b(ec(dsa|dh)|secp256[rk]1|prime256v1|P-256|P-384|nistp256|curve25519|ed25519|x25519)\b",
        "Elliptic-curve crypto — broken by Shor's algorithm",
        "Replace ECDH with ML-KEM; ECDSA/EdDSA with ML-DSA or SLH-DSA.",
    ),
    (
        "QR-DH",
        "high",
        r"(?i)\b(diffie[-_ ]?hellman|\bdhparam\b|modp|ffdhe)\b",
        "Finite-field Diffie-Hellman — quantum-vulnerable",
        "Adopt ML-KEM (FIPS 203) for key establishment.",
    ),
    (
        "QR-DSA",
        "medium",
        r"(?i)\b(dsa\b|dss)\b",
        "DSA signatures — quantum-vulnerable + legacy",
        "Move to ML-DSA (FIPS 204).",
    ),
    (
        "QR-WEAKRSA",
        "critical",
        r"(?i)rsa[^0-9]{0,8}(512|1024)\b",
        "Undersized RSA key (<=1024) — weak even classically",
        "Immediate: >=3072-bit RSA classically; plan ML-KEM/ML-DSA for PQC.",
    ),
    (
        "QR-TLS",
        "low",
        r"(?i)\b(TLS_ECDHE|TLS_RSA|kRSA|kEECDH)\b",
        "Classical TLS key-exchange suite",
        "Enable hybrid PQC TLS (X25519MLKEM768) where supported.",
    ),
    (
        "QR-GOODKEM",
        "info",
        r"(?i)\b(ml[-_]?kem|kyber|mlkem768|x25519mlkem768)\b",
        "ML-KEM / Kyber present — PQC KEM in use",
        "Good. Verify it's FIPS 203 (ML-KEM), not a draft Kyber.",
    ),
    (
        "QR-GOODSIG",
        "info",
        r"(?i)\b(ml[-_]?dsa|dilithium|slh[-_]?dsa|sphincs)\b",
        "PQC signature present",
        "Good. Confirm FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA).",
    ),
]


@dataclass
class Finding:
    id: str
    severity: str
    label: str
    where: str
    line: int
    match: str
    recommend: str


def scan_text(text: str, path: str = "<text>") -> list[Finding]:
    """Scan a string for quantum-vulnerable crypto patterns.

    Returns an empty list for empty or None input rather than raising.
    """
    if not text:
        return []
    out: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        for rid, sev, rx, label, rec in RULES:
            m = re.search(rx, line)
            if m:
                out.append(
                    Finding(rid, sev, label, path, i, m.group(0)[:60], rec)
                )
    return out


def scan_path(path: str) -> list[Finding]:
    """Scan a file or directory tree.

    Raises ``ValueError`` for a path that does not exist so the caller can
    show a clear error message rather than silently returning zero results.
    """
    from pathlib import Path as _P

    p = _P(path)
    if not p.exists():
        raise ValueError(f"Path does not exist: {path!r}")

    out: list[Finding] = []
    files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file()]
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
            out += scan_text(text, str(f))
        except OSError:
            # Skip files we cannot read (permission errors, broken symlinks, …)
            pass
    return out


def readiness(findings: list[Finding]) -> dict:
    """Compute a PQC readiness score from a list of findings.

    Safe for empty input — returns grade "A" / score 100 when no findings.
    """
    sev: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    vuln = sev["critical"] * 4 + sev["high"] * 2 + sev["medium"]
    score = max(0, 100 - vuln * 3) if vuln else 100
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    return {
        "score": score,
        "grade": grade,
        "severity_counts": sev,
        "pqc_present": bool(sev["info"]),
    }


def to_json(findings: list[Finding]) -> str:
    return json.dumps(
        {
            "tool": TOOL_NAME,
            "findings": [asdict(f) for f in findings],
            "readiness": readiness(findings),
        },
        indent=2,
    )
