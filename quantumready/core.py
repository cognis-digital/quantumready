"""quantumready core — find quantum-vulnerable crypto and map it to NIST PQC replacements.

Scans source, configs, and cert/algorithm strings for RSA/ECC/DH/DSA usage that a
cryptographically-relevant quantum computer (CRQC) breaks, and recommends the NIST
PQC standards: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205). Pure stdlib.
"""
from __future__ import annotations
import re, json
from dataclasses import dataclass, asdict
TOOL_NAME = "quantumready"; TOOL_VERSION = "1.0.0"

# (id, severity, regex, label, pqc_recommendation)
RULES = [
    ("QR-RSA", "high", r"(?i)\b(rsa\.generate_private_key|RSA\.generate|genrsa|PKCS1|rsa_pkcs1|ssh-rsa)\b",
     "RSA (key exchange/signature) — broken by Shor's algorithm",
     "Migrate KEM→ML-KEM (FIPS 203); signatures→ML-DSA (FIPS 204). Use hybrid during transition."),
    ("QR-ECC", "high", r"(?i)\b(ec(dsa|dh)|secp256[rk]1|prime256v1|P-256|P-384|nistp256|curve25519|ed25519|x25519)\b",
     "Elliptic-curve crypto — broken by Shor's algorithm",
     "Replace ECDH with ML-KEM; ECDSA/EdDSA with ML-DSA or SLH-DSA."),
    ("QR-DH", "high", r"(?i)\b(diffie[-_ ]?hellman|\bdhparam\b|modp|ffdhe)\b",
     "Finite-field Diffie-Hellman — quantum-vulnerable",
     "Adopt ML-KEM (FIPS 203) for key establishment."),
    ("QR-DSA", "medium", r"(?i)(?<![a-z0-9-])(dsa|dss)\b",
     "DSA signatures — quantum-vulnerable + legacy",
     "Move to ML-DSA (FIPS 204)."),
    ("QR-WEAKRSA", "critical", r"(?i)rsa[^0-9]{0,8}(512|1024)\b",
     "Undersized RSA key (<=1024) — weak even classically",
     "Immediate: >=3072-bit RSA classically; plan ML-KEM/ML-DSA for PQC."),
    ("QR-TLS", "low", r"(?i)\b(TLS_ECDHE|TLS_RSA|kRSA|kEECDH)\b",
     "Classical TLS key-exchange suite",
     "Enable hybrid PQC TLS (X25519MLKEM768) where supported."),
    ("QR-GOODKEM", "info", r"(?i)\b(ml[-_]?kem|kyber|mlkem768|x25519mlkem768)\b",
     "ML-KEM / Kyber present — PQC KEM in use", "Good. Verify it's FIPS 203 (ML-KEM), not a draft Kyber."),
    ("QR-GOODSIG", "info", r"(?i)\b(ml[-_]?dsa|dilithium|slh[-_]?dsa|sphincs)\b",
     "PQC signature present", "Good. Confirm FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA)."),
]

@dataclass
class Finding:
    id: str; severity: str; label: str; where: str; line: int; match: str; recommend: str

def scan_text(text: str, path="<text>"):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        for rid, sev, rx, label, rec in RULES:
            m = re.search(rx, line)
            if m:
                out.append(Finding(rid, sev, label, path, i, m.group(0)[:60], rec))
    return out

def scan_path(path):
    from pathlib import Path as _P
    p = _P(path); out = []
    files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file()]
    for f in files:
        try: out += scan_text(f.read_text(encoding="utf-8", errors="ignore"), str(f))
        except Exception: pass
    return out

def readiness(findings):
    sev = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for f in findings: sev[f.severity] = sev.get(f.severity,0)+1
    vuln = sev["critical"]*4 + sev["high"]*2 + sev["medium"]
    score = max(0, 100 - vuln*3) if vuln else (100 if sev["info"] else 100)
    grade = "A" if score>=90 else "B" if score>=75 else "C" if score>=60 else "D" if score>=40 else "F"
    return {"score": score, "grade": grade, "severity_counts": sev, "pqc_present": bool(sev["info"])}

def to_json(findings):
    return json.dumps({"tool": TOOL_NAME, "findings": [asdict(f) for f in findings],
                       "readiness": readiness(findings)}, indent=2)

# SARIF severity -> SARIF result.level (errors gate CI; notes are informational).
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def to_sarif(findings):
    """Emit SARIF 2.1.0 — the OASIS standard consumed by GitHub code scanning,
    Azure DevOps, and most SAST dashboards. One rule per QR rule id; one result
    per finding with a physicalLocation so it annotates the exact source line."""
    seen, rules = {}, []
    for rid, sev, _rx, label, rec in RULES:
        if rid in seen:
            continue
        seen[rid] = len(rules)
        rules.append({
            "id": rid,
            "name": rid.replace("-", ""),
            "shortDescription": {"text": label},
            "fullDescription": {"text": rec},
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(sev, "note")},
            "properties": {"security-severity": {
                "critical": "9.8", "high": "8.1", "medium": "5.5",
                "low": "3.1", "info": "0.0"}.get(sev, "0.0"),
                "tags": ["cryptography", "post-quantum", "nist-pqc"]},
        })
    results = []
    for f in findings:
        results.append({
            "ruleId": f.id,
            "ruleIndex": seen.get(f.id, 0),
            "level": _SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": f"{f.label}. {f.recommend}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.where.replace("\\", "/")},
                "region": {"startLine": max(1, f.line),
                           "snippet": {"text": f.match}}}}],
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": "https://github.com/cognis-digital/quantumready",
                "rules": rules,
            }},
            "results": results,
        }],
    }, indent=2)
