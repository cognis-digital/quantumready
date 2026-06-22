# 01 — Basic source scan (start here)

**Where the data came from.** A tiny Python snippet (`sample.py`) that generates an RSA key
and references the `secp256k1` curve — the minimal "does it work" example.

**What to expect.** One QR-RSA and one QR-ECC finding (both high), grade **B**. The fastest
way to confirm your install detects both signature and key-exchange primitives.

**Run it.**
```bash
quantumready scan demos/01-basic/sample.py
quantumready scan demos/01-basic/sample.py --format json
```

**How to act.** See demos 02-10 for realistic configs, certificates, VPN/SSH/TLS, a
target-state PQC baseline, and a CI gate. Migrate RSA/ECC to ML-KEM (FIPS 203) for key
exchange and ML-DSA (FIPS 204) for signatures.
