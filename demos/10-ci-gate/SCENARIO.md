# 10 — CI gate + GitHub code-scanning (SARIF)

**Where the data came from.** A Go crypto-helpers file (`crypto_helpers.go`) plus a
ready-to-use GitHub Actions workflow (`pqc-scan.yml`). This demo shows the end-to-end CI
use case: block PRs that introduce quantum-vulnerable crypto and surface findings inline in
GitHub's **Code scanning** tab via SARIF.

**What to expect.** The scan flags the ECDSA / `P256` usage (QR-ECC, high) in the Go file.
The RSA-3072 `GenerateKey` is *not* flagged by QR-WEAKRSA (it's appropriately sized
classically) — only the elliptic-curve usage is quantum-relevant here. `--fail-on high`
exits with code `2`, failing the build.

**Run it.**
```bash
# What the gate step runs:
quantumready scan demos/10-ci-gate/crypto_helpers.go --fail-on high; echo "exit=$?"   # -> exit=2

# What the SARIF-upload step produces:
quantumready scan demos/10-ci-gate/crypto_helpers.go --format sarif
```
Copy `pqc-scan.yml` to `.github/workflows/` to wire it into a real repo. The
`upload-sarif` action needs `security-events: write` (already set in the workflow).

**How to act.** Treat the gate as a ratchet: existing exposure is visible in the Security
tab, and new PRs that add RSA/ECC/DH fail until they use ML-KEM (FIPS 203) / ML-DSA
(FIPS 204) or are explicitly accepted with a hybrid-transition note.
