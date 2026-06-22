# 04 — Python PKI / token-signing service

**Where the data came from.** An excerpt of a microservice (`token_service.py`) that mints
and verifies signed auth tokens, using the `cryptography` library. Reviewed before the team
commits to a post-quantum signature roadmap.

**What to expect.** `rsa.generate_private_key` (QR-RSA, high), `ec.generate_private_key` /
`SECP256R1` / `prime256v1` (QR-ECC, high). This is source-code detection, not config — it
shows quantumready reading real Python crypto calls.

**Run it.**
```bash
quantumready scan demos/04-python-pki/token_service.py --format json | jq '.readiness'
```

**How to act.** Token signatures should migrate to ML-DSA (FIPS 204) or, where signature
size is less constrained and conservative security is preferred, SLH-DSA (FIPS 205). The
ephemeral ECDH session key agreement should move to ML-KEM (FIPS 203), running hybrid
(classical + PQC) during the transition window.
