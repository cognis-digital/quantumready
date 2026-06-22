# 06 — PQC-hybrid target state (the "good" baseline)

**Where the data came from.** The platform team's target-state TLS policy after migration —
the configuration they are driving toward. Use it to confirm quantumready *recognizes* PQC
and doesn't just flag everything.

**What to expect.** `X25519MLKEM768` / `mlkem768` match QR-GOODKEM (info), and `ml-dsa-65` /
`slh-dsa-sha2-128s` match QR-GOODSIG (info). With no high/medium/critical findings the
grade is **A** and `readiness.pqc_present` is `true`.

**Run it.**
```bash
quantumready scan demos/06-pqc-hybrid-ready/tls_policy.yaml --format json | jq '.readiness'
```

**How to act.** Nothing to remediate. Verify the implementations are the *ratified* FIPS
203/204/205 algorithms (not pre-standard Kyber/Dilithium drafts), keep the classical half
of the hybrid until interop is universal, and treat this file as the reference others are
graded against.
