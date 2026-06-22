# 08 — X.509 certificate inventory (fleet-wide)

**Where the data came from.** A CSV export of the certificate inventory (CN, expiry,
public-key algorithm, signature algorithm) across the fleet — the kind of file you get from
a cert-management platform or an `openssl x509`-driven inventory script. This is the
"crypto-agility / where-is-my-exposure" use case.

**What to expect.** Per-row detection: RSA-2048/4096 edge + root CA certs, ECDSA on
`prime256v1` and `secp384r1` (QR-ECC), an EOL `RSA 1024` + SHA-1 cert (QR-WEAKRSA,
**critical**), and a pilot `ml-dsa-65` code-signing cert recognized as PQC (QR-GOODSIG,
info — and notably *not* mis-flagged as legacy DSA). Mixed grade.

**Run it.**
```bash
quantumready scan demos/08-x509-inventory/cert_inventory.csv
quantumready scan demos/08-x509-inventory/cert_inventory.csv --format sarif > certs.sarif
```

**How to act.** Prioritize by lifetime: the long-lived private root CA (expires 2031) is
the highest-value harvest target — plan its migration to ML-DSA first. Retire the 1024-bit
SHA-1 portal cert immediately. The `ml-dsa-65` pilot is the template to roll out.
