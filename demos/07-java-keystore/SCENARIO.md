# 07 — JVM service tier (Spring Boot application.properties)

**Where the data came from.** The crypto-relevant slice of a Spring Boot service's
`application.properties`, pulled for a PQC exposure review of the JVM service tier.

**What to expect.** The JWT `P-256` curve (QR-ECC), the RSA/PKCS1 mTLS client key
(QR-RSA), and the classical `TLS_RSA` key-transport suite all match. Expect several high
findings and a B-ish grade — typical of a real service that has no PQC yet but no
obviously-broken legacy crypto either.

**Run it.**
```bash
quantumready scan demos/07-java-keystore/application.properties
quantumready scan demos/07-java-keystore/application.properties --format sarif > jvm.sarif
```

**How to act.** On the JVM, track BouncyCastle / Java's PQC provider support: move JWT/
webhook signing to ML-DSA (FIPS 204), mTLS key agreement to ML-KEM (FIPS 203) hybrid, and
drop the non-forward-secret `TLS_RSA` suite in favor of an ECDHE (then PQC-hybrid) suite.
