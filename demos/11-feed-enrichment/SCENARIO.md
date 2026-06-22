# Demo 11 — Feed enrichment (CISA-KEV + NVD), offline / air-gap

**Goal:** show how quantumready turns a static PQC crypto inventory into a
*prioritized, exploited-in-the-wild* patch list using two authoritative,
keyless feeds — and do it with **no network** (air-gap safe).

`payment_gateway.py` is a service that leans on quantum-vulnerable crypto
(RSA key generation, an `secp256k1` / ECDSA curve, a classical TLS_RSA suite).

The scanner flags the *families* (RSA, elliptic-curve). The enrichment then:

1. queries **NVD** (NIST CVE database) for CVEs naming those primitives, then
2. intersects with the **CISA-KEV** catalog of *actively-exploited* CVEs.

Result: the crypto weaknesses an attacker is exploiting **today** that you must
patch before (and during) the multi-year migration to NIST PQC
(ML-KEM / ML-DSA / SLH-DSA).

## Run it (offline, from the committed fixture cache)

```bash
# point the feed cache at the trimmed fixtures (or at a snapshot you sneakernetted in)
export COGNIS_FEEDS_CACHE=tests/fixtures/feeds-cache

quantumready scan demos/11-feed-enrichment/payment_gateway.py --enrich --offline
```

## Live / connected

```bash
quantumready feeds update                 # fetch + cache cisa-kev, nvd-cve
quantumready scan path/to/code --enrich   # cross-reference against live feeds
```

## Air-gap workflow

On a connected host:
```bash
quantumready feeds update
python -m quantumready.datafeeds snapshot-export feeds.tar.gz
```
Carry `feeds.tar.gz` to the disconnected enclave:
```bash
python -m quantumready.datafeeds snapshot-import feeds.tar.gz
quantumready scan code/ --enrich --offline
```

Defensive / authorized-use only.
