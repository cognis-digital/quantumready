# 09 — Site-to-site VPN (strongSwan IPsec)

**Where the data came from.** A strongSwan `ipsec.conf` for a site-to-site tunnel between
two datacenters. Long-lived VPN tunnels carry bulk traffic and rekey for years, so recorded
IKE handshakes are a classic harvest-now-decrypt-later target.

**What to expect.** The IKE Diffie-Hellman group and the ESP `modp2048` PFS group match
QR-DH; the ECDSA P-384 peer identity matches QR-ECC. Expect high findings and no PQC.

**Run it.**
```bash
quantumready scan demos/09-vpn-ipsec/ipsec.conf
quantumready scan demos/09-vpn-ipsec/ipsec.conf --fail-on high; echo "exit=$?"
```

**How to act.** strongSwan supports PQC/hybrid IKEv2 key exchange (RFC 9370 multiple key
exchanges + ML-KEM plugins). Add an ML-KEM key-exchange round to the `ike=` proposal
alongside the classical ECP/MODP group during transition, and plan ML-DSA peer identity
certs to replace the ECDSA/RSA ones.
