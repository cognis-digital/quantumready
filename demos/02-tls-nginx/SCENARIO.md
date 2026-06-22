# 02 — TLS termination (nginx) audit

**Where the data came from.** An `nginx.conf` pulled from the edge reverse proxy that
terminates TLS for `api.example.com`. The security team wants to know whether any of the
negotiated handshakes are quantum-vulnerable before enabling
"harvest-now-decrypt-later"-resistant TLS.

**What to expect.** The classical cipher suites (`TLS_ECDHE_RSA`, `TLS_RSA`), the named
curves (`prime256v1`, `secp384r1`), the `ssl-rsa` certificate key, and the `dhparam`
finite-field DH group all match. None of the key exchange is PQC — expect a non-A grade
and a cluster of QR-TLS / QR-ECC / QR-DH / QR-RSA findings.

**Run it.**
```bash
quantumready scan demos/02-tls-nginx/nginx.conf
quantumready scan demos/02-tls-nginx/nginx.conf --format sarif > tls.sarif
```

**How to act.** Enable a hybrid PQC key-exchange group (e.g. `X25519MLKEM768`) on the
TLS 1.3 listener once your TLS library supports it, keep the classical curve as the
hybrid's classical half during transition, and retire the `TLS_RSA` suite (no forward
secrecy and fully Shor-breakable).
