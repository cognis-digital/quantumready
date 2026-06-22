# 03 — OpenSSH bastion host config

**Where the data came from.** The `sshd_config` from a jump/bastion host during a
hardening review. SSH host keys and authorized client keys are long-lived secrets — a
prime "harvest now, decrypt later" target because recorded handshakes can be broken once a
CRQC exists.

**What to expect.** `ssh-rsa` host + client keys (QR-RSA), the `curve25519`/`ed25519`/
`ecdsa-sha2-nistp256` algorithms (QR-ECC), and the `diffie-hellman-group14` KEX (QR-DH).
All key exchange here is quantum-vulnerable; expect multiple high findings and no PQC.

**Run it.**
```bash
quantumready scan demos/03-openssh-config/sshd_config
quantumready scan demos/03-openssh-config/sshd_config --fail-on high
```
`--fail-on high` exits non-zero, so this is the form you would drop into a config-audit
pipeline.

**How to act.** Track OpenSSH's PQC key-exchange support (the `sntrup761x25519` /
`mlkem768x25519` hybrid KEX) and prefer it once available across your fleet; rotate
`ssh-rsa` host keys to `ssh-ed25519` now as an interim step and plan ML-DSA host keys for
the PQC era.
