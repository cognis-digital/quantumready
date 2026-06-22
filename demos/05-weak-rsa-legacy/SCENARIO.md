# 05 — Legacy / undersized crypto on EOL hardware

**Where the data came from.** A firmware crypto config from an end-of-life OT/IoT gateway,
captured during an asset inventory of embedded field gear.

**What to expect.** This is the worst-case grade. `RSA` `1024` matches QR-WEAKRSA
(**critical** — weak even classically, before any quantum threat), plus QR-RSA and QR-DSA.
Expect a D/F readiness grade. The critical finding means this triggers `--fail-on critical`.

**Run it.**
```bash
quantumready scan demos/05-weak-rsa-legacy/legacy_device.conf
quantumready scan demos/05-weak-rsa-legacy/legacy_device.conf --fail-on critical; echo "exit=$?"
```

**How to act.** Two problems, two timelines. *Now:* 1024-bit RSA and SHA-1 signatures are
already unacceptable — replace with >=3072-bit RSA or move to ECC as a classical stopgap.
*Q-Day track:* the device cannot be made quantum-safe in place; schedule hardware
replacement with platforms that support ML-KEM / ML-DSA firmware signing.
