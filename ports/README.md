# quantumready — language ports

Native ports of `quantumready`'s **core `scan` surface** in three additional
languages, so you can drop a single self-contained binary/script into a Go, Rust,
or Node/TypeScript toolchain and CI without a Python runtime.

Every port is a faithful mirror of [`quantumready/core.py`](../quantumready/core.py):
the **same 8 detection rules** (`QR-RSA`, `QR-ECC`, `QR-DH`, `QR-DSA`,
`QR-WEAKRSA`, `QR-TLS`, `QR-GOODKEM`, `QR-GOODSIG`), the **same weighted
readiness score / A–F grade**, the **same JSON shape**, and the **same
`--fail-on` CI exit code (2)**.

All ports are **passive / offline by design** — they read only local files, open
no socket, and never perform active network scanning. Defensive / authorized-use
only. COCL v1.0.

| Port | Path | Run | Test |
|------|------|-----|------|
| Go | [`go/`](go) | `go run . scan ../../demos/01-basic` | `go test ./...` |
| Rust | [`rust/`](rust) | `cargo run -- scan ../../demos/01-basic` | `cargo test` |
| Node / TS | [`node/`](node) | `node quantumready.mjs scan ../../demos/01-basic` | `node --test` |

The Node port ships a `.d.ts` so it type-checks under TypeScript (`npm run typecheck`).

## Parity & verification

`go`, `rust`, and `node` ports are built **and tested in CI** on every push
(see [`.github/workflows/ports.yml`](../.github/workflows/ports.yml)). Each has a
smoke + behavior test suite asserting the same canonical cases the Python suite
covers, including the PQC false-positive fix (`ml-dsa`/`slh-dsa` must NOT trip the
legacy `QR-DSA` rule).

### Lookbehind note (Go / Rust)

Python and JavaScript regex engines support negative lookbehind, which the
`QR-DSA` rule uses (`(?<![a-z0-9-])`) to avoid matching `ecdsa`/`mldsa`. Go's
`regexp` and Rust's `regex` crate are RE2-style and have no lookbehind, so both
ports reproduce that behavior with an explicit `dsa_guard()` boundary check on the
preceding byte. The test suites pin this equivalence.

## Example (identical across all four)

```bash
$ quantumready scan demos/05-weak-rsa-legacy --format table
  [CRITICAL] QR-WEAKRSA  Undersized RSA key (<=1024) — weak even classically  (...:3)
  [HIGH    ] QR-RSA      RSA (key exchange/signature) — broken by Shor's algorithm  (...:5)

PQC readiness: D (52/100) — 4 findings
```

The full feed-enrichment (CISA-KEV / NVD) and the bundled 262k-vuln OSV database
live in the Python package only — they are the data-heavy components. The ports
deliberately cover the portable, dependency-light scanning core.
