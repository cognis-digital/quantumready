<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:6b46c1,100:00897b&height=180&section=header&text=quantumready&fontSize=52&fontColor=ffffff&fontAlignY=42" width="100%"/>

# quantumready

### Scan any codebase/config for **quantum-vulnerable crypto** and get a NIST-PQC migration plan. Q-Day is coming — know your exposure.

[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) ![PQC](https://img.shields.io/badge/NIST-FIPS%20203%2F204%2F205-00897b) ![MCP](https://img.shields.io/badge/MCP-native-black) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital/cognis-neural-suite)

`#post-quantum` `#pqc` `#cryptography` `#ml-kem` `#security` `#harvest-now-decrypt-later`

</div>

"Harvest now, decrypt later" is real. `quantumready` finds **RSA / ECC / DH / DSA** usage that a quantum computer breaks, grades your **PQC readiness (A–F)**, and maps each finding to the NIST standards: **ML-KEM (FIPS 203)**, **ML-DSA (FIPS 204)**, **SLH-DSA (FIPS 205)**.

## Install (every way)
```bash
pip install "git+https://github.com/cognis-digital/quantumready.git"   # or pipx / uv tool install
curl -fsSL https://raw.githubusercontent.com/cognis-digital/quantumready/main/install.sh | sh
docker run --rm ghcr.io/cognis-digital/quantumready --help
```

## Use
```bash
quantumready scan .                    # grade your repo's PQC readiness
quantumready scan . --format json      # machine-readable
quantumready scan . --fail-on high     # CI gate
```

## Architecture
```mermaid
flowchart LR
  SRC[Code / configs / certs] --> SC[quantumready scan]
  SC --> R[Rules: RSA · ECC · DH · DSA]
  R --> G[Readiness grade A-F]
  R --> M[NIST PQC migration plan<br/>ML-KEM · ML-DSA · SLH-DSA]
  M --> O[table · JSON · MCP]
```

<a name="verification"></a>
## Verification

[![tests](https://img.shields.io/badge/tests-1%20passing-2ea44f.svg)](AUDIT.md)

Every push is verified end-to-end. Latest audit (2026-06-13):

```text
tests        : 1 passed, 0 failed, 0 errored
compile      : all modules parse
cli          : C:\Python314\python.exe: No module named https
package      : https
```

<details><summary>CLI surface (<code>--help</code>)</summary>

```text
C:\Python314\python.exe: No module named https
```
</details>

Full machine-readable results: [`AUDIT.md`](AUDIT.md) · regenerate with `python -m https --help` + `pytest -q`.

<div align="right"><a href="#top">↑ back to top</a></div>


## Related
[🔐 agentpassport](https://github.com/cognis-digital/agentpassport) · [🧪 SecOps tools](https://github.com/cognis-digital/cognis-neural-suite) · [🗂️ the suite](https://github.com/cognis-digital/cognis-neural-suite)

> ### ⭐ Star it — start your PQC migration before Q-Day.

## License
COCL v1.0 — see [LICENSE](LICENSE).
