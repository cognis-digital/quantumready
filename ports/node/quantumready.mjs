#!/usr/bin/env node
// quantumready (Node/TypeScript-compatible ESM port) — post-quantum readiness scanner.
//
// Mirrors the primary Python CLI's core `scan` surface: detect quantum-vulnerable
// crypto (RSA / ECC / DH / DSA), grade PQC readiness A-F, and map each finding to
// the NIST PQC standards (ML-KEM FIPS 203, ML-DSA FIPS 204, SLH-DSA FIPS 205).
//
// Pure Node standard library (node:fs / node:path). Passive / offline by design:
// reads only local files, never opens a socket, never scans a network target.
// Authored as ESM so it runs unbuilt (`node quantumready.mjs`) and also type-checks
// under TypeScript via the bundled .d.ts. Defensive / authorized-use only. COCL v1.0.

import { readFileSync, statSync, readdirSync } from "node:fs";
import { join } from "node:path";

export const TOOL_NAME = "quantumready";
export const TOOL_VERSION = "1.0.1";

// RULES kept equivalent to quantumready/core.py RULES (id, severity, regex, label, recommend).
// JS RegExp has no lookbehind-free guarantee issues here; QR-DSA uses a real lookbehind.
export const RULES = [
  ["QR-RSA", "high",
    /\b(rsa\.generate_private_key|RSA\.generate|genrsa|PKCS1|rsa_pkcs1|ssh-rsa)\b/i,
    "RSA (key exchange/signature) — broken by Shor's algorithm",
    "Migrate KEM→ML-KEM (FIPS 203); signatures→ML-DSA (FIPS 204). Use hybrid during transition."],
  ["QR-ECC", "high",
    /\b(ec(dsa|dh)|secp256[rk]1|prime256v1|P-256|P-384|nistp256|curve25519|ed25519|x25519)\b/i,
    "Elliptic-curve crypto — broken by Shor's algorithm",
    "Replace ECDH with ML-KEM; ECDSA/EdDSA with ML-DSA or SLH-DSA."],
  ["QR-DH", "high",
    /\b(diffie[-_ ]?hellman|\bdhparam\b|modp|ffdhe)\b/i,
    "Finite-field Diffie-Hellman — quantum-vulnerable",
    "Adopt ML-KEM (FIPS 203) for key establishment."],
  ["QR-DSA", "medium",
    /(?<![a-z0-9-])(dsa|dss)\b/i,
    "DSA signatures — quantum-vulnerable + legacy",
    "Move to ML-DSA (FIPS 204)."],
  ["QR-WEAKRSA", "critical",
    /rsa[^0-9]{0,8}(512|1024)\b/i,
    "Undersized RSA key (<=1024) — weak even classically",
    "Immediate: >=3072-bit RSA classically; plan ML-KEM/ML-DSA for PQC."],
  ["QR-TLS", "low",
    /\b(TLS_ECDHE|TLS_RSA|kRSA|kEECDH)\b/i,
    "Classical TLS key-exchange suite",
    "Enable hybrid PQC TLS (X25519MLKEM768) where supported."],
  ["QR-GOODKEM", "info",
    /\b(ml[-_]?kem|kyber|mlkem768|x25519mlkem768)\b/i,
    "ML-KEM / Kyber present — PQC KEM in use",
    "Good. Verify it's FIPS 203 (ML-KEM), not a draft Kyber."],
  ["QR-GOODSIG", "info",
    /\b(ml[-_]?dsa|dilithium|slh[-_]?dsa|sphincs)\b/i,
    "PQC signature present",
    "Good. Confirm FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA)."],
];

/** Scan one text blob; returns findings in rule order per line. */
export function scanText(text, path = "<text>") {
  const out = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].replace(/\r$/, "");
    for (const [id, severity, re, label, recommend] of RULES) {
      const m = re.exec(line);
      if (m) {
        out.push({ id, severity, label, where: path, line: i + 1,
          match: m[0].slice(0, 60), recommend });
      }
    }
  }
  return out;
}

/** Scan a file or recurse a directory. Reads only; never writes. */
export function scanPath(target) {
  const out = [];
  const st = statSync(target);
  const scanFile = (p) => {
    try { out.push(...scanText(readFileSync(p, "utf8"), p)); } catch { /* skip unreadable */ }
  };
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else scanFile(p);
    }
  };
  if (st.isDirectory()) walk(target);
  else scanFile(target);
  return out;
}

/** Weighted readiness score + A-F grade (mirrors core.readiness). */
export function readiness(findings) {
  const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) sev[f.severity] = (sev[f.severity] || 0) + 1;
  const vuln = sev.critical * 4 + sev.high * 2 + sev.medium;
  const score = vuln ? Math.max(0, 100 - vuln * 3) : 100;
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  return { score, grade, severity_counts: sev, pqc_present: sev.info > 0 };
}

export function toJSON(findings) {
  return JSON.stringify({ tool: TOOL_NAME, findings, readiness: readiness(findings) }, null, 2);
}

const SEV_RANK = { critical: 4, high: 3, medium: 2 };

export function run(argv) {
  if (argv.length === 0) { usage(); return 0; }
  if (argv[0] === "--version") { console.log(`${TOOL_NAME} ${TOOL_VERSION}`); return 0; }
  if (argv[0] !== "scan" || argv.length < 2) { usage(); return 0; }
  const target = argv[1];
  let format = "table", failOn = null;
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === "--format" && argv[i + 1]) format = argv[++i];
    else if (argv[i] === "--fail-on" && argv[i + 1]) failOn = argv[++i];
  }
  let findings;
  try { findings = scanPath(target); }
  catch (e) { console.error(`error: ${e.message}`); return 1; }

  if (format === "json") {
    console.log(toJSON(findings));
  } else {
    for (const f of findings)
      console.log(`  [${f.severity.toUpperCase().padEnd(8)}] ${f.id}  ${f.label}  (${f.where}:${f.line})`);
    const r = readiness(findings);
    console.log(`\nPQC readiness: ${r.grade} (${r.score}/100) — ${findings.length} findings`);
  }
  if (failOn) {
    const threshold = SEV_RANK[failOn] || 0;
    if (findings.some((f) => (SEV_RANK[f.severity] || 0) >= threshold)) return 2;
  }
  return 0;
}

function usage() {
  console.log("quantumready (Node port) — post-quantum readiness scanner");
  console.log("usage: quantumready scan <path> [--format table|json] [--fail-on critical|high|medium]");
  console.log("       quantumready --version");
  console.log("\nPassive/offline only. Defensive / authorized-use. COCL v1.0.");
}

// Direct execution (node quantumready.mjs ...)
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("quantumready.mjs")) {
  process.exit(run(process.argv.slice(2)));
}
