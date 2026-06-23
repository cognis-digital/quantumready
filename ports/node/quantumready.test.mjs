// Smoke + behavior tests for the Node port. Runs on the Node built-in test
// runner (node --test) — no third-party deps, hermetic, offline.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanText, scanPath, readiness, toJSON, run, RULES } from "./quantumready.mjs";

const ids = (fs) => new Set(fs.map((f) => f.id));

test("detects RSA, ECC, and PQC KEM", () => {
  const f = scanText("key = rsa.generate_private_key(2048)\nuse secp256k1 and ML-KEM");
  const i = ids(f);
  assert.ok(i.has("QR-RSA") && i.has("QR-ECC") && i.has("QR-GOODKEM"));
});

test("weak RSA is critical", () => {
  const f = scanText("rsa_1024 used here");
  assert.ok(ids(f).has("QR-WEAKRSA"));
  assert.ok(readiness(f).severity_counts.critical >= 1);
});

test("ml-dsa / slh-dsa not flagged as legacy DSA", () => {
  const f = scanText("signature = ml-dsa-65\nroot = slh-dsa-sha2-128s");
  const i = ids(f);
  assert.ok(!i.has("QR-DSA"));
  assert.ok(i.has("QR-GOODSIG"));
});

test("ecdsa is ECC only, not DSA", () => {
  const i = ids(scanText("ecdsa-with-SHA256"));
  assert.ok(i.has("QR-ECC") && !i.has("QR-DSA"));
});

test("legacy dsa/dss still flagged", () => {
  assert.ok(ids(scanText("host_key = dsa\ncert uses DSS")).has("QR-DSA"));
});

test("PQC-only code grades A", () => {
  const r = readiness(scanText("only x25519mlkem768 and ml-dsa here\n"));
  assert.equal(r.grade, "A");
  assert.equal(r.pqc_present, true);
});

test("JSON output shape", () => {
  const doc = JSON.parse(toJSON(scanText("genrsa 2048")));
  assert.equal(doc.tool, "quantumready");
  assert.ok(doc.findings.length >= 1);
  assert.ok("readiness" in doc);
});

test("scanPath reads a file", () => {
  const dir = mkdtempSync(join(tmpdir(), "qr-"));
  const p = join(dir, "svc.py");
  writeFileSync(p, "k = rsa.generate_private_key(2048)\n");
  assert.ok(ids(scanPath(p)).has("QR-RSA"));
});

test("run --fail-on exits 2 on high finding, 0 on clean", () => {
  const dir = mkdtempSync(join(tmpdir(), "qr-"));
  const bad = join(dir, "x.conf");
  writeFileSync(bad, "ssh-rsa AAAA\n");
  assert.equal(run(["scan", bad, "--fail-on", "high"]), 2);
  const clean = join(dir, "clean.txt");
  writeFileSync(clean, "ml-kem only\n");
  assert.equal(run(["scan", clean, "--fail-on", "high"]), 0);
});

test("rule table covers all 8 QR rules", () => {
  assert.equal(new Set(RULES.map((r) => r[0])).size, 8);
});
