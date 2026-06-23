package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ids(fs []Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.ID] = true
	}
	return m
}

func TestDetectsRSAandECC(t *testing.T) {
	f := ScanText("key = rsa.generate_private_key(2048)\nuse secp256k1 and ML-KEM", "<t>")
	id := ids(f)
	for _, want := range []string{"QR-RSA", "QR-ECC", "QR-GOODKEM"} {
		if !id[want] {
			t.Fatalf("expected %s in findings, got %v", want, id)
		}
	}
}

func TestWeakRSACritical(t *testing.T) {
	f := ScanText("rsa_1024 used here", "<t>")
	if !ids(f)["QR-WEAKRSA"] {
		t.Fatal("expected QR-WEAKRSA critical")
	}
	if ComputeReadiness(f).SeverityCounts["critical"] < 1 {
		t.Fatal("expected at least one critical")
	}
}

func TestMLDSANotFlaggedAsLegacyDSA(t *testing.T) {
	f := ScanText("signature = ml-dsa-65\nroot = slh-dsa-sha2-128s", "<t>")
	id := ids(f)
	if id["QR-DSA"] {
		t.Fatal("QR-DSA must not fire on PQC ml-dsa/slh-dsa")
	}
	if !id["QR-GOODSIG"] {
		t.Fatal("expected QR-GOODSIG")
	}
}

func TestEcdsaNotDoubleFlaggedAsDSA(t *testing.T) {
	f := ScanText("ecdsa-with-SHA256", "<t>")
	id := ids(f)
	if !id["QR-ECC"] || id["QR-DSA"] {
		t.Fatalf("ecdsa should be QR-ECC only, got %v", id)
	}
}

func TestLegacyDSAStillFlagged(t *testing.T) {
	f := ScanText("host_key = dsa\ncert uses DSS", "<t>")
	if !ids(f)["QR-DSA"] {
		t.Fatal("standalone dsa/dss should flag QR-DSA")
	}
}

func TestReadinessGradeA(t *testing.T) {
	f := ScanText("only x25519mlkem768 and ml-dsa here\n", "<t>")
	r := ComputeReadiness(f)
	if r.Grade != "A" || !r.PQCPresent {
		t.Fatalf("expected grade A with pqc present, got %+v", r)
	}
}

func TestJSONShape(t *testing.T) {
	f := ScanText("genrsa 2048", "<t>")
	var doc report
	if err := json.Unmarshal([]byte(ToJSON(f)), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc.Tool != "quantumready" || len(doc.Findings) < 1 {
		t.Fatalf("bad report: %+v", doc)
	}
}

func TestScanPathFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "svc.py")
	if err := os.WriteFile(p, []byte("k = rsa.generate_private_key(2048)\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := ScanPath(p)
	if err != nil {
		t.Fatal(err)
	}
	if !ids(f)["QR-RSA"] {
		t.Fatal("expected QR-RSA from file scan")
	}
}

func TestRunFailOn(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.conf")
	_ = os.WriteFile(p, []byte("ssh-rsa AAAA\n"), 0644)
	if rc := run([]string{"scan", p, "--fail-on", "high"}); rc != 2 {
		t.Fatalf("expected exit 2 on high finding, got %d", rc)
	}
	clean := filepath.Join(dir, "clean.txt")
	_ = os.WriteFile(clean, []byte("ml-kem only\n"), 0644)
	if rc := run([]string{"scan", clean, "--fail-on", "high"}); rc != 0 {
		t.Fatalf("expected exit 0 on clean, got %d", rc)
	}
}

func TestVersion(t *testing.T) {
	if rc := run([]string{"--version"}); rc != 0 {
		t.Fatalf("version exit %d", rc)
	}
}

func TestNoNetworkImports(t *testing.T) {
	// Passive/offline guarantee: the port must not import net/http.
	b, _ := os.ReadFile("quantumready.go")
	if strings.Contains(string(b), "net/http") || strings.Contains(string(b), "\"net\"") {
		t.Fatal("Go port must not import networking packages (passive/offline only)")
	}
}
