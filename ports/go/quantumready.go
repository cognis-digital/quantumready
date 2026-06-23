// Command quantumready (Go port) — post-quantum migration readiness scanner.
//
// Mirrors the core surface of the primary Python CLI: scan source/configs/certs
// for quantum-vulnerable crypto (RSA / ECC / DH / DSA), grade PQC readiness A-F,
// and map each finding to the NIST PQC standards (ML-KEM FIPS 203, ML-DSA FIPS
// 204, SLH-DSA FIPS 205). Passive / offline by nature: it only reads local files
// and emits a report. No network, no active scanning.
//
// Defensive / authorized-use only. COCL v1.0.
package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	toolName    = "quantumready"
	toolVersion = "1.0.1"
)

// rule mirrors the Python RULES table (id, severity, regex, label, recommendation).
type rule struct {
	ID        string
	Severity  string
	Re        *regexp.Regexp
	Label     string
	Recommend string
}

// Finding is one rule hit at a file:line location.
type Finding struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	Label     string `json:"label"`
	Where     string `json:"where"`
	Line      int    `json:"line"`
	Match     string `json:"match"`
	Recommend string `json:"recommend"`
}

// rules are kept byte-for-byte equivalent to quantumready/core.py RULES.
var rules = []rule{
	{"QR-RSA", "high",
		regexp.MustCompile(`(?i)\b(rsa\.generate_private_key|RSA\.generate|genrsa|PKCS1|rsa_pkcs1|ssh-rsa)\b`),
		"RSA (key exchange/signature) — broken by Shor's algorithm",
		"Migrate KEM→ML-KEM (FIPS 203); signatures→ML-DSA (FIPS 204). Use hybrid during transition."},
	{"QR-ECC", "high",
		regexp.MustCompile(`(?i)\b(ec(dsa|dh)|secp256[rk]1|prime256v1|P-256|P-384|nistp256|curve25519|ed25519|x25519)\b`),
		"Elliptic-curve crypto — broken by Shor's algorithm",
		"Replace ECDH with ML-KEM; ECDSA/EdDSA with ML-DSA or SLH-DSA."},
	{"QR-DH", "high",
		regexp.MustCompile(`(?i)\b(diffie[-_ ]?hellman|\bdhparam\b|modp|ffdhe)\b`),
		"Finite-field Diffie-Hellman — quantum-vulnerable",
		"Adopt ML-KEM (FIPS 203) for key establishment."},
	{"QR-DSA", "medium",
		// Go RE2 has no lookbehind; emulate Python's (?<![a-z0-9-]) via a guard in scanLine.
		regexp.MustCompile(`(?i)(dsa|dss)\b`),
		"DSA signatures — quantum-vulnerable + legacy",
		"Move to ML-DSA (FIPS 204)."},
	{"QR-WEAKRSA", "critical",
		regexp.MustCompile(`(?i)rsa[^0-9]{0,8}(512|1024)\b`),
		"Undersized RSA key (<=1024) — weak even classically",
		"Immediate: >=3072-bit RSA classically; plan ML-KEM/ML-DSA for PQC."},
	{"QR-TLS", "low",
		regexp.MustCompile(`(?i)\b(TLS_ECDHE|TLS_RSA|kRSA|kEECDH)\b`),
		"Classical TLS key-exchange suite",
		"Enable hybrid PQC TLS (X25519MLKEM768) where supported."},
	{"QR-GOODKEM", "info",
		regexp.MustCompile(`(?i)\b(ml[-_]?kem|kyber|mlkem768|x25519mlkem768)\b`),
		"ML-KEM / Kyber present — PQC KEM in use",
		"Good. Verify it's FIPS 203 (ML-KEM), not a draft Kyber."},
	{"QR-GOODSIG", "info",
		regexp.MustCompile(`(?i)\b(ml[-_]?dsa|dilithium|slh[-_]?dsa|sphincs)\b`),
		"PQC signature present",
		"Good. Confirm FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA)."},
}

// dsaGuard emulates Python's negative lookbehind (?<![a-z0-9-]) for QR-DSA so
// "ecdsa"/"mldsa" do NOT match but a standalone "dsa"/"dss" does.
func dsaGuard(line string, loc []int) bool {
	if loc[0] == 0 {
		return true
	}
	prev := line[loc[0]-1]
	if (prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') ||
		(prev >= '0' && prev <= '9') || prev == '-' {
		return false
	}
	return true
}

// ScanText scans one text blob, returning findings in rule order per line.
func ScanText(text, path string) []Finding {
	out := []Finding{}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		for _, r := range rules {
			loc := r.Re.FindStringIndex(line)
			if loc == nil {
				continue
			}
			if r.ID == "QR-DSA" && !dsaGuard(line, loc) {
				continue
			}
			m := line[loc[0]:loc[1]]
			if len(m) > 60 {
				m = m[:60]
			}
			out = append(out, Finding{r.ID, r.Severity, r.Label, path, i + 1, m, r.Recommend})
		}
	}
	return out
}

// ScanPath scans a file or recurses a directory (reads only; never writes).
func ScanPath(root string) ([]Finding, error) {
	out := []Finding{}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	scanFile := func(p string) {
		b, err := os.ReadFile(p)
		if err != nil {
			return
		}
		out = append(out, ScanText(string(b), p)...)
	}
	if !info.IsDir() {
		scanFile(root)
		return out, nil
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries, keep going
		}
		if !d.IsDir() {
			scanFile(p)
		}
		return nil
	})
	return out, err
}

// Readiness mirrors core.readiness: weighted score, A-F grade, severity counts.
type Readiness struct {
	Score          int            `json:"score"`
	Grade          string         `json:"grade"`
	SeverityCounts map[string]int `json:"severity_counts"`
	PQCPresent     bool           `json:"pqc_present"`
}

func ComputeReadiness(fs []Finding) Readiness {
	sev := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range fs {
		sev[f.Severity]++
	}
	vuln := sev["critical"]*4 + sev["high"]*2 + sev["medium"]
	score := 100
	if vuln > 0 {
		score = 100 - vuln*3
		if score < 0 {
			score = 0
		}
	}
	grade := "F"
	switch {
	case score >= 90:
		grade = "A"
	case score >= 75:
		grade = "B"
	case score >= 60:
		grade = "C"
	case score >= 40:
		grade = "D"
	}
	return Readiness{score, grade, sev, sev["info"] > 0}
}

type report struct {
	Tool      string    `json:"tool"`
	Findings  []Finding `json:"findings"`
	Readiness Readiness `json:"readiness"`
}

// ToJSON mirrors core.to_json.
func ToJSON(fs []Finding) string {
	b, _ := json.MarshalIndent(report{toolName, fs, ComputeReadiness(fs)}, "", "  ")
	return string(b)
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	}
	return 0
}

func usage() {
	fmt.Println("quantumready (Go port) — post-quantum readiness scanner")
	fmt.Println("usage: quantumready scan <path> [--format table|json] [--fail-on critical|high|medium]")
	fmt.Println("       quantumready --version")
	fmt.Println("\nPassive/offline only. Defensive / authorized-use. COCL v1.0.")
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 0
	}
	if args[0] == "--version" {
		fmt.Printf("%s %s\n", toolName, toolVersion)
		return 0
	}
	if args[0] != "scan" || len(args) < 2 {
		usage()
		return 0
	}
	target := args[1]
	format := "table"
	failOn := ""
	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--format":
			if i+1 < len(args) {
				i++
				format = args[i]
			}
		case "--fail-on":
			if i+1 < len(args) {
				i++
				failOn = args[i]
			}
		}
	}
	findings, err := ScanPath(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if format == "json" {
		fmt.Println(ToJSON(findings))
	} else {
		for _, f := range findings {
			fmt.Printf("  [%-8s] %s  %s  (%s:%d)\n", strings.ToUpper(f.Severity), f.ID, f.Label, f.Where, f.Line)
		}
		r := ComputeReadiness(findings)
		fmt.Printf("\nPQC readiness: %s (%d/100) — %d findings\n", r.Grade, r.Score, len(findings))
	}
	if failOn != "" {
		threshold := severityRank(failOn)
		ranks := []int{}
		for _, f := range findings {
			ranks = append(ranks, severityRank(f.Severity))
		}
		sort.Sort(sort.Reverse(sort.IntSlice(ranks)))
		if len(ranks) > 0 && ranks[0] >= threshold {
			return 2
		}
	}
	return 0
}
