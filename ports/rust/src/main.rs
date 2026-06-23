//! quantumready (Rust port) — post-quantum migration readiness scanner.
//!
//! Mirrors the primary Python CLI's core `scan` surface: detect quantum-vulnerable
//! crypto (RSA / ECC / DH / DSA), grade PQC readiness A-F, and map each finding to
//! the NIST PQC standards (ML-KEM FIPS 203, ML-DSA FIPS 204, SLH-DSA FIPS 205).
//!
//! Passive / offline by design: reads only local files, opens no socket, performs
//! no active network scanning. Defensive / authorized-use only. COCL v1.0.

use regex::Regex;
use std::fs;
use std::path::Path;
use std::process::exit;

pub const TOOL_NAME: &str = "quantumready";
pub const TOOL_VERSION: &str = "1.0.1";

/// (id, severity, pattern, label, recommendation)
struct Rule {
    id: &'static str,
    severity: &'static str,
    re: Regex,
    label: &'static str,
    recommend: &'static str,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub id: String,
    pub severity: String,
    pub label: String,
    pub where_: String,
    pub line: usize,
    pub match_: String,
    pub recommend: String,
}

fn rules() -> Vec<Rule> {
    // Kept equivalent to quantumready/core.py RULES. The `regex` crate (RE2-like)
    // has no lookbehind, so QR-DSA uses a plain pattern plus `dsa_guard`.
    vec![
        Rule { id: "QR-RSA", severity: "high",
            re: Regex::new(r"(?i)\b(rsa\.generate_private_key|RSA\.generate|genrsa|PKCS1|rsa_pkcs1|ssh-rsa)\b").unwrap(),
            label: "RSA (key exchange/signature) — broken by Shor's algorithm",
            recommend: "Migrate KEM->ML-KEM (FIPS 203); signatures->ML-DSA (FIPS 204). Use hybrid during transition." },
        Rule { id: "QR-ECC", severity: "high",
            re: Regex::new(r"(?i)\b(ec(dsa|dh)|secp256[rk]1|prime256v1|P-256|P-384|nistp256|curve25519|ed25519|x25519)\b").unwrap(),
            label: "Elliptic-curve crypto — broken by Shor's algorithm",
            recommend: "Replace ECDH with ML-KEM; ECDSA/EdDSA with ML-DSA or SLH-DSA." },
        Rule { id: "QR-DH", severity: "high",
            re: Regex::new(r"(?i)\b(diffie[-_ ]?hellman|\bdhparam\b|modp|ffdhe)\b").unwrap(),
            label: "Finite-field Diffie-Hellman — quantum-vulnerable",
            recommend: "Adopt ML-KEM (FIPS 203) for key establishment." },
        Rule { id: "QR-DSA", severity: "medium",
            re: Regex::new(r"(?i)(dsa|dss)\b").unwrap(),
            label: "DSA signatures — quantum-vulnerable + legacy",
            recommend: "Move to ML-DSA (FIPS 204)." },
        Rule { id: "QR-WEAKRSA", severity: "critical",
            re: Regex::new(r"(?i)rsa[^0-9]{0,8}(512|1024)\b").unwrap(),
            label: "Undersized RSA key (<=1024) — weak even classically",
            recommend: "Immediate: >=3072-bit RSA classically; plan ML-KEM/ML-DSA for PQC." },
        Rule { id: "QR-TLS", severity: "low",
            re: Regex::new(r"(?i)\b(TLS_ECDHE|TLS_RSA|kRSA|kEECDH)\b").unwrap(),
            label: "Classical TLS key-exchange suite",
            recommend: "Enable hybrid PQC TLS (X25519MLKEM768) where supported." },
        Rule { id: "QR-GOODKEM", severity: "info",
            re: Regex::new(r"(?i)\b(ml[-_]?kem|kyber|mlkem768|x25519mlkem768)\b").unwrap(),
            label: "ML-KEM / Kyber present — PQC KEM in use",
            recommend: "Good. Verify it's FIPS 203 (ML-KEM), not a draft Kyber." },
        Rule { id: "QR-GOODSIG", severity: "info",
            re: Regex::new(r"(?i)\b(ml[-_]?dsa|dilithium|slh[-_]?dsa|sphincs)\b").unwrap(),
            label: "PQC signature present",
            recommend: "Good. Confirm FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA)." },
    ]
}

/// Emulate Python's negative lookbehind `(?<![a-z0-9-])` for QR-DSA so that
/// "ecdsa"/"mldsa" do NOT match but a standalone "dsa"/"dss" does.
fn dsa_guard(line: &str, start: usize) -> bool {
    if start == 0 {
        return true;
    }
    match line.as_bytes()[start - 1] {
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' => false,
        _ => true,
    }
}

pub fn scan_text(text: &str, path: &str) -> Vec<Finding> {
    let rs = rules();
    let mut out = Vec::new();
    for (i, raw) in text.split('\n').enumerate() {
        let line = raw.trim_end_matches('\r');
        for r in &rs {
            if let Some(m) = r.re.find(line) {
                if r.id == "QR-DSA" && !dsa_guard(line, m.start()) {
                    continue;
                }
                let mut matched = m.as_str().to_string();
                if matched.len() > 60 {
                    matched.truncate(60);
                }
                out.push(Finding {
                    id: r.id.into(), severity: r.severity.into(), label: r.label.into(),
                    where_: path.into(), line: i + 1, match_: matched, recommend: r.recommend.into(),
                });
            }
        }
    }
    out
}

pub fn scan_path(target: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let p = Path::new(target);
    if p.is_file() {
        if let Ok(t) = fs::read_to_string(p) {
            out.extend(scan_text(&t, target));
        }
        return out;
    }
    let mut stack = vec![p.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(t) = fs::read_to_string(&path) {
                out.extend(scan_text(&t, &path.to_string_lossy()));
            }
        }
    }
    out
}

pub struct Readiness {
    pub score: i64,
    pub grade: char,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub info: i64,
    pub pqc_present: bool,
}

pub fn readiness(findings: &[Finding]) -> Readiness {
    let (mut c, mut h, mut m, mut l, mut info) = (0, 0, 0, 0, 0);
    for f in findings {
        match f.severity.as_str() {
            "critical" => c += 1,
            "high" => h += 1,
            "medium" => m += 1,
            "low" => l += 1,
            "info" => info += 1,
            _ => {}
        }
    }
    let vuln = c * 4 + h * 2 + m;
    let score = if vuln > 0 { (100 - vuln * 3).max(0) } else { 100 };
    let grade = if score >= 90 { 'A' } else if score >= 75 { 'B' }
        else if score >= 60 { 'C' } else if score >= 40 { 'D' } else { 'F' };
    Readiness { score, grade, critical: c, high: h, medium: m, low: l, info, pqc_present: info > 0 }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

pub fn to_json(findings: &[Finding]) -> String {
    let r = readiness(findings);
    let mut items = Vec::new();
    for f in findings {
        items.push(format!(
            "    {{\"id\": \"{}\", \"severity\": \"{}\", \"label\": \"{}\", \"where\": \"{}\", \"line\": {}, \"match\": \"{}\", \"recommend\": \"{}\"}}",
            json_escape(&f.id), json_escape(&f.severity), json_escape(&f.label),
            json_escape(&f.where_), f.line, json_escape(&f.match_), json_escape(&f.recommend)
        ));
    }
    format!(
        "{{\n  \"tool\": \"{}\",\n  \"findings\": [\n{}\n  ],\n  \"readiness\": {{\"score\": {}, \"grade\": \"{}\", \"severity_counts\": {{\"critical\": {}, \"high\": {}, \"medium\": {}, \"low\": {}, \"info\": {}}}, \"pqc_present\": {}}}\n}}",
        TOOL_NAME, items.join(",\n"), r.score, r.grade,
        r.critical, r.high, r.medium, r.low, r.info, r.pqc_present
    )
}

fn sev_rank(s: &str) -> i32 {
    match s { "critical" => 4, "high" => 3, "medium" => 2, _ => 0 }
}

fn usage() {
    println!("quantumready (Rust port) — post-quantum readiness scanner");
    println!("usage: quantumready scan <path> [--format table|json] [--fail-on critical|high|medium]");
    println!("       quantumready --version");
    println!("\nPassive/offline only. Defensive / authorized-use. COCL v1.0.");
}

pub fn run(args: &[String]) -> i32 {
    if args.is_empty() {
        usage();
        return 0;
    }
    if args[0] == "--version" {
        println!("{} {}", TOOL_NAME, TOOL_VERSION);
        return 0;
    }
    if args[0] != "scan" || args.len() < 2 {
        usage();
        return 0;
    }
    let target = &args[1];
    let mut format = "table".to_string();
    let mut fail_on: Option<String> = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--format" if i + 1 < args.len() => { i += 1; format = args[i].clone(); }
            "--fail-on" if i + 1 < args.len() => { i += 1; fail_on = Some(args[i].clone()); }
            _ => {}
        }
        i += 1;
    }
    let findings = scan_path(target);
    if format == "json" {
        println!("{}", to_json(&findings));
    } else {
        for f in &findings {
            println!("  [{:8}] {}  {}  ({}:{})",
                f.severity.to_uppercase(), f.id, f.label, f.where_, f.line);
        }
        let r = readiness(&findings);
        println!("\nPQC readiness: {} ({}/100) — {} findings", r.grade, r.score, findings.len());
    }
    if let Some(t) = fail_on {
        let threshold = sev_rank(&t);
        if findings.iter().any(|f| sev_rank(&f.severity) >= threshold) {
            return 2;
        }
    }
    0
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    exit(run(&args));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(fs: &[Finding]) -> std::collections::HashSet<String> {
        fs.iter().map(|f| f.id.clone()).collect()
    }

    #[test]
    fn detects_rsa_ecc_kem() {
        let f = scan_text("key = rsa.generate_private_key(2048)\nuse secp256k1 and ML-KEM", "<t>");
        let i = ids(&f);
        assert!(i.contains("QR-RSA") && i.contains("QR-ECC") && i.contains("QR-GOODKEM"));
    }

    #[test]
    fn weak_rsa_critical() {
        let f = scan_text("rsa_1024 used here", "<t>");
        assert!(ids(&f).contains("QR-WEAKRSA"));
        assert!(readiness(&f).critical >= 1);
    }

    #[test]
    fn mldsa_not_flagged_as_legacy_dsa() {
        let f = scan_text("signature = ml-dsa-65\nroot = slh-dsa-sha2-128s", "<t>");
        let i = ids(&f);
        assert!(!i.contains("QR-DSA"));
        assert!(i.contains("QR-GOODSIG"));
    }

    #[test]
    fn ecdsa_not_double_flagged() {
        let i = ids(&scan_text("ecdsa-with-SHA256", "<t>"));
        assert!(i.contains("QR-ECC") && !i.contains("QR-DSA"));
    }

    #[test]
    fn legacy_dsa_flagged() {
        assert!(ids(&scan_text("host_key = dsa\ncert uses DSS", "<t>")).contains("QR-DSA"));
    }

    #[test]
    fn pqc_only_grades_a() {
        let r = readiness(&scan_text("only x25519mlkem768 and ml-dsa here\n", "<t>"));
        assert_eq!(r.grade, 'A');
        assert!(r.pqc_present);
    }

    #[test]
    fn json_has_tool_and_findings() {
        let j = to_json(&scan_text("genrsa 2048", "<t>"));
        assert!(j.contains("\"tool\": \"quantumready\""));
        assert!(j.contains("QR-RSA"));
    }

    #[test]
    fn run_fail_on_exits_2_then_0() {
        let dir = std::env::temp_dir().join(format!("qr-rust-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let bad = dir.join("x.conf");
        fs::write(&bad, "ssh-rsa AAAA\n").unwrap();
        assert_eq!(run(&["scan".into(), bad.to_string_lossy().into(), "--fail-on".into(), "high".into()]), 2);
        let clean = dir.join("clean.txt");
        fs::write(&clean, "ml-kem only\n").unwrap();
        assert_eq!(run(&["scan".into(), clean.to_string_lossy().into(), "--fail-on".into(), "high".into()]), 0);
    }

    #[test]
    fn version_runs() {
        assert_eq!(run(&["--version".into()]), 0);
    }

    #[test]
    fn rule_table_has_eight() {
        assert_eq!(rules().len(), 8);
    }
}
