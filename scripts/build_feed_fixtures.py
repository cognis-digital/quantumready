"""Build SMALL, trimmed, OFFLINE test fixtures for the feed enrichment.

Strategy that guarantees a REAL KEV<->NVD intersection using REAL data:
  1. Scan the live CISA-KEV catalog for entries whose name/description name a
     quantum-relevant crypto primitive (RSA / ECC / Diffie-Hellman / certificate
     / cryptographic).
  2. Look those exact CVE ids up in the live NVD API (?cveId=...), so the NVD
     fixture really describes the same actively-exploited crypto CVEs.
  3. Write trimmed copies (+ a couple of unrelated entries) as datafeeds cache
     files so the committed test suite runs entirely offline.

Run once with network; the emitted fixtures are committed.

    python scripts/build_feed_fixtures.py
"""
import json, re, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from quantumready import datafeeds as df  # noqa: E402

FIX = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "feeds-cache"
FIX.mkdir(parents=True, exist_ok=True)

# crypto words quantumready cares about, matched against KEV entry text, mapped
# to the keyword the enrichment will use so offline keyword-filtering still hits.
CRYPTO_RX = re.compile(r"\bRSA\b|elliptic curve|\bECDSA\b|\bECDH\b|Diffie-Hellman|"
                       r"cryptograph|\bcertificate\b|\bTLS\b|\bSSL\b|key exchange|"
                       r"signature (forg|bypass|validation)|\bcipher\b", re.I)
# which enrichment keyword each fixture CVE should answer to (so offline filter matches)
def keyword_for(text):
    t = text.lower()
    if "rsa" in t: return "RSA"
    if "elliptic" in t or "ecdsa" in t or "ecdh" in t: return "elliptic curve"
    if "diffie" in t: return "Diffie-Hellman"
    return "RSA"


def fetch_retry(url, tries=6, wait=10):
    for i in range(tries):
        try:
            return json.loads(df.fetch(url))
        except Exception as e:  # NVD 503 rate-limit
            print(f"  retry {i+1}/{tries} ({e})", flush=True)
            time.sleep(wait)
    raise SystemExit(f"gave up on {url}")


def main():
    kev = df.get("cisa-kev")
    cat = df.load_catalog()
    nvd_url = {f["id"]: f for f in cat["feeds"]}["nvd-cve"]["url"]

    # crypto KEV entries (prefer recent ones)
    crypto = []
    for v in sorted(kev["vulnerabilities"], key=lambda x: x.get("dateAdded", ""), reverse=True):
        text = f"{v.get('vulnerabilityName','')} {v.get('shortDescription','')}"
        if CRYPTO_RX.search(text):
            crypto.append((v, keyword_for(text)))
    print(f"crypto KEV candidates: {len(crypto)}", flush=True)

    # take up to 4, confirm each exists in NVD (real record)
    keep_kev, nvd_keep, expected = [], {}, {}
    for v, kw in crypto:
        if len(keep_kev) >= 4:
            break
        cid = v["cveID"].upper()
        print(f"NVD cveId={cid} (kw={kw})", flush=True)
        d = fetch_retry(nvd_url + f"?cveId={cid}")
        items = d.get("vulnerabilities", [])
        if not items:
            print(f"  {cid} not in NVD, skip", flush=True)
            continue
        cve = items[0]["cve"]
        ndesc = " ".join(x.get("value", "") for x in cve.get("descriptions", [])).lower()
        # pick a keyword that ACTUALLY appears in the NVD description so the
        # offline keyword filter in feeds.nvd_cves_for_keyword() will match it.
        chosen = None
        # require a PRIMITIVE keyword the scanner's families actually search for,
        # so the offline enrichment (RSA / ECC / DH) genuinely intersects.
        for cand in ("RSA", "elliptic curve", "ECDSA", "ECDH", "Diffie-Hellman"):
            if cand.lower() in ndesc:
                chosen = cand
                break
        if not chosen:
            print(f"  {cid} NVD desc has no enrichment keyword, skip", flush=True)
            time.sleep(7)
            continue
        nvd_keep[cid] = cve
        keep_kev.append(v)
        expected.setdefault(chosen, []).append(cid)
        time.sleep(7)

    if not keep_kev:
        raise SystemExit("no KEV/NVD crypto intersection confirmed")

    crypto_kev_ids = sorted(nvd_keep)
    print(f"confirmed KEV+NVD crypto CVEs: {crypto_kev_ids}", flush=True)

    # add a few unrelated KEV entries so the catalog isn't only the intersection
    for v in kev["vulnerabilities"]:
        if len(keep_kev) >= len(crypto_kev_ids) + 3:
            break
        if v["cveID"].upper() not in crypto_kev_ids:
            keep_kev.append(v)

    kev_trim = {
        "title": kev.get("title", "CISA KEV (trimmed fixture)"),
        "catalogVersion": kev.get("catalogVersion", "fixture"),
        "dateReleased": kev.get("dateReleased", ""),
        "count": len(keep_kev),
        "vulnerabilities": keep_kev,
    }
    nvd_trim = {
        "resultsPerPage": len(nvd_keep), "startIndex": 0,
        "totalResults": len(nvd_keep), "format": "NVD_CVE", "version": "2.0",
        "vulnerabilities": [{"cve": c} for c in nvd_keep.values()],
    }

    def write_cache(feed_id, obj):
        (FIX / f"{feed_id}.data").write_text(json.dumps(obj), encoding="utf-8")
        (FIX / f"{feed_id}.meta.json").write_text(json.dumps({
            "feed": feed_id, "url": "fixture", "fetched_at": time.time(),
            "bytes": 0, "format": "json"}), encoding="utf-8")

    write_cache("cisa-kev", kev_trim)
    write_cache("nvd-cve", nvd_trim)
    (FIX / "_expected.json").write_text(json.dumps(
        {"crypto_kev_ids": crypto_kev_ids, "by_keyword": expected}, indent=2),
        encoding="utf-8")
    print(f"wrote fixtures to {FIX}", flush=True)
    print(f"  cisa-kev: {len(keep_kev)} CVEs ; nvd-cve: {len(nvd_keep)} CVEs", flush=True)


if __name__ == "__main__":
    main()
