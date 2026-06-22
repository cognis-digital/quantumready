"""quantumready feed enrichment — turn a PQC crypto scan into a prioritized,
exploited-in-the-wild patch list using two authoritative, keyless feeds:

  * cisa-kev  — CISA Known Exploited Vulnerabilities (actively-exploited CVEs)
  * nvd-cve   — NIST National Vulnerability Database (authoritative CVE detail)

REAL enrichment (not cosmetic)
------------------------------
quantumready's scanner finds *which* quantum-vulnerable algorithm families a
codebase relies on (RSA / ECC / DH / DSA). On its own that is a migration
backlog with no urgency signal. This module cross-references those families
against live CVE intelligence:

  1. For each crypto family present in the scan, pull NVD CVEs whose description
     names that primitive (keyword search) -> the universe of known crypto CVEs
     relevant to *this* codebase.
  2. Intersect with the CISA-KEV catalog -> the subset that is being **actively
     exploited right now** ("known-exploited" flag).

The output answers a defender's real question: "I depend on RSA/ECC — which of
those weaknesses are attackers exploiting today, and must I patch before I even
start the multi-year PQC migration?"

Edge / air-gap
--------------
All access goes through the bundled ``datafeeds`` module: keyless HTTPS fetch ->
disk cache -> ``offline=True`` re-serve. Point ``COGNIS_FEEDS_CACHE`` at a
snapshot directory (see ``datafeeds snapshot-export/-import``) to run fully
disconnected. Defensive / authorized-use only.
"""

from __future__ import annotations

import json
from typing import Iterable, Optional

from quantumready import datafeeds as _df

# Feed ids this tool is allowed to consume (from the bundled catalog only).
RELEVANT_FEEDS = ["cisa-kev", "nvd-cve"]

# quantumready rule-id -> (crypto family label, NVD keyword search terms).
# Only the quantum-vulnerable families map to CVE intel; PQC "good" findings do not.
#
# Each family searches BOTH its primitive name and the crypto-weakness vocabulary
# real CVE/KEV advisories actually use (advisories rarely say "RSA" outright — they
# say "improper verification of cryptographic signature", "certificate validation",
# "key exchange"). This keeps the intersection meaningful against live data.
_FAMILY_KEYWORDS = {
    "QR-RSA": ("RSA", ["RSA", "cryptographic key"]),
    "QR-WEAKRSA": ("RSA", ["RSA", "cryptographic key"]),
    "QR-ECC": ("Elliptic-curve", ["ECDSA", "elliptic curve", "ECDH", "cryptographic signature"]),
    "QR-DH": ("Diffie-Hellman", ["Diffie-Hellman", "key exchange"]),
    "QR-DSA": ("DSA", ["DSA", "cryptographic signature"]),
    "QR-TLS": ("TLS key-exchange", ["certificate validation", "TLS"]),
}


# --------------------------------------------------------------------------- #
# raw feed access (cache-first / offline-capable, via bundled datafeeds)
# --------------------------------------------------------------------------- #
def _check_feed(feed_id: str) -> None:
    if feed_id not in RELEVANT_FEEDS:
        raise ValueError(
            f"feed {feed_id!r} is not wired into quantumready; "
            f"allowed: {', '.join(RELEVANT_FEEDS)}"
        )


def feed_get(feed_id: str, *, offline: bool = False, query: Optional[dict] = None):
    """Fetch/serve a quantumready-relevant feed via the bundled datafeeds cache."""
    _check_feed(feed_id)
    return _df.get(feed_id, offline=offline, query=query)


def kev_cve_ids(*, offline: bool = False) -> set[str]:
    """Set of CVE ids in the CISA Known-Exploited-Vulnerabilities catalog."""
    kev = feed_get("cisa-kev", offline=offline)
    return {v.get("cveID", "").upper() for v in kev.get("vulnerabilities", []) if v.get("cveID")}


def kev_index(*, offline: bool = False) -> dict[str, dict]:
    """CVE id -> KEV record (vendor/product/ransomware/dueDate/...)."""
    kev = feed_get("cisa-kev", offline=offline)
    return {v["cveID"].upper(): v for v in kev.get("vulnerabilities", []) if v.get("cveID")}


def nvd_cves_for_keyword(keyword: str, *, offline: bool = False) -> list[dict]:
    """NVD CVE records whose text matches ``keyword``.

    Online: appends ``?keywordSearch=`` to the catalog NVD endpoint (the cache
    key stays the bare feed, so an offline snapshot of nvd-cve serves any query).
    """
    if offline:
        d = feed_get("nvd-cve", offline=True)
    else:
        cat = _df.load_catalog()
        feeds = {f["id"]: f for f in cat.get("feeds", [])}
        url = feeds["nvd-cve"]["url"] + f"?keywordSearch={keyword}&resultsPerPage=50"
        d = json.loads(_df.fetch(url))
    kw = keyword.lower()
    out = []
    for item in d.get("vulnerabilities", []):
        cve = item.get("cve", {})
        text = " ".join(x.get("value", "") for x in cve.get("descriptions", []))
        if not offline or kw in text.lower():
            out.append(cve)
    return out


def _cve_summary(cve: dict) -> dict:
    descs = cve.get("descriptions", [])
    desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
    if not desc and descs:
        desc = descs[0].get("value", "")
    return {"id": cve.get("id", "").upper(), "description": desc[:240],
            "published": cve.get("published", "")[:10]}


# --------------------------------------------------------------------------- #
# THE enrichment: scan families -> crypto CVEs -> KEV known-exploited subset
# --------------------------------------------------------------------------- #
def enrich_findings(findings: Iterable, *, offline: bool = False,
                    max_per_family: int = 25) -> dict:
    """Cross-reference quantum-vulnerable findings against live CVE intelligence.

    Returns a dict with, per crypto family detected in the scan:
      * ``cve_count``        — NVD CVEs naming that primitive (relevant universe)
      * ``known_exploited``  — the subset on the CISA-KEV catalog (patch NOW)
    plus a top-level ``priority`` list (the union of KEV hits) and counts.
    """
    families = {}
    for f in findings:
        fam = _FAMILY_KEYWORDS.get(getattr(f, "id", None))
        if fam:
            families.setdefault(fam[0], set()).update(fam[1])

    kev = kev_index(offline=offline)
    report: dict = {"feeds": RELEVANT_FEEDS, "offline": offline,
                    "families": {}, "priority": []}
    seen_priority: set[str] = set()

    for fam_label, keywords in families.items():
        cves: dict[str, dict] = {}
        for kw in keywords:
            for cve in nvd_cves_for_keyword(kw, offline=offline):
                s = _cve_summary(cve)
                if s["id"]:
                    cves[s["id"]] = s
            if len(cves) >= max_per_family:
                break
        known = []
        for cid, summary in cves.items():
            if cid in kev:
                rec = kev[cid]
                hit = {
                    **summary,
                    "known_exploited": True,
                    "kev_vendor": rec.get("vendorProject", ""),
                    "kev_product": rec.get("product", ""),
                    "kev_date_added": rec.get("dateAdded", ""),
                    "ransomware": rec.get("knownRansomwareCampaignUse", "Unknown"),
                    "due_date": rec.get("dueDate", ""),
                }
                known.append(hit)
                if cid not in seen_priority:
                    seen_priority.add(cid)
                    report["priority"].append({"family": fam_label, **hit})
        report["families"][fam_label] = {
            "cve_count": len(cves),
            "known_exploited_count": len(known),
            "known_exploited": sorted(known, key=lambda h: h["id"]),
        }

    report["priority"].sort(key=lambda h: h["id"])
    report["summary"] = {
        "families_detected": sorted(families),
        "total_priority_cves": len(report["priority"]),
        "advice": (
            "Patch the actively-exploited CVEs below before/while migrating to "
            "NIST PQC (ML-KEM FIPS 203, ML-DSA FIPS 204, SLH-DSA FIPS 205). "
            "KEV listing means real-world exploitation now."
        ) if report["priority"] else
        "No KEV-listed CVEs matched the detected crypto families in this snapshot.",
    }
    return report
