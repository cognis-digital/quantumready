"""quantumready CLI."""
import argparse, json, sys
from quantumready.core import scan_path, to_json, to_sarif, readiness, TOOL_NAME, TOOL_VERSION
from quantumready import datafeeds, feeds as feedmod


def _feeds_cmd(a) -> int:
    """`quantumready feeds ...` — keyless, cache-first, air-gap-capable feed access.

    Restricted to the feeds this tool consumes: cisa-kev, nvd-cve.
    """
    if a.feeds_cmd == "list":
        cat = datafeeds.load_catalog()
        feeds = {f["id"]: f for f in cat.get("feeds", [])}
        for fid in feedmod.RELEVANT_FEEDS:
            f = feeds.get(fid, {})
            age = datafeeds.cached_age_hours(fid)
            fresh = "uncached" if age is None else f"{age:.1f}h old"
            print(f"  {fid:10} [{fresh:9}] {f.get('name','')}")
            print(f"             {f.get('url','')}")
        return 0
    if a.feeds_cmd == "update":
        for fid in feedmod.RELEVANT_FEEDS:
            try:
                p = datafeeds.update(fid)
                print(f"  updated {fid} -> {p} ({p.stat().st_size} bytes)")
            except Exception as e:  # network / catalog
                print(f"  {fid}: {e}", file=sys.stderr)
        return 0
    if a.feeds_cmd == "get":
        try:
            data = feedmod.feed_get(a.id, offline=a.offline)
        except (ValueError, KeyError, FileNotFoundError, ConnectionError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(json.dumps(data, indent=2)[:4000] if isinstance(data, (dict, list)) else str(data)[:4000])
        return 0
    return 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="quantumready", description="Post-quantum migration readiness scanner (NIST FIPS 203/204/205).")
    ap.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("scan"); s.add_argument("target"); s.add_argument("--format", choices=["table","json","sarif"], default="table")
    s.add_argument("--fail-on", choices=["critical","high","medium"], default=None)
    s.add_argument("--enrich", action="store_true", help="cross-reference detected crypto families against CISA-KEV / NVD")
    s.add_argument("--offline", action="store_true", help="serve feeds from cache only (air-gap)")

    fp = sub.add_parser("feeds", help="keyless CISA-KEV / NVD feed access (cache-first, air-gap)")
    fsub = fp.add_subparsers(dest="feeds_cmd")
    fsub.add_parser("list", help="list the feeds this tool consumes")
    fsub.add_parser("update", help="fetch + cache cisa-kev and nvd-cve")
    fg = fsub.add_parser("get", help="print a feed (cisa-kev | nvd-cve)")
    fg.add_argument("id", choices=feedmod.RELEVANT_FEEDS)
    fg.add_argument("--offline", action="store_true")

    a = ap.parse_args(argv)
    if a.cmd == "feeds":
        if not a.feeds_cmd:
            fp.print_help(); return 0
        return _feeds_cmd(a)
    if a.cmd != "scan":
        ap.print_help(); return 0

    f = scan_path(a.target)
    enrichment = None
    if a.enrich:
        try:
            enrichment = feedmod.enrich_findings(f, offline=a.offline)
        except (FileNotFoundError, ConnectionError) as e:
            print(f"enrichment unavailable: {e}", file=sys.stderr)

    if a.format == "json":
        out = json.loads(to_json(f))
        if enrichment is not None:
            out["enrichment"] = enrichment
        print(json.dumps(out, indent=2))
    elif a.format == "sarif":
        print(to_sarif(f))
    else:
        for x in f: print(f"  [{x.severity.upper():8}] {x.id}  {x.label}  ({x.where}:{x.line})")
        r = readiness(f); print(f"\nPQC readiness: {r['grade']} ({r['score']}/100) — {len(f)} findings")
        if enrichment is not None:
            pr = enrichment["priority"]
            print(f"\nActively-exploited (CISA-KEV) crypto CVEs for detected families: {len(pr)}")
            for h in pr[:20]:
                rw = " [RANSOMWARE]" if h.get("ransomware") == "Known" else ""
                print(f"  [{h['family']:14}] {h['id']}  {h['kev_vendor']} {h['kev_product']} (KEV {h['kev_date_added']}){rw}")
            print(f"\n{enrichment['summary']['advice']}")
    order={"critical":4,"high":3,"medium":2}
    if a.fail_on and any(order.get(x.severity,0)>=order[a.fail_on] for x in f): return 2
    return 0
if __name__ == "__main__": sys.exit(main())
