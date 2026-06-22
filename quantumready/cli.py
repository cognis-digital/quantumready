"""quantumready CLI."""
import argparse, sys
from quantumready.core import scan_path, to_json, to_sarif, readiness, TOOL_NAME, TOOL_VERSION
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="quantumready", description="Post-quantum migration readiness scanner (NIST FIPS 203/204/205).")
    ap.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("scan"); s.add_argument("target"); s.add_argument("--format", choices=["table","json","sarif"], default="table")
    s.add_argument("--fail-on", choices=["critical","high","medium"], default=None)
    a = ap.parse_args(argv)
    if a.cmd != "scan": ap.print_help(); return 0
    f = scan_path(a.target)
    if a.format == "json": print(to_json(f))
    elif a.format == "sarif": print(to_sarif(f))
    else:
        for x in f: print(f"  [{x.severity.upper():8}] {x.id}  {x.label}  ({x.where}:{x.line})")
        r = readiness(f); print(f"\nPQC readiness: {r['grade']} ({r['score']}/100) — {len(f)} findings")
    order={"critical":4,"high":3,"medium":2}
    if a.fail_on and any(order.get(x.severity,0)>=order[a.fail_on] for x in f): return 2
    return 0
if __name__ == "__main__": sys.exit(main())
