import os
import json
import sys
from collections import Counter
from pathlib import Path

REPORT_PATH = Path("grype-report.json")

FAIL_ON_CRITICAL = 999         # fail if >= 1 Critical
WARN_ON_HIGH = 1              # warn if >= 5 High

def norm_sev(sev: str) -> str:
    if not sev:
        return "Unknown"
    s = sev.strip().lower()
    if s == "negligible":
        return "Negligible"
    if s == "unknown":
        return "Unknown"
    return s.capitalize()

def main() -> int:
    if not REPORT_PATH.exists():
        print(f"[POLICY] Missing {REPORT_PATH}. Did the Grype scan run?")
        return 2

    data = json.loads(REPORT_PATH.read_text())
    matches = data.get("matches", [])

    # Deduplicate by vulnerability ID (e.g., CVE-xxxx) across packages/locations
    unique = {}
    for m in matches:
        vuln = (m.get("vulnerability") or {})
        vid = vuln.get("id") or "UNKNOWN-ID"
        sev = norm_sev(vuln.get("severity") or "Unknown")

        # Keep the "worst" severity if we see the same CVE multiple times
        # Rough ordering:
        order = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Negligible": 1, "Unknown": 0}
        prev = unique.get(vid)
        if prev is None or order.get(sev, 0) > order.get(prev, 0):
            unique[vid] = sev

    counts = Counter(unique.values())

    critical = counts.get("Critical", 0)
    high = counts.get("High", 0)

    print(f"[POLICY] Unique vulnerabilities: {len(unique)}")
    print(f"[POLICY] Counts (deduped): {dict(counts)}")

    # Print a quick “top list” for humans
    top = ["Critical", "High", "Medium"]
    for sev in top:
        ids = [vid for vid, s in unique.items() if s == sev][:10]
        if ids:
            print(f"[POLICY] Sample {sev} IDs (up to 10): {', '.join(ids)}")

    print("\n[SECURITY SUMMARY]")
    print("=" * 50)
    print(f"Target image: {os.environ.get('TARGET_IMAGE', 'unknown')}")
    print(f"Unique vulnerabilities: {len(unique)}")
    print(f"Critical: {critical}")
    print(f"High: {high}")
    print(f"Medium: {counts.get('Medium', 0)}")
    print("=" * 50)

    if critical >= FAIL_ON_CRITICAL:
        print(f"[POLICY] FAIL: Critical deduped findings = {critical} (threshold: {FAIL_ON_CRITICAL})")
        return 1

    if high >= WARN_ON_HIGH:
        print(f"[POLICY] WARN: High deduped findings = {high} (threshold: {WARN_ON_HIGH})")
        return 0

    print("[POLICY] PASS: thresholds satisfied.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
