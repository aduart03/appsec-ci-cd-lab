import os
import json
import sys
from collections import Counter
from pathlib import Path

# Thresholds
FAIL_ON_CRITICAL = 1   # fail if >= 1 Critical
WARN_ON_HIGH = 1       # warn if >= 1 High (but still pass)

def norm_sev(sev: str) -> str:
    if not sev:
        return "Unknown"
    s = sev.strip().lower()
    if s == "negligible":
        return "Negligible"
    if s == "unknown":
        return "Unknown"
    return s.capitalize()

def load_baseline(path: Path) -> set[str]:
    if not path:
        return set()
    if not path.exists():
        print(f"[POLICY] Baseline file not found: {path} (continuing with empty baseline)")
        return set()
    data = json.loads(path.read_text())
    ignore = data.get("ignore_ids", [])
    return set(ignore)


def main() -> int:
    # Allow: python policy_gate.py <report.json>
    report_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("grype-report.json")
    baseline_path = Path(sys.argv[2]) if len(sys.argv) > 2 else None

    if not report_path.exists():
        print(f"[POLICY] Missing {report_path}. Did the Grype scan run?")
        return 2
    
    ignored_ids = load_baseline(baseline_path) if baseline_path else set()
    if baseline_path:
        print(f"[POLICY] Baseline: {baseline_path} (ignore_ids={len(ignore_ids)})")

    data = json.loads(report_path.read_text())
    matches = data.get("matches", [])

    # Deduplicate by vulnerability ID (e.g., CVE-xxxx) across packages/locations
    unique = {}
    order = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Negligible": 1, "Unknown": 0}

    for m in matches:
        vuln = (m.get("vulnerability") or {})
        vid = vuln.get("id") or "UNKNOWN-ID"
        sev = norm_sev(vuln.get("severity") or "Unknown")

        prev = unique.get(vid)
        if prev is None or order.get(sev, 0) > order.get(prev, 0):
            unique[vid] = sev

    counts = Counter(unique.values())
    if ignored_ids:
        before = len(unique)
        unique = {vid: sev for vid, sev in unique.items() if vid not in ignored_ids}
        removed = before - len(unique)
        print(f"[POLICY] Baseline removed {removed} known IDs")
        counts = Counter(unique.values())
    critical = counts.get("Critical", 0)
    high = counts.get("High", 0)

    print(f"[POLICY] Report: {report_path}")
    print(f"[POLICY] Unique vulnerabilities: {len(unique)}")
    print(f"[POLICY] Counts (deduped): {dict(counts)}")

    # Print a quick “top list” for humans
    for sev in ["Critical", "High", "Medium"]:
        ids = [vid for vid, s in unique.items() if s == sev][:10]
        if ids:
            print(f"[POLICY] Sample {sev} IDs (up to 10): {', '.join(ids)}")

    print("\n[SECURITY SUMMARY]")
    print("=" * 50)
    print(f"Target: {os.environ.get('TARGET_NAME', os.environ.get('TARGET_IMAGE', 'unknown'))}")
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
