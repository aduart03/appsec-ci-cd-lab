import json
import sys
from pathlib import Path

REPORT_PATH = Path("grype-report.json")

# Policy: fail on any Critical; warn if High >= 5
FAIL_ON_CRITICAL = 1
WARN_ON_HIGH = 5

def main() -> int:
    if not REPORT_PATH.exists():
        print(f"[POLICY] Missing {REPORT_PATH}. Did the Grype scan run?")
        return 2

    data = json.loads(REPORT_PATH.read_text())

    # Grype JSON: matches is a list; each item has vulnerability.severity
    matches = data.get("matches", [])
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0}

    for m in matches:
        vuln = (m.get("vulnerability") or {})
        sev = (vuln.get("severity") or "Unknown")
        # Normalize capitalization
        sev_norm = sev.capitalize() if sev.lower() not in ["negligible", "unknown"] else sev.title()
        if sev_norm not in counts:
            sev_norm = "Unknown"
        counts[sev_norm] += 1

    critical = counts.get("Critical", 0)
    high = counts.get("High", 0)

    print("[POLICY] Vulnerability counts:", counts)

    if critical >= FAIL_ON_CRITICAL:
        print(f"[POLICY] FAIL: Critical findings = {critical} (threshold: {FAIL_ON_CRITICAL})")
        return 1

    if high >= WARN_ON_HIGH:
        print(f"[POLICY] WARN: High findings = {high} (threshold: {WARN_ON_HIGH})")
        # We warn but don't fail
        return 0

    print("[POLICY] PASS: thresholds satisfied.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
