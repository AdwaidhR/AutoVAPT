"""
Risk Scoring Engine
-----------------------
Transparent, explainable scoring - not a black box. Weight by severity,
then apply a confidence multiplier (a Low-confidence Critical counts
for less than a High-confidence Critical) so the score reflects
evidence quality, not just raw finding counts.
"""

SEVERITY_WEIGHTS = {"Critical": 10, "High": 8, "Medium": 5, "Low": 2, "Info": 0}
CONFIDENCE_MULTIPLIER = {"High": 1.0, "Medium": 0.7, "Low": 0.4}


def score(findings, cve_results=None):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    weighted_total = 0.0

    for f in findings or []:
        sev = f.get("severity", "Info")
        conf = f.get("confidence", "Medium")
        if sev not in counts:
            sev = "Info"
        counts[sev] += 1
        weighted_total += SEVERITY_WEIGHTS.get(sev, 0) * CONFIDENCE_MULTIPLIER.get(conf, 0.5)

    cve_critical_high = 0
    if cve_results:
        for svc in cve_results.get("results", []):
            for cve in svc.get("cves", []):
                sev = (cve.get("severity") or "").title()
                if sev in ("Critical",):
                    cve_critical_high += 1
                    counts["Critical"] += 1
                    weighted_total += SEVERITY_WEIGHTS["Critical"] * 0.6  # unverified CVE match
                elif sev == "High":
                    cve_critical_high += 1
                    counts["High"] += 1
                    weighted_total += SEVERITY_WEIGHTS["High"] * 0.6

    if counts["Critical"] > 0:
        overall = "Critical"
    elif counts["High"] >= 2:
        overall = "High"
    elif counts["High"] >= 1 or counts["Medium"] >= 3:
        overall = "Medium"
    elif counts["Medium"] >= 1 or counts["Low"] >= 1:
        overall = "Low"
    else:
        overall = "Informational"

    return {
        "counts": counts,
        "weighted_score": round(weighted_total, 1),
        "overall_risk": overall,
        "methodology": (
            "weighted_score = sum(severity_weight x confidence_multiplier) across all "
            "findings, including unverified CVE keyword matches (discounted 40%). "
            "overall_risk is derived from counts, not the raw score, so a handful of "
            "unrelated Low findings can't inflate the headline rating."
        ),
    }
