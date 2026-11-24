
SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1
}


def calculate_risk(findings):

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    total_points = 0

    for finding in findings:
        severity = finding.get("severity", "LOW").upper()

        if severity in counts:
            counts[severity] += 1
            total_points += SEVERITY_WEIGHTS[severity]

    # Maximum score is capped at 100
    risk_score = min(total_points, 100)

    if risk_score >= 70:
        risk_level = "CRITICAL"
    elif risk_score >= 40:
        risk_level = "HIGH"
    elif risk_score >= 15:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "severity_counts": counts,
        "total_findings": len(findings)
    }

SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1
}


def calculate_risk(findings):
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    total_points = 0

    for finding in findings:
        severity = finding.get("severity", "LOW").upper()

        if severity in counts:
            counts[severity] += 1
            total_points += SEVERITY_WEIGHTS[severity]

    risk_score = min(total_points, 100)

    if risk_score >= 70:
        risk_level = "CRITICAL"
    elif risk_score >= 40:
        risk_level = "HIGH"
    elif risk_score >= 15:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "severity_counts": counts,
        "total_findings": len(findings)
    }
