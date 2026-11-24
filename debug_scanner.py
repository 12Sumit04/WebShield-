
import re

DEBUG_PATTERNS = [
    # Debug mode enabled
    re.compile(r"\bDEBUG\s*=\s*True\b", re.IGNORECASE),

    # Flask debug mode
    re.compile(r"\bapp\.run\s*\([^)]*debug\s*=\s*True", re.IGNORECASE),

    # Detailed exception output
    re.compile(r"\btraceback\.print_exc\s*\(", re.IGNORECASE),

    # Exposing exception details in HTTP responses
    re.compile(r"\breturn\s+str\s*\(\s*(?:e|exc|exception)\s*\)", re.IGNORECASE),
]


def scan_debug(file_path):
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            lines = file.readlines()

        for line_number, line in enumerate(lines, start=1):
            for pattern in DEBUG_PATTERNS:
                if pattern.search(line):
                    findings.append({
                        "type": "Debug Mode / Error Disclosure",
                        "severity": "MEDIUM",
                        "file": str(file_path),
                        "line": line_number,
                        "description": "Potential debug configuration or sensitive error disclosure detected.",
                        "recommendation": "Disable debug mode in production and avoid exposing internal exception details to users."
                    })
                    break

    except OSError:
        pass

    return findings
