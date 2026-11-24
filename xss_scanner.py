
import re

XSS_PATTERNS = [
    re.compile(r"\.innerHTML\s*=", re.IGNORECASE),
    re.compile(r"\.outerHTML\s*=", re.IGNORECASE),
    re.compile(r"document\.write\s*\(", re.IGNORECASE),
    re.compile(r"insertAdjacentHTML\s*\(", re.IGNORECASE),
    re.compile(r"\beval\s*\(", re.IGNORECASE),
]


def scan_xss(file_path):
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            lines = file.readlines()

        for line_number, line in enumerate(lines, start=1):
            for pattern in XSS_PATTERNS:
                if pattern.search(line):
                    findings.append({
                        "type": "Cross-Site Scripting (XSS)",
                        "severity": "HIGH",
                        "file": str(file_path),
                        "line": line_number,
                        "description": "Potentially unsafe JavaScript or HTML operation detected.",
                        "recommendation": "Avoid inserting untrusted input into HTML. Use textContent and safe output encoding."
                    })
                    break

    except OSError:
        pass

    return findings
