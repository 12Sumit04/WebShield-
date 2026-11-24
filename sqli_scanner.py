
import re

SQLI_PATTERNS = [
    # String concatenation inside execute()
    re.compile(
        r"""\.execute\s*\(\s*(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\s*\+""",
        re.IGNORECASE
    ),

    # F-string inside execute()
    re.compile(r"""\.execute\s*\(\s*f["']""", re.IGNORECASE),

    # Percent-based query formatting
    re.compile(
        r"""\.execute\s*\(\s*["'][^"']*%s[^"']*["']\s*%""",
        re.IGNORECASE
    )
]


def scan_sql_injection(file_path):
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            lines = file.readlines()

        for line_number, line in enumerate(lines, start=1):
            for pattern in SQLI_PATTERNS:
                if pattern.search(line):
                    findings.append({
                        "type": "SQL Injection",
                        "severity": "HIGH",
                        "file": str(file_path),
                        "line": line_number,
                        "description": "Potential unsafe SQL query construction detected.",
                        "recommendation": "Use parameterized queries instead of string concatenation or interpolation."
                    })
                    break

    except OSError:
        pass

    return findings
