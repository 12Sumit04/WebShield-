
import re

SECRET_PATTERNS = [
    re.compile(
        r"""(?:password|passwd|pwd)\s*=\s*["'][^"']{3,}["']""",
        re.IGNORECASE
    ),
    re.compile(
        r"""(?:api_key|apikey|secret_key|access_token)\s*=\s*["'][^"']{3,}["']""",
        re.IGNORECASE
    ),
]


def scan_file(file_path):
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            lines = file.readlines()

        for line_number, line in enumerate(lines, start=1):
            for pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append({
                        "type": "Hardcoded Secret",
                        "severity": "HIGH",
                        "file": str(file_path),
                        "line": line_number,
                        "description": "A possible hardcoded secret was detected.",
                        "recommendation": "Store secrets in environment variables or a secure secrets manager."
                    })
                    break

    except OSError:
        pass

    return findings
