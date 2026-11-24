
import re

CORS_PATTERNS = [
    re.compile(
        r"""allow_origins\s*=\s*\[\s*["']\*["']\s*\]""",
        re.IGNORECASE
    ),
    re.compile(
        r"""(?:CORS_ORIGIN|origins)\s*=\s*["']\*["']""",
        re.IGNORECASE
    ),
    re.compile(
        r"""Access-Control-Allow-Origin\s*[:=]\s*["']\*["']""",
        re.IGNORECASE
    )
]


def scan_cors(file_path):
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            lines = file.readlines()

        for line_number, line in enumerate(lines, start=1):
            for pattern in CORS_PATTERNS:
                if pattern.search(line):
                    findings.append({
                        "type": "Insecure CORS Configuration",
                        "severity": "MEDIUM",
                        "file": str(file_path),
                        "line": line_number,
                        "description": "Wildcard CORS origin detected.",
                        "recommendation": "Restrict allowed origins to explicitly trusted domains."
                    })
                    break

    except OSError:
        pass

    return findings
