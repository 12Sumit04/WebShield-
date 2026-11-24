
import re

AUTH_PATTERNS = [
    # Hardcoded Flask secret key
    re.compile(r"""app\.secret_key\s*=\s*["'][^"']+["']""", re.IGNORECASE),

    # Insecure cookie settings
    re.compile(r"""SESSION_COOKIE_SECURE\s*=\s*False""", re.IGNORECASE),

    re.compile(r"""SESSION_COOKIE_HTTPONLY\s*=\s*False""", re.IGNORECASE),

    # Disabled CSRF protection
    re.compile(r"""WTF_CSRF_ENABLED\s*=\s*False""", re.IGNORECASE),
]


def scan_auth(file_path):
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            lines = file.readlines()

        for line_number, line in enumerate(lines, start=1):
            for pattern in AUTH_PATTERNS:
                if pattern.search(line):
                    findings.append({
                        "type": "Weak Authentication / Session Security",
                        "severity": "MEDIUM",
                        "file": str(file_path),
                        "line": line_number,
                        "description": "Potentially insecure authentication or session configuration detected.",
                        "recommendation": "Use environment-managed secrets, enable secure cookie settings and enforce CSRF protection."
                    })
                    break

    except OSError:
        pass

    return findings
