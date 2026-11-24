
import re

CRYPTO_PATTERNS = [
    # Weak hashing algorithms
    re.compile(r"\bhashlib\.md5\s*\(", re.IGNORECASE),
    re.compile(r"\bhashlib\.sha1\s*\(", re.IGNORECASE),

    # Weak random number generation for security-sensitive use
    re.compile(r"\brandom\.(?:random|randint|choice)\s*\(", re.IGNORECASE),

    # Weak encryption algorithms
    re.compile(r"\bDES\.new\s*\(", re.IGNORECASE),

    # Insecure ECB encryption mode
    re.compile(r"\bAES\.MODE_ECB\b", re.IGNORECASE),
]


def scan_crypto(file_path):
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            lines = file.readlines()

        for line_number, line in enumerate(lines, start=1):
            for pattern in CRYPTO_PATTERNS:
                if pattern.search(line):
                    findings.append({
                        "type": "Weak Cryptography",
                        "severity": "MEDIUM",
                        "file": str(file_path),
                        "line": line_number,
                        "description": "Potentially weak cryptographic algorithm or insecure random generator detected.",
                        "recommendation": "Use modern cryptographic algorithms such as SHA-256 for hashing and cryptographically secure random generators for security-sensitive operations."
                    })
                    break

    except OSError:
        pass

    return findings
