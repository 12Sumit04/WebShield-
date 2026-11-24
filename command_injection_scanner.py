
import re

COMMAND_PATTERNS = [
    # Dangerous shell execution
    re.compile(r"\bos\.system\s*\(", re.IGNORECASE),

    # Subprocess with shell=True
    re.compile(r"\bsubprocess\.(?:run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True", re.IGNORECASE),

    # Direct command execution functions
    re.compile(r"\b(?:os\.popen|commands\.getoutput)\s*\(", re.IGNORECASE),

    # Node.js command execution
    re.compile(r"\bchild_process\.(?:exec|execSync)\s*\(", re.IGNORECASE),
]


def scan_command_injection(file_path):
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as file:
            lines = file.readlines()

        for line_number, line in enumerate(lines, start=1):
            for pattern in COMMAND_PATTERNS:
                if pattern.search(line):
                    findings.append({
                        "type": "Command Injection",
                        "severity": "HIGH",
                        "file": str(file_path),
                        "line": line_number,
                        "description": "Potentially unsafe operating-system command execution detected.",
                        "recommendation": "Avoid passing untrusted input to shell commands. Use safe APIs and argument lists with shell=False."
                    })
                    break

    except OSError:
        pass

    return findings
