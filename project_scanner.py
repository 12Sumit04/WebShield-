
import os
from pathlib import Path

from backend.secrets_scanner import scan_file
from backend.sqli_scanner import scan_sql_injection
from backend.xss_scanner import scan_xss
from backend.command_injection_scanner import scan_command_injection
from backend.cors_scanner import scan_cors
from backend.auth_scanner import scan_auth
from backend.crypto_scanner import scan_crypto
from backend.debug_scanner import scan_debug


EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".idea",
    ".vscode"
}

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".html", ".css", ".json", ".php",
    ".java", ".go", ".rb", ".sql",
    ".yaml", ".yml", ".toml", ".ini"
}

MAX_FILE_SIZE = 1024 * 1024  # 1 MB


def scan_project(project_path):

    root_path = Path(project_path).resolve()

    if not root_path.is_dir():
        raise ValueError("Invalid project directory")

    findings = []

    for root, dirs, files in os.walk(root_path, followlinks=False):

        dirs[:] = [
            directory for directory in dirs
            if directory not in EXCLUDED_DIRS
            and not (Path(root) / directory).is_symlink()
        ]

        for filename in files:

            file_path = Path(root) / filename

            if file_path.is_symlink():
                continue

            if file_path.suffix.lower() not in SUPPORTED_EXTENSIONS:
                if filename != ".env":
                    continue

            try:
                if file_path.stat().st_size > MAX_FILE_SIZE:
                    continue

                relative_path = str(file_path.relative_to(root_path))

                def add_findings(scanner_findings):
                    for finding in scanner_findings:
                        finding["file"] = relative_path
                        findings.append(finding)

                # 1. Hardcoded secrets
                add_findings(scan_file(str(file_path)))

                # 2. SQL injection
                add_findings(scan_sql_injection(str(file_path)))

                # 3. Cross-site scripting
                add_findings(scan_xss(str(file_path)))

                # 4. Command injection
                add_findings(scan_command_injection(str(file_path)))

                # 5. Insecure CORS
                add_findings(scan_cors(str(file_path)))

                # 6. Authentication and session security
                add_findings(scan_auth(str(file_path)))

                # 7. Weak cryptography
                add_findings(scan_crypto(str(file_path)))

                # 8. Debug mode and error disclosure
                add_findings(scan_debug(str(file_path)))

            except (OSError, UnicodeError):
                continue

    return findings
