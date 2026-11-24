# WebShield

### Static Security Analysis Tool for Web Applications

WebShield is a Python-based static security analysis tool that identifies potential vulnerabilities in web application source code. It helps developers detect common security weaknesses, understand their severity, and prioritize remediation.

## Features

- ZIP-based source code upload and scanning.
- Hardcoded secret detection.
- SQL Injection detection.
- Cross-Site Scripting (XSS) detection.
- Command Injection detection.
- Insecure CORS configuration detection.
- Authentication weakness detection.
- Weak cryptographic practice detection.
- Debug information exposure detection.
- Severity-based vulnerability classification.
- Overall project risk scoring.
- Remediation recommendations.

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, Flask |
| Frontend | HTML, CSS, JavaScript |
| Detection | Regex-based Static Analysis |
| API | Flask REST API |
| Testing | Python unittest |

## Project Structure

```text
WebShield/
├── backend/
│   ├── main.py
│   ├── archive_handler.py
│   ├── project_scanner.py
│   ├── scoring.py
│   └── *_scanner.py
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
├── tests/
│   └── test_archive_handler.py
├── .gitignore
├── README.md
└── requirements.txt
```

## Installation and Execution

1. Clone the repository:

```bash
git clone https://github.com/12Sumit04/WebShield-.git
cd WebShield-
```

2. Create and activate a virtual environment:

```bash
python -m venv .venv
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Start the Flask backend:

```bash
python -m flask --app backend.main run --host 127.0.0.1 --port 5000
```

5. Open the frontend `index.html` in your browser.

## Testing

Run the unit tests:

```bash
python -m unittest discover -s tests -v
```

The archive handling module was evaluated using eight unit tests covering invalid archives, path traversal, oversized files, duplicate paths, excessive file counts, compression ratios, and extraction cleanup.

## Evaluation Results

- Vulnerable sample project: 10 findings (5 HIGH and 5 MEDIUM).
- Overall risk score: 55 (HIGH).
- Clean sample project: 0 findings.
- Archive handling tests: 8 passed.

## Limitations

WebShield currently uses pattern-based static analysis. It identifies potential security issues but does not guarantee detection of every vulnerability or certify an application's security.

## Project Goal

To make basic application security analysis more accessible to students, independent developers, and small development teams.