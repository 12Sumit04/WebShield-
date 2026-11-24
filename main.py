
import tempfile
from pathlib import Path

from flask import Flask, jsonify, request
from werkzeug.utils import secure_filename
from backend.archive_handler import extract_zip, InvalidArchiveError
from backend.project_scanner import scan_project
from backend.scoring import calculate_risk


app = Flask(__name__)

MAX_UPLOAD_SIZE = 20 * 1024 * 1024  # 20 MB
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE

@app.get("/")
def home():
    return jsonify({
        "message": "Welcome to WebShield!",
        "status": "running"
    })


@app.get("/health")
def health_check():
    return jsonify({
        "status": "healthy"
    })


@app.errorhandler(413)
def file_too_large(error):
    return jsonify({
        "error": "ZIP upload exceeds the 20 MB limit."
    }), 413


@app.post("/api/scan")
def scan_uploaded_project():

    if "file" not in request.files:
        return jsonify({
            "error": "No file was uploaded."
        }), 400

    uploaded_file = request.files["file"]

    if not uploaded_file.filename:
        return jsonify({
            "error": "Please select a ZIP file."
        }), 400

    if not uploaded_file.filename.lower().endswith(".zip"):
        return jsonify({
            "error": "Please upload a ZIP file."
        }), 400

    try:
        with tempfile.TemporaryDirectory() as temp_directory:

            temp_root = Path(temp_directory)
            zip_path = temp_root / "upload.zip"
            project_directory = temp_root / "project"

            uploaded_size = 0

            with open(zip_path, "wb") as destination:
                while True:
                    chunk = uploaded_file.stream.read(64 * 1024)

                    if not chunk:
                        break

                    uploaded_size += len(chunk)

                    if uploaded_size > MAX_UPLOAD_SIZE:
                        return jsonify({
                            "error": "ZIP upload exceeds the 20 MB limit."
                        }), 413

                    destination.write(chunk)

            if uploaded_size == 0:
                return jsonify({
                    "error": "The uploaded ZIP file is empty."
                }), 400

            extract_zip(zip_path, project_directory)

            findings = scan_project(project_directory)
            summary = calculate_risk(findings)

            return jsonify({
               "project_name": Path(secure_filename(uploaded_file.filename)).stem,
                "summary": summary,
                "findings": findings
            })

    except InvalidArchiveError as error:
        return jsonify({
            "error": str(error)
        }), 400

    except Exception:
        app.logger.exception("Unexpected scanning error")

        return jsonify({
            "error": "An unexpected error occurred while scanning the project."
        }), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
