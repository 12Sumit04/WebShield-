
const API_URL = "http://127.0.0.1:5000/api/scan";

const fileInput = document.getElementById("fileInput");
const uploadBox = document.getElementById("uploadBox");
const browseButton = document.getElementById("browseButton");
const scanButton = document.getElementById("scanButton");
const fileInfo = document.getElementById("fileInfo");
const errorMessage = document.getElementById("errorMessage");

let selectedFile = null;

browseButton.addEventListener("click", () => {
    fileInput.click();
});

fileInput.addEventListener("change", () => {
    selectFile(fileInput.files[0]);
});

function selectFile(file) {
    errorMessage.textContent = "";

    if (!file) return;

    if (!file.name.toLowerCase().endsWith(".zip")) {
        selectedFile = null;
        scanButton.disabled = true;
        fileInfo.textContent = "Please select a ZIP file.";
        errorMessage.textContent = "Only ZIP files are supported.";
        return;
    }

    if (file.size > 20 * 1024 * 1024) {
        selectedFile = null;
        scanButton.disabled = true;
        fileInfo.textContent = "File exceeds the 20 MB limit.";
        errorMessage.textContent = "Please select a smaller ZIP file.";
        return;
    }

    selectedFile = file;
    fileInfo.textContent = `${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)`;
    scanButton.disabled = false;
}

uploadBox.addEventListener("dragover", (event) => {
    event.preventDefault();
    uploadBox.classList.add("drag-over");
});

uploadBox.addEventListener("dragleave", () => {
    uploadBox.classList.remove("drag-over");
});

uploadBox.addEventListener("drop", (event) => {
    event.preventDefault();
    uploadBox.classList.remove("drag-over");

    const file = event.dataTransfer.files[0];
    selectFile(file);
});

scanButton.addEventListener("click", scanProject);

async function scanProject() {
    if (!selectedFile) return;

    const formData = new FormData();
    formData.append("file", selectedFile);

    scanButton.disabled = true;
    scanButton.textContent = "Scanning project...";
    errorMessage.textContent = "";

    try {
        const response = await fetch(API_URL, {
            method: "POST",
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || data.message || "Scan failed.");
        }

        displayResults(data);

    } catch (error) {
        errorMessage.textContent = error.message.includes("Failed to fetch")
            ? "Cannot connect to the scanner. Make sure the Flask backend is running."
            : error.message;

    } finally {
        scanButton.disabled = false;
        scanButton.innerHTML = "<span>⌕</span> Start security scan";
    }
}

function displayResults(data) {
    const summary = data.summary;
    const findings = data.findings || [];

    document.getElementById("projectName").textContent =
        `Project: ${data.project_name}`;

    document.getElementById("scanStatus").textContent = "SCAN COMPLETE";

    document.getElementById("riskScore").textContent =
        summary.risk_score;

    document.getElementById("riskLevel").textContent =
        summary.risk_level;

    document.getElementById("totalFindings").textContent =
        summary.total_findings;

    document.getElementById("highCount").textContent =
        summary.severity_counts.HIGH || 0;

    document.getElementById("mediumCount").textContent =
        summary.severity_counts.MEDIUM || 0;

    const findingsBody = document.getElementById("findingsBody");
    const recommendationsList =
        document.getElementById("recommendationsList");

    findingsBody.replaceChildren();
    recommendationsList.replaceChildren();

    if (findings.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 4;
        cell.className = "empty-state";
        cell.textContent = "No vulnerabilities detected.";

        row.appendChild(cell);
        findingsBody.appendChild(row);

        recommendationsList.textContent =
            "No recommendations are necessary based on this scan.";

        return;
    }

    findings.forEach((finding) => {
        const row = document.createElement("tr");

        const typeCell = document.createElement("td");
        typeCell.textContent = finding.type || "Unknown";

        const severityCell = document.createElement("td");
        const severityBadge = document.createElement("span");

        const severity = (finding.severity || "LOW").toUpperCase();

        severityBadge.className = `severity ${severity}`;
        severityBadge.textContent = severity;
        severityCell.appendChild(severityBadge);

        const fileCell = document.createElement("td");
        fileCell.textContent = finding.file || "Unknown";

        const lineCell = document.createElement("td");
        lineCell.textContent = finding.line ?? "—";

        row.append(typeCell, severityCell, fileCell, lineCell);
        findingsBody.appendChild(row);

        const recommendation = document.createElement("div");
        recommendation.className = "recommendation-item";

        const heading = document.createElement("h4");
        heading.textContent = finding.type || "Security finding";

        const description = document.createElement("p");
        description.textContent =
            finding.recommendation || finding.description || "Review this finding.";

        recommendation.append(heading, description);
        recommendationsList.appendChild(recommendation);
    });
}
