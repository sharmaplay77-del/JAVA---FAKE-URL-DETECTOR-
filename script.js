// ========================================
// FAKE URL DETECTOR - FRONTEND JAVASCRIPT
// Connected to Java Backend
// ========================================

"use strict";

const API_URL = "http://localhost:8080/api/scan";
const REPORT_API_URL = "http://localhost:8080/api/reports";

// Main scan elements
const scanForm = document.getElementById("scanForm");
const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");
const message = document.getElementById("message");
const resultBox = document.getElementById("resultBox");

const scannedUrl = document.getElementById("scannedUrl");
const riskScore = document.getElementById("riskScore");
const riskStatus = document.getElementById("riskStatus");
const riskBar = document.getElementById("riskBar");
const findingsList = document.getElementById("findingsList");

// History elements
const historyTable = document.getElementById("historyTable");
const clearHistoryButton =
    document.getElementById("clearHistoryButton");

// Scam report elements
const reportForm = document.getElementById("reportForm");
const reportUrl = document.getElementById("reportUrl");
const reportReason = document.getElementById("reportReason");
const reportMessage = document.getElementById("reportMessage");

// Saved reports elements
const loadReportsButton =
    document.getElementById("loadReportsButton");

const scamReportsTable =
    document.getElementById("scamReportsTable");

const reportsMessage =
    document.getElementById("reportsMessage");


// ========================================
// 1. HELPER FUNCTIONS
// ========================================

function validateURL(input) {
    try {
        const parsedURL = new URL(input);

        if (
            parsedURL.protocol !== "http:" &&
            parsedURL.protocol !== "https:"
        ) {
            return null;
        }

        if (
            !parsedURL.hostname ||
            !parsedURL.hostname.includes(".")
        ) {
            return null;
        }

        return parsedURL;
    } catch (error) {
        return null;
    }
}


// Safely read JSON responses from the backend
async function readResponse(response) {
    const text = await response.text();

    if (!text) {
        return {};
    }

    try {
        return JSON.parse(text);
    } catch (error) {
        throw new Error("Server returned an invalid response.");
    }
}


// Display a message and keep it visible.
// It will change only when another message is shown.
function showReportMessage(text, type) {
    if (!reportMessage) return;

    reportMessage.textContent = text;
    reportMessage.style.display = "block";
    reportMessage.style.visibility = "visible";
    reportMessage.style.fontWeight = "bold";
    reportMessage.style.padding = "10px";
    reportMessage.style.marginTop = "10px";
    reportMessage.style.borderRadius = "6px";

    if (type === "success") {
        reportMessage.style.color = "#087f3e";
        reportMessage.style.backgroundColor = "#e4f8ec";
    } else if (type === "error") {
        reportMessage.style.color = "#b42318";
        reportMessage.style.backgroundColor = "#ffebe9";
    } else {
        reportMessage.style.color = "#174ea6";
        reportMessage.style.backgroundColor = "#e8f0fe";
    }
}


// ========================================
// 2. DISPLAY SCAN RESULT
// ========================================

function displayResult(url, result) {
    if (!resultBox) return;

    resultBox.hidden = false;

    if (scannedUrl) {
        scannedUrl.textContent = url;
    }

    if (riskScore) {
        riskScore.textContent = result.score + "/100";
    }

    if (riskStatus) {
        riskStatus.textContent = result.status;
    }

    if (riskBar) {
        riskBar.style.width =
            Math.max(0, Math.min(100, Number(result.score) || 0)) + "%";

        if (result.score >= 60) {
            riskBar.style.backgroundColor = "#ff4d6d";
        } else if (result.score >= 30) {
            riskBar.style.backgroundColor = "#ffca28";
        } else {
            riskBar.style.backgroundColor = "#00c853";
        }
    }

    if (riskStatus) {
        if (result.score >= 60) {
            riskStatus.style.color = "#ff4d6d";
        } else if (result.score >= 30) {
            riskStatus.style.color = "#b77900";
        } else {
            riskStatus.style.color = "#087f3e";
        }
    }

    if (findingsList) {
        findingsList.replaceChildren();

        const findings = Array.isArray(result.findings)
            ? result.findings
            : ["Scan completed."];

        findings.forEach(function (finding) {
            const item = document.createElement("li");
            item.textContent = String(finding);
            findingsList.appendChild(item);
        });
    }
}


// ========================================
// 3. SCAN HISTORY
// ========================================

function getHistory() {
    try {
        const history = JSON.parse(
            localStorage.getItem("fakeURLScanHistory") || "[]"
        );

        return Array.isArray(history) ? history : [];
    } catch (error) {
        return [];
    }
}


function saveHistory(url, result) {
    const history = getHistory();

    history.unshift({
        url: url,
        score: result.score,
        status: result.status,
        date: new Date().toLocaleString()
    });

    try {
        localStorage.setItem(
            "fakeURLScanHistory",
            JSON.stringify(history.slice(0, 20))
        );
    } catch (error) {
        console.error("Could not save scan history:", error);
    }

    displayHistory();
}


function displayHistory() {
    if (!historyTable) return;

    const history = getHistory();
    historyTable.replaceChildren();

    if (history.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 4;
        cell.textContent = "No scan history available.";

        row.appendChild(cell);
        historyTable.appendChild(row);
        return;
    }

    history.forEach(function (item) {
        const row = document.createElement("tr");

        const urlCell = document.createElement("td");
        const scoreCell = document.createElement("td");
        const statusCell = document.createElement("td");
        const dateCell = document.createElement("td");

        urlCell.textContent = item.url || "";
        scoreCell.textContent = (item.score ?? "N/A") + "/100";
        statusCell.textContent = item.status || "";
        dateCell.textContent = item.date || "";

        row.append(
            urlCell,
            scoreCell,
            statusCell,
            dateCell
        );

        historyTable.appendChild(row);
    });
}


// Clear scan history
if (clearHistoryButton) {
    clearHistoryButton.addEventListener("click", function (event) {
        event.preventDefault();

        const confirmed = confirm(
            "Are you sure you want to clear your scan history?"
        );

        if (confirmed) {
            localStorage.removeItem("fakeURLScanHistory");
            displayHistory();

            if (message) {
                message.textContent = "Scan history cleared.";
            }
        }
    });
}


// ========================================
// 4. SCAN URL USING JAVA BACKEND
// ========================================

if (scanForm) {
    scanForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        if (!urlInput || !message) return;

        const url = urlInput.value.trim();

        if (!validateURL(url)) {
            message.textContent =
                "Please enter a valid URL beginning with http:// or https://";

            if (resultBox) resultBox.hidden = true;
            return;
        }

        message.textContent = "Analyzing URL...";

        if (scanButton) scanButton.disabled = true;

        try {
            const response = await fetch(API_URL, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ url: url })
            });

            const result = await readResponse(response);

            if (!response.ok || result.error) {
                throw new Error(
                    result.error || "Unable to scan this URL."
                );
            }

            displayResult(url, result);
            saveHistory(url, result);

            message.textContent = "Scan completed successfully.";
        } catch (error) {
            console.error("Scan error:", error);

            message.textContent =
                error.message === "Failed to fetch"
                    ? "Backend connection failed. Make sure the Java server is running."
                    : error.message;

            if (resultBox) resultBox.hidden = true;
        } finally {
            if (scanButton) scanButton.disabled = false;
        }
    });
}


// ========================================
// 5. SUBMIT SCAM REPORT
// ========================================

if (reportForm) {
    reportForm.addEventListener("submit", async function (event) {
        // Prevent the page from jumping to the top/reloading.
        event.preventDefault();
        event.stopPropagation();

        if (!reportUrl || !reportReason) {
            showReportMessage(
                "Report form fields could not be found in the HTML.",
                "error"
            );
            return;
        }

        const url = reportUrl.value.trim();
        const reason = reportReason.value;

        if (!validateURL(url)) {
            showReportMessage(
                "Please enter a valid URL beginning with http:// or https://.",
                "error"
            );
            return;
        }

        if (!reason) {
            showReportMessage("Please select a report reason.", "error");
            return;
        }

        const submitButton = reportForm.querySelector(
            'button[type="submit"], input[type="submit"]'
        );

        if (submitButton) {
            submitButton.disabled = true;
            submitButton.textContent =
                submitButton.tagName === "BUTTON"
                    ? "Submitting..."
                    : submitButton.value;
        }

        showReportMessage("Submitting your report...", "info");

        const report = {
            url: url,
            reason: reason,
            date: new Date().toLocaleString()
        };

        try {
            const response = await fetch(REPORT_API_URL, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(report)
            });

            const result = await readResponse(response);

            if (!response.ok || result.error) {
                throw new Error(
                    result.error || "Unable to submit the report."
                );
            }

            // Save a browser copy after the backend accepts the report.
            try {
                const reports = JSON.parse(
                    localStorage.getItem("fakeURLScamReports") || "[]"
                );

                if (Array.isArray(reports)) {
                    reports.push(report);

                    localStorage.setItem(
                        "fakeURLScamReports",
                        JSON.stringify(reports)
                    );
                }
            } catch (storageError) {
                console.error(
                    "Could not save browser copy:",
                    storageError
                );
            }

            // Keep the success message visible.
            showReportMessage(
                "Success! Your scam report has been submitted.",
                "success"
            );

            reportForm.reset();

            // Refresh the list without replacing the success message.
            if (scamReportsTable && reportsMessage) {
                await loadScamReports(false);
            }
        } catch (error) {
            console.error("Report submission error:", error);

            showReportMessage(
                error.message === "Failed to fetch"
                    ? "Could not connect to the Java backend. Check that the server is running."
                    : "Report failed: " + error.message,
                "error"
            );
        } finally {
            if (submitButton) {
                submitButton.disabled = false;

                if (submitButton.tagName === "BUTTON") {
                    submitButton.textContent = "Submit Report";
                }
            }
        }
    });
}


// ========================================
// 6. VIEW SAVED SCAM REPORTS
// ========================================

async function loadScamReports(showLoading = true) {
    if (!scamReportsTable || !reportsMessage) return;

    if (showLoading) {
        reportsMessage.textContent = "Loading reports...";
    }

    if (loadReportsButton) {
        loadReportsButton.disabled = true;
    }

    try {
        const response = await fetch(REPORT_API_URL, {
            method: "GET"
        });

        const reports = await readResponse(response);

        if (!response.ok) {
            throw new Error("Unable to load saved reports.");
        }

        if (!Array.isArray(reports)) {
            throw new Error("The server did not return a reports list.");
        }

        scamReportsTable.replaceChildren();

        if (reports.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.textContent = "No reports saved yet.";

            row.appendChild(cell);
            scamReportsTable.appendChild(row);

            reportsMessage.textContent = "No reports found.";
            return;
        }

        reports.forEach(function (report) {
            let reportData = report;

            if (typeof report === "string") {
                try {
                    reportData = JSON.parse(report);
                } catch (error) {
                    reportData = { details: report };
                }
            }

            const row = document.createElement("tr");
            const cell = document.createElement("td");

            if (
                reportData &&
                typeof reportData === "object" &&
                !Array.isArray(reportData)
            ) {
                cell.textContent =
                    "URL: " + (reportData.url || "Not provided") +
                    "\nReason: " + (reportData.reason || "Not provided") +
                    "\nDate: " + (reportData.date || "Not provided");

                cell.style.whiteSpace = "pre-line";
            } else {
                cell.textContent = String(reportData);
            }

            row.appendChild(cell);
            scamReportsTable.appendChild(row);
        });

        reportsMessage.textContent =
            "Reports loaded successfully: " + reports.length;
    } catch (error) {
        console.error("Load reports error:", error);

        reportsMessage.textContent =
            "Could not load reports. Check that your Java backend supports GET /api/reports.";
    } finally {
        if (loadReportsButton) {
            loadReportsButton.disabled = false;
        }
    }
}


if (loadReportsButton) {
    loadReportsButton.addEventListener("click", function (event) {
        event.preventDefault();
        loadScamReports();
    });
}


// ========================================
// 7. INITIALIZE WEBSITE
// ========================================

displayHistory();

console.log("Fake URL Detector frontend loaded successfully.");