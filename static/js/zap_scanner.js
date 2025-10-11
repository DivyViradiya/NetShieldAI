document.addEventListener('DOMContentLoaded', () => {
    // --- API Endpoints ---
    const API_BASE_URL = '/zap_scanner';
    const SCAN_ENDPOINT = `${API_BASE_URL}/scan`;
    const RESULTS_ENDPOINT = `${API_BASE_URL}/scan_results`;
    const CLEAR_LOG_ENDPOINT = `${API_BASE_URL}/clear_log`;
    const LOG_STREAM_ENDPOINT = `${API_BASE_URL}/log_stream`;

    // --- DOM Elements ---
    const targetUrlInput = document.getElementById('targetUrl');
    const startScanBtn = document.getElementById('startScanBtn'); // Changed from multiple buttons to one
    
    const scanStatus = document.getElementById('scanStatus');
    const logOutput = document.getElementById('logOutput');
    const clearLogBtn = document.getElementById('clearLogBtn');

    const lastScannedUrlDisplay = document.getElementById('lastScannedUrlDisplay');
    const totalAlertsDisplay = document.getElementById('totalAlertsDisplay');
    const highAlertsDisplay = document.getElementById('highAlertsDisplay');
    const mediumAlertsDisplay = document.getElementById('mediumAlertsDisplay');
    const lowAlertsDisplay = document.getElementById('lowAlertsDisplay');
    const infoAlertsDisplay = document.getElementById('infoAlertsDisplay');
    const zapAlertsTableBody = document.getElementById('zapAlertsTableBody');

    const refreshResultsBtn = document.getElementById('refreshResultsBtn');
    const copyResultsBtn = document.getElementById('copyResultsBtn');
    const resultsContent = document.getElementById('resultsContent'); // For showing raw JSON

    // --- Utility Functions ---

    /**
     * Shows a loading spinner and updates button text.
     * @param {HTMLElement} button The button element.
     */
    function showSpinner(button) {
        button.querySelector('.button-text').classList.add('hidden');
        button.querySelector('.spinner').classList.remove('hidden');
        button.disabled = true;
    }

    /**
     * Hides the loading spinner and restores button text.
     * @param {HTMLElement} button The button element.
     */
    function hideSpinner(button) {
        button.querySelector('.button-text').classList.remove('hidden');
        button.querySelector('.spinner').classList.add('hidden');
        button.disabled = false;
    }

    /**
     * Updates the scan status display.
     * @param {string} message The message to display.
     * @param {string} type 'success', 'error', or 'info' for styling.
     */
    function updateScanStatus(message, type = 'info') {
        scanStatus.textContent = message;
        scanStatus.classList.remove('bg-green-700', 'bg-red-700', 'bg-gray-700', 'text-green-400', 'text-red-400', 'text-gray-300');
        if (type === 'success') {
            scanStatus.classList.add('bg-green-700', 'text-green-400');
        } else if (type === 'error') {
            scanStatus.classList.add('bg-red-700', 'text-red-400');
        } else {
            scanStatus.classList.add('bg-gray-700', 'text-gray-300');
        }
    }

    /**
     * Appends a log message to the log output area and scrolls to the bottom.
     * @param {string} message The log message.
     */
    function appendLog(message) {
        const p = document.createElement('p');
        p.textContent = message;
        logOutput.appendChild(p);
        logOutput.scrollTop = logOutput.scrollHeight;
    }

    /**
     * Fetches and displays the ZAP scan report.
     */
    async function fetchAndDisplayResults() {
        zapAlertsTableBody.innerHTML = `<tr><td colspan="6" class="px-4 py-2 text-sm text-gray-400 text-center">Loading results...</td></tr>`;
        resultsContent.textContent = 'Loading raw report...';

        try {
            const response = await fetch(RESULTS_ENDPOINT);
            const result = await response.json();

            if (response.status === 404) {
                 updateSummaryDisplay({}, 'N/A'); // Clear summary
                 zapAlertsTableBody.innerHTML = `<tr><td colspan="6" class="px-4 py-2 text-sm text-gray-400 text-center">${result.message}</td></tr>`;
                 resultsContent.textContent = result.message;
                 return;
            }

            if (result.status === 'success' && result.data) {
                const report = result.data;
                updateSummaryDisplay(report.summary, report.target_url);
                populateAlertsTable(report.findings);
                // Display pretty-printed JSON in the raw view
                resultsContent.textContent = JSON.stringify(report, null, 2);
            } else {
                updateSummaryDisplay({}, 'N/A');
                const errorMessage = result.message || 'Error fetching results.';
                zapAlertsTableBody.innerHTML = `<tr><td colspan="6" class="px-4 py-2 text-sm text-red-400 text-center">${errorMessage}</td></tr>`;
                resultsContent.textContent = errorMessage;
            }
        } catch (error) {
            console.error('Error fetching ZAP report:', error);
            appendLog(`[!] Error fetching ZAP report: ${error.message}`);
            updateSummaryDisplay({}, 'N/A');
            zapAlertsTableBody.innerHTML = `<tr><td colspan="6" class="px-4 py-2 text-sm text-red-400 text-center">Failed to load results. Check connection to the server.</td></tr>`;
            resultsContent.textContent = 'Failed to load raw report.';
        }
    }
    
    /**
     * Updates the summary cards with data from the report.
     * @param {object} summary - The summary object from the report.
     * @param {string} targetUrl - The URL that was scanned.
     */
    function updateSummaryDisplay(summary, targetUrl) {
        lastScannedUrlDisplay.textContent = targetUrl || 'N/A';
        totalAlertsDisplay.textContent = summary.Total || '0';
        highAlertsDisplay.textContent = summary.High || '0';
        mediumAlertsDisplay.textContent = summary.Medium || '0';
        lowAlertsDisplay.textContent = summary.Low || '0';
        infoAlertsDisplay.textContent = summary.Informational || '0';
    }

    /**
     * Populates the alerts table with findings.
     * @param {Array} findings - The array of finding objects from the report.
     */
    function populateAlertsTable(findings) {
        zapAlertsTableBody.innerHTML = ''; // Clear existing rows
        if (findings && findings.length > 0) {
            findings.forEach(alert => {
                const row = zapAlertsTableBody.insertRow();
                row.classList.add('hover:bg-gray-700');
                row.innerHTML = `
                    <td class="px-4 py-2 whitespace-nowrap text-sm font-medium ${getRiskColorClass(alert.risk)}">${alert.risk}</td>
                    <td class="px-4 py-2 whitespace-nowrap text-sm font-medium ${getPredictedScoreColorClass(alert.predicted_risk_score)}">${alert.predicted_risk_score}</td>
                    <td class="px-4 py-2 text-sm text-gray-200">${alert.name}</td>
                    <td class="px-4 py-2 text-sm text-gray-300 truncate max-w-xs"><a href="${alert.url}" target="_blank" class="text-blue-400 hover:underline">${alert.url}</a></td>
                    <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-300">${alert.confidence}</td>
                    <td class="px-4 py-2 text-sm text-gray-300 max-w-md overflow-hidden text-ellipsis" title="${alert.description}">${alert.description.substring(0, 100)}...</td>
                `;
            });
        } else {
            zapAlertsTableBody.innerHTML = `<tr><td colspan="6" class="px-4 py-2 text-sm text-gray-400 text-center">No alerts found in the report.</td></tr>`;
        }
    }

    /**
     * Returns Tailwind CSS class for ZAP's risk level.
     */
    function getRiskColorClass(risk) {
        switch (risk) {
            case 'High': return 'text-red-500';
            case 'Medium': return 'text-orange-400';
            case 'Low': return 'text-yellow-400';
            case 'Informational': return 'text-blue-400';
            default: return 'text-gray-300';
        }
    }

    /**
     * Returns Tailwind CSS class for the predicted risk score.
     */
    function getPredictedScoreColorClass(score) {
        if (typeof score !== 'number') return 'text-gray-500';
        if (score >= 7.0) return 'text-red-500 font-bold';
        if (score >= 4.0) return 'text-orange-400 font-semibold';
        if (score > 0) return 'text-yellow-400';
        return 'text-gray-300';
    }


    /**
     * Handles the click event for the ZAP scan button.
     */
    async function handleScanButtonClick() {
        showSpinner(startScanBtn);
        updateScanStatus(`Initiating Quick Scan...`, 'info');
        logOutput.innerHTML = ''; // Clear log for new scan

        const targetUrl = targetUrlInput.value.trim();
        if (!targetUrl) {
            updateScanStatus("Error: Target URL cannot be empty.", 'error');
            appendLog("[!] Scan aborted: Target URL is empty.");
            hideSpinner(startScanBtn);
            return;
        }

        try {
            const response = await fetch(SCAN_ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_url: targetUrl })
            });
            const data = await response.json();

            if (response.ok) {
                updateScanStatus(data.message, 'success');
            } else {
                updateScanStatus(`Error: ${data.message}`, 'error');
            }
        } catch (error) {
            console.error('Error initiating ZAP scan:', error);
            updateScanStatus(`Error: Could not connect to the server. ${error.message}`, 'error');
            appendLog(`[!] Network error or unexpected response: ${error.message}`);
        } finally {
            hideSpinner(startScanBtn);
        }
    }

    /**
     * Sets up the Server-Sent Events (SSE) stream for logs.
     */
    function setupLogStream() {
        const eventSource = new EventSource(LOG_STREAM_ENDPOINT);

        eventSource.onmessage = function(event) {
            appendLog(event.data);
            // Check for completion message to trigger a results refresh
            if (event.data.includes("Scan, analysis, and prediction complete")) {
                appendLog("[*] Scan complete. Refreshing results...");
                fetchAndDisplayResults();
            }
        };

        eventSource.onerror = function(error) {
            console.error('EventSource failed:', error);
            eventSource.close();
            appendLog("[!] Log stream disconnected. Attempting to reconnect in 5 seconds...");
            setTimeout(setupLogStream, 5000); // Attempt to reconnect
        };
    }

    /**
     * Copies the content of the raw results view to the clipboard.
     */
    function copyResultsToClipboard() {
        const textToCopy = resultsContent.textContent;
        if (!textToCopy || textToCopy.includes('Loading') || textToCopy.includes('No raw report')) {
            alert('No results to copy.');
            return;
        }
        
        const textarea = document.createElement('textarea');
        textarea.value = textToCopy;
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            alert('Raw JSON report copied to clipboard!');
        } catch (err) {
            console.error('Failed to copy text: ', err);
            alert('Failed to copy results. Please copy manually.');
        } finally {
            document.body.removeChild(textarea);
        }
    }

    // --- Event Listeners ---
    startScanBtn.addEventListener('click', handleScanButtonClick);

    clearLogBtn.addEventListener('click', async () => {
        showSpinner(clearLogBtn);
        try {
            const response = await fetch(CLEAR_LOG_ENDPOINT, { method: 'POST' });
            const data = await response.json();
            if (response.ok) {
                logOutput.innerHTML = '';
                appendLog("[*] Log file cleared by user.");
                updateScanStatus("Log cleared.", 'info');
            } else {
                updateScanStatus(`Error clearing log: ${data.message}`, 'error');
            }
        } catch (error) {
            console.error('Error clearing log:', error);
            updateScanStatus(`Error clearing log: ${error.message}`, 'error');
        } finally {
            hideSpinner(clearLogBtn);
        }
    });

    refreshResultsBtn.addEventListener('click', () => {
        appendLog(`[*] Manually refreshing results...`);
        fetchAndDisplayResults();
    });

    copyResultsBtn.addEventListener('click', copyResultsToClipboard);

    // --- Initializer ---
    function initialize() {
        fetchAndDisplayResults(); // Fetch any existing results on page load
        setupLogStream();       // Start log streaming
    }

    initialize();
});
