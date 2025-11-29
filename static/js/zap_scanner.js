document.addEventListener('DOMContentLoaded', () => {
    // --- API Endpoints ---
    const API_BASE_URL = '/zap_scanner';
    const SCAN_ENDPOINT = `${API_BASE_URL}/scan`;
    const RESULTS_ENDPOINT = `${API_BASE_URL}/scan_results`;
    const CLEAR_LOG_ENDPOINT = `${API_BASE_URL}/clear_log`;
    const LOG_STREAM_ENDPOINT = `${API_BASE_URL}/log_stream`;
    const REPORT_FILES_ENDPOINT = `${API_BASE_URL}/report_files`; 
    const ANALYZE_ENDPOINT = `${API_BASE_URL}/trigger_ai_analysis`; // 🚨 NEW ENDPOINT
    const CHATBOT_REDIRECT_URL = '/chatbot'; // 🚨 NEW REDIRECT URL


    // --- DOM Elements ---
    const targetUrlInput = document.getElementById('targetUrl');
    const startScanBtn = document.getElementById('startScanBtn'); 
    
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
    const resultsContent = document.getElementById('resultsContent'); 
    const downloadPdfBtn = document.getElementById('downloadReportBtn'); 
    
    // 🚨 NEW SELECTORS for AI Analysis
    const analyzeReportDropdown = document.getElementById('analyzeReportDropdown');
    const llmAnalysisOptions = document.getElementById('llmAnalysisOptions');


    // --- Utility Functions ---

    /**
     * Shows a loading spinner and updates button text.
     * 🚨 MODIFIED to support dropdown button structure.
     * @param {HTMLElement} button The button element.
     */
    function showSpinner(button) {
        button.querySelector('.button-text').classList.add('hidden');
        button.querySelector('.spinner').classList.remove('hidden');
        button.disabled = true;
        // Hide caret for dropdown button
        const caret = button.querySelector('.fa-caret-down');
        if (caret) caret.classList.add('hidden');
    }

    /**
     * Hides the loading spinner and restores button text.
     * 🚨 MODIFIED to support dropdown button structure.
     * @param {HTMLElement} button The button element.
     */
    function hideSpinner(button) {
        button.querySelector('.button-text').classList.remove('hidden');
        button.querySelector('.spinner').classList.add('hidden');
        button.disabled = false;
        // Show caret for dropdown button
        const caret = button.querySelector('.fa-caret-down');
        if (caret) caret.classList.remove('hidden');
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

    // --- NEW: Function to check for PDF report and Analysis Button status ---
    /**
     * Checks the server for available report files (JSON and PDF).
     * Updates the Download PDF and Analyze Report buttons.
     */
    async function checkReportStatus() {
        // Function to disable and reset a button
        const disableButton = (button, hoverClass) => {
            button.disabled = true;
            button.classList.add('opacity-50', 'cursor-not-allowed');
            button.classList.remove(hoverClass);
        };
        
        // Disable both buttons initially
        disableButton(downloadPdfBtn, 'hover:bg-red-500');
        disableButton(analyzeReportDropdown, 'hover:bg-indigo-500');

        try {
            const response = await fetch(REPORT_FILES_ENDPOINT);
            
            if (!response.ok) return;
    
            const data = await response.json();
    
            if (data.status === "success" && data.pdf_report) {
                // --- PDF Button Logic ---
                downloadPdfBtn.href = data.pdf_report; 
                downloadPdfBtn.setAttribute('download', 'zap_report.pdf'); 
                downloadPdfBtn.disabled = false;
                downloadPdfBtn.classList.remove('opacity-50', 'cursor-not-allowed');
                downloadPdfBtn.classList.add('hover:bg-red-500');
                
                // --- Analysis Button Logic ---
                analyzeReportDropdown.disabled = false;
                analyzeReportDropdown.classList.remove('opacity-50', 'cursor-not-allowed');
                analyzeReportDropdown.classList.add('hover:bg-indigo-500');
            }
        } catch (error) {
            console.error("Error checking report status:", error);
        }
    }
    
    /**
     * 🚨 NEW FUNCTION: Triggers the server-side proxy to upload the PDF for AI analysis.
     * @param {string} llmMode - The selected LLM mode ('local' or 'gemini').
     */
async function analyzeReport(llmMode) {
        const button = analyzeReportDropdown;
        if (button.disabled) return;
        
        updateScanStatus(`Preparing ZAP report for AI analysis (${llmMode})...`, 'info');
        appendLog(`[*] Preparing ZAP PDF for analysis using ${llmMode} LLM...`);
        
        showSpinner(button);
        downloadPdfBtn.disabled = true;

        try {
            // 1. First, check local PDF availability via the local blueprint.
            let response = await fetch(ANALYZE_ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ llm_mode: llmMode })
            });
            let data = await response.json();
            
            if (data.status !== 'success') {
                throw new Error(data.message || 'PDF availability check failed.');
            }
            
            // 2. Now call the central proxy route on the chatbot blueprint.
            const CHATBOT_PROXY_URL = `${CHATBOT_REDIRECT_URL}/scanner_analysis`;
            response = await fetch(CHATBOT_PROXY_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ llm_mode: llmMode, scanner_type: data.scanner_type }) // Pass scanner_type
            });

            data = await response.json(); // Data now contains summary and llm_mode

            if (response.ok && data.status === 'success') {
                appendLog(`[✓] AI analysis initiated. Summary received. Redirecting...`);
                updateScanStatus('Analysis complete. Redirecting...', 'success');
                
                // 3. Redirect, passing summary and mode (from the server response)
                window.location.href = `${CHATBOT_REDIRECT_URL}?mode=${data.llm_mode}&summary=${encodeURIComponent(data.summary)}`;
                return;
            } else {
                throw new Error(data.message || `Analysis failed with status ${response.status}`);
            }
        } catch (error) {
            appendLog(`[x] AI Analysis Error: ${error.message}`);
            updateScanStatus('Analysis failed', 'error');
        } finally {
            // Only run cleanup if no redirect happened (i.e., if it failed)
            hideSpinner(button);
            checkReportStatus(); 
        }
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
        } finally {
            // UPDATED: Always check for the PDF file after attempting to refresh results
            await checkReportStatus();
        }
    }
    
    // ... (updateSummaryDisplay, populateAlertsTable, getRiskColorClass, getPredictedScoreColorClass unchanged)

    function updateSummaryDisplay(summary, targetUrl) {
        lastScannedUrlDisplay.textContent = targetUrl || 'N/A';
        totalAlertsDisplay.textContent = summary.Total || '0';
        highAlertsDisplay.textContent = summary.High || '0';
        mediumAlertsDisplay.textContent = summary.Medium || '0';
        lowAlertsDisplay.textContent = summary.Low || '0';
        infoAlertsDisplay.textContent = summary.Info || '0';
    }

    function populateAlertsTable(findings) {
        zapAlertsTableBody.innerHTML = ''; // Clear existing rows
        if (findings && findings.length > 0) {
            findings.forEach(alert => {
                const row = zapAlertsTableBody.insertRow();
                row.innerHTML = `
                    <td class="px-4 py-2 whitespace-nowrap text-sm font-medium ${getRiskColorClass(alert.risk)}">${alert.risk}</td>
                    <td class="px-4 py-2 whitespace-nowrap text-sm font-medium ${getPredictedScoreColorClass(alert.predicted_risk_score)}">${alert.predicted_risk_score}</td>
                    <td class="px-4 py-2 text-sm text-gray-200">${alert.name}</td>
                    <td class="px-4 py-2 text-sm text-gray-300 truncate max-w-xs"><a href="${alert.url}" target="_blank" class="text-blue-400 hover:underline">${alert.url}</a></td>
                    <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-300">${alert.confidence}</td>
                    <td class="px-4 py-2 text-sm text-gray-300 max-w-md overflow-hidden text-ellipsis" title="${alert.description.replace(/<[^>]+>/g, '')}">${alert.description.replace(/<[^>]+>/g, '').substring(0, 100)}...</td>
                `;
            });
        } else {
            zapAlertsTableBody.innerHTML = `<tr><td colspan="6" class="px-4 py-2 text-sm text-gray-400 text-center">No alerts found in the report.</td></tr>`;
        }
    }

    function getRiskColorClass(risk) {
        switch (risk) {
            case 'High': return 'risk-high'; 
            case 'Medium': return 'risk-medium';
            case 'Low': return 'risk-low';
            case 'Info': return 'risk-info';
            default: return 'text-gray-300';
        }
    }

    function getPredictedScoreColorClass(score) {
        if (typeof score !== 'number') return 'text-gray-500';
        if (score >= 10.0) return 'text-red-500 font-bold'; 
        if (score >= 5.0) return 'text-orange-400 font-semibold'; 
        if (score > 0) return 'text-yellow-400';
        return 'text-gray-300';
    }

    /**
     * Handles the click event for the ZAP scan button.
     */
    async function handleScanButtonClick() {
        showSpinner(startScanBtn);
        updateScanStatus(`Initiating Quick Scan...`, 'info');
        logOutput.innerHTML = ''; 

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

    // ... (setupLogStream unchanged)
    function setupLogStream() {
        const eventSource = new EventSource(LOG_STREAM_ENDPOINT);

        eventSource.onmessage = function(event) {
            appendLog(event.data);
            if (event.data.includes("Scan, analysis, and prediction complete") || event.data.includes("PDF report generated")) {
                appendLog("[*] Scan complete. Refreshing results...");
                fetchAndDisplayResults();
            }
        };

        eventSource.onerror = function(error) {
            console.error('EventSource failed:', error);
            eventSource.close();
            appendLog("[!] Log stream disconnected. Attempting to reconnect in 5 seconds...");
            setTimeout(setupLogStream, 5000); 
        };
    }

    // ... (copyResultsToClipboard unchanged)
    function copyResultsToClipboard() {
        const textToCopy = resultsContent.textContent;
        const originalText = copyResultsBtn.textContent;

        if (!textToCopy || textToCopy.includes('Loading') || textToCopy.includes('Awaiting scan results...')) {
            copyResultsBtn.textContent = 'No results!';
            setTimeout(() => {
                copyResultsBtn.textContent = originalText;
            }, 1000);
            return;
        }
        
        navigator.clipboard.writeText(textToCopy).then(() => {
            copyResultsBtn.textContent = 'Copied!';
            setTimeout(() => {
                copyResultsBtn.textContent = originalText;
            }, 1500);
        }).catch(err => {
            console.error('Failed to copy text: ', err);
            copyResultsBtn.textContent = 'Failed!';
            setTimeout(() => {
                copyResultsBtn.textContent = originalText;
            }, 1500);
        });
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
    
    // 🚨 NEW: Analysis Dropdown Toggle
    analyzeReportDropdown.addEventListener('click', (e) => {
        if (!analyzeReportDropdown.disabled) {
            llmAnalysisOptions.classList.toggle('hidden');
            e.stopPropagation(); 
        }
    });
    
    // 🚨 NEW: Analysis Option Selection
    llmAnalysisOptions.addEventListener('click', (e) => {
        e.preventDefault();
        const option = e.target.closest('a[data-llm-mode]');
        if (option) {
            const llmMode = option.dataset.llmMode;
            llmAnalysisOptions.classList.add('hidden'); 
            analyzeReport(llmMode); // Start the analysis and redirection
        }
    });

    // Close dropdown when clicking outside
    document.addEventListener('click', (e) => {
        if (llmAnalysisOptions && analyzeReportDropdown && !analyzeReportDropdown.contains(e.target)) {
            llmAnalysisOptions.classList.add('hidden');
        }
    });


    // --- Initializer ---
    function initialize() {
        checkReportStatus(); // Initial status check is now separate
        fetchAndDisplayResults(); 
        setupLogStream();       
    }

    initialize();
});