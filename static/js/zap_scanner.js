document.addEventListener('DOMContentLoaded', () => {
    // --- API Endpoints ---
    const API_BASE_URL = '/zap_scanner';
    const SCAN_ENDPOINT = `${API_BASE_URL}/scan`;
    const RESULTS_ENDPOINT = `${API_BASE_URL}/scan_results`;
    const CLEAR_LOG_ENDPOINT = `${API_BASE_URL}/clear_log`;
    const LOG_STREAM_ENDPOINT = `${API_BASE_URL}/log_stream`;
    const REPORT_FILES_ENDPOINT = `${API_BASE_URL}/report_files`; 
    const ANALYZE_ENDPOINT = `${API_BASE_URL}/trigger_ai_analysis`; 
    const CHATBOT_REDIRECT_URL = '/chatbot'; 

    // --- DOM Elements ---
    const targetUrlInput = document.getElementById('targetUrl');
    const startScanBtn = document.getElementById('startScanBtn'); 
    
    const scanStatus = document.getElementById('scanStatus');
    const logOutput = document.getElementById('logOutput');
    const clearLogBtn = document.getElementById('clearLogBtn');

    // Metrics
    const lastScannedUrlDisplay = document.getElementById('lastScannedUrlDisplay');
    const totalAlertsDisplay = document.getElementById('totalAlertsDisplay');
    const highAlertsDisplay = document.getElementById('highAlertsDisplay');
    const mediumAlertsDisplay = document.getElementById('mediumAlertsDisplay');
    const lowAlertsDisplay = document.getElementById('lowAlertsDisplay');
    const infoAlertsDisplay = document.getElementById('infoAlertsDisplay');
    const zapAlertsTableBody = document.getElementById('zapAlertsTableBody');

    // Actions
    const refreshResultsBtn = document.getElementById('refreshResultsBtn');
    const copyResultsBtn = document.getElementById('copyResultsBtn');
    const resultsContent = document.getElementById('resultsContent'); 
    const downloadPdfBtn = document.getElementById('downloadReportBtn'); 
    
    // AI Analysis
    const analyzeReportDropdown = document.getElementById('analyzeReportDropdown');
    const llmAnalysisOptions = document.getElementById('llmAnalysisOptions');

    // --- Utility Functions ---

    /**
     * Toggles the loading state of a button.
     */
    function toggleButtonLoading(button, isLoading) {
        if (!button) return;
        const spinner = button.querySelector('.spinner');
        const icon = button.querySelector('.material-symbols-outlined');
        const text = button.querySelector('.button-text');
        
        button.disabled = isLoading;

        if (isLoading) {
            button.style.opacity = '0.7';
            button.style.cursor = 'not-allowed';
            if (spinner) spinner.classList.remove('hidden');
            // Hide icon only if it's not the dropdown arrow
            if (icon && !icon.textContent.includes('expand_more')) icon.style.display = 'none';
        } else {
            button.style.opacity = '1';
            button.style.cursor = 'pointer';
            if (spinner) spinner.classList.add('hidden');
            if (icon) icon.style.display = 'inline-block';
        }
    }

    /**
     * Updates the status badge color and text.
     */
    function updateScanStatus(message, type = 'info') {
        scanStatus.textContent = message;
        
        // Reset colors
        scanStatus.style.color = '#a1a1aa'; // Default gray
        
        if (type === 'success') scanStatus.style.color = '#10b981'; // Green
        else if (type === 'error') scanStatus.style.color = '#ef4444'; // Red
        else if (type === 'busy') scanStatus.style.color = '#eab308'; // Yellow
    }

    function appendLog(message) {
        const div = document.createElement('div');
        div.textContent = message;
        div.style.marginBottom = '4px';
        
        if (message.includes('[!]') || message.includes('Error')) div.style.color = '#ef4444';
        else if (message.includes('[+]') || message.includes('[✓]')) div.style.color = '#10b981';
        else if (message.includes('[*]')) div.style.color = '#3b82f6';
        else div.style.color = '#a1a1aa';

        logOutput.appendChild(div);
        logOutput.scrollTop = logOutput.scrollHeight;
    }

    // --- Report & Button Management ---

    async function checkReportStatus() {
        // Disable initially
        if (downloadPdfBtn) {
            downloadPdfBtn.disabled = true;
            downloadPdfBtn.style.opacity = '0.5';
        }
        if (analyzeReportDropdown) {
            analyzeReportDropdown.disabled = true;
            analyzeReportDropdown.style.opacity = '0.5';
        }

        try {
            const response = await fetch(REPORT_FILES_ENDPOINT);
            if (!response.ok) return;
            const data = await response.json();
    
            if (data.status === "success" && data.pdf_report) {
                // Enable PDF Download
                if (downloadPdfBtn) {
                    downloadPdfBtn.href = data.pdf_report; 
                    downloadPdfBtn.setAttribute('download', 'zap_report.pdf'); 
                    downloadPdfBtn.disabled = false;
                    downloadPdfBtn.style.opacity = '1';
                    
                    // Remove existing listeners to avoid duplicates, then add click handler
                    // Note: Since it's an <a> tag or wrapped button, setting href might be enough 
                    // but if it's a <button>, we need a click handler:
                    if (downloadPdfBtn.tagName === 'BUTTON') {
                        downloadPdfBtn.onclick = () => window.location.href = data.pdf_report;
                    }
                }
                
                // Enable AI Analysis
                if (analyzeReportDropdown) {
                    analyzeReportDropdown.disabled = false;
                    analyzeReportDropdown.style.opacity = '1';
                }
            }
        } catch (error) {
            console.error("Error checking report status:", error);
        }
    }
    
    async function analyzeReport(llmMode) {
        if (analyzeReportDropdown.disabled) return;
        
        updateScanStatus(`Analyzing with ${llmMode}...`, 'busy');
        appendLog(`[*] Preparing ZAP PDF for analysis using ${llmMode} LLM...`);
        
        toggleButtonLoading(analyzeReportDropdown, true);

        try {
            // 1. Prepare Analysis
            let response = await fetch(ANALYZE_ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ llm_mode: llmMode })
            });
            let data = await response.json();
            
            if (data.status !== 'success') throw new Error(data.message || 'Check failed.');
            
            // 2. Call Proxy
            const CHATBOT_PROXY_URL = `${CHATBOT_REDIRECT_URL}/scanner_analysis`;
            response = await fetch(CHATBOT_PROXY_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ llm_mode: llmMode, scanner_type: data.scanner_type })
            });

            data = await response.json();

            if (response.ok && data.status === 'success') {
                appendLog(`[✓] Analysis complete. Redirecting...`);
                updateScanStatus('Redirecting...', 'success');
                window.location.href = `${CHATBOT_REDIRECT_URL}?mode=${data.llm_mode}&summary=${encodeURIComponent(data.summary)}`;
            } else {
                throw new Error(data.message || `Analysis failed`);
            }
        } catch (error) {
            appendLog(`[!] AI Analysis Error: ${error.message}`);
            updateScanStatus('Analysis failed', 'error');
        } finally {
            toggleButtonLoading(analyzeReportDropdown, false);
            checkReportStatus(); 
        }
    }

    // --- Main Rendering Logic ---

    async function fetchAndDisplayResults() {
        // Clear table with loading state
        zapAlertsTableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 2rem; color: #555;">Loading results...</td></tr>`;

        try {
            const response = await fetch(RESULTS_ENDPOINT);
            const result = await response.json();

            if (result.status === 'success' && result.data) {
                const report = result.data;
                updateSummaryDisplay(report.summary, report.target_url);
                populateAlertsTable(report.findings || report.alerts); // Handle 'findings' or 'alerts' key
                resultsContent.textContent = JSON.stringify(report, null, 2);
            } else {
                zapAlertsTableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 2rem; color: #555;">No results available.</td></tr>`;
            }
        } catch (error) {
            console.error(error);
            zapAlertsTableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 2rem; color: #ef4444;">Connection error.</td></tr>`;
        } finally {
            await checkReportStatus();
        }
    }
    
    function updateSummaryDisplay(summary, targetUrl) {
        if (!summary) return;
        lastScannedUrlDisplay.textContent = targetUrl || 'N/A';
        // Handle case sensitivity (Summary vs summary) if needed
        totalAlertsDisplay.textContent = summary.Total || summary.total || '0';
        highAlertsDisplay.textContent = summary.High || summary.high || '0';
        mediumAlertsDisplay.textContent = summary.Medium || summary.medium || '0';
        lowAlertsDisplay.textContent = summary.Low || summary.low || '0';
        infoAlertsDisplay.textContent = summary.Info || summary.info || '0';
    }

    function populateAlertsTable(findings) {
        zapAlertsTableBody.innerHTML = ''; 
        if (findings && findings.length > 0) {
            findings.forEach(alert => {
                const row = document.createElement('tr');
                
                // Determine Colors based on CSS Variables in your HTML
                const risk = alert.risk || 'Info';
                let riskColor = '#3b82f6'; // Default Info
                if (risk === 'High') riskColor = '#ef4444';
                if (risk === 'Medium') riskColor = '#f97316';
                if (risk === 'Low') riskColor = '#eab308';

                row.innerHTML = `
                    <td style="color: ${riskColor}; font-weight: 700;">${risk}</td>
                    <td style="font-weight: 600;">${alert.confidence || 'N/A'}</td>
                    <td>${alert.name || alert.alert}</td>
                    <td style="font-family: monospace; font-size: 0.8rem; color: #a1a1aa;">${alert.url || (alert.method + ' ' + alert.path)}</td>
                    <td style="font-size: 0.8rem; opacity: 0.8;">${(alert.description || '').substring(0, 100)}...</td>
                `;
                zapAlertsTableBody.appendChild(row);
            });
        } else {
            zapAlertsTableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 2rem; color: #555;">No alerts found.</td></tr>`;
        }
    }

    // --- Core Action: Start Scan ---

    async function handleScanButtonClick() {
        const targetUrl = targetUrlInput.value.trim();
        if (!targetUrl) {
            alert("Please enter a URL");
            return;
        }

        toggleButtonLoading(startScanBtn, true);
        updateScanStatus(`Scanning...`, 'busy');
        logOutput.innerHTML = ''; 
        appendLog(`> Initiating ZAP Scan on ${targetUrl}...`);

        try {
            const response = await fetch(SCAN_ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_url: targetUrl })
            });
            const data = await response.json();

            if (!response.ok || data.status !== 'success') {
                appendLog(`[!] Error: ${data.message}`);
                updateScanStatus('Failed', 'error');
                toggleButtonLoading(startScanBtn, false);
            }
            // If success, SSE will handle the completion
        } catch (error) {
            appendLog(`[!] Network error: ${error.message}`);
            toggleButtonLoading(startScanBtn, false);
        }
    }

    // --- SSE & Event Listeners ---

    function setupLogStream() {
        const eventSource = new EventSource(LOG_STREAM_ENDPOINT);
        eventSource.onmessage = function(event) {
            if (event.data === ': keep-alive') return;
            appendLog(event.data);
            
            if (event.data.includes("Scan, analysis, and prediction complete")) {
                updateScanStatus('Complete', 'success');
                toggleButtonLoading(startScanBtn, false);
                fetchAndDisplayResults();
            }
        };
    }

    startScanBtn.addEventListener('click', handleScanButtonClick);

    clearLogBtn.addEventListener('click', async () => {
        logOutput.innerHTML = '';
        await fetch(CLEAR_LOG_ENDPOINT, { method: 'POST' });
        appendLog("[*] Log cleared.");
    });

    refreshResultsBtn.addEventListener('click', () => {
        appendLog(`[*] Refreshing results...`);
        fetchAndDisplayResults();
    });

    copyResultsBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(resultsContent.textContent);
        const original = copyResultsBtn.textContent;
        copyResultsBtn.textContent = 'Copied!';
        setTimeout(() => copyResultsBtn.textContent = original, 1000);
    });
    
    // Dropdown Handling
    analyzeReportDropdown.addEventListener('click', (e) => {
        if (!analyzeReportDropdown.disabled) {
            llmAnalysisOptions.classList.toggle('hidden');
            e.stopPropagation(); 
        }
    });
    
    llmAnalysisOptions.addEventListener('click', (e) => {
        e.preventDefault();
        const option = e.target.closest('a[data-llm-mode]');
        if (option) {
            const llmMode = option.dataset.llmMode;
            llmAnalysisOptions.classList.add('hidden'); 
            analyzeReport(llmMode);
        }
    });

    document.addEventListener('click', (e) => {
        if (llmAnalysisOptions && !analyzeReportDropdown.contains(e.target)) {
            llmAnalysisOptions.classList.add('hidden');
        }
    });

    // Initialize
    checkReportStatus();
    fetchAndDisplayResults();
    setupLogStream();
});