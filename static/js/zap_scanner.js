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
    
    // AI Analysis & Overlay Elements
    const analyzeReportDropdown = document.getElementById('analyzeReportDropdown');
    const llmAnalysisOptions = document.getElementById('llmAnalysisOptions');
    const aiProcessingOverlay = document.getElementById('aiProcessingOverlay');
    const aiProcessingText = document.getElementById('aiProcessingText');

    // --- 🔒 CSRF TOKEN RETRIEVAL ---
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

    // --- Utility Functions ---

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
            if (icon && !icon.textContent.includes('expand_more')) icon.style.display = 'none';
        } else {
            button.style.opacity = '1';
            button.style.cursor = 'pointer';
            if (spinner) spinner.classList.add('hidden');
            if (icon) icon.style.display = 'inline-block';
        }
    }

    function updateScanStatus(message, type = 'info') {
        scanStatus.textContent = message;
        const isLight = document.body.classList.contains("light-mode");
        scanStatus.style.color = isLight ? '#64748b' : '#a1a1aa'; // Slate-500 / Zinc-400
        
        if (type === 'success') scanStatus.style.color = '#10b981'; // Green
        else if (type === 'error') scanStatus.style.color = '#ef4444'; // Red
        else if (type === 'busy') scanStatus.style.color = '#eab308'; // Yellow
    }

    // --- UPDATED LOG APPEND FUNCTION ---
    function appendLog(message) {
        if (!logOutput) return;

        // 1. Get Local Timestamp
        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });

        // 2. Clean Message: Remove backend timestamp [YYYY-MM-DD HH:MM:SS] if present
        let cleanedMessage = message.replace(/\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s*/g, "");
        cleanedMessage = cleanedMessage.trim();

        // 3. Determine Color Style
        const isLight = document.body.classList.contains("light-mode");
        let contentStyle = isLight ? 'color:#334155' : 'color:#d4d4d8'; // Slate-700 / Zinc-300
        
        const lowerMsg = cleanedMessage.toLowerCase();
        if (cleanedMessage.includes('[!]') || lowerMsg.includes('error') || lowerMsg.includes('failed')) {
            contentStyle = 'color:#ef4444'; // Red
        } else if (cleanedMessage.includes('[+]') || cleanedMessage.includes('[✓]') || lowerMsg.includes('success') || lowerMsg.includes('complete')) {
            contentStyle = 'color:#10b981'; // Green
        } else if (cleanedMessage.includes('[*]') || lowerMsg.includes('initiating')) {
            contentStyle = 'color:#3b82f6'; // Blue
        }

        const timeColor = isLight ? "#64748b" : "#555";

        const line = document.createElement('div');
        line.className = 'log-line';
        // Flex layout: Time on left, Content on right
        line.innerHTML = `
            <div class="log-time" style="color:${timeColor}">${timeStr}</div>
            <div class="log-content" style="${contentStyle}">${cleanedMessage}</div>
        `;
        
        logOutput.appendChild(line);
        logOutput.scrollTop = logOutput.scrollHeight;
    }

    // --- Report & Button Management ---

    async function checkReportStatus() {
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
                if (downloadPdfBtn) {
                    downloadPdfBtn.href = data.pdf_report; 
                    downloadPdfBtn.setAttribute('download', 'zap_report.pdf'); 
                    downloadPdfBtn.disabled = false;
                    downloadPdfBtn.style.opacity = '1';
                    
                    if (downloadPdfBtn.tagName === 'BUTTON') {
                        downloadPdfBtn.onclick = () => window.location.href = data.pdf_report;
                    }
                }
                
                if (analyzeReportDropdown) {
                    analyzeReportDropdown.disabled = false;
                    analyzeReportDropdown.style.opacity = '1';
                }
            }
        } catch (error) {
            console.error("Error checking report status:", error);
        }
    }
    
    // --- UPDATED AI ANALYSIS LOGIC (With Overlay) ---
    async function analyzeReport(llmMode) {
        if (analyzeReportDropdown.disabled) return;
        if (!csrfToken) {
            appendLog('[!] Error: CSRF Token missing. Refresh page.');
            return;
        }

        // 1. LOCK UI & SHOW OVERLAY
        if (llmAnalysisOptions) llmAnalysisOptions.classList.add('hidden');
        if (aiProcessingOverlay) {
            aiProcessingOverlay.classList.remove('hidden');
            if (aiProcessingText) {
                aiProcessingText.textContent = llmMode === 'gemini' 
                    ? 'CONTACTING GEMINI...' 
                    : 'LOADING LOCAL MODEL...';
            }
        }

        updateScanStatus(`AI Analysis (${llmMode})...`, 'busy');
        
        // Disable dropdown interactions
        analyzeReportDropdown.disabled = true;

        try {
            // 2. Trigger Context Preparation (Backend loads Scan Data)
            let response = await fetch(ANALYZE_ENDPOINT, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ llm_mode: llmMode })
            });
            let data = await response.json();
            
            if (data.status !== 'success') throw new Error(data.message || 'Check failed.');
            
            // 3. Synthesize Report (Backend calls LLM)
            if (aiProcessingText) aiProcessingText.textContent = 'SYNTHESIZING REPORT...';

            const CHATBOT_PROXY_URL = `${CHATBOT_REDIRECT_URL}/scanner_analysis`;
            response = await fetch(CHATBOT_PROXY_URL, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ llm_mode: llmMode, scanner_type: data.scanner_type })
            });

            data = await response.json();

            if (response.ok && data.status === 'success') {
                if (aiProcessingText) aiProcessingText.textContent = 'REDIRECTING...';
                updateScanStatus('Redirecting...', 'success');
                // Brief delay to let the user see the "Redirecting" state
                setTimeout(() => {
                    window.location.href = `${CHATBOT_REDIRECT_URL}?mode=${data.llm_mode}&summary=${encodeURIComponent(data.summary)}`;
                }, 800);
            } else {
                throw new Error(data.message || `Analysis failed`);
            }
        } catch (error) {
            appendLog(`[!] AI Analysis Error: ${error.message}`);
            updateScanStatus('Analysis failed', 'error');
            
            // Hide overlay to allow retry
            if (aiProcessingOverlay) aiProcessingOverlay.classList.add('hidden');
            analyzeReportDropdown.disabled = false;
        } finally {
            checkReportStatus(); 
        }
    }

    // --- Main Rendering Logic ---

    async function fetchAndDisplayResults() {
        zapAlertsTableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 2rem; color: #555;">Loading results...</td></tr>`;

        try {
            const response = await fetch(RESULTS_ENDPOINT);
            const result = await response.json();

            if (result.status === 'success' && result.data) {
                const report = result.data;
                updateSummaryDisplay(report.summary, report.target_url);
                populateAlertsTable(report.findings || report.alerts); 
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
                
                const risk = alert.risk || 'Info';
                let riskColor = '#3b82f6';
                if (risk === 'High') riskColor = '#ef4444';
                if (risk === 'Medium') riskColor = '#f97316';
                if (risk === 'Low') riskColor = '#eab308';

                // Increased truncate limit to 350 to match wider column
                const description = (alert.description || '').substring(0, 350) + (alert.description?.length > 350 ? '...' : '');

                row.innerHTML = `
                    <td style="color: ${riskColor}; font-weight: 700;">${risk}</td>
                    <td style="font-weight: 600;">${alert.predicted_risk_score || 'N/A'}</td>
                    <td>${alert.name || alert.alert}</td>
                    <td style="font-family: monospace; font-size: 0.8rem; color: #a1a1aa;">${alert.url || (alert.method + ' ' + alert.path)}</td>
                    <td style="font-size: 0.8rem; opacity: 0.8;">${description}</td>
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

        if (!csrfToken) {
            appendLog('[!] Error: CSRF Token missing. Refresh page.');
            return;
        }

        toggleButtonLoading(startScanBtn, true);
        updateScanStatus(`Scanning...`, 'busy');
        // Clear log but maintain cursor/layout
        logOutput.innerHTML = ''; 
        appendLog(`> Initiating ZAP Scan on ${targetUrl}...`);

        try {
            const response = await fetch(SCAN_ENDPOINT, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ target_url: targetUrl })
            });
            const data = await response.json();

            if (!response.ok || data.status !== 'success') {
                appendLog(`[!] Error: ${data.message}`);
                updateScanStatus('Failed', 'error');
                toggleButtonLoading(startScanBtn, false);
            }
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
        if (!csrfToken) {
            appendLog('[!] Error: CSRF Token missing. Refresh page.');
            return;
        }
        
        logOutput.innerHTML = '';
        await fetch(CLEAR_LOG_ENDPOINT, { 
            method: 'POST',
            headers: { 'X-CSRFToken': csrfToken }
        });
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
    setTimeout(() => appendLog('System Ready. Initializing ZAP Scanner interface...'), 100);
    checkReportStatus();
    fetchAndDisplayResults();
    setupLogStream();
});