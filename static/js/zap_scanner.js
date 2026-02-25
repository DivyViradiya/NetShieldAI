document.addEventListener('DOMContentLoaded', () => {
    // --- API Endpoints ---
    const API_BASE_URL = '/zap_scanner';
    const SCAN_ENDPOINT = `${API_BASE_URL}/scan`;
    const RESULTS_ENDPOINT = `${API_BASE_URL}/scan_results`;
    const CLEAR_LOG_ENDPOINT = `${API_BASE_URL}/clear_log`;
    const LOG_STREAM_ENDPOINT = `${API_BASE_URL}/log_stream`;
    const REPORT_FILES_ENDPOINT = `${API_BASE_URL}/report_files`; 
    const ANALYZE_ENDPOINT = `${API_BASE_URL}/trigger_ai_analysis`; 
    const STATUS_ENDPOINT = `${API_BASE_URL}/status`;
    const CHATBOT_REDIRECT_URL = '/chatbot'; 

    // --- DOM Elements ---
    const targetUrlInput = document.getElementById('targetUrl');
    const startScanBtn = document.getElementById('startScanBtn'); 
    
    // Scan Options UI
    const scanOptionsBtn = document.getElementById('scanOptionsBtn');
    const scanOptionsDropdown = document.getElementById('scanOptionsDropdown');
    const scanModeSelect = document.getElementById('scanMode');
    const useAjaxCheckbox = document.getElementById('useAjax');
    const loginUrlInput = document.getElementById('loginUrl');
    const userFieldInput = document.getElementById('userField');
    const passFieldInput = document.getElementById('passField');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');

    const scanStatus = document.getElementById('scanStatus');
    const hostStatusDisplay = document.getElementById('hostStatusDisplay');
    const logOutput = document.getElementById('logOutput');
    const clearLogBtn = document.getElementById('clearLogBtn');

    // Metrics
    const lastScannedUrlDisplay = document.getElementById('lastScannedUrlDisplay');
    const totalAlertsDisplay = document.getElementById('totalAlertsDisplay');
    const highAlertsDisplay = document.getElementById('highAlertsDisplay');
    const mediumAlertsDisplay = document.getElementById('mediumAlertsDisplay');
    const lowAlertsDisplay = document.getElementById('lowAlertsDisplay');
    const infoAlertsDisplay = document.getElementById('infoAlertsDisplay');
    const findingsList = document.getElementById('findingsList');
    const findingsSearch = document.getElementById('findingsSearch');
    const filterChips = document.querySelectorAll('.filter-chip');
    const findingsCountDisplay = document.getElementById('findingsCountDisplay');

    // Insights Panel
    const avgRiskScore = document.getElementById('avgRiskScore');
    const topVectorsList = document.getElementById('topVectorsList');
    const metaTarget = document.getElementById('metaTarget');
    const metaDuration = document.getElementById('metaDuration');

    let allFindings = [];
    let currentFilter = 'all';
    let scanStartTime = null;

    // Actions
    const refreshResultsBtn = document.getElementById('refreshResultsBtn');
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
        
        if (hostStatusDisplay) {
            if (type === 'busy') {
                hostStatusDisplay.textContent = 'SCANNING';
                hostStatusDisplay.style.color = '#eab308'; // Yellow
            } else if (type === 'success') {
                hostStatusDisplay.textContent = 'COMPLETE';
                hostStatusDisplay.style.color = '#10b981'; // Green
            } else if (type === 'error') {
                hostStatusDisplay.textContent = 'FAILED';
                hostStatusDisplay.style.color = '#ef4444'; // Red
            } else {
                hostStatusDisplay.textContent = 'READY';
                hostStatusDisplay.style.color = '#10b981'; // Green
            }
        }

        const isLight = document.body.classList.contains("light-mode");
        scanStatus.style.color = isLight ? '#64748b' : '#a1a1aa'; // Slate-500 / Zinc-400
        
        if (type === 'success') scanStatus.style.color = '#10b981'; // Green
        else if (type === 'error') scanStatus.style.color = '#ef4444'; // Red
        else if (type === 'busy') scanStatus.style.color = '#eab308'; // Yellow
    }

    // --- UPDATED LOG APPEND FUNCTION ---
    function appendLog(message) {
        if (!logOutput) return;

        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });

        let cleanedMessage = message.replace(/\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s*/g, "");
        cleanedMessage = cleanedMessage.trim();

        const isProgressBar = cleanedMessage.startsWith('[PROGRESS]') || (cleanedMessage.startsWith('[') && cleanedMessage.includes('%'));
        if (isProgressBar) {
            const lastLine = logOutput.lastElementChild;
            if (lastLine) {
                const logContent = lastLine.querySelector('.log-content');
                if (logContent && logContent.getAttribute('data-is-progress') === 'true') {
                    lastLine.querySelector('.log-time').textContent = timeStr;
                    logContent.textContent = cleanedMessage;
                    return;
                }
            }
        }
        
        let contentStyle = '';
        if (cleanedMessage.includes('[!]') || cleanedMessage.includes('Error')) {
            contentStyle = 'color:#ef4444';
        } else if (cleanedMessage.includes('[+]') || cleanedMessage.includes('Success')) {
            contentStyle = 'color:#10b981';
        } else if (cleanedMessage.includes('[*]')) {
            contentStyle = 'color:#3b82f6';
        }

        const line = document.createElement('div');
        line.className = 'log-line';
        const dataAttr = isProgressBar ? ' data-is-progress="true"' : '';
        
        line.innerHTML = `
            <div class="log-time">${timeStr}</div>
            <div class="log-content" style="${contentStyle}"${dataAttr}>${cleanedMessage}</div>
        `;
        
        logOutput.appendChild(line);
        logOutput.scrollTop = logOutput.scrollHeight;
    }

    // --- Report & Button Management ---

    async function checkReportStatus() {
        const target = targetUrlInput.value.trim();
        if (downloadPdfBtn) {
            downloadPdfBtn.disabled = true;
            downloadPdfBtn.style.opacity = '0.5';
        }
        if (analyzeReportDropdown) {
            analyzeReportDropdown.disabled = true;
            analyzeReportDropdown.style.opacity = '0.5';
        }

        try {
            const url = target ? `${REPORT_FILES_ENDPOINT}?target=${encodeURIComponent(target)}` : REPORT_FILES_ENDPOINT;
            const response = await fetch(url);
            if (!response.ok) return;
            const data = await response.json();
    
            if (data.status === "success" && data.pdf_report) {
                if (downloadPdfBtn) {
                    downloadPdfBtn.href = data.pdf_report; 
                    downloadPdfBtn.setAttribute('download', `zap_report_${target.replace(/[^a-z0-9]/gi, '_')}.pdf`); 
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
        const target = targetUrlInput.value.trim();
        
        if (!csrfToken) {
            appendLog('[!] Error: CSRF Token missing. Refresh page.');
            return;
        }

        // 1. LOCK UI & SHOW OVERLAY
        if (llmAnalysisOptions) llmAnalysisOptions.classList.add('hidden');
        if (aiProcessingOverlay) {
            aiProcessingOverlay.classList.remove('hidden');
            if (aiProcessingText) {
                aiProcessingText.textContent = llmMode.includes('gemini') 
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
                body: JSON.stringify({ llm_mode: llmMode, target: target })
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
                body: JSON.stringify({ 
                    llm_mode: llmMode, 
                    scanner_type: data.scanner_type,
                    target: data.target,
                    force_new_session: true // [NEW] Force a fresh chat
                })
            });

            data = await response.json();

            if (response.ok && data.status === 'success') {
                if (aiProcessingText) aiProcessingText.textContent = 'REDIRECTING...';
                updateScanStatus('Redirecting...', 'success');
                // Brief delay to let the user see the "Redirecting" state
                setTimeout(() => {
                    const params = new URLSearchParams({
                        mode: data.llm_mode,
                        summary: data.summary,
                        session_id: data.session_id
                    });
                    window.location.href = `${CHATBOT_REDIRECT_URL}?${params.toString()}`;
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
        findingsList.innerHTML = `<div style="text-align:center; padding: 4rem; color: #555; font-family: monospace;">LOADING SCAN DATA...</div>`;

        try {
            const response = await fetch(RESULTS_ENDPOINT);
            const result = await response.json();

            if (result.status === 'success' && result.data) {
                const report = result.data;
                updateSummaryDisplay(report.summary, report.target_url);
                allFindings = report.findings || report.alerts || [];
                renderFindings();
                updateInsightsDisplay(report);
            } else {
                findingsList.innerHTML = `<div style="text-align:center; padding: 4rem; color: #555; font-family: monospace;">NO RESULTS AVAILABLE.</div>`;
            }
        } catch (error) {
            console.error(error);
            findingsList.innerHTML = `<div style="text-align:center; padding: 4rem; color: #ef4444; font-family: monospace;">CONNECTION ERROR.</div>`;
        } finally {
            await checkReportStatus();
        }
    }
    
    function updateSummaryDisplay(summary, targetUrl) {
        if (!summary) return;
        lastScannedUrlDisplay.textContent = targetUrl || '---';
        totalAlertsDisplay.textContent = summary.Total || summary.total || '0';
        highAlertsDisplay.textContent = summary.High || summary.high || '0';
        mediumAlertsDisplay.textContent = summary.Medium || summary.medium || '0';
        lowAlertsDisplay.textContent = summary.Low || summary.low || '0';
        infoAlertsDisplay.textContent = summary.Info || summary.info || '0';
    }

    function updateInsightsDisplay(report) {
        if (!report) return;

        // 1. Target & Metadata
        if (metaTarget) metaTarget.textContent = report.target_url || '---';
        if (scanStartTime && metaDuration) {
            const duration = Math.floor((Date.now() - scanStartTime) / 1000);
            metaDuration.textContent = `${duration}s`;
        }

        // 2. Risk Index (Average of Predicted Scores)
        const scores = allFindings
            .map(f => parseFloat(f.predicted_risk_score))
            .filter(s => !isNaN(s));
        
        if (scores.length > 0 && avgRiskScore) {
            const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
            avgRiskScore.textContent = avg.toFixed(1);
            
            if (avg > 15) avgRiskScore.style.color = '#ef4444';
            else if (avg > 8) avgRiskScore.style.color = '#f97316';
            else avgRiskScore.style.color = '#3b82f6';
        }

        // 3. Top Attack Vectors
        const vectorMap = {};
        allFindings.forEach(f => {
            const name = f.name || f.alert;
            vectorMap[name] = (vectorMap[name] || 0) + 1;
        });

        const sortedVectors = Object.entries(vectorMap)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 3);

        if (topVectorsList) {
            topVectorsList.innerHTML = '';
            if (sortedVectors.length > 0) {
                sortedVectors.forEach(([name, count]) => {
                    const item = document.createElement('div');
                    item.className = 'vector-item';
                    item.innerHTML = `
                        <span class="vector-name" title="${name}">${name}</span>
                        <span class="vector-count">${count}x</span>
                    `;
                    topVectorsList.appendChild(item);
                });
            } else {
                topVectorsList.innerHTML = `<div style="text-align:center; padding: 1rem; color: #444; font-size: 0.7rem;">NO VECTORS IDENTIFIED</div>`;
            }
        }
    }

    function getRiskColor(risk) {
        if (risk === 'High') return '#ef4444';
        if (risk === 'Medium') return '#f97316';
        if (risk === 'Low') return '#eab308';
        return '#3b82f6';
    }

    function renderFindings() {
        const searchTerm = findingsSearch.value.toLowerCase();
        findingsList.innerHTML = '';
        
        const filtered = allFindings.filter(f => {
            const matchesFilter = currentFilter === 'all' || f.risk === currentFilter;
            const matchesSearch = (f.name || f.alert || '').toLowerCase().includes(searchTerm) || 
                                  (f.url || '').toLowerCase().includes(searchTerm);
            return matchesFilter && matchesSearch;
        });

        if (findingsCountDisplay) findingsCountDisplay.textContent = filtered.length;

        if (filtered.length === 0) {
            findingsList.innerHTML = `<div style="text-align:center; padding: 4rem; color: #555; font-family: monospace;">NO FINDINGS MATCHING CRITERIA.</div>`;
            return;
        }

        filtered.forEach(finding => {
            const card = createFindingCard(finding);
            findingsList.appendChild(card);
        });
    }

    function createFindingCard(finding) {
        const risk = finding.risk || 'Info';
        const confidence = finding.confidence || 'Medium';
        const color = getRiskColor(risk);
        const card = document.createElement('div');
        card.className = 'finding-card';
        card.style.setProperty('--accent-gradient', color);
        
        card.innerHTML = `
            <div class="finding-header">
                <div class="risk-indicator" style="color: ${color};">
                    <div class="risk-dot" style="background: ${color};"></div>
                    <span>${risk}</span>
                </div>
                
                <div class="finding-title">${finding.name || finding.alert}</div>
                
                <div class="score-container">
                    <span class="score-label">Risk Score</span>
                    <span class="score-val">${(parseFloat(finding.predicted_risk_score || 0) * 10).toFixed(1)}</span>
                </div>

                <span class="material-symbols-outlined expand-icon" style="margin-left: 0.5rem; font-size: 1.25rem;">expand_more</span>
            </div>
            
            <div class="finding-details">
                <div class="details-content">
                    <div class="detail-section">
                        <span class="detail-label">Vulnerable Endpoint</span>
                        <div class="flex items-center gap-3">
                            <div class="badge-pill" style="background: var(--neo-input); border: 1px solid var(--neo-border); color: var(--neo-text-main); font-family: var(--font-mono); font-size: 0.7rem; padding: 4px 8px;">${finding.method || 'GET'}</div>
                            <a href="${finding.url || '#'}" target="_blank" class="finding-url-link" style="font-family: var(--font-mono); font-size: 0.8rem;">${finding.url || 'N/A'}</a>
                        </div>
                        ${finding.param ? `<div class="detail-text" style="font-size: 0.75rem; margin-top: 4px; color: var(--neo-text-muted);">PARAMETER: <span style="color: var(--neo-text-main);">${finding.param}</span></div>` : ''}
                    </div>

                    <div class="detail-section">
                        <span class="detail-label">Vulnerability Analysis</span>
                        <div class="detail-text">${finding.description || 'Detailed vulnerability analysis is unavailable for this finding.'}</div>
                    </div>

                    <div class="detail-section">
                        <span class="detail-label">Remediation & Solution</span>
                        <div class="detail-text" style="border-left: 3px solid var(--neo-green); padding-left: 1rem; opacity: 1;">${finding.solution || 'Consult industry best practices for specific remediation steps.'}</div>
                    </div>

                    <div class="detail-section">
                        <div class="flex justify-between items-center mb-1">
                            <span class="detail-label">Technical Details</span>
                            <div class="flex gap-4">
                                <span style="font-size: 0.65rem; color: var(--neo-text-muted); font-weight: 700;">CONFIDENCE: <span style="color: var(--neo-text-main);">${confidence}</span></span>
                                ${finding.cweid ? `<span style="font-size: 0.65rem; color: var(--neo-text-muted); font-weight: 700;">CWE: <span style="color: var(--neo-blue); cursor: pointer;" onclick="window.open('https://cwe.mitre.org/data/definitions/${finding.cweid}.html', '_blank')">${finding.cweid}</span></span>` : ''}
                            </div>
                        </div>
                        <div class="detail-text detail-text-mono" style="color: #a1a1aa; background: #000; padding: 1rem; border-radius: 6px; border: 1px solid #222; overflow-x: auto; white-space: pre-wrap;">${finding.evidence || 'NO RAW EVIDENCE CAPTURED'}</div>
                    </div>

                    ${finding.reference ? `
                    <div class="detail-section" style="border-bottom: none; padding-bottom: 0;">
                        <span class="detail-label">References</span>
                        <div class="detail-text" style="font-size: 0.75rem; line-height: 1.6; color: var(--neo-blue); opacity: 0.8;">${finding.reference.split('\n').map(ref => `<a href="${ref.trim()}" target="_blank" style="color: inherit; display: block; margin-bottom: 2px;">${ref.trim()}</a>`).join('')}</div>
                    </div>` : ''}
                </div>
            </div>
        `;

        card.addEventListener('click', () => {
            card.classList.toggle('expanded');
        });

        return card;
    }

    // --- Filter & Search Listeners ---
    filterChips.forEach(chip => {
        chip.addEventListener('click', () => {
            filterChips.forEach(c => c.classList.remove('active'));
            chip.classList.add('active');
            currentFilter = chip.dataset.filter;
            renderFindings();
        });
    });

    findingsSearch.addEventListener('input', renderFindings);

    // --- Core Action: Start Scan ---

    async function handleScanButtonClick() {
        const targetUrl = targetUrlInput.value.trim();
        const scanMode = scanModeSelect ? scanModeSelect.value : 'Quick Scan';
        const useAjax = useAjaxCheckbox ? useAjaxCheckbox.checked : false;

        // Collect Auth Config if provided
        let authConfig = null;
        if (loginUrlInput && loginUrlInput.value.trim() && usernameInput.value.trim() && passwordInput.value.trim()) {
            authConfig = {
                login_url: loginUrlInput.value.trim(),
                username_field: userFieldInput.value.trim() || 'username',
                password_field: passFieldInput.value.trim() || 'password',
                username: usernameInput.value.trim(),
                password: passwordInput.value.trim()
            };
        }

        if (!targetUrl) {
            alert("Please enter a URL");
            return;
        }

        if (!csrfToken) {
            appendLog('[!] Error: CSRF Token missing. Refresh page.');
            return;
        }

        toggleButtonLoading(startScanBtn, true);
        const authMsg = authConfig ? 'Authenticated' : 'Anonymous';
        updateScanStatus(`Scanning (${scanMode}, ${authMsg})...`, 'busy');
        // Clear log but maintain cursor/layout
        logOutput.innerHTML = ''; 
        appendLog(`> Initiating ZAP ${scanMode} on ${targetUrl} (AJAX: ${useAjax}, Auth: ${authMsg})...`);

        try {
            const response = await fetch(SCAN_ENDPOINT, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ 
                    target_url: targetUrl,
                    scan_mode: scanMode,
                    use_ajax: useAjax,
                    auth_config: authConfig
                })
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
    
    // Toggle Scan Options Dropdown
    if (scanOptionsBtn && scanOptionsDropdown) {
        scanOptionsBtn.addEventListener('click', (e) => {
            scanOptionsDropdown.classList.toggle('hidden');
            e.stopPropagation();
        });

        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (!scanOptionsBtn.contains(e.target) && !scanOptionsDropdown.contains(e.target)) {
                scanOptionsDropdown.classList.add('hidden');
            }
        });
    }

    function setupLogStream() {
        const eventSource = new EventSource(LOG_STREAM_ENDPOINT);
        eventSource.onmessage = function(event) {
            if (event.data === ': keep-alive') return;

            // Check for completion signals BEFORE filtering EVENT: lines
            if (event.data.includes("Scan, analysis, and prediction complete")) {
                updateScanStatus('Complete', 'success');
                toggleButtonLoading(startScanBtn, false);
                fetchAndDisplayResults();
            }

            // [NEW] Handle Failures from Stream to reset UI
            if (event.data.includes("[!] ZAP scan failed") || event.data.includes("ZAP Scan Error:")) {
                updateScanStatus('Failed', 'error');
                toggleButtonLoading(startScanBtn, false);
            }

            if (event.data.includes("SYSTEM_EVENT: READY_FOR_ANALYSIS")) {
                checkReportStatus();
            }

            if (event.data.includes("EVENT:") || event.data.startsWith("EVENT:")) return;
            appendLog(event.data);
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
        fetchAndDisplayResults();
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

    async function checkScanStatus() {
        try {
            const response = await fetch(STATUS_ENDPOINT);
            const data = await response.json();
            
            if (data.status === 'success' && data.is_running) {
                toggleButtonLoading(startScanBtn, true);
                updateScanStatus(`Scanning: ${data.target}...`, 'busy');
                if (targetUrlInput) targetUrlInput.value = data.target;
                appendLog(`[*] Detected active scan on ${data.target}. Re-attaching to stream...`);
            }
        } catch (error) {
            console.error("Error checking scan status:", error);
        }
    }

    // Initialize
    setTimeout(() => appendLog('System Ready. Initializing ZAP Scanner interface...'), 100);
    checkReportStatus();
    fetchAndDisplayResults();
    checkScanStatus();
    setupLogStream();
});