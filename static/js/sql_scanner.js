document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Element Selectors ---
    const elements = {
        // Inputs & Controls
        targetUrlInput: document.getElementById('targetUrl'),
        scanQuickBtn: document.getElementById('scanQuickBtn'),
        scanFullBtn: document.getElementById('scanFullBtn'),
        
        // Advanced Config (Modes Dropdown)
        advancedScanToggle: document.getElementById('advancedScanToggle'),
        advancedScanOptions: document.getElementById('advancedScanOptions'),
        
        // Database Actions (Right Panel)
        dumpSchemaBtn: document.getElementById('dumpSchemaBtn'), // Placeholder for future expansion
        checkWafBtn: document.getElementById('checkWafBtn'), // Placeholder

        // Results Header / Metrics
        scanStatus: document.getElementById('scanStatus'),
        targetDisplay: document.getElementById('targetDisplay'),
        hostStatusDisplay: document.getElementById('hostStatusDisplay'),
        vulnCountDisplay: document.getElementById('vulnCountDisplay'),
        dbmsDisplay: document.getElementById('dbmsDisplay'),
        
        // Risk Distribution Bars
        criticalCount: document.getElementById('criticalCount'),
        criticalBar: document.getElementById('criticalBar'),
        highCount: document.getElementById('highCount'),
        highBar: document.getElementById('highBar'),

        // Toolbar
        refreshResultsBtn: document.getElementById('refreshResultsBtn'),
        analyzeReportDropdown: document.getElementById('analyzeReportDropdown'),
        llmAnalysisOptions: document.getElementById('llmAnalysisOptions'),
        downloadReportBtn: document.getElementById('downloadReportBtn'),
        
        // AI Animation Elements
        aiProcessingOverlay: document.getElementById('aiProcessingOverlay'),
        aiProcessingText: document.getElementById('aiProcessingText'),

        // Tabs
        findingsTabBtn: document.getElementById('findingsTabBtn'),
        rawTabBtn: document.getElementById('rawTabBtn'),
        findingsContent: document.getElementById('findingsContent'),
        rawContent: document.getElementById('rawContent'),
        
        // Content Areas
        vulnTableBody: document.getElementById('vulnTableBody'),
        rawScanTypeDisplay: document.getElementById('rawScanTypeDisplay'),
        copyResultsBtn: document.getElementById('copyResultsBtn'),
        resultsContent: document.getElementById('resultsContent'), 
        
        // Live Terminal
        clearLogBtn: document.getElementById('clearLogBtn'),
        logOutput: document.getElementById('logOutput'),
    };

    // --- State Variables ---
    const API_BASE_URL = '/sql_scanner';
    const CHATBOT_REDIRECT_URL = '/chatbot'; 
    let isActionInProgress = false;
    let reportDownloadUrl = null;

    // --- 🔒 CSRF TOKEN RETRIEVAL ---
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

    // --- Helper Functions ---
    
    function setButtonsDisabled(isDisabled) {
        // 1. Always manageable buttons (Control/Refresh)
        const controlBtns = [
            elements.scanQuickBtn,
            elements.scanFullBtn,
            elements.advancedScanToggle,
            elements.checkWafBtn,
            elements.refreshResultsBtn
        ];

        // 2. Report-dependent buttons
        const reportBtns = [
            elements.dumpSchemaBtn,
            elements.analyzeReportDropdown,
            elements.downloadReportBtn
        ];

        controlBtns.forEach(btn => {
            if (btn) {
                btn.disabled = isDisabled;
                btn.style.opacity = isDisabled ? '0.5' : '1';
                if (isDisabled) btn.classList.add('cursor-not-allowed');
                else btn.classList.remove('cursor-not-allowed');
            }
        });

        // For report buttons, if enabling, only do it if we have a report
        reportBtns.forEach(btn => {
            if (btn) {
                if (isDisabled) {
                    btn.disabled = true;
                    btn.style.opacity = '0.5';
                    btn.classList.add('cursor-not-allowed');
                } else {
                    // Only re-enable if there is a valid report URL found previously
                    const hasReport = !!reportDownloadUrl;
                    btn.disabled = !hasReport;
                    btn.style.opacity = hasReport ? '1' : '0.5';
                    btn.classList.toggle('cursor-not-allowed', !hasReport);
                }
            }
        });
        
        if (elements.targetUrlInput) {
            elements.targetUrlInput.disabled = isDisabled;
        }
    }

    function toggleSpinner(button, isLoading) {
        if (!button) return;
        const spinner = button.querySelector('.spinner');
        const icon = button.querySelector('.material-symbols-outlined'); 
        
        // Don't disable the main dropdown trigger, only its options interactions
        if (button.id !== 'analyzeReportDropdown') {
            button.disabled = isLoading;
        }

        if (isLoading) {
            button.classList.add('opacity-70');
            if (button.tagName !== 'A' && button.id !== 'analyzeReportDropdown') button.classList.add('cursor-not-allowed');
            
            if (icon) icon.classList.add('hidden'); 
            if (spinner) spinner.classList.remove('hidden');
            
        } else {
            button.classList.remove('opacity-70', 'cursor-not-allowed');
            
            if (spinner) spinner.classList.add('hidden');
            if (icon) icon.classList.remove('hidden');
        }
        
        // Handle expand_more icon specifically
        if (icon && icon.textContent === 'expand_more') {
            icon.style.display = isLoading ? 'none' : 'inline-block';
        }
    }
    
    function appendLog(message) {
        if (!elements.logOutput) return;

        // --- NEW: CLEANING LOGIC ---
        // 1. Remove Backend Timestamp: [YYYY-MM-DD HH:MM:SS]
        // Matches the timestamp added by your Python 'log' function
        message = message.replace(/^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s*/, '');

        // 2. Remove SQLMap Internal Timestamp: [HH:MM:SS]
        // Matches the timestamp that comes from the sqlmap CLI output itself
        message = message.replace(/\[\d{2}:\d{2}:\d{2}\]\s*/g, '');

        // 3. Cleanup double spaces left behind
        message = message.replace(/\s\s+/g, ' ');

        // --- Existing Logic Below ---
        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });

        let contentStyle = 'color:var(--neo-text-muted)'; 
        
        // Parse SQLMap specific logs for styling
        if (message.includes('[!]') || message.includes('CRITICAL')) {
            contentStyle = 'color:#ef4444'; // Red
        } else if (message.includes('[+]') || message.includes('vulnerable')) {
            contentStyle = 'color:#10b981'; // Green
        } else if (message.includes('[*]') || message.includes('Testing')) {
            contentStyle = 'color:#3b82f6'; // Blue
        } else if (message.includes('[DATA]')) {
            contentStyle = 'color:#f59e0b; font-weight:bold;'; // Orange for extracted data
            message = message.replace('[DATA]', ''); // Clean tag
        } else if (message.includes('[SQLMap]')) {
             contentStyle = 'color:#64748b'; // Muted for generic SQLMap output
        }

        const line = document.createElement('div');
        line.className = 'log-line';
        line.innerHTML = `
            <div class="log-time">${timeStr}</div>
            <div class="log-content" style="${contentStyle}">${message}</div>
        `;
        
        elements.logOutput.appendChild(line);
        elements.logOutput.scrollTop = elements.logOutput.scrollHeight;
    }

    function setStatus(text, type = 'ready') {
        if (!elements.scanStatus) return;
        
        elements.scanStatus.className = 'status-val font-mono ml-2';
        
        switch (type) {
            case 'busy':
                elements.scanStatus.style.color = '#eab308'; 
                elements.scanStatus.textContent = `BUSY...`;
                break;
            case 'error':
                elements.scanStatus.style.color = '#ef4444'; 
                elements.scanStatus.textContent = text;
                break;
            case 'success':
                elements.scanStatus.style.color = '#10b981'; 
                elements.scanStatus.textContent = text;
                break;
            default: 
                elements.scanStatus.style.color = '#10b981';
                elements.scanStatus.textContent = 'READY';
        }
    }

    // --- API & Data Functions ---

    async function apiPost(endpoint, body = {}, button = null) {
        if (isActionInProgress) return;
        isActionInProgress = true;
        if (button) toggleSpinner(button, true);

        if (!csrfToken) {
            appendLog('[!] Error: CSRF Token missing. Refresh page.');
            isActionInProgress = false;
            if (button) toggleSpinner(button, false);
            setButtonsDisabled(false); // Enable back if CSRF fails
            return null;
        }

        try {
            const response = await fetch(`${API_BASE_URL}${endpoint}`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken 
                },
                body: JSON.stringify(body),
            });
            const data = await response.json();
            if (!response.ok) {
                setButtonsDisabled(false); // Enable back on 4xx/5xx errors
                throw new Error(data.message || `Request failed with status ${response.status}`);
            }
            if(data.message) appendLog(`[✓] ${data.message}`);
            return data;
        } catch (error) {
            appendLog(`[!] Error: ${error.message}`);
            setStatus('Error', 'error');
            setButtonsDisabled(false); // Enable back on network/system errors
            return null;
        } finally {
            if (button) toggleSpinner(button, false);
            isActionInProgress = false;
        }
    }

    async function fetchReportData() {
        try {
            // 1. Get JSON content for UI
            const response = await fetch(`${API_BASE_URL}/report`);
            if (response.ok) {
                const data = await response.json();
                if(data.status === 'success') {
                    updateDashboard(data.content);
                    // Update Raw Tab
                    elements.resultsContent.textContent = JSON.stringify(data.content, null, 2);
                }
            } else {
                elements.resultsContent.textContent = '// No scan data found. Run a scan to generate results.';
            }

            // 2. Check PDF availability
            await checkReportAvailability();

        } catch (error) {
            console.error('Error fetching report:', error);
        }
    }

    function updateDashboard(data) {
        // --- 1. Update Metrics ---
        // Target
        if(elements.targetDisplay) elements.targetDisplay.textContent = data.target || '---';
        if(elements.targetUrlInput && elements.targetUrlInput.value === '') {
            elements.targetUrlInput.value = data.target || ''; // Autofill if empty
        }

        // DBMS
        const dbms = data.database_info?.dbms || 'Not Detected';
        elements.dbmsDisplay.textContent = dbms;
        elements.dbmsDisplay.title = `${dbms} (${data.database_info?.version || 'v?'})`;
        
        // Vuln Count
        const vulns = data.vulnerabilities || [];
        elements.vulnCountDisplay.textContent = vulns.length;
        
        // Host Status
        if(data.scan_time) {
            elements.hostStatusDisplay.textContent = "SCANNED";
            elements.hostStatusDisplay.style.color = '#10b981';
        }

        // --- 2. Update Risk Distribution ---
        // Simple logic: SQLi is usually High or Critical
        let highCount = 0;
        let criticalCount = 0;

        vulns.forEach(v => {
            // Assume most SQLi is High risk, Union/Stacked often Critical
            const type = (v.type || '').toLowerCase();
            if (type.includes('stacked') || type.includes('union') || type.includes('order')) {
                criticalCount++;
            } else {
                highCount++;
            }
        });

        const total = criticalCount + highCount;
        const totalMax = total > 0 ? total : 1; // Avoid divide by zero

        if(elements.criticalCount) elements.criticalCount.textContent = criticalCount;
        if(elements.highCount) elements.highCount.textContent = highCount;

        if(elements.criticalBar) elements.criticalBar.style.width = `${(criticalCount / totalMax) * 100}%`;
        if(elements.highBar) elements.highBar.style.width = `${(highCount / totalMax) * 100}%`;

        // --- 3. Populate Findings Table ---
        elements.vulnTableBody.innerHTML = '';
        if (vulns.length === 0) {
             elements.vulnTableBody.innerHTML = `
                <tr><td colspan="4" style="text-align: center; padding: 2rem;">
                    <div style="color: #555;">No Vulnerabilities Detected</div>
                </td></tr>`;
        } else {
            vulns.forEach(v => {
                // Determine Risk Label
                let riskBadge = '<span class="badge-pill" style="color:#f59e0b; border-color:#f59e0b55; background:#f59e0b11;">HIGH</span>';
                if ((v.type || '').toLowerCase().includes('stacked')) {
                     riskBadge = '<span class="badge-pill" style="color:#f43f5e; border-color:#f43f5e55; background:#f43f5e11;">CRITICAL</span>';
                }

                const row = `
                <tr>
                    <td style="color: var(--neo-text-main); font-weight:600;">${v.type || 'Unknown'}</td>
                    <td>
                        <div style="font-family: monospace; font-size: 0.75rem; color: var(--neo-text-muted); background: var(--neo-input); padding: 4px; border-radius: 4px; max-width: 300px; overflow-x: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${v.payload}">
                            ${v.payload || 'N/A'}
                        </div>
                    </td>
                    <td>${riskBadge}</td>
                    <td style="color: var(--neo-text-muted); font-size: 0.75rem;">${v.title || 'SQL Injection Detected'}</td>
                </tr>`;
                elements.vulnTableBody.insertAdjacentHTML('beforeend', row);
            });
        }
    }

    async function checkReportAvailability() {
        try {
            const response = await fetch(`${API_BASE_URL}/report_files`);
            if (response.ok) {
                const data = await response.json();
                if (data.status === 'success' && data.pdf_report) {
                    reportDownloadUrl = data.pdf_report;
                    
                    // Enable Buttons
                    [elements.downloadReportBtn, elements.analyzeReportDropdown].forEach(btn => {
                        if (btn) {
                            btn.disabled = false;
                            btn.style.opacity = '1';
                        }
                    });
                    return;
                }
            }
        } catch (error) { console.error(error); }

        reportDownloadUrl = null;
        [elements.downloadReportBtn, elements.analyzeReportDropdown].forEach(btn => {
            if (btn) {
                btn.disabled = true;
                btn.style.opacity = '0.5';
            }
        });
    }

    async function analyzeReport(llmMode) {
        const button = elements.analyzeReportDropdown;
        const overlay = elements.aiProcessingOverlay;
        const processingText = elements.aiProcessingText;
        const llmOptions = elements.llmAnalysisOptions;

        if (!button || button.disabled) return;
        
        if (llmOptions) llmOptions.classList.add('hidden');
        if (overlay) overlay.classList.remove('hidden');
        
        if (processingText) {
            processingText.textContent = llmMode === 'gemini' 
                ? 'CONTACTING GEMINI...' 
                : 'LOADING LOCAL MODEL...';
        }

        setStatus(`Analyzing via ${llmMode}...`, 'busy');
        
        try {
            // 1. Trigger backend preparation
            let response = await fetch(`${API_BASE_URL}/trigger_ai_analysis`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken 
                },
                body: JSON.stringify({ llm_mode: llmMode })
            });
            let data = await response.json();
            
            if (data.status !== 'success') throw new Error(data.message);
            
            if (processingText) processingText.textContent = 'SYNTHESIZING REPORT...';

            // 2. Call Chatbot Analysis
            // FIXED: Passing report_file and user_identifier to ensure Chatbot can find the file
            response = await fetch(`${CHATBOT_REDIRECT_URL}/scanner_analysis`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken 
                },
                body: JSON.stringify({ 
                    llm_mode: llmMode, 
                    scanner_type: data.scanner_type,
                    report_file: data.report_file,       // [ADDED] Filename
                    user_identifier: data.user_identifier, // [ADDED] User folder ID
                    force_new_session: true // [NEW] Force a fresh chat
                })
            });

            data = await response.json();

            if (response.ok && data.status === 'success') {
                if (processingText) processingText.textContent = 'REDIRECTING...';
                appendLog(`[✓] Analysis complete. Redirecting...`);
                
                setTimeout(() => {
                    const params = new URLSearchParams({
                        mode: data.llm_mode,
                        summary: data.summary,
                        session_id: data.session_id
                    });
                    window.location.href = `${CHATBOT_REDIRECT_URL}?${params.toString()}`;
                }, 800);
            } else {
                throw new Error(data.message);
            }
        } catch (error) {
            appendLog(`[!] AI Analysis Error: ${error.message}`);
            setStatus('Analysis failed', 'error');
            if (overlay) overlay.classList.add('hidden');
        } 
    }

    async function initiateScan(scanMode, button) {
        const targetUrl = elements.targetUrlInput.value.trim();
        if (!targetUrl) {
            appendLog('[!] Error: Target URL is required (e.g., http://example.com/page.php?id=1)');
            return;
        }
        
        // Basic URL validation
        if (!targetUrl.startsWith('http')) {
            appendLog('[!] Error: URL must start with http:// or https://');
            return;
        }

        setButtonsDisabled(true); // LOCK UI
        setStatus(`Scanning (${scanMode})...`, 'busy');
        switchTab('findings'); 
        
        // Clear previous results visually
        elements.vulnTableBody.innerHTML = `<tr><td colspan="4" style="text-align:center; padding: 2rem; color: #666;">Scanning in progress...</td></tr>`;

        await apiPost('/scan', {
            target_url: targetUrl,
            scan_mode: scanMode // 'quick' or 'full'
        }, button);
    }
    
    function initializeLogStream() {
        const eventSource = new EventSource(`${API_BASE_URL}/log_stream`);
        eventSource.onmessage = (event) => {
            const message = event.data;
            if (message.startsWith(':')) return; // Ignore keep-alive
            appendLog(message);

            if (message.toLowerCase().includes("scan complete") || message.toLowerCase().includes("finished")) {
                setStatus('Scan Complete', 'success');
                fetchReportData().then(() => {
                    setButtonsDisabled(false); // UNLOCK UI
                });
            }
        };
        eventSource.onerror = () => {
            // console.warn('Log stream disconnected.');
            // eventSource.close();
            // Optional: Reconnect logic could go here
        };
    }
    
    function switchTab(tabName) {
        elements.findingsTabBtn.classList.toggle('active', tabName === 'findings');
        elements.rawTabBtn.classList.toggle('active', tabName === 'raw');
        elements.findingsContent.classList.toggle('hidden', tabName !== 'findings');
        elements.rawContent.classList.toggle('hidden', tabName !== 'raw');
    }

    // --- Event Listeners ---
    function setupEventListeners() {
        // Main Scan Buttons
        if(elements.scanQuickBtn) elements.scanQuickBtn.addEventListener('click', () => initiateScan('quick', elements.scanQuickBtn));
        if(elements.scanFullBtn) elements.scanFullBtn.addEventListener('click', () => initiateScan('full', elements.scanFullBtn));

        // Tabs
        elements.findingsTabBtn.addEventListener('click', () => switchTab('findings'));
        elements.rawTabBtn.addEventListener('click', () => switchTab('raw'));

        // Advanced Toggle
        if(elements.advancedScanToggle && elements.advancedScanOptions) {
            elements.advancedScanToggle.addEventListener('click', (e) => {
                e.stopPropagation(); 
                elements.advancedScanOptions.classList.toggle('hidden');
                
                const closeMenu = (docEvent) => {
                    if (!elements.advancedScanOptions.contains(docEvent.target) && docEvent.target !== elements.advancedScanToggle) {
                        elements.advancedScanOptions.classList.add('hidden');
                        document.removeEventListener('click', closeMenu);
                    }
                };
                document.addEventListener('click', closeMenu);
            });
        }

        // Advanced Mode Selection (Mapping to Scan Modes)
        if(elements.advancedScanOptions) {
            elements.advancedScanOptions.addEventListener('click', (e) => {
                e.preventDefault();
                const link = e.target.closest('a[data-scan-mode]');
                if(link) {
                    const mode = link.dataset.scanMode;
                    elements.advancedScanOptions.classList.add('hidden');
                    
                    // Logic mapping
                    let backendMode = 'quick';
                    if (mode === 'risk3') backendMode = 'full';
                    
                    appendLog(`[*] Advanced Option Selected: ${link.textContent.trim()}`);
                    initiateScan(backendMode, elements.advancedScanToggle); 
                }
            });
        }

        // Clear Log
        if(elements.clearLogBtn) {
            elements.clearLogBtn.addEventListener('click', () => {
                elements.logOutput.innerHTML = '';
                apiPost('/clear_log');
            });
        }

        // Refresh Data
        if(elements.refreshResultsBtn) {
            elements.refreshResultsBtn.addEventListener('click', () => {
                setStatus('Refreshing...', 'busy');
                toggleSpinner(elements.refreshResultsBtn, true); 
                fetchReportData().then(() => {
                    setStatus('System Ready', 'success');
                    setTimeout(() => toggleSpinner(elements.refreshResultsBtn, false), 500);
                });
            });
        }

        // Copy Raw
        if(elements.copyResultsBtn) {
            elements.copyResultsBtn.addEventListener('click', () => {
                const text = elements.resultsContent.textContent;
                navigator.clipboard.writeText(text).then(() => {
                    const originalText = elements.copyResultsBtn.textContent;
                    elements.copyResultsBtn.textContent = 'COPIED!';
                    setTimeout(() => elements.copyResultsBtn.textContent = originalText, 2000);
                });
            });
        }

        // Download PDF
        if (elements.downloadReportBtn) {
            elements.downloadReportBtn.addEventListener('click', () => {
                if (reportDownloadUrl) {
                    window.location.href = reportDownloadUrl;
                    appendLog('[✓] PDF Download started.');
                }
            });
        }
        
        // AI Dropdown
        if(elements.analyzeReportDropdown) {
            elements.analyzeReportDropdown.addEventListener('click', (e) => {
                if (!elements.analyzeReportDropdown.disabled) {
                    e.stopPropagation();
                    elements.llmAnalysisOptions.classList.toggle('hidden');
                    
                      const closeAiMenu = (docEvent) => {
                        if (!elements.llmAnalysisOptions.contains(docEvent.target) && docEvent.target !== elements.analyzeReportDropdown) {
                            elements.llmAnalysisOptions.classList.add('hidden');
                            document.removeEventListener('click', closeAiMenu);
                        }
                    };
                    document.addEventListener('click', closeAiMenu);
                }
            });
        }
        
        // AI Options
        if(elements.llmAnalysisOptions) {
            elements.llmAnalysisOptions.addEventListener('click', (e) => {
                e.preventDefault();
                const option = e.target.closest('a[data-llm-mode]');
                if (option) {
                    const llmMode = option.dataset.llmMode;
                    elements.llmAnalysisOptions.classList.add('hidden');
                    analyzeReport(llmMode);
                }
            });
        }
        
        // Placeholder Buttons
        if(elements.dumpSchemaBtn) {
             elements.dumpSchemaBtn.addEventListener('click', () => {
                 appendLog('[!] Schema dumping requires Full Scan mode completion first.');
             });
        }
        if(elements.checkWafBtn) {
             elements.checkWafBtn.addEventListener('click', () => {
                 appendLog('[*] WAF check is included in the standard scan process.');
             });
        }
    }

    // --- Init ---
    function init() {
        setupEventListeners();
        initializeLogStream();
        switchTab('findings');
        
        // Initial Check
        fetchReportData();
        
        setTimeout(() => appendLog('SQL Scanner Engine Ready. Waiting for target...'), 100);
    }

    init();
});