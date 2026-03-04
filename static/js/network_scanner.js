document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Element Selectors ---
    const elements = {
        // Inputs & Controls
        targetIpInput: document.getElementById('targetIp'),
        scanTiming: document.getElementById('scanTiming'), 
        detectIpBtn: document.getElementById('detectIpBtn'),
        scanTcpBtn: document.getElementById('scanTcpBtn'), // Button now serves as generic 'Start Scan'
        scanVulnBtn: document.getElementById('scanVulnBtn'),
        
        // Advanced Config (Modes Dropdown)
        advancedScanToggle: document.getElementById('advancedScanToggle'),
        advancedScanOptions: document.getElementById('advancedScanOptions'),
        whitelistPortsInput: document.getElementById('whitelistPorts'),
        updateWhitelistBtn: document.getElementById('updateWhitelistBtn'),
        clearWhitelistBtn: document.getElementById('clearWhitelistBtn'), 
        
        // Admin Actions (Right Panel)
        verifyPortsBtn: document.getElementById('verifyPortsBtn'), 
        blockPortsBtn: document.getElementById('blockPortsBtn'), 

        // Results Header
        scanStatus: document.getElementById('scanStatus'),
        localIpDisplay: document.getElementById('localIpDisplay'),
        portCountDisplay: document.getElementById('portCountDisplay'),
        vulnCountDisplay: document.getElementById('vulnCountDisplay'),

        // Target Intelligence
        osGuessDisplay: document.getElementById('osGuessDisplay'),
        threatLevelDisplay: document.getElementById('threatLevelDisplay'),
        latencyDisplay: document.getElementById('latencyDisplay'),
        discoveryInsights: document.getElementById('discoveryInsights'),
        
        // Toolbar
        refreshResultsBtn: document.getElementById('refreshResultsBtn'),
        analyzeReportDropdown: document.getElementById('analyzeReportDropdown'),
        llmAnalysisOptions: document.getElementById('llmAnalysisOptions'),
        downloadReportBtn: document.getElementById('downloadReportBtn'),
        
        // AI Animation Elements
        aiProcessingOverlay: document.getElementById('aiProcessingOverlay'),
        aiProcessingText: document.getElementById('aiProcessingText'),

        // Tabs
        portsTabBtn: document.getElementById('portsTabBtn'),
        rawTabBtn: document.getElementById('rawTabBtn'),
        portsContent: document.getElementById('portsContent'),
        rawContent: document.getElementById('rawContent'),
        
        // Content Areas
        openPortsTableBody: document.getElementById('openPortsTableBody'),
        rawScanTypeDisplay: document.getElementById('rawScanTypeDisplay'),
        copyResultsBtn: document.getElementById('copyResultsBtn'),
        resultsContent: document.getElementById('resultsContent'), 
        
        // Live Terminal
        clearLogBtn: document.getElementById('clearLogBtn'),
        logOutput: document.getElementById('logOutput'),

        // History
        nmapHistoryBtn: document.getElementById('nmapHistoryBtn'),
        historyModal: document.getElementById('historyModal'),
        closeHistoryModal: document.getElementById('closeHistoryModal'),
        historyTableBody: document.getElementById('historyTableBody'),
    };

    // --- State Variables ---
    const API_BASE_URL = '/network_scanner';
    const CHATBOT_REDIRECT_URL = '/chatbot'; 
    let lastScanType = 'tcp'; 
    let isActionInProgress = false;
    let reportDownloadUrl = null;
    let eventSource = null;

    // [NEW] Scan Mode State
    let currentScanMode = 'default';
    let currentProtocol = 'TCP';

    // --- 🔒 CSRF TOKEN RETRIEVAL ---
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

    // --- Helper Functions ---
    
    function toggleSpinner(button, isLoading) {
        if (!button) return;
        const spinner = button.querySelector('.spinner');
        const icon = button.querySelector('.material-symbols-outlined'); 
        
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
        
        if (icon && icon.textContent === 'expand_more') {
            icon.style.display = isLoading ? 'none' : 'inline-block';
        }
    }
    
    function appendLog(message) {
        if (!elements.logOutput) return;

        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });

        let cleanedMessage = message.replace(/^\[\d{2}:\d{2}:\d{2}\]\s*/, '').trim();
        cleanedMessage = cleanedMessage.replace(/\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s*/g, "");
        cleanedMessage = cleanedMessage.replace(/^\[?\d{1,2}:\d{2}:\d{2}\]?\s*/, '');
        cleanedMessage = cleanedMessage.replace(/(\[[A-Z]+\])\s*\1/g, '$1');
        cleanedMessage = cleanedMessage.trim();

        if (!cleanedMessage || cleanedMessage === '|' || cleanedMessage.includes('deprecated method')) return;
        if (cleanedMessage.includes('[!]') || cleanedMessage.includes('[x]')) {
            contentStyle = 'color:#ef4444';
        } else if (cleanedMessage.includes('[✓]') || cleanedMessage.includes('[+]')) {
            contentStyle = 'color:#10b981';
        } else if (cleanedMessage.includes('[*]')) {
            contentStyle = 'color:#3b82f6';
        }

        const line = document.createElement('div');
        line.className = 'log-line';
        
        line.innerHTML = `
            <div class="log-time">${timeStr}</div>
            <div class="log-content" style="${contentStyle}">${cleanedMessage}</div>
        `;
        
        elements.logOutput.appendChild(line);
        elements.logOutput.scrollTop = elements.logOutput.scrollHeight;
    }

    function setStatus(text, type = 'ready') {
        if (!elements.scanStatus) return;
        
        elements.scanStatus.textContent = text.toUpperCase();
        
        const isLight = document.body.classList.contains("light-mode");
        elements.scanStatus.style.color = isLight ? '#64748b' : '#a1a1aa';

        if (type === 'busy') elements.scanStatus.style.color = '#eab308';
        else if (type === 'success') elements.scanStatus.style.color = '#10b981';
        else if (type === 'error') elements.scanStatus.style.color = '#ef4444';
    }

    // --- API & Data Functions ---

    async function apiPost(endpoint, body = {}, button = null) {
        // Allow /scan endpoint to run even if isActionInProgress is true, as it's the initiating action
        // For other endpoints, block if an action is already in progress.
        const isScanEndpoint = (endpoint === '/scan' || endpoint === '/start_vuln_scan');
        if (isActionInProgress && !isScanEndpoint) return null; 

        // For /scan endpoint, isActionInProgress and spinner toggling should be handled by initiateScan()
        if (!isScanEndpoint) {
            isActionInProgress = true;
            if (button) toggleSpinner(button, true);
        }

        if (!csrfToken) {
            appendLog('[x] Error: CSRF Token missing. Refresh page.');
            // Only reset if this wasn't a scan initiation
            if (!isScanEndpoint) {
                isActionInProgress = false;
                if (button) toggleSpinner(button, false);
            }
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
                throw new Error(data.message || `Request failed with status ${response.status}`);
            }
            if(data.message) appendLog(`[✓] ${data.message}`);
            return data;
        } catch (error) {
            appendLog(`[x] Error: ${error.message}`);
            setStatus('Error', 'error');
            return null;
        } finally {
            // Only reset if this wasn't a scan initiation
            if (!isScanEndpoint) {
                if (button) toggleSpinner(button, false);
                isActionInProgress = false;
            }
        }
    }
    
    async function fetchAndDisplayLocalIp() {
        try {
            const response = await fetch(`${API_BASE_URL}/local_ip`);
            const data = await response.json();
            elements.localIpDisplay.textContent = data.local_ip || '---';
            
            if (elements.targetIpInput.value === '') {
                const parts = data.local_ip.split('.');
                if(parts.length === 4) {
                    parts.pop();
                    elements.targetIpInput.value = parts.join('.') + '.1';
                } else {
                    elements.targetIpInput.value = data.local_ip;
                }
            }
        } catch (error) {
            appendLog('[x] Error detecting local IP.');
        }
    }

    async function fetchAndDisplayWhitelist() {
        try {
            const response = await fetch(`${API_BASE_URL}/whitelisted_ports`);
            const data = await response.json();
            const ports = data.whitelisted_ports;
            if(elements.whitelistPortsInput) {
                if(elements.whitelistPortsInput.value === '') elements.whitelistPortsInput.value = ports.join(', ');
            }
        } catch (error) {
            console.error(error);
        }
    }
    
    // --- [UPDATED] Dropdown Selection Setup ---
    function setupDropdownSelectors() {
        const scanCategorySelect = document.getElementById('scanCategory');
        const scanTimingSelect = document.getElementById('scanTiming');

        if (scanCategorySelect) {
            scanCategorySelect.addEventListener('change', (e) => {
                const val = e.target.value;
                currentScanMode = val;
                currentProtocol = (val === 'udp') ? 'UDP' : 'TCP';
                
                const btnText = elements.scanTcpBtn.querySelector('.button-text');
                if(btnText) {
                    btnText.textContent = `START SCAN (${val.toUpperCase().replace('_', ' ')})`;
                }
            });
        }
    }

    function updateOpenPortsTable(ports) {
        if (!elements.openPortsTableBody) return;
        
        elements.portCountDisplay.textContent = ports ? ports.length : 0; 
        
        let highRiskCount = 0;
        if (ports) {
            ports.forEach(p => {
                if ((p.predicted_risk_score !== undefined ? p.predicted_risk_score : 0) >= 0.5) highRiskCount++;
            });
        }
        if (elements.vulnCountDisplay) elements.vulnCountDisplay.textContent = highRiskCount;

        // [FIX] Clear the grid first
        elements.openPortsTableBody.innerHTML = ''; 

        if (!ports || ports.length === 0) {
            // Check if we are currently scanning or just ready
            const statusText = elements.scanStatus.textContent.toUpperCase();
            const isScanning = statusText.includes('SCANNING');
            const isReady = statusText.includes('READY') || statusText === 'SYSTEM READY';
            
            if (isReady && (!ports || ports.length === 0)) {
                // Keep the initial "READY" state instead of showing "NO INFRASTRUCTURE DETECTED"
                elements.openPortsTableBody.innerHTML = `
                    <div class="w-full flex flex-col items-center justify-center animate-card" style="grid-column: 1 / -1; padding: 6rem 2rem;">
                      <div class="ai-pulse-container" style="opacity: 0.3;">
                        <div class="ai-pulse-ring"></div>
                        <span class="material-symbols-outlined" style="font-size: 3rem; color: var(--neo-text-muted);">radar</span>
                      </div>
                      <div style="font-family: var(--font-mono); font-size: 0.9rem; color: var(--neo-text-muted); text-transform: uppercase; letter-spacing: 0.2em; text-align: center;">
                        READY FOR INFRASTRUCTURE SCAN
                      </div>
                    </div>`;
                return;
            }

            elements.openPortsTableBody.innerHTML = `
                <div class="w-full flex flex-col items-center justify-center animate-card" style="grid-column: 1 / -1; padding: 6rem 2rem;">
                  <div class="ai-pulse-container" style="opacity: 0.5;">
                    <div class="ai-pulse-ring"></div>
                    <span class="material-symbols-outlined" style="font-size: 3rem; color: ${isScanning ? 'var(--neo-blue)' : 'var(--neo-text-muted)'};">
                        ${isScanning ? 'radar' : 'info'}
                    </span>
                  </div>
                  <div style="font-family: var(--font-mono); font-size: 0.9rem; color: var(--neo-text-muted); text-transform: uppercase; letter-spacing: 0.2em; text-align: center;">
                    ${isScanning ? 'SCANNING INFRASTRUCTURE...' : 'NO INFRASTRUCTURE DETECTED'}
                  </div>
                  <div style="font-size: 0.75rem; color: var(--neo-text-muted); opacity: 0.6; margin-top: 1rem; max-width: 300px; text-align: center;">
                    ${isScanning ? 'Actively probing target for open services and vulnerabilities.' : 'The scan did not identify any publicly exposed services or infrastructure on the target host.'}
                  </div>
                </div>`;
            return;
        }
        
        ports.forEach((p, index) => {
            const rawScore = p.predicted_risk_score !== undefined ? p.predicted_risk_score : 0;
            const displayScore = (rawScore * 10).toFixed(1);
            
            let riskClass = 'risk-safe';
            let riskLabel = 'LOW';
            if (rawScore >= 0.8) { riskClass = 'risk-critical'; riskLabel = 'CRITICAL'; }
            else if (rawScore >= 0.6) { riskClass = 'risk-high'; riskLabel = 'HIGH'; }
            else if (rawScore >= 0.4) { riskClass = 'risk-medium'; riskLabel = 'MEDIUM'; }
            else if (rawScore >= 0.1) { riskClass = 'risk-low'; riskLabel = 'LOW'; }

            const assessment = p.vulnerability || (p.vulnerability_notes ? 'Notes Available' : 'Safe / Low Priority');

            const card = `
                <div class="discovery-card ${riskClass} animate-card" style="animation-delay: ${index * 0.05}s">
                    <div class="card-header">
                        <div class="service-main">
                            <span class="service-title">${p.service}</span>
                            <span class="service-ver">${p.version || 'VERSION UNDETECTED'}</span>
                        </div>
                        <div class="port-badge">
                            <span class="port-num">${p.port}</span>
                            <span class="protocol-label">${p.protocol}</span>
                        </div>
                    </div>

                    <div class="risk-section">
                        <div class="risk-header">
                            <span style="color: var(--card-accent)">${riskLabel} RISK LEVEL</span>
                            <span>${displayScore}/10</span>
                        </div>
                        <div class="risk-score-bar">
                            <div class="risk-score-fill" style="width: ${rawScore * 100}%"></div>
                        </div>
                    </div>

                    <div class="analysis-footer">
                        <div style="font-weight: 800; font-size: 0.6rem; color: var(--card-accent); margin-bottom: 0.25rem;">[AI ANALYSIS]</div>
                        ${assessment}
                    </div>
                </div>`;
            elements.openPortsTableBody.insertAdjacentHTML('beforeend', card);
        });
    }

    function updateIntelligenceUI(metadata) {
        if (elements.osGuessDisplay) {
            elements.osGuessDisplay.textContent = metadata.os_guess || 'UNKNOWN';
            elements.osGuessDisplay.style.color = metadata.os_guess !== 'Unknown' ? 'var(--neo-blue)' : 'var(--neo-text-muted)';
        }
        if (elements.threatLevelDisplay) {
            elements.threatLevelDisplay.textContent = metadata.host_status === 'Scanning' ? 'ANALYZING' : (metadata.host_status === 'Online' ? 'AWAITING' : 'UNKNOWN');
            elements.threatLevelDisplay.style.color = metadata.host_status === 'Online' ? 'var(--neo-green)' : 'var(--neo-text-muted)';
        }

        if (elements.latencyDisplay) {
            elements.latencyDisplay.textContent = metadata.latency || '0ms';
        }

        if (elements.discoveryInsights) {
            elements.discoveryInsights.textContent = metadata.insights || 'No infrastructure data.';
        }
    }

    async function fetchAndDisplayOpenPorts() {
        try {
            const response = await fetch(`${API_BASE_URL}/open_ports`);
            const data = await response.json();
            updateOpenPortsTable(data.open_ports);
            if (data.metadata) updateIntelligenceUI(data.metadata);
        } catch (error) {
            console.error('Error fetching ports', error);
        }
    }

    async function loadScanResults(scanType) {
        elements.resultsContent.textContent = '// Loading data...';
        if(elements.rawScanTypeDisplay) elements.rawScanTypeDisplay.textContent = `RAW DATA (${scanType.toUpperCase()})`;
        try {
            const response = await fetch(`${API_BASE_URL}/get_scan_results?type=${scanType}`);
            const data = await response.json();
            elements.resultsContent.textContent = response.ok ? data.content : '// No raw data available for this scan type.';
        } catch (error) {
            elements.resultsContent.textContent = '// Failed to load results.';
        }
    }

    async function checkReportStatus() {
        const target = elements.targetIpInput.value.trim();
        if (elements.downloadReportBtn) {
            elements.downloadReportBtn.disabled = true;
            elements.downloadReportBtn.style.opacity = '0.5';
        }
        if (elements.analyzeReportDropdown) {
            elements.analyzeReportDropdown.disabled = true;
            elements.analyzeReportDropdown.style.opacity = '0.5';
        }

        try {
            const url = target 
                ? `/network_scanner/report_files?target=${encodeURIComponent(target)}`
                : '/network_scanner/report_files';
            
            const response = await fetch(url);
            if (!response.ok) return;
            const data = await response.json();
    
            if (data.status === "success" && data.pdf_report) {
                if (elements.downloadReportBtn) {
                    elements.downloadReportBtn.disabled = false;
                    elements.downloadReportBtn.style.opacity = '1';
                    elements.downloadReportBtn.onclick = () => {
                        window.location.href = data.pdf_report;
                    };
                }
                
                if (elements.analyzeReportDropdown) {
                    elements.analyzeReportDropdown.disabled = false;
                    elements.analyzeReportDropdown.style.opacity = '1';
                }
            }
        } catch (error) {
            console.error("Error checking report status:", error);
        }
    }

    // [NEW] Fixed AI Analysis Dropdown Handler
    const aiDropdownLinks = document.querySelectorAll('#llmAnalysisOptions .dropdown-link');
    aiDropdownLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const llmMode = e.currentTarget.getAttribute('data-llm-mode');
            if (llmMode) {
                // Ensure the dropdown is closed after clicking
                if (elements.llmAnalysisOptions) elements.llmAnalysisOptions.classList.add('hidden');
                analyzeReport(llmMode);
            }
        });
    });

    async function analyzeReport(llmMode) {
        if (elements.analyzeReportDropdown.disabled) return;
        const target = elements.targetIpInput.value.trim();

        if (!csrfToken) {
            appendLog('[!] Error: CSRF Token missing. Refresh page.');
            return;
        }

        // 1. LOCK UI & SHOW OVERLAY
        if (elements.llmAnalysisOptions) elements.llmAnalysisOptions.classList.add('hidden');
        if (elements.aiProcessingOverlay) {
            elements.aiProcessingOverlay.classList.remove('hidden');
            if (elements.aiProcessingText) {
                elements.aiProcessingText.textContent = llmMode.includes('gemini') 
                    ? 'CONTACTING GEMINI...' 
                    : 'LOADING LOCAL MODEL...';
            }
        }

        setStatus(`AI Analysis (${llmMode})...`, 'busy');
        
        // Disable dropdown interactions
        elements.analyzeReportDropdown.disabled = true;
        
        try {
            let response = await fetch(`${API_BASE_URL}/trigger_ai_analysis`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken 
                },
                body: JSON.stringify({ llm_mode: llmMode, target: target })
            });
            let data = await response.json();
            
            if (data.status !== 'success') throw new Error(data.message);
            
            if (elements.aiProcessingText) elements.aiProcessingText.textContent = 'SYNTHESIZING REPORT...';

            response = await fetch(`${CHATBOT_REDIRECT_URL}/scanner_analysis`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken 
                },
                body: JSON.stringify({ 
                    llm_mode: llmMode, 
                    scanner_type: data.scanner_type,
                    target: data.target, // Pass sanitized target
                    force_new_session: true 
                })
            });

            data = await response.json();

            if (response.ok && data.status === 'success') {
                if (elements.aiProcessingText) elements.aiProcessingText.textContent = 'REDIRECTING...';
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
            
            // Hide overlay to allow retry
            if (elements.aiProcessingOverlay) elements.aiProcessingOverlay.classList.add('hidden');
            elements.analyzeReportDropdown.disabled = false;
        } finally {
            checkReportStatus(); 
        }
    }

    // --- HISTORY LOGIC ---

    async function fetchHistory() {
        if (!elements.historyTableBody) return;
        elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-text-muted);">LOADING HISTORY...</td></tr>';
        
        try {
            const res = await fetch(`${API_BASE_URL}/report_history`);
            const data = await res.json();
            
            if (data.status === 'success' && data.history) {
                if (data.history.length === 0) {
                    elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-text-muted);">NO PRIOR SCANS FOUND</td></tr>';
                    return;
                }
                
                elements.historyTableBody.innerHTML = '';
                data.history.forEach(item => {
                    const row = document.createElement('tr');
                    // Extract target from filename (scanner_target.pdf)
                    let target = item.filename.split('_').slice(1).join('_').replace('.pdf', '');
                    if (!target) target = 'Previous Scan';
                    
                    row.innerHTML = `
                        <td>${item.created_at}</td>
                        <td class="font-mono text-blue-400">${target}</td>
                        <td style="text-align: right;">
                            <a href="${API_BASE_URL}/download_pdf?filename=${item.filename}" class="btn-dash btn-secondary" style="display: inline-flex; height: 32px; padding: 0 10px;">
                                <span class="material-symbols-outlined" style="font-size: 1.1rem;">download</span>
                            </a>
                        </td>
                    `;
                    elements.historyTableBody.appendChild(row);
                });
            } else {
                elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-red);">FAILED TO LOAD HISTORY</td></tr>';
            }
        } catch (e) {
            console.error('History fetch failed:', e);
            elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-red);">ERROR LOADING HISTORY</td></tr>';
        }
    }

    if (elements.nmapHistoryBtn) {
        elements.nmapHistoryBtn.addEventListener('click', () => {
            elements.historyModal.classList.remove('hidden');
            fetchHistory();
        });
    }

    if (elements.closeHistoryModal) {
        elements.closeHistoryModal.addEventListener('click', () => {
            elements.historyModal.classList.add('hidden');
        });
    }

    if (elements.historyModal) {
        elements.historyModal.addEventListener('click', (e) => {
            if (e.target === elements.historyModal) {
                elements.historyModal.classList.add('hidden');
            }
        });
    }

    async function initiateScan(protocolType, scanType, button) {
        const targetIp = elements.targetIpInput.value.trim();
        const timingVal = elements.scanTiming ? elements.scanTiming.value : 4; // Capture Timing

        if (!targetIp) {
            appendLog('[!] Error: Target IP or URL is required.');
            return;
        }

        // Update state
        lastScanType = scanType;

        // Set action in progress and show spinner immediately
        isActionInProgress = true;
        if (button) toggleSpinner(button, true);

        setStatus(`Scanning (${scanType})...`, 'busy');
        switchTab('ports'); 

        // [NEW] Reset Intelligence UI
        if (elements.osGuessDisplay) elements.osGuessDisplay.textContent = '---';
        if (elements.latencyDisplay) elements.latencyDisplay.textContent = '---';
        if (elements.discoveryInsights) elements.discoveryInsights.textContent = 'Analyzing infrastructure...';
        if (elements.hostStatusBadge) elements.hostStatusBadge.textContent = '---';
        if (elements.portCountDisplay) elements.portCountDisplay.textContent = '0';
        if (elements.vulnCountDisplay) elements.vulnCountDisplay.textContent = '0';

        const whitelist = elements.whitelistPortsInput ? elements.whitelistPortsInput.value.split(',').map(s => s.trim()).filter(s => s) : [];

        try {
            const data = await apiPost('/scan', { // Note: this apiPost won't toggle spinner itself
                target_ip: targetIp,
                protocol_type: protocolType,
                scan_type: scanType,
                timing: parseInt(timingVal), // Pass timing to backend
                whitelist: whitelist
            });

            if (data && data.queue_id) {
                initializeLogStream(data.queue_id); // Pass queue_id to log stream
            } else {
                throw new Error("Scan initiation failed or no queue_id received.");
            }
        } catch (error) {
            appendLog(`[x] Scan initiation failed: ${error.message}`);
            setStatus('Error', 'error');
            isActionInProgress = false; // Reset on failure
            if (button) toggleSpinner(button, false); // Hide spinner on failure
        }
    }
    
    function initializeLogStream(queueId) {
        if (eventSource) {
            eventSource.close();
            if (queueId) appendLog('[*] Existing log stream closed.');
        }

        // Establish EventSource - queueId is optional for general logs
        const url = queueId ? `${API_BASE_URL}/log_stream?queue_id=${queueId}` : `${API_BASE_URL}/log_stream`;
        eventSource = new EventSource(url);

        eventSource.onmessage = (event) => {
            let rawData = event.data;
            if (rawData.startsWith(':')) return; // Keep-alive messages

            let displayMessage = rawData;
            try {
                const logData = JSON.parse(rawData);
                
                // If a specific queueId is being tracked, ignore messages from other queues
                if (queueId && logData.queue_id && logData.queue_id !== queueId) {
                    return;
                }
                
                displayMessage = logData.message || rawData;
            } catch (e) {
                // Message is not JSON, use as is
            }

            // [NEW] Real-time event handling from log stream
            if (displayMessage.includes("EVENT: metadata_updated")) {
                try {
                    const parts = displayMessage.split('| PAYLOAD: ');
                    if (parts.length > 1) {
                        const payload = JSON.parse(parts[1]);
                        updateIntelligenceUI(payload);
                    }
                } catch (e) { console.error('Error parsing metadata event', e); }
                return; // Don't log event lines to terminal
            }

            if (displayMessage.includes("EVENT: ports_updated")) {
                try {
                    const parts = displayMessage.split('| PAYLOAD: ');
                    if (parts.length > 1) {
                        const payload = JSON.parse(parts[1]);
                        if (payload.ports) updateOpenPortsTable(payload.ports);
                    }
                } catch (e) { console.error('Error parsing ports event', e); }
                return; // Don't log event lines to terminal
            }

            if (displayMessage.includes("SYSTEM_EVENT: READY_FOR_ANALYSIS")) {
                appendLog('[✓] Network Scan Complete!');
                setStatus('FINISHED', 'success');
                fetchAndDisplayOpenPorts();
                loadScanResults(lastScanType);
                
                // [FIX] Extract actual target IP from SYSTEM_EVENT: READY_FOR_ANALYSIS:1.2.3.4
                const targetFromMsg = displayMessage.split('READY_FOR_ANALYSIS:').pop();
                if (targetFromMsg && targetFromMsg.trim() && !elements.targetIpInput.value) {
                    elements.targetIpInput.value = targetFromMsg.trim();
                }
                
                checkReportStatus(); 
                
                isActionInProgress = false;
                toggleSpinner(elements.scanTcpBtn, false);
                toggleSpinner(elements.scanVulnBtn, false);
                eventSource.close();
                return;
            }

            if (displayMessage.includes("[!] Scan failed") || displayMessage.includes("Scan failed to produce")) {
                setStatus('Scan Failed', 'error');
                isActionInProgress = false;
                toggleSpinner(elements.scanTcpBtn, false);
                toggleSpinner(elements.scanVulnBtn, false);
                eventSource.close();
            }
            
            // [FIX] Filter out EVENT: messages even if they have timestamps
            if (displayMessage.includes("EVENT:") || displayMessage.startsWith("EVENT:")) return;
            appendLog(displayMessage);
        };

        eventSource.onerror = (error) => {
            console.error('EventSource failed:', error);
            // Don't show error log immediately if it's just a closure
            if (eventSource.readyState !== EventSource.CLOSED) {
                 // appendLog('[x] Log stream error or disconnected.'); // Silent reconnect better
            }
            eventSource.close();
            
            // Re-enable buttons only if not manually stopped by complete/failed event
            if (isActionInProgress) {
                isActionInProgress = false;
                toggleSpinner(elements.scanTcpBtn, false);
                toggleSpinner(elements.scanVulnBtn, false);
                setStatus('Error', 'error');
            }
        };
        
        // Removed generic queue ID log as per user request
    }
    
    function switchTab(tabName) {
        elements.portsTabBtn.classList.toggle('active', tabName === 'ports');
        elements.rawTabBtn.classList.toggle('active', tabName === 'raw');
        elements.portsContent.classList.toggle('hidden', tabName !== 'ports');
        elements.rawContent.classList.toggle('hidden', tabName !== 'raw');
        
        if (tabName === 'raw') loadScanResults(lastScanType);
    }

    // --- Event Listeners (Setup) ---
    function setupEventListeners() {
        if(elements.detectIpBtn) elements.detectIpBtn.addEventListener('click', fetchAndDisplayLocalIp);

        // [UPDATED] Main Scan Button Listener
        // Triggers scan based on selected value in the scanCategory dropdown
        if(elements.scanTcpBtn) {
            elements.scanTcpBtn.addEventListener('click', () => {
                const scanCategorySelect = document.getElementById('scanCategory');
                if (scanCategorySelect) {
                    currentScanMode = scanCategorySelect.value;
                    currentProtocol = (currentScanMode === 'udp') ? 'UDP' : 'TCP';
                }
                initiateScan(currentProtocol, currentScanMode, elements.scanTcpBtn);
            });
        }
        
        // Vuln scan has its own logic/button still
        if(elements.scanVulnBtn) elements.scanVulnBtn.addEventListener('click', () => initiateScan('TCP', 'vuln', elements.scanVulnBtn));

        elements.portsTabBtn.addEventListener('click', () => switchTab('ports'));
        elements.rawTabBtn.addEventListener('click', () => switchTab('raw'));

        if(elements.verifyPortsBtn) {
            elements.verifyPortsBtn.addEventListener('click', async () => {
                const targetIp = elements.targetIpInput.value.trim();
                if(!targetIp) {
                    appendLog('[!] Enter IP/URL before verifying.');
                    return;
                }
                appendLog('[*] Verifying closed ports...');
                await apiPost('/verify_ports', { target_ip: targetIp }, elements.verifyPortsBtn);
            });
        }

        if(elements.blockPortsBtn) {
            elements.blockPortsBtn.addEventListener('click', async () => {
                if(confirm("Are you sure you want to attempt blocking ALL currently detected open ports? This requires admin privileges.")) {
                    appendLog('[*] Initiating Firewall Block...');
                    await apiPost('/block_ports', {}, elements.blockPortsBtn);
                }
            });
        }

        if(elements.updateWhitelistBtn) {
            elements.updateWhitelistBtn.addEventListener('click', async () => {
                const ports = elements.whitelistPortsInput.value.trim();
                if (ports && await apiPost('/add_whitelist', { ports }, elements.updateWhitelistBtn)) {
                    appendLog('[*] Whitelist updated locally.');
                }
            });
        }
        
        if(elements.clearWhitelistBtn) {
            elements.clearWhitelistBtn.addEventListener('click', async () => {
                 if(await apiPost('/clear_whitelist', {}, elements.clearWhitelistBtn)) {
                      elements.whitelistPortsInput.value = '';
                      appendLog('[*] Whitelist cleared.');
                 }
            });
        }

        if(elements.clearLogBtn) {
            elements.clearLogBtn.addEventListener('click', () => {
                elements.logOutput.innerHTML = '';
                apiPost('/clear_log');
            });
        }

        if(elements.refreshResultsBtn) {
            elements.refreshResultsBtn.addEventListener('click', () => {
                setStatus('Refreshing...', 'busy');
                toggleSpinner(elements.refreshResultsBtn, true); 

                elements.openPortsTableBody.innerHTML = `
                    <div style="grid-column: 1 / -1; text-align:center; padding: 3rem; color: #a1a1aa;">
                        <span class="spinner inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></span>
                        Refreshing data...
                    </div>`;
                
                elements.resultsContent.textContent = '// Refreshing log data...';

                Promise.all([
                    fetchAndDisplayOpenPorts(),
                    loadScanResults(lastScanType),
                    checkReportStatus()
                ]).then(() => {
                    setStatus('System Ready', 'success');
                    setTimeout(() => toggleSpinner(elements.refreshResultsBtn, false), 500);
                }).catch((err) => {
                    console.error(err);
                    setStatus('Refresh Failed', 'error');
                    toggleSpinner(elements.refreshResultsBtn, false);
                });
            });
        }

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

        if (elements.downloadReportBtn) {
            elements.downloadReportBtn.addEventListener('click', () => {
                if (reportDownloadUrl) {
                    window.location.href = reportDownloadUrl;
                    appendLog('[✓] Download started.');
                }
            });
        }
        
        if(elements.llmAnalysisOptions) {
            elements.llmAnalysisOptions.addEventListener('click', (e) => {
                e.preventDefault();
                // Support both <a> (desktop) and <button> (mobile)
                const option = e.target.closest('[data-llm-mode]');
                if (option) {
                    const llmMode = option.dataset.llmMode;
                    elements.llmAnalysisOptions.classList.add('hidden');
                    analyzeReport(llmMode);
                }
            });
        }
    }

    async function init() {
        setupEventListeners();
        setupDropdownSelectors();
        initializeLogStream();
        switchTab('ports');
        
        try {
            // [NEW] Use consolidated init_data for reliable results on page load
            const response = await fetch(`${API_BASE_URL}/init_data`);
            const data = await response.json();
            
            if (data.local_ip && elements.targetIpInput && !elements.targetIpInput.value) {
                elements.targetIpInput.value = data.local_ip;
            }
            
            if (data.whitelisted_ports) {
                // Whitelist is handled by fetchAndDisplayWhitelist usually, 
                // but we can sync here if needed.
            }
            
            if (data.summary) {
                updateOpenPortsTable(data.summary.open_ports);
                updateIntelligenceUI(data.summary.metadata);
            }
            
            checkReportStatus();
        } catch (error) {
            console.error('Init failure:', error);
            // Fallback to individual fetches if init_data fails
            fetchAndDisplayLocalIp();
            fetchAndDisplayOpenPorts();
        }
        
        setTimeout(() => appendLog('System Ready. Waiting for target...'), 100);
    }

    init();
});