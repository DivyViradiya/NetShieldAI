document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Element Selectors ---
    const elements = {
        // Inputs & Controls
        targetIpInput: document.getElementById('targetIp'),
        scanTiming: document.getElementById('scanTiming'), 
        scanTcpBtn: document.getElementById('scanTcpBtn'),
        scanVulnBtn: document.getElementById('scanVulnBtn'),
        mobileScanType: document.getElementById('mobileScanType'),
        whitelistPortsInput: document.getElementById('whitelistPorts'),
        updateWhitelistBtn: document.getElementById('updateWhitelistBtn'),
        clearWhitelistBtn: document.getElementById('clearWhitelistBtn'),
        
        // Status & Metrics
        scanStatus: document.getElementById('scanStatus'),
        localIpDisplay: document.getElementById('localIpDisplay'),
        portCountDisplay: document.getElementById('portCountDisplay'),
        vulnCountDisplay: document.getElementById('vulnCountDisplay'),

        // Target Intelligence
        osGuessDisplay: document.getElementById('osGuessDisplay'),
        hostStatusBadge: document.getElementById('hostStatusBadge'),
        threatLevelDisplay: document.getElementById('threatLevelDisplay'),
        latencyDisplay: document.getElementById('latencyDisplay'),
        discoveryInsights: document.getElementById('discoveryInsights'),
        
        // Analysis & Reports
        analyzeReportDropdown: document.getElementById('analyzeReportDropdown'),
        llmAnalysisOptions: document.getElementById('llmAnalysisOptions'),
        downloadReportBtn: document.getElementById('downloadReportBtn'),
        
        // AI Executive Summary
        execSummaryBtn: document.getElementById('execSummaryBtn'),
        execSummaryLabel: document.getElementById('execSummaryLabel'),
        execSummaryIcon: document.getElementById('execSummaryIcon'),
        execSummarySpinner: document.getElementById('execSummarySpinner'),
        
        // AI Animation Elements
        aiProcessingOverlay: document.getElementById('aiProcessingOverlay'),
        aiProcessingText: document.getElementById('aiProcessingText'),

        // History Modal
        nmapHistoryBtn: document.getElementById('nmapHistoryBtn'),
        historyModal: document.getElementById('historyModal'),
        closeHistoryModal: document.getElementById('closeHistoryModal'),
        historyTableBody: document.getElementById('historyTableBody'),

        // Content Areas
        openPortsTableBody: document.getElementById('openPortsTableBody'),
        resultsContent: document.getElementById('resultsContent'), 
        tabPortCount: document.getElementById('tabPortCount'),
        
        // Live Terminal
        logOutput: document.getElementById('logOutput'),
        clearLogBtn: document.getElementById('clearLogBtn'),
    };

    // --- State Variables ---
    const API_BASE_URL = '/network_scanner';
    const CHATBOT_REDIRECT_URL = '/chatbot'; 
    let lastScanType = 'default'; 
    let isActionInProgress = false;
    let reportDownloadUrl = null;
    let eventSource = null;

    let currentScanMode = 'default';
    let currentProtocol = 'TCP';
    let currentResolvedTarget = null;
    let lastScanLogId = null;

    // --- 🔒 CSRF TOKEN RETRIEVAL ---
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

    // --- Mobile Helper Functions (Internal) ---

    window.toggleMobileDropdown = function(id) {
        const el = document.getElementById(id);
        if (!el) return;
        const menu = el.querySelector('.dropdown-menu');
        if (!menu) return;
        
        const isShow = menu.classList.contains('show') && !menu.classList.contains('hidden') && menu.style.display !== 'none';
        
        document.querySelectorAll('.dropdown-menu').forEach(m => {
            m.classList.remove('show');
            m.classList.add('hidden');
            m.style.display = 'none';
        });
        
        if (!isShow) {
            menu.classList.remove('hidden');
            menu.classList.add('show');
            menu.style.display = 'flex';
        }
        
        const closeDropdown = (e) => {
            if (!el.contains(e.target)) {
                menu.classList.remove('show');
                menu.classList.add('hidden');
                menu.style.display = 'none';
                document.removeEventListener('click', closeDropdown);
            }
        };
        setTimeout(() => document.addEventListener('click', closeDropdown), 10);
    };

    window.selectDropdownItem = function(dropdownId, value, text) {
        const dropdown = document.getElementById(dropdownId);
        const triggerText = dropdown.querySelector('.trigger-text');
        const items = dropdown.querySelectorAll('.dropdown-item');
        const menu = dropdown.querySelector('.dropdown-menu');
        
        triggerText.textContent = text;
        
        items.forEach(item => {
            item.classList.toggle('active', item.dataset.value === value);
        });
        
        if (dropdownId === 'profileDropdown') {
            if (elements.mobileScanType) elements.mobileScanType.value = value;
            // Direct state update instead of trigger click
            currentScanMode = value;
            currentProtocol = (value === 'udp') ? 'UDP' : 'TCP';
            appendLog(`[*] Mode selected: ${value.toUpperCase()}. Click INITIATE SCAN to begin.`);
        } else if (dropdownId === 'timingDropdown') {
            if (elements.scanTiming) elements.scanTiming.value = value;
        }
        
        menu.classList.remove('show');
        menu.classList.add('hidden');
    };

    window.toggleDashPanel = function(id) {
        const el = document.getElementById(id);
        if (!el) return;
        el.classList.toggle('open');
        // Refresh raw data if opening raw panel
        if (id === 'acc-raw-panel' && el.classList.contains('open')) {
            loadScanResults(lastScanType);
        }
    };

    window.toggleTerminal = function() {
        const sheet = document.getElementById('terminalSheet');
        if (sheet) sheet.classList.toggle('open');
    };

    window.toggleCommandCenter = function() {
        const content = document.getElementById('commandCenterContent');
        const icon = document.getElementById('commandCenterToggleIcon');
        if (content && icon) {
            content.classList.toggle('hidden');
            if (content.classList.contains('hidden')) {
                icon.textContent = 'expand_more';
            } else {
                icon.textContent = 'expand_less';
            }
        }
    };

    window.switchMobileTab = function(tabName) {
        document.querySelectorAll('.mobile-tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        const activeBtn = document.getElementById(`tabBtn-${tabName}`);
        if (activeBtn) activeBtn.classList.add('active');

        document.querySelectorAll('.mobile-tab-panel').forEach(panel => {
            panel.classList.add('hidden');
        });
        const activePanel = document.getElementById(`tabPanel-${tabName}`);
        if (activePanel) activePanel.classList.remove('hidden');

        if (tabName === 'raw') {
            loadScanResults(lastScanType);
        }
    };

    window.copyRawLogs = function() {
        if (elements.resultsContent) {
            navigator.clipboard.writeText(elements.resultsContent.innerText).then(() => {
                const btn = document.getElementById('copyResultsBtn');
                if (!btn) return;
                const originalIcon = btn.innerHTML;
                btn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 1.1rem;">check</span>';
                setTimeout(() => { btn.innerHTML = originalIcon; }, 2000);
            });
        }
    };

    // --- UI Update Helpers ---

    function toggleSpinner(button, isLoading) {
        if (!button) return;
        const spinner = button.querySelector('.spinner');
        const icon = button.querySelector('.material-symbols-outlined'); 
        
        button.disabled = isLoading;

        if (isLoading) {
            button.classList.add('opacity-70', 'cursor-not-allowed');
            if (icon) icon.classList.add('hidden'); 
            if (spinner) spinner.classList.remove('hidden');
        } else {
            button.classList.remove('opacity-70', 'cursor-not-allowed');
            if (spinner) spinner.classList.add('hidden');
            if (icon) icon.classList.remove('hidden');
        }
    }

    function appendLog(message) {
        if (!elements.logOutput) return;

        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });

        let cleanedMessage = message.replace(/^\[\d{2}:\d{2}:\d{2}\]\s*/, '').trim();

        let contentStyle = '';
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
        elements.scanStatus.style.color = '#a1a1aa';

        if (type === 'busy') elements.scanStatus.style.color = '#eab308';
        else if (type === 'success') elements.scanStatus.style.color = '#10b981';
        else if (type === 'error') elements.scanStatus.style.color = '#ef4444';
    }

    // --- API & Data Functions ---

    async function apiPost(endpoint, body = {}, button = null) {
        const isScanEndpoint = (endpoint === '/scan' || endpoint === '/start_vuln_scan');
        if (isActionInProgress && !isScanEndpoint) return null; 

        if (!isScanEndpoint) {
            isActionInProgress = true;
            if (button) toggleSpinner(button, true);
        }

        if (!csrfToken) {
            appendLog('[x] Error: CSRF Token missing. Refresh page.');
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

    function updateOpenPortsTable(ports) {
        if (!elements.openPortsTableBody) return;
        
        const count = ports ? ports.length : 0;
        elements.portCountDisplay.textContent = count;
        if (elements.tabPortCount) elements.tabPortCount.textContent = count;
        
        let highRiskCount = 0;
        if (ports) {
            ports.forEach(p => {
                if ((p.predicted_risk_score !== undefined ? p.predicted_risk_score : 0) >= 0.5) highRiskCount++;
            });
        }
        if (elements.vulnCountDisplay) elements.vulnCountDisplay.textContent = highRiskCount;

        // [FIX] Clear the list first
        elements.openPortsTableBody.innerHTML = ''; 

        if (!ports || ports.length === 0) {
            const statusText = elements.scanStatus.textContent.toUpperCase();
            const isScanning = statusText.includes('SCANNING');
            const isReady = statusText.includes('READY') || statusText === 'SYSTEM READY';

            if (isReady && (!ports || ports.length === 0)) {
                elements.openPortsTableBody.innerHTML = `
                    <div class="animate-card" style="text-align: center; padding: 4rem 1rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.8rem; width: 100%;">
                        <span class="material-symbols-outlined" style="font-size: 2.5rem; opacity: 0.3; margin-bottom: 1rem; display: block;">
                            radar
                        </span>
                        <div style="letter-spacing: 0.1em; font-weight: 700;">
                            READY FOR INFRASTRUCTURE SCAN
                        </div>
                    </div>`;
                return;
            }
            
            elements.openPortsTableBody.innerHTML = `
                <div class="animate-card" style="text-align: center; padding: 4rem 1rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.8rem; width: 100%;">
                    <span class="material-symbols-outlined" style="font-size: 2.5rem; opacity: 0.3; margin-bottom: 1rem; display: block;">
                        ${isScanning ? 'radar' : 'cloud_off'}
                    </span>
                    <div style="letter-spacing: 0.1em; font-weight: 700;">
                        ${isScanning ? 'ANALYZING INFRASTRUCTURE...' : 'NO INFRASTRUCTURE DETECTED'}
                    </div>
                </div>`;
            return;
        }
        
        ports.forEach((p, index) => {
            const rawScore = p.predicted_risk_score !== undefined ? p.predicted_risk_score : 0;
            const displayScore = (rawScore * 10).toFixed(1);
            
            let riskClass = 'risk-safe';
            if (rawScore >= 0.8) { riskClass = 'risk-critical'; }
            else if (rawScore >= 0.6) { riskClass = 'risk-high'; }
            else if (rawScore >= 0.4) { riskClass = 'risk-medium'; }
            else if (rawScore >= 0.1) { riskClass = 'risk-low'; }

            const assessment = p.vulnerability || (p.vulnerability_notes ? 'Notes Available' : 'Safe / Low Priority');

            const card = `
                <div class="discovery-card ${riskClass} animate-card" style="animation-delay: ${index * 0.05}s">
                    <div class="card-header">
                        <div class="port-badge">
                            <span class="port-num">${p.port}</span>
                            <span class="protocol-label">${p.protocol}</span>
                        </div>
                        <div class="service-main" style="text-align: right;">
                            <span class="service-title">${p.service}</span>
                            <span class="service-ver">${p.version || 'UNKNOWN VERSION'}</span>
                        </div>
                    </div>

                    <div class="risk-section">
                        <div class="risk-header">
                            <span style="color: var(--neo-text-muted);">RISK SCORE</span>
                            <span class="risk-val" style="font-family: var(--font-mono); color: var(--card-accent); font-weight: 800;">${displayScore} / 10.0</span>
                        </div>
                        <div class="risk-score-bar">
                            <div class="risk-score-fill" style="width: ${rawScore * 100}%;"></div>
                        </div>
                    </div>

                    <div class="analysis-footer">
                        <span style="color: var(--card-accent); font-weight: 800; font-size: 0.6rem;">[ANALYSIS] </span>${assessment}
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
        if (elements.hostStatusBadge) {
            elements.hostStatusBadge.textContent = metadata.host_status || 'IDLE';
            elements.hostStatusBadge.style.color = metadata.host_status === 'Online' ? 'var(--neo-green)' : 'var(--neo-text-muted)';
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
        if (!elements.resultsContent) return;
        elements.resultsContent.textContent = '// Loading engine data...';
        try {
            const response = await fetch(`${API_BASE_URL}/get_scan_results?type=${scanType}`);
            const data = await response.json();
            elements.resultsContent.textContent = response.ok ? data.content : '// No raw data available for this scan type.';
        } catch (error) {
            elements.resultsContent.textContent = '// Failed to load results.';
        }
    }

    window.loadRawScanResults = function() {
        loadScanResults(lastScanType);
    };

    async function checkReportStatus() {
        const target = currentResolvedTarget || elements.targetIpInput.value.trim().toLowerCase();
        
        if (elements.downloadReportBtn) {
            elements.downloadReportBtn.disabled = true;
            elements.downloadReportBtn.style.opacity = '0.5';
        }
        if (elements.analyzeReportDropdown) {
            elements.analyzeReportDropdown.disabled = true;
            elements.analyzeReportDropdown.style.opacity = '0.5';
        }
        
        updateExecSummaryButton('disabled');

        try {
            const url = target 
                ? `${API_BASE_URL}/report_files?target=${encodeURIComponent(target)}`
                : `${API_BASE_URL}/report_files`;
            
            const response = await fetch(url);
            if (!response.ok) return;
            const data = await response.json();
    
            if (data.status === "success") {
                if (data.pdf_report && elements.downloadReportBtn) {
                    reportDownloadUrl = data.pdf_report;
                    elements.downloadReportBtn.disabled = false;
                    elements.downloadReportBtn.style.opacity = '1';
                    
                    if (elements.analyzeReportDropdown) {
                        elements.analyzeReportDropdown.disabled = false;
                        elements.analyzeReportDropdown.style.opacity = '1';
                    }
                }
                
                lastScanLogId = data.scan_log_id;
                
                if (data.exec_summary_report) {
                    updateExecSummaryButton('download', data.exec_summary_report);
                } else if (data.pdf_report) {
                    updateExecSummaryButton('ready');
                }
            }
        } catch (error) {
            console.error("Error checking report status:", error);
        }
    }

    // --- AI Executive Summary Logic ---
    function updateExecSummaryButton(state, downloadUrl = null) {
        if (!elements.execSummaryBtn) return;
        
        const btn = elements.execSummaryBtn;
        const label = elements.execSummaryLabel;
        const icon = elements.execSummaryIcon;
        const spinner = elements.execSummarySpinner;

        btn.classList.remove('btn-intel-success-glass', 'btn-intel-processing');
        btn.style.opacity = '1';
        if (icon) icon.textContent = 'auto_awesome';

        if (state === 'disabled') {
            btn.disabled = true;
            btn.style.opacity = '0.5';
            if (label) label.textContent = 'NETWORK BRIEF';
            if (icon) icon.classList.remove('hidden');
            if (spinner) spinner.classList.add('hidden');
            btn.onclick = null;
        } else if (state === 'ready') {
            btn.disabled = false;
            if (label) label.textContent = 'GENERATE BRIEF';
            if (icon) icon.classList.remove('hidden');
            if (spinner) spinner.classList.add('hidden');
            btn.onclick = () => generateExecutiveSummary();
        } else if (state === 'generating') {
            btn.disabled = true;
            btn.classList.add('btn-intel-processing');
            if (label) label.textContent = 'SYNTHESIZING...';
            if (icon) icon.classList.add('hidden');
            if (spinner) spinner.classList.remove('hidden');
        } else if (state === 'download') {
            btn.disabled = false;
            btn.classList.add('btn-intel-success-glass');
            if (label) label.textContent = 'DOWNLOAD BRIEF';
            if (icon) {
                icon.textContent = 'file_download';
                icon.classList.remove('hidden');
            }
            if (spinner) spinner.classList.add('hidden');
            btn.onclick = () => { window.location.href = downloadUrl; };
        }
    }

    async function generateExecutiveSummary() {
        if (!lastScanLogId) {
            appendLog('[!] Error: No recent scan log identifier found.');
            return;
        }
        
        const target = currentResolvedTarget || elements.targetIpInput.value.trim();
        updateExecSummaryButton('generating');
        appendLog('[*] Initiating AI Executive Brief generation flow...');
        
        try {
            const response = await fetch(`${API_BASE_URL}/trigger_executive_summary`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken 
                },
                body: JSON.stringify({ 
                    log_id: lastScanLogId,
                    target: target 
                })
            });
            
            const data = await response.json();
            if (data.status === 'success') {
                appendLog('[✓] AI Executive Brief synthesized successfully.');
                updateExecSummaryButton('download', data.download_url);
            } else {
                throw new Error(data.message);
            }
        } catch (error) {
            console.error('Executive brief failed:', error);
            appendLog(`[x] Brief Generation Failed: ${error.message}`);
            updateExecSummaryButton('ready');
        }
    }

    // --- Authorization & Blocked Modals Dialogs ---
    function showAuthModal(message, onConfirm) {
        const modal = document.getElementById('authModal');
        const msgEl = document.getElementById('authModalMessage');
        const confirmBtn = document.getElementById('confirmAuthBtn');
        const cancelBtn = document.getElementById('cancelAuthBtn');

        if (msgEl) msgEl.textContent = message;
        if (modal) modal.classList.remove('hidden');

        const newConfirmBtn = confirmBtn.cloneNode(true);
        confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);

        newConfirmBtn.addEventListener('click', () => {
            if (modal) modal.classList.add('hidden');
            if (onConfirm) onConfirm();
        });

        cancelBtn.onclick = () => {
            if (modal) modal.classList.add('hidden');
            toggleSpinner(elements.scanTcpBtn, false);
            setStatus('Ready');
            isActionInProgress = false;
        };
    }

    function showBlockedModal(message) {
        const modal = document.getElementById('blockedModal');
        const msgEl = document.getElementById('blockedModalMessage');
        const closeBtn = document.getElementById('closeBlockedModalBtn');

        if (msgEl) msgEl.textContent = message;
        if (modal) modal.classList.remove('hidden');

        closeBtn.onclick = () => {
            if (modal) modal.classList.add('hidden');
            toggleSpinner(elements.scanTcpBtn, false);
            setStatus('Ready');
            isActionInProgress = false;
        };
    }

    async function analyzeReport(llmMode) {
        const button = elements.analyzeReportDropdown;
        const overlay = elements.aiProcessingOverlay;
        const processingText = elements.aiProcessingText;
        const llmOptions = elements.llmAnalysisOptions;
        const target = elements.targetIpInput.value.trim().toLowerCase();

        if (!button || button.disabled) return;
        
        if (llmOptions) llmOptions.classList.add('hidden');
        if (overlay) overlay.classList.remove('hidden');
        
        if (processingText) {
            processingText.textContent = llmMode.includes('gemini') 
                ? 'CONTACTING GEMINI...' 
                : 'LOADING LOCAL MODEL...';
        }

        setStatus(`Analyzing via ${llmMode}...`, 'busy');
        
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
            
            if (processingText) processingText.textContent = 'SYNTHESIZING REPORT...';

            response = await fetch(`${CHATBOT_REDIRECT_URL}/scanner_analysis`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken 
                },
                body: JSON.stringify({ 
                    llm_mode: llmMode, 
                    scanner_type: data.scanner_type,
                    target: data.target,
                    force_new_session: true 
                })
            });

            data = await response.json();

            if (response.ok && data.status === 'success') {
                if (processingText) processingText.textContent = 'REDIRECTING...';
                
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
            appendLog(`[x] AI Analysis Error: ${error.message}`);
            setStatus('Analysis failed', 'error');
            if (overlay) overlay.classList.add('hidden');
        } 
    }

    async function fetchHistory() {
        if (!elements.historyTableBody) return;
        elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-text-muted);">LOADING HISTORY...</td></tr>';
        
        try {
            const res = await fetch(`${API_BASE_URL}/report_history`);
            const data = await res.json();
            
            if (data.status === 'success' && data.history) {
                if (data.history.length === 0) {
                    elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-text-muted);">NO PRIOR SCANS FOUND</td></tr>';
                    return;
                }
                
                elements.historyTableBody.innerHTML = '';
                data.history.forEach(item => {
                    const row = document.createElement('tr');
                    let target = item.filename.split('_').slice(1).join('_').replace('.pdf', '');                    target = target.replace(/_\d{8}_\d{6}$/, '');
                    if (!target || target === 'report') target = 'Previous Scan';
                    
                    row.innerHTML = `
                        <td style="padding: 1rem; font-size: 0.7rem; color: var(--neo-text-main); font-family: var(--font-mono);">${item.created_at}</td>
                        <td style="padding: 1rem; font-size: 0.7rem; color: var(--neo-blue); font-family: var(--font-mono);">${target}</td>
                        <td style="padding: 1rem; text-align: right;">
                            <a href="${API_BASE_URL}/download_pdf?filename=${item.filename}" class="btn-dash btn-secondary" style="display: inline-flex; height: 36px; padding: 0 12px; border-radius: 8px;">
                                <span class="material-symbols-outlined" style="font-size: 1.1rem;">download</span>
                            </a>
                        </td>
                    `;
                    elements.historyTableBody.appendChild(row);
                });
            } else {
                elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-red);">FAILED TO LOAD HISTORY</td></tr>';
            }
        } catch (e) {
            console.error('History fetch failed:', e);
            elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-red);">ERROR LOADING HISTORY</td></tr>';
        }
    }

    async function initiateScan(protocolType, scanType, button, userConfirmedAuth = false) {
        const targetIp = elements.targetIpInput.value.trim().toLowerCase();
        const timingVal = elements.scanTiming ? elements.scanTiming.value : 4;

        if (!targetIp) {
            appendLog('[!] Error: Target IP or URL is required.');
            return;
        }

        // Auto-collapse Command Center on scan start
        const content = document.getElementById('commandCenterContent');
        const icon = document.getElementById('commandCenterToggleIcon');
        if (content && !content.classList.contains('hidden')) {
            content.classList.add('hidden');
            if (icon) icon.textContent = 'expand_more';
        }

        lastScanType = scanType;
        lastScanLogId = null;
        isActionInProgress = true;
        if (button) toggleSpinner(button, true);

        updateExecSummaryButton('disabled');
        setStatus(`Scanning (${scanType})...`, 'busy');

        if (!userConfirmedAuth) {
            if (elements.osGuessDisplay) elements.osGuessDisplay.textContent = '---';
            if (elements.latencyDisplay) elements.latencyDisplay.textContent = '---';
            if (elements.discoveryInsights) elements.discoveryInsights.textContent = 'Analyzing infrastructure...';
            if (elements.hostStatusBadge) elements.hostStatusBadge.textContent = '---';
            if (elements.threatLevelDisplay) {
                elements.threatLevelDisplay.textContent = 'ANALYZING';
                elements.threatLevelDisplay.style.color = 'var(--neo-text-muted)';
            }
            if (elements.portCountDisplay) elements.portCountDisplay.textContent = '0';
            if (elements.vulnCountDisplay) elements.vulnCountDisplay.textContent = '0';
        }

        const whitelist = elements.whitelistPortsInput ? elements.whitelistPortsInput.value.split(',').map(s => s.trim()).filter(s => s) : [];

        try {
            const response = await fetch(`${API_BASE_URL}/scan`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken 
                },
                body: JSON.stringify({ 
                    target_ip: targetIp,
                    protocol_type: protocolType,
                    scan_type: scanType,
                    timing: parseInt(timingVal),
                    whitelist: whitelist,
                    user_confirmed_auth: userConfirmedAuth
                })
            });

            const data = await response.json();

            if (response.ok) {
                if (data && data.queue_id) {
                    if (data.target_ip) {
                        currentResolvedTarget = data.target_ip;
                        appendLog(`[*] Resolution Complete: Target established at ${currentResolvedTarget}`);
                    }
                    initializeLogStream(data.queue_id);
                } else {
                    throw new Error("Scan initiation failed.");
                }
            } else {
                if (data.status === 'auth_required') {
                    showAuthModal(data.message, () => initiateScan(protocolType, scanType, button, true));
                    return;
                }
                if (data.status === 'blocked') {
                    showBlockedModal(data.message);
                    return;
                }
                throw new Error(data.message || 'Scan initiation failed.');
            }
        } catch (error) {
            appendLog(`[x] Scan initiation failed: ${error.message}`);
            setStatus('Error', 'error');
            isActionInProgress = false;
            if (button) toggleSpinner(button, false);
        }
    }
    
    function initializeLogStream(queueId) {
        if (eventSource) {
            eventSource.close();
        }

        const url = queueId ? `${API_BASE_URL}/log_stream?queue_id=${queueId}` : `${API_BASE_URL}/log_stream`;
        eventSource = new EventSource(url);

        eventSource.onmessage = (event) => {
            let rawData = event.data;
            if (rawData.startsWith(':')) return;

            let displayMessage = rawData;
            try {
                const logData = JSON.parse(rawData);
                if (queueId && logData.queue_id && logData.queue_id !== queueId) {
                    return;
                }
                displayMessage = logData.message || rawData;
            } catch (e) {}

            if (displayMessage.includes("EVENT: metadata_updated")) {
                try {
                    const parts = displayMessage.split('| PAYLOAD: ');
                    if (parts.length > 1) {
                        const payload = JSON.parse(parts[1]);
                        updateIntelligenceUI(payload);
                    }
                } catch (e) {}
                return;
            }

            if (displayMessage.includes("EVENT: ports_updated")) {
                try {
                    const parts = displayMessage.split('| PAYLOAD: ');
                    if (parts.length > 1) {
                        const payload = JSON.parse(parts[1]);
                        if (payload.ports) updateOpenPortsTable(payload.ports);
                    }
                } catch (e) {}
                return;
            }

            if (displayMessage.includes("SYSTEM_EVENT: READY_FOR_ANALYSIS")) {
                appendLog('[✓] Network Scan Complete!');
                setStatus('FINISHED', 'success');
                fetchAndDisplayOpenPorts();
                loadScanResults(lastScanType);
                
                checkReportStatus(); 
                
                isActionInProgress = false;
                toggleSpinner(elements.scanTcpBtn, false);
                eventSource.close();
                return;
            }

            if (displayMessage.includes("[!] Scan failed") || displayMessage.includes("Scan failed to produce")) {
                setStatus('Scan Failed', 'error');
                isActionInProgress = false;
                toggleSpinner(elements.scanTcpBtn, false);
                eventSource.close();
            }
            
            if (displayMessage.includes("EVENT:") || displayMessage.startsWith("EVENT:")) return;
            appendLog(displayMessage);
        };

        eventSource.onerror = (error) => {
            console.error('EventSource failed:', error);
            eventSource.close();
            if (isActionInProgress) {
                isActionInProgress = false;
                toggleSpinner(elements.scanTcpBtn, false);
                setStatus('Error', 'error');
            }
        };
    }

    // --- Whitelist toggles ---
    window.toggleWhitelistCollapse = function() {
        const content = document.getElementById('whitelistCollapseContent');
        const icon = document.getElementById('whitelistToggleIcon');
        if (content && icon) {
            content.classList.toggle('hidden');
            if (content.classList.contains('hidden')) {
                icon.textContent = 'expand_more';
            } else {
                icon.textContent = 'expand_less';
            }
        }
    };

    // --- Event Listeners ---
    function setupEventListeners() {
        if (elements.scanTcpBtn) {
            elements.scanTcpBtn.addEventListener('click', () => {
                if (currentScanMode === 'vuln') {
                    initiateScan('TCP', 'vuln', elements.scanTcpBtn);
                } else {
                    initiateScan(currentProtocol, currentScanMode, elements.scanTcpBtn);
                }
            });
        }
        
        if (elements.clearLogBtn) {
            elements.clearLogBtn.addEventListener('click', () => {
                if (elements.logOutput) {
                    elements.logOutput.innerHTML = '';
                    appendLog('// Terminal cleared.');
                }
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
        
        if (elements.llmAnalysisOptions) {
            elements.llmAnalysisOptions.addEventListener('click', (e) => {
                e.preventDefault();
                const option = e.target.closest('[data-llm-mode]');
                if (option) {
                    const llmMode = option.dataset.llmMode;
                    analyzeReport(llmMode);
                    
                    const aiDropdown = document.getElementById('aiDropdown');
                    if (aiDropdown) {
                        const menu = aiDropdown.querySelector('.dropdown-menu');
                        if (menu) {
                            menu.classList.remove('show');
                            menu.classList.add('hidden');
                        }
                    }
                }
            });
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

        // Whitelist Actions
        if (elements.updateWhitelistBtn) {
            elements.updateWhitelistBtn.addEventListener('click', async () => {
                const ports = elements.whitelistPortsInput.value.trim();
                if (ports && await apiPost('/add_whitelist', { ports }, elements.updateWhitelistBtn)) {
                    appendLog('[*] Whitelist updated locally.');
                }
            });
        }
        
        if (elements.clearWhitelistBtn) {
            elements.clearWhitelistBtn.addEventListener('click', async () => {
                 if (await apiPost('/clear_whitelist', {}, elements.clearWhitelistBtn)) {
                      elements.whitelistPortsInput.value = '';
                      appendLog('[*] Whitelist cleared.');
                 }
            });
        }
    }

    // --- Init ---
    async function init() {
        setupEventListeners();
        initializeLogStream();

        try {
            // [NEW] Use consolidated init_data for reliable results on page load
            const response = await fetch(`${API_BASE_URL}/init_data`);
            const data = await response.json();
            
            if (data.local_ip && elements.targetIpInput && !elements.targetIpInput.value) {
                elements.targetIpInput.value = data.local_ip;
            }
            
            if (data.summary) {
                updateOpenPortsTable(data.summary.open_ports);
                updateIntelligenceUI(data.summary.metadata);
            }
            
            checkReportStatus();
        } catch (error) {
            console.error('Mobile Init failure:', error);
            fetchAndDisplayLocalIp();
            fetchAndDisplayOpenPorts();
        }

        setTimeout(() => appendLog('System Ready. Waiting for target...'), 100);
    }

    init();
});
