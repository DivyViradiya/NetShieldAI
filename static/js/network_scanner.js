document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Element Selectors ---
    const elements = {
        // Inputs & Controls
        targetIpInput: document.getElementById('targetIp'),
        detectIpBtn: document.getElementById('detectIpBtn'),
        scanTcpBtn: document.getElementById('scanTcpBtn'),
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
    };

    // --- State Variables ---
    const API_BASE_URL = '/network_scanner';
    const CHATBOT_REDIRECT_URL = '/chatbot'; 
    let lastScanType = 'tcp'; 
    let isActionInProgress = false;
    let reportDownloadUrl = null;

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

        let contentStyle = 'color:#d4d4d8'; 
        
        if (message.includes('[!]') || message.includes('[x]')) {
            contentStyle = 'color:#ef4444'; 
        } else if (message.includes('[✓]') || message.includes('[+]')) {
            contentStyle = 'color:#10b981'; 
        } else if (message.includes('[*]')) {
            contentStyle = 'color:#3b82f6'; 
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
                elements.scanStatus.innerHTML = `BUSY...`;
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
            appendLog('[x] Error: CSRF Token missing. Refresh page.');
            isActionInProgress = false;
            if (button) toggleSpinner(button, false);
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
            if (button) toggleSpinner(button, false);
            isActionInProgress = false;
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
    
    function updateOpenPortsTable(ports) {
        elements.openPortsTableBody.innerHTML = ''; 
        elements.portCountDisplay.textContent = ports ? ports.length : 0; 

        if (!ports || ports.length === 0) {
            elements.openPortsTableBody.innerHTML = `
                <tr><td colspan="4" style="text-align: center; padding: 2rem;">
                    <div style="color: #555;">No Open Ports Detected</div>
                </td></tr>`;
            return;
        }
        
        ports.forEach(p => {
            let vulnStyle = 'color: #a1a1aa;';
            let vulnText = p.vulnerability || 'N/A';
            
            if (vulnText.toLowerCase().includes('exploit') || vulnText.toLowerCase().includes('cve')) {
                vulnStyle = 'color: #ef4444; font-weight: bold;';
            } else if (vulnText.toLowerCase().includes('run vuln scan')) {
                vulnStyle = 'color: #3b82f6; font-style: italic;';
            }

            const row = `
                <tr>
                    <td style="font-family: monospace; color: white;">${p.port}</td>
                    <td style="color: #d4d4d8;">${p.protocol}</td>
                    <td style="color: #d4d4d8;">${p.service} <span style="font-size: 0.75em; color: #71717a;">(${p.version || ''})</span></td>
                    <td style="${vulnStyle} font-family: monospace; font-size: 0.8em;">${vulnText}</td>
                </tr>`;
            elements.openPortsTableBody.insertAdjacentHTML('beforeend', row);
        });
    }

    async function fetchAndDisplayOpenPorts() {
        try {
            const response = await fetch(`${API_BASE_URL}/open_ports`);
            const data = await response.json();
            updateOpenPortsTable(data.open_ports);
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

    async function checkReportAvailability() {
        try {
            const response = await fetch(`${API_BASE_URL}/report_files`);
            if (response.ok) {
                const data = await response.json();
                if (data.status === 'success' && data.pdf_report) {
                    reportDownloadUrl = data.pdf_report;
                    if (elements.downloadReportBtn) {
                        elements.downloadReportBtn.disabled = false;
                        elements.downloadReportBtn.style.opacity = '1';
                    }
                    if (elements.analyzeReportDropdown) {
                        elements.analyzeReportDropdown.disabled = false;
                        elements.analyzeReportDropdown.style.opacity = '1';
                    }
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

            response = await fetch(`${CHATBOT_REDIRECT_URL}/scanner_analysis`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken 
                },
                body: JSON.stringify({ llm_mode: llmMode, scanner_type: data.scanner_type })
            });

            data = await response.json();

            if (response.ok && data.status === 'success') {
                if (processingText) processingText.textContent = 'REDIRECTING...';
                appendLog(`[✓] Analysis complete. Redirecting...`);
                
                setTimeout(() => {
                    window.location.href = `${CHATBOT_REDIRECT_URL}?mode=${data.llm_mode}&summary=${encodeURIComponent(data.summary)}`;
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

    async function initiateScan(protocolType, scanType, button) {
        const targetIp = elements.targetIpInput.value.trim();
        if (!targetIp) {
            appendLog('[!] Error: Target IP or URL is required.');
            return;
        }

        // --- Multi-Mode UI Update ---
        const originalBtnHtml = button ? button.innerHTML : null;
        if (button && scanType !== 'default' && scanType !== 'vuln') {
            const btnLabel = button.querySelector('span:not(.material-symbols-outlined)');
            if (btnLabel) btnLabel.textContent = scanType.toUpperCase();
        }
        
        lastScanType = scanType === 'default' ? protocolType.toLowerCase() : scanType;
        setStatus(`Scanning...`, 'busy');
        switchTab('ports'); 

        const whitelist = elements.whitelistPortsInput ? elements.whitelistPortsInput.value.split(',').map(s => s.trim()).filter(s => s) : [];

        const result = await apiPost('/scan', {
            target_ip: targetIp,
            protocol_type: protocolType,
            scan_type: scanType,
            whitelist: whitelist
        }, button);

        // Reset button text after delay if it was a special mode
        if (button && originalBtnHtml && scanType !== 'default' && scanType !== 'vuln') {
            setTimeout(() => { button.innerHTML = originalBtnHtml; }, 10000);
        }
    }
    
    function initializeLogStream() {
        const eventSource = new EventSource(`${API_BASE_URL}/log_stream`);
        eventSource.onmessage = (event) => {
            const message = event.data;
            if (message.startsWith(':')) return;
            appendLog(message);

            if (message.toLowerCase().includes("scan complete") || message.toLowerCase().includes("finished")) {
                setStatus('Scan Complete', 'success');
                fetchAndDisplayOpenPorts();
                loadScanResults(lastScanType);
                checkReportAvailability();
            }
        };
        eventSource.onerror = () => {
            console.warn('Log stream disconnected.');
            eventSource.close();
        };
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

        if(elements.scanTcpBtn) elements.scanTcpBtn.addEventListener('click', () => initiateScan('TCP', 'default', elements.scanTcpBtn));
        if(elements.scanVulnBtn) elements.scanVulnBtn.addEventListener('click', () => initiateScan('TCP', 'vuln', elements.scanVulnBtn));

        elements.portsTabBtn.addEventListener('click', () => switchTab('ports'));
        elements.rawTabBtn.addEventListener('click', () => switchTab('raw'));

        // Advanced Config / Modes Toggle
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

        // Handling all Advanced Scan Types via delegation
        if(elements.advancedScanOptions) {
            elements.advancedScanOptions.addEventListener('click', (e) => {
                e.preventDefault();
                const link = e.target.closest('a[data-scan-type]');
                if(link) {
                    const type = link.dataset.scanType;
                    const protocol = (type === 'udp') ? 'UDP' : 'TCP';
                    elements.advancedScanOptions.classList.add('hidden');
                    appendLog(`[*] Switching mode to: ${type.toUpperCase()}`);
                    initiateScan(protocol, type, elements.advancedScanToggle); 
                }
            });
        }

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
                    <tr><td colspan="4" style="text-align:center; padding: 3rem; color: #a1a1aa;">
                        <span class="spinner inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></span>
                        Refreshing data...
                    </td></tr>`;
                
                elements.resultsContent.textContent = '// Refreshing log data...';

                Promise.all([
                    fetchAndDisplayOpenPorts(),
                    loadScanResults(lastScanType),
                    checkReportAvailability()
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
    }

    // --- Init ---
    function init() {
        setupEventListeners();
        initializeLogStream();
        switchTab('ports');
        
        fetchAndDisplayLocalIp();
        fetchAndDisplayWhitelist();
        fetchAndDisplayOpenPorts();
        checkReportAvailability();
        
        setTimeout(() => appendLog('System Ready. Waiting for target...'), 100);
    }

    init();
});