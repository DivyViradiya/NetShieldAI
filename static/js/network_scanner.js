document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Element Selectors ---
    const elements = {
        // Inputs & Controls
        targetIpInput: document.getElementById('targetIp'),
        detectIpBtn: document.getElementById('detectIpBtn'),
        scanTcpBtn: document.getElementById('scanTcpBtn'),
        scanVulnBtn: document.getElementById('scanVulnBtn'),
        
        // Advanced Config (Settings)
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

    // --- Helper Functions ---
    
    function toggleSpinner(button, isLoading) {
        if (!button) return;
        const spinner = button.querySelector('.spinner');
        const icon = button.querySelector('.material-symbols-outlined'); // Select the icon
        
        // Don't disable dropdown toggles, just main action buttons
        if (button.id !== 'analyzeReportDropdown') {
            button.disabled = isLoading;
        }

        if (isLoading) {
            button.classList.add('opacity-70');
            if (button.tagName !== 'A' && button.id !== 'analyzeReportDropdown') button.classList.add('cursor-not-allowed');
            
            // Swap Icon for Spinner (Hides the icon so button size doesn't change)
            if (icon) icon.classList.add('hidden'); 
            if (spinner) spinner.classList.remove('hidden');
            
        } else {
            button.classList.remove('opacity-70', 'cursor-not-allowed');
            
            // Swap Spinner back for Icon
            if (spinner) spinner.classList.add('hidden');
            if (icon) icon.classList.remove('hidden');
        }
        
        // Caret handling for dropdowns (Special Case)
        if (icon && icon.textContent === 'expand_more') {
            icon.style.display = isLoading ? 'none' : 'inline-block';
        }
    }
    
    function appendLog(message) {
        if (!elements.logOutput) return;
        const line = document.createElement('div');
        
        if (message.includes('[!]') || message.includes('[x]')) line.className = 'text-[#ef4444]'; // Tailwind Red-500 equivalent
        else if (message.includes('[✓]') || message.includes('[+]')) line.className = 'text-[#10b981]'; // Tailwind Green-500 equivalent
        else if (message.includes('[*]')) line.className = 'text-[#3b82f6]'; // Tailwind Blue-500 equivalent
        else line.className = 'text-[#a1a1aa]';
        
        line.textContent = message;
        elements.logOutput.appendChild(line);
        elements.logOutput.scrollTop = elements.logOutput.scrollHeight;
    }

    function setStatus(text, type = 'ready') {
        if (!elements.scanStatus) return;
        
        // Reset classes
        elements.scanStatus.className = 'status-val font-mono ml-2';
        
        switch (type) {
            case 'busy':
                elements.scanStatus.style.color = '#eab308'; // Yellow
                elements.scanStatus.innerHTML = `BUSY...`;
                break;
            case 'error':
                elements.scanStatus.style.color = '#ef4444'; // Red
                elements.scanStatus.textContent = text;
                break;
            case 'success':
                elements.scanStatus.style.color = '#10b981'; // Green
                elements.scanStatus.textContent = text;
                break;
            default: // ready
                elements.scanStatus.style.color = '#10b981';
                elements.scanStatus.textContent = 'READY';
        }
    }

    // --- API & Data Functions ---

    async function apiPost(endpoint, body = {}, button = null) {
        if (isActionInProgress) return;
        isActionInProgress = true;
        if (button) toggleSpinner(button, true);

        try {
            const response = await fetch(`${API_BASE_URL}${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
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
        if (!button || button.disabled) return;
        
        setStatus(`Analyzing...`, 'busy');
        toggleSpinner(button, true); 
        
        try {
            // 1. Trigger Proxy
            let response = await fetch(`${API_BASE_URL}/trigger_ai_analysis`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ llm_mode: llmMode })
            });
            let data = await response.json();
            
            if (data.status !== 'success') throw new Error(data.message);
            
            // 2. Call Chatbot Proxy
            response = await fetch(`${CHATBOT_REDIRECT_URL}/scanner_analysis`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ llm_mode: llmMode, scanner_type: data.scanner_type })
            });

            data = await response.json();

            if (response.ok && data.status === 'success') {
                appendLog(`[✓] Analysis complete. Redirecting...`);
                window.location.href = `${CHATBOT_REDIRECT_URL}?mode=${data.llm_mode}&summary=${encodeURIComponent(data.summary)}`;
            } else {
                throw new Error(data.message);
            }
        } catch (error) {
            appendLog(`[x] AI Analysis Error: ${error.message}`);
            setStatus('Analysis failed', 'error');
        } finally {
            toggleSpinner(button, false);
        }
    }

    async function initiateScan(protocolType, scanType, button) {
        const targetIp = elements.targetIpInput.value.trim();
        if (!targetIp) {
            appendLog('[!] Error: Target IP/CIDR is required.');
            return;
        }
        
        lastScanType = scanType === 'default' ? protocolType.toLowerCase() : scanType;
        setStatus(`Scanning...`, 'busy');
        switchTab('ports'); 

        const whitelist = elements.whitelistPortsInput ? elements.whitelistPortsInput.value.split(',').map(s => s.trim()).filter(s => s) : [];

        await apiPost('/scan', {
            target_ip: targetIp,
            protocol_type: protocolType,
            scan_type: scanType,
            whitelist: whitelist
        }, button);
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

        // Scans
        if(elements.scanTcpBtn) elements.scanTcpBtn.addEventListener('click', () => initiateScan('TCP', 'default', elements.scanTcpBtn));
        if(elements.scanVulnBtn) elements.scanVulnBtn.addEventListener('click', () => initiateScan('TCP', 'vuln', elements.scanVulnBtn));

        // Tabs
        elements.portsTabBtn.addEventListener('click', () => switchTab('ports'));
        elements.rawTabBtn.addEventListener('click', () => switchTab('raw'));

        // Advanced Options Toggle
        if(elements.advancedScanToggle && elements.advancedScanOptions) {
            elements.advancedScanToggle.addEventListener('click', (e) => {
                e.stopPropagation(); // Stop click from reaching document
                elements.advancedScanOptions.classList.toggle('hidden');
                
                // Add event listener to document to close when clicking outside
                const closeMenu = (docEvent) => {
                    if (!elements.advancedScanOptions.contains(docEvent.target) && docEvent.target !== elements.advancedScanToggle) {
                        elements.advancedScanOptions.classList.add('hidden');
                        document.removeEventListener('click', closeMenu);
                    }
                };
                document.addEventListener('click', closeMenu);
            });
        }

        // Advanced Options Click inside Menu (UDP/OS Scan etc)
        if(elements.advancedScanOptions) {
            elements.advancedScanOptions.addEventListener('click', (e) => {
                const btn = e.target.closest('button[data-scan-type]');
                if(btn) {
                    const type = btn.dataset.scanType;
                    const protocol = type === 'udp' ? 'UDP' : 'TCP';
                    elements.advancedScanOptions.classList.add('hidden'); 
                    initiateScan(protocol, type, null); 
                }
            });
        }

        // Admin Actions (Right Panel)
        // Verify Ports
        if(elements.verifyPortsBtn) {
            elements.verifyPortsBtn.addEventListener('click', async () => {
                const targetIp = elements.targetIpInput.value.trim();
                if(!targetIp) {
                    appendLog('[!] Enter IP before verifying.');
                    return;
                }
                appendLog('[*] Verifying closed ports...');
                await apiPost('/verify_ports', { target_ip: targetIp }, elements.verifyPortsBtn);
            });
        }

        // Block Ports
        if(elements.blockPortsBtn) {
            elements.blockPortsBtn.addEventListener('click', async () => {
                if(confirm("Are you sure you want to attempt blocking ALL currently detected open ports? This requires admin privileges.")) {
                    appendLog('[*] Initiating Firewall Block...');
                    await apiPost('/block_ports', {}, elements.blockPortsBtn);
                }
            });
        }

        // Whitelist Actions
        if(elements.updateWhitelistBtn) {
            elements.updateWhitelistBtn.addEventListener('click', async () => {
                const ports = elements.whitelistPortsInput.value.trim();
                if (ports && await apiPost('/add_whitelist', { ports }, elements.updateWhitelistBtn)) {
                    appendLog('[*] Whitelist updated locally.');
                }
            });
        }
        
        // Clear Whitelist
        if(elements.clearWhitelistBtn) {
            elements.clearWhitelistBtn.addEventListener('click', async () => {
                 if(await apiPost('/clear_whitelist', {}, elements.clearWhitelistBtn)) {
                     elements.whitelistPortsInput.value = '';
                     appendLog('[*] Whitelist cleared.');
                 }
            });
        }

        // Logs
        if(elements.clearLogBtn) {
            elements.clearLogBtn.addEventListener('click', () => {
                elements.logOutput.innerHTML = '';
                apiPost('/clear_log');
            });
        }

        // Refresh with Visual Feedback
        if(elements.refreshResultsBtn) {
            elements.refreshResultsBtn.addEventListener('click', () => {
                setStatus('Refreshing...', 'busy');
                toggleSpinner(elements.refreshResultsBtn, true); // Spin the button

                // 1. VISUAL FEEDBACK: Force Table to "Loading" state immediately
                elements.openPortsTableBody.innerHTML = `
                    <tr><td colspan="4" style="text-align:center; padding: 3rem; color: #a1a1aa;">
                        <span class="spinner inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></span>
                        Refreshing data...
                    </td></tr>`;
                
                // 2. VISUAL FEEDBACK: Force Raw Log to "Loading"
                elements.resultsContent.textContent = '// Refreshing log data...';

                // 3. Perform Fetches
                Promise.all([
                    fetchAndDisplayOpenPorts(),
                    loadScanResults(lastScanType),
                    checkReportAvailability()
                ]).then(() => {
                    setStatus('System Ready', 'success');
                    // Small delay to ensure the user sees the refresh happen if it's too fast
                    setTimeout(() => toggleSpinner(elements.refreshResultsBtn, false), 500);
                }).catch((err) => {
                    console.error(err);
                    setStatus('Refresh Failed', 'error');
                    toggleSpinner(elements.refreshResultsBtn, false);
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
                    appendLog('[✓] Download started.');
                }
            });
        }
        
        // AI Dropdown Toggle
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
        
        // AI Selection
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
        
        // Initial Fetch
        fetchAndDisplayLocalIp();
        fetchAndDisplayWhitelist();
        fetchAndDisplayOpenPorts();
        checkReportAvailability();
        
        appendLog('System Initialized... Waiting for input...');
    }

    init();
});