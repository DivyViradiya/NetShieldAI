document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Element Selectors ---
    const elements = {
        detectIpBtn: document.getElementById('detectIpBtn'),
        scanTcpBtn: document.getElementById('scanTcpBtn'),
        scanVulnBtn: document.getElementById('scanVulnBtn'), 
        
        advancedScanToggle: document.getElementById('advancedScanToggle'),
        advancedScanOptions: document.getElementById('advancedScanOptions'),
        advancedScanArrow: document.getElementById('advancedScanArrow'),
        updateWhitelistBtn: document.getElementById('updateWhitelistBtn'),
        clearWhitelistBtn: document.getElementById('clearWhitelistBtn'),
        blockPortsBtn: document.getElementById('blockPortsBtn'),
        verifyPortsBtn: document.getElementById('verifyPortsBtn'),
        clearLogBtn: document.getElementById('clearLogBtn'),
        refreshResultsBtn: document.getElementById('refreshResultsBtn'),
        
        copyResultsBtn: document.getElementById('copyResultsBtn'),
        resultsContent: document.getElementById('resultsContent'), 
        
        downloadReportBtn: document.getElementById('downloadReportBtn'),
        
        // 🚨 NEW SELECTORS for AI Analysis
        analyzeReportDropdown: document.getElementById('analyzeReportDropdown'),
        llmAnalysisOptions: document.getElementById('llmAnalysisOptions'),
        
        targetIpInput: document.getElementById('targetIp'),
        whitelistPortsInput: document.getElementById('whitelistPorts'),
        logOutput: document.getElementById('logOutput'),
        scanStatus: document.getElementById('scanStatus'),
        localIpDisplay: document.getElementById('localIpDisplay'),
        whitelistedPortsDisplay: document.getElementById('whitelistedPortsDisplay'),
        
        portsTabBtn: document.getElementById('portsTabBtn'),
        rawTabBtn: document.getElementById('rawTabBtn'),
        portsContent: document.getElementById('portsContent'),
        rawContent: document.getElementById('rawContent'),
        portCountDisplay: document.getElementById('portCountDisplay'),
        rawScanTypeDisplay: document.getElementById('rawScanTypeDisplay'),
        
        openPortsTableBody: document.getElementById('openPortsTableBody'),
    };

    // --- State Variables ---
    const API_BASE_URL = '/network_scanner';
    const CHATBOT_REDIRECT_URL = '/chatbot'; // Target page for Q&A
    let lastScanType = 'tcp'; // Track the last scan type for refreshing results
    let isActionInProgress = false;
    let reportDownloadUrl = null;


    // --- Helper Functions ---
    
    /**
     * Toggles the loading spinner on a button.
     * 🚨 MODIFIED to support nested button/span structures like the analyzeReportDropdown
     */
    function toggleSpinner(button, isLoading) {
        if (!button) return;
        // Check for direct children with .button-text and .spinner
        let buttonText = button.querySelector('.button-text');
        let spinner = button.querySelector('.spinner');
        
        // If not found, assume it is the button itself (for primary/secondary)
        if (!buttonText) buttonText = button;
        if (!spinner) spinner = button.querySelector('.spinner');

        button.disabled = isLoading;
        if (buttonText && spinner) {
            buttonText.classList.toggle('hidden', isLoading);
            spinner.classList.toggle('hidden', !isLoading);
        } else if (isLoading) {
             // For buttons without explicit spinner/text, dim them
             button.classList.add('opacity-50', 'cursor-not-allowed');
        } else {
             button.classList.remove('opacity-50', 'cursor-not-allowed');
        }
        
        // Ensure the dropdown caret is hidden when busy
        const caret = button.querySelector('.fa-caret-down');
        if (caret) caret.classList.toggle('hidden', isLoading);
    }
    
    /**
     * Appends a message to the log display.
     */
    function appendLog(message) {
        if (!elements.logOutput) return;
        elements.logOutput.textContent += message + '\n'; 
        elements.logOutput.scrollTop = elements.logOutput.scrollHeight;
    }

    /**
     * Sets the main status message text and color.
     */
    function setStatus(text, type = 'ready') {
        if (!elements.scanStatus) return;
        
        // Remove old classes and icons
        elements.scanStatus.className = 'text-center text-xs py-2 rounded border border-slate-800 bg-slate-900/50 text-slate-400';
        const currentIcon = elements.scanStatus.querySelector('i');
        if (currentIcon) currentIcon.remove();

        let iconClass = '';

        switch (type) {
            case 'busy':
                elements.scanStatus.classList.add('bg-yellow-900/50', 'text-yellow-400');
                iconClass = 'fas fa-cog fa-spin';
                break;
            case 'error':
                elements.scanStatus.classList.add('bg-red-900/50', 'text-red-400');
                iconClass = 'fas fa-times-circle';
                break;
            case 'success':
                elements.scanStatus.classList.add('bg-green-900/50', 'text-green-400');
                iconClass = 'fas fa-check-circle';
                break;
            default: // ready
                elements.scanStatus.classList.add('bg-slate-900/50', 'text-green-400');
                iconClass = 'fas fa-circle';
        }
        
        const iconElement = document.createElement('i');
        iconElement.className = `${iconClass} text-[8px] mr-2`;
        elements.scanStatus.prepend(iconElement);

        elements.scanStatus.textContent = text;
    }


    // --- API & Data Functions ---

    /**
     * A generic function to handle API POST requests.
     */
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
            appendLog(`[✓] ${data.message}`);
            return data;
        } catch (error) {
            appendLog(`[x] Error: ${error.message}`);
            setStatus('Error occurred', 'error');
            return null;
        } finally {
            if (button) toggleSpinner(button, false);
            isActionInProgress = false;
        }
    }
    
    // ... (fetchAndDisplayLocalIp, fetchAndDisplayWhitelist, updateOpenPortsTable unchanged)

    async function fetchAndDisplayLocalIp() {
        try {
            const response = await fetch(`${API_BASE_URL}/local_ip`);
            const data = await response.json();
            elements.localIpDisplay.textContent = data.local_ip || 'Not Detected';
            if (elements.targetIpInput.value === '') {
                elements.targetIpInput.value = data.local_ip;
            }
        } catch (error) {
            appendLog('[x] Error fetching local IP.');
        }
    }

    async function fetchAndDisplayWhitelist() {
        try {
            const response = await fetch(`${API_BASE_URL}/whitelisted_ports`);
            const data = await response.json();
            const ports = data.whitelisted_ports;
            elements.whitelistedPortsDisplay.textContent = ports.length > 0 ? ports.join(', ') : 'None';
        } catch (error) {
            appendLog('[x] Error fetching whitelist.');
        }
    }
    
    /**
     * Updates the Open Ports table with all new columns.
     * @param {Array} ports Array of port objects, including 'process_name' and 'vulnerability'.
     */
    function updateOpenPortsTable(ports) {
        elements.openPortsTableBody.innerHTML = ''; // Clear table
        elements.portCountDisplay.textContent = ports ? ports.length : 0; // Update port count

        // Colspan changed from 4 to 5 for new column
        if (!ports || ports.length === 0) {
            elements.openPortsTableBody.innerHTML = `<tr><td colspan="5" class="p-12 text-center">
                <div class="text-slate-600 mb-2"><i class="fas fa-radar text-4xl opacity-20"></i></div>
                <p class="text-slate-500">Initiate a scan to view open ports.</p>
                </td></tr>`;
            return;
        }
        
        ports.forEach(p => {
            // Determine text color for vulnerability cell
            let vulnTextColor = 'text-slate-400';
            if (p.vulnerability && p.vulnerability.toLowerCase().includes('run vuln scan')) {
                vulnTextColor = 'text-blue-400/80';
            } else if (p.vulnerability && (p.vulnerability.toLowerCase().includes('vulnerable') || p.vulnerability.toLowerCase().includes('cve'))) {
                vulnTextColor = 'text-red-400'; // Highlight critical findings
            } else if (p.vulnerability && p.vulnerability.toLowerCase() !== 'n/a') {
                vulnTextColor = 'text-yellow-400/80';
            }


            const row = `
                <tr>
                    <td class="px-6 py-3 text-sm font-mono">${p.port || 'N/A'}</td>
                    <td class="px-6 py-3 text-sm">${p.protocol || 'N/A'}</td>
                    <td class="px-6 py-3 text-sm">${p.service || 'N/A'} (${p.version || 'N/A'})</td>
                    <td class="px-6 py-3 text-sm font-mono text-blue-400/80">${p.process_name || 'Not Found'}</td>
                    <td class="px-6 py-3 text-sm ${vulnTextColor}">
                         <pre class="vuln-cell-content">${p.vulnerability || 'N/A'}</pre>
                    </td>
                </tr>`;
            elements.openPortsTableBody.insertAdjacentHTML('beforeend', row);
        });
    }

    /**
     * Fetches the current list of open ports and updates the table.
     */
    async function fetchAndDisplayOpenPorts() {
        try {
            const response = await fetch(`${API_BASE_URL}/open_ports`);
            const data = await response.json();
            // Use the modified table rendering function
            updateOpenPortsTable(data.open_ports);
        } catch (error) {
            appendLog('[x] Error fetching open ports.');
        }
    }

    /**
     * Loads the raw text content for a specific scan type.
     */
    async function loadScanResults(scanType) {
        elements.resultsContent.textContent = 'Loading...';
        elements.rawScanTypeDisplay.textContent = `RAW OUTPUT (${scanType.toUpperCase()})`;
        try {
            const response = await fetch(`${API_BASE_URL}/get_scan_results?type=${scanType}`);
            const data = await response.json();
            elements.resultsContent.textContent = response.ok ? data.content : data.message;
        } catch (error) {
            elements.resultsContent.textContent = 'Failed to load results.';
        }
    }

    /**
     * Checks if a PDF report is available and updates the download/analysis buttons.
     * 🚨 MODIFIED: Now enables the Analysis button as well.
     */
    async function checkReportAvailability() {
        try {
            const response = await fetch(`${API_BASE_URL}/report_files`);
            if (response.ok) {
                const data = await response.json();
                if (data.status === 'success' && data.pdf_report) {
                    reportDownloadUrl = data.pdf_report;
                    
                    // Enable Download Button
                    if (elements.downloadReportBtn) {
                        elements.downloadReportBtn.disabled = false;
                        elements.downloadReportBtn.classList.remove('opacity-50', 'cursor-not-allowed');
                        elements.downloadReportBtn.classList.add('hover:bg-red-500'); 
                    }
                    
                    // 🚨 Enable Analysis Button
                    if (elements.analyzeReportDropdown) {
                        elements.analyzeReportDropdown.disabled = false;
                        elements.analyzeReportDropdown.classList.remove('opacity-50', 'cursor-not-allowed');
                        elements.analyzeReportDropdown.classList.add('hover:bg-indigo-500');
                    }
                    return;
                }
            }
        } catch (error) {
            console.error('Error checking report availability:', error);
        }

        // Disable all report actions if no PDF is found
        reportDownloadUrl = null;
        [elements.downloadReportBtn, elements.analyzeReportDropdown].forEach(btn => {
            if (btn) {
                btn.disabled = true;
                btn.classList.add('opacity-50', 'cursor-not-allowed');
                btn.classList.remove('hover:bg-red-500', 'hover:bg-indigo-500'); 
            }
        });
    }

    /**
     * 🚨 NEW FUNCTION: Triggers the server-side proxy to upload the PDF for AI analysis.
     * @param {string} llmMode - The selected LLM mode ('local' or 'gemini').
     */
async function analyzeReport(llmMode) {
        const button = elements.analyzeReportDropdown;
        if (!button || button.disabled) return;
        
        setStatus(`Preparing Nmap report for AI analysis (${llmMode})...`, 'busy');
        toggleSpinner(button, true); 
        elements.downloadReportBtn.disabled = true;

        try {
            // 1. First, check local PDF availability via the local blueprint.
            // This prevents unnecessarily trying to hit the proxy if no PDF exists.
            let response = await fetch(`${API_BASE_URL}/trigger_ai_analysis`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ llm_mode: llmMode }) // Sending llm_mode, though not strictly needed here
            });
            let data = await response.json();
            
            if (data.status !== 'success') {
                throw new Error(data.message || 'PDF availability check failed.');
            }
            
            // 2. Now call the central proxy route on the chatbot blueprint.
            // This request relies on the browser's session cookie.
            response = await fetch(`${CHATBOT_REDIRECT_URL}/scanner_analysis`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ llm_mode: llmMode, scanner_type: data.scanner_type }) // Pass scanner_type
            });

            data = await response.json(); // Data now contains summary and llm_mode

            if (response.ok && data.status === 'success') {
                appendLog(`[✓] AI analysis initiated. Summary received. Redirecting...`);
                setStatus('Analysis complete. Redirecting...', 'success');
                
                // 3. Redirect, passing summary and mode (from the server response)
                window.location.href = `${CHATBOT_REDIRECT_URL}?mode=${data.llm_mode}&summary=${encodeURIComponent(data.summary)}`;
            } else {
                throw new Error(data.message || `Analysis failed with status ${response.status}`);
            }
        } catch (error) {
            appendLog(`[x] AI Analysis Error: ${error.message}`);
            setStatus('Analysis failed', 'error');
        } finally {
            // Only run cleanup if no redirect happened (i.e., if it failed)
            toggleSpinner(button, false);
            checkReportAvailability(); 
        }
    }

    /**
     * Initiates a network scan.
     */
    async function initiateScan(protocolType, scanType, button) {
        const targetIp = elements.targetIpInput.value.trim();
        if (!targetIp) {
            appendLog('[!] Target IP is required.');
            setStatus('Target IP is required', 'error');
            return;
        }
        
        lastScanType = scanType === 'default' ? protocolType.toLowerCase() : scanType;
        setStatus(`Scanning (${lastScanType.toUpperCase()})...`, 'busy');
        
        // Switch to Ports tab automatically when scan is initiated
        switchTab('ports');

        await apiPost('/scan', {
            target_ip: targetIp,
            protocol_type: protocolType,
            scan_type: scanType
        }, button);
    }
    
    /**
     * Server-Sent Events (SSE) for Live Log.
     */
    function initializeLogStream() {
        const eventSource = new EventSource(`${API_BASE_URL}/log_stream`);

        eventSource.onmessage = (event) => {
            const message = event.data;
            if (message.startsWith(':')) return;

            appendLog(message);

            if (message.includes("scan complete") || message.includes("process completed") || message.includes("finished")) {
                setStatus('Action complete!', 'success');
                // Auto-refresh data on completion
                fetchAndDisplayOpenPorts();
                loadScanResults(lastScanType);
                checkReportAvailability();
            }
        };

        eventSource.onerror = () => {
            appendLog('[!] Log stream connection failed. Please refresh.');
            setStatus('Log stream disconnected', 'error');
            eventSource.close();
        };
    }
    
    /**
     * Tab Switching Logic.
     */
    function switchTab(tabName) {
        // Update tab buttons
        elements.portsTabBtn.classList.toggle('active', tabName === 'ports');
        elements.rawTabBtn.classList.toggle('active', tabName === 'raw');

        // Update content containers
        elements.portsContent.classList.toggle('hidden', tabName !== 'ports');
        elements.rawContent.classList.toggle('hidden', tabName !== 'raw');
        
        // Ensure raw output view is updated if switching to it
        if (tabName === 'raw') {
            loadScanResults(lastScanType);
        }
    }


    // --- Event Listeners ---
    
    function setupEventListeners() {
        elements.detectIpBtn.addEventListener('click', fetchAndDisplayLocalIp);

        // Main Button Listeners: TCP & VULN
        elements.scanTcpBtn.addEventListener('click', () => initiateScan('TCP', 'default', elements.scanTcpBtn));
        elements.scanVulnBtn.addEventListener('click', () => initiateScan('TCP', 'vuln', elements.scanVulnBtn));

        // Tab Event Listeners
        elements.portsTabBtn.addEventListener('click', () => switchTab('ports'));
        elements.rawTabBtn.addEventListener('click', () => switchTab('raw'));

        elements.advancedScanToggle.addEventListener('click', () => {
            elements.advancedScanOptions.classList.toggle('hidden');
            elements.advancedScanArrow.classList.toggle('rotate-180');
        });

        elements.advancedScanOptions.addEventListener('click', (e) => {
            const button = e.target.closest('button[data-scan-type]');
            if (button) {
                const scanType = button.dataset.scanType;
                
                // Determine Protocol: UDP scan uses UDP protocol, all others use TCP
                const protocolType = scanType === 'udp' ? 'UDP' : 'TCP';

                initiateScan(protocolType, scanType, null);
                elements.advancedScanOptions.classList.add('hidden');
                elements.advancedScanArrow.classList.remove('rotate-180');
            }
        });

        elements.updateWhitelistBtn.addEventListener('click', async () => {
            const ports = elements.whitelistPortsInput.value.trim();
            if (ports && await apiPost('/add_whitelist', { ports }, elements.updateWhitelistBtn)) {
                elements.whitelistPortsInput.value = '';
                fetchAndDisplayWhitelist();
            }
        });

        elements.clearWhitelistBtn.addEventListener('click', async () => {
            if (await apiPost('/clear_whitelist', {}, elements.clearWhitelistBtn)) {
                fetchAndDisplayWhitelist();
            }
        });

        elements.blockPortsBtn.addEventListener('click', () => apiPost('/block_ports', {}, elements.blockPortsBtn));

        elements.verifyPortsBtn.addEventListener('click', () => {
            const targetIp = elements.targetIpInput.value.trim();
            if (!targetIp) {
                appendLog('[!] Target IP is required for verification.');
                return;
            }
            apiPost('/verify_ports', { target_ip: targetIp }, elements.verifyPortsBtn);
        });
        
        elements.clearLogBtn.addEventListener('click', async () => {
            const originalContent = elements.clearLogBtn.innerHTML;
            elements.clearLogBtn.disabled = true;
            elements.clearLogBtn.innerHTML = '<span class="spinner ml-1"></span>';
            
            try {
                if (await apiPost('/clear_log', {})) {
                    elements.logOutput.textContent = '';
                }
            } finally {
                elements.clearLogBtn.disabled = false;
                elements.clearLogBtn.innerHTML = originalContent;
            }
        });

        elements.refreshResultsBtn.addEventListener('click', () => {
            setStatus('Refreshing data...', 'busy');
            Promise.all([
                fetchAndDisplayLocalIp(),
                fetchAndDisplayWhitelist(),
                fetchAndDisplayOpenPorts(),
                loadScanResults(lastScanType),
                checkReportAvailability()
            ]).then(() => setStatus('System Ready', 'ready'));
        });

        elements.copyResultsBtn.addEventListener('click', () => {
            const textToCopy = elements.resultsContent.textContent;
            const originalContent = elements.copyResultsBtn.innerHTML;

            if (!textToCopy || textToCopy.includes('Loading') || textToCopy.includes('Failed to load') || textToCopy.includes('Awaiting output stream')) {
                appendLog('[!] No valid results to copy.');
                return;
            }

            navigator.clipboard.writeText(textToCopy).then(() => {
                elements.copyResultsBtn.innerHTML = '<i class="fas fa-check text-green-500 mr-1"></i> COPIED!';
                elements.copyResultsBtn.style.pointerEvents = 'none';

                appendLog('[✓] Raw output copied to clipboard.');
                
                setTimeout(() => { 
                    elements.copyResultsBtn.innerHTML = originalContent; 
                    elements.copyResultsBtn.style.pointerEvents = 'auto'; 
                }, 2000);
            }).catch(err => {
                appendLog(`[x] Failed to copy: ${err.message}. Please copy manually.`);
            });
        });

        if (elements.downloadReportBtn) {
            elements.downloadReportBtn.addEventListener('click', () => {
                if (reportDownloadUrl) {
                    window.location.href = reportDownloadUrl;
                    appendLog('[✓] Downloading PDF report...');
                } else {
                    appendLog('[!] No report available to download.');
                }
            });
        }
        
        // 🚨 NEW: Analysis Dropdown Toggle
        elements.analyzeReportDropdown.addEventListener('click', (e) => {
            // Only toggle if the button is NOT disabled
            if (!elements.analyzeReportDropdown.disabled) {
                elements.llmAnalysisOptions.classList.toggle('hidden');
                e.stopPropagation(); // Prevent document click from immediately closing it
            }
        });
        
        // 🚨 NEW: Analysis Option Selection
        elements.llmAnalysisOptions.addEventListener('click', (e) => {
            e.preventDefault();
            const option = e.target.closest('a[data-llm-mode]');
            if (option) {
                const llmMode = option.dataset.llmMode;
                elements.llmAnalysisOptions.classList.add('hidden'); // Close dropdown
                analyzeReport(llmMode); // Start the analysis and redirection
            }
        });

        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (elements.llmAnalysisOptions && elements.analyzeReportDropdown && !elements.analyzeReportDropdown.contains(e.target)) {
                elements.llmAnalysisOptions.classList.add('hidden');
            }
        });
    }

    // --- Initialization ---
    function init() {
        appendLog('Initializing UI...');
        setupEventListeners();
        initializeLogStream();
        
        // Ensure default tab is 'ports'
        switchTab('ports'); 

        // Initial data fetch
        setStatus('Initializing...', 'busy');
        Promise.all([
            fetchAndDisplayLocalIp(),
            fetchAndDisplayWhitelist(),
            fetchAndDisplayOpenPorts(),
            loadScanResults(lastScanType),
            checkReportAvailability()
        ]).then(() => {
            setStatus('System Ready', 'ready');
            appendLog('Initialization complete. Ready for commands.');
        });
    }

    init();
});