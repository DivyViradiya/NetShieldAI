document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Element Selectors ---
    const elements = {
        detectIpBtn: document.getElementById('detectIpBtn'),
        scanTcpBtn: document.getElementById('scanTcpBtn'),
        scanUdpBtn: document.getElementById('scanUdpBtn'),
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
        targetIpInput: document.getElementById('targetIp'),
        whitelistPortsInput: document.getElementById('whitelistPorts'),
        logOutput: document.getElementById('logOutput'),
        scanStatus: document.getElementById('scanStatus'),
        localIpDisplay: document.getElementById('localIpDisplay'),
        whitelistedPortsDisplay: document.getElementById('whitelistedPortsDisplay'),
        openPortsTableBody: document.getElementById('openPortsTableBody'),
        resultsContent: document.getElementById('resultsContent'),
        rawReportTitle: document.getElementById('rawReportTitle'),
    };

    // --- State Variables ---
    const API_BASE_URL = '/network_scanner';
    let lastScanType = 'tcp'; // Track the last scan type for refreshing results
    let isActionInProgress = false;

    // --- Helper Functions ---

    /**
     * Toggles the loading spinner on a button.
     * @param {HTMLElement} button The button element.
     * @param {boolean} isLoading True to show spinner, false to hide.
     */
    function toggleSpinner(button, isLoading) {
        if (!button) return;
        const buttonText = button.querySelector('.button-text');
        const spinner = button.querySelector('.spinner');
        
        button.disabled = isLoading;
        if (buttonText && spinner) {
            buttonText.classList.toggle('hidden', isLoading);
            spinner.classList.toggle('hidden', !isLoading);
        }
    }
    
    /**
         * Appends a message to the log display.
         * @param {string} message The log message.
         */
    function appendLog(message) {
        if (!elements.logOutput) return;
        // Use textContent for better performance and security.
        // Append a newline character (\n) to ensure proper line breaks.
        elements.logOutput.textContent += message + '\n'; 
        // Automatically scroll to the bottom of the log.
        elements.logOutput.scrollTop = elements.logOutput.scrollHeight;
    }

    /**
     * Sets the main status message text and color.
     * @param {string} text The message to display.
     * @param {'ready'|'busy'|'error'|'success'} type The status type for styling.
     */
    function setStatus(text, type = 'ready') {
        if (!elements.scanStatus) return;
        elements.scanStatus.textContent = text;
        elements.scanStatus.className = 'text-center text-sm mt-4 p-2 rounded-md ';
        switch (type) {
            case 'busy':
                elements.scanStatus.classList.add('bg-yellow-100', 'text-yellow-800');
                break;
            case 'error':
                elements.scanStatus.classList.add('bg-red-100', 'text-red-800');
                break;
            case 'success':
                 elements.scanStatus.classList.add('bg-green-100', 'text-green-800');
                 break;
            default: // ready
                elements.scanStatus.classList.add('bg-blue-100', 'text-blue-800');
        }
    }

    // --- API & Data Functions ---

    /**
     * A generic function to handle API POST requests.
     * @param {string} endpoint The API endpoint to call.
     * @param {object} body The request body.
     * @param {HTMLElement} [button] The button that triggered the action, for spinner toggling.
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
    
    /**
     * Fetches and displays the local IP address.
     */
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

    /**
     * Fetches and displays the list of whitelisted ports.
     */
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
     * Updates the Open Ports table in the UI.
     * @param {Array} ports Array of port objects.
     */
    function updateOpenPortsTable(ports) {
        elements.openPortsTableBody.innerHTML = ''; // Clear table
        if (!ports || ports.length === 0) {
            elements.openPortsTableBody.innerHTML = `<tr><td colspan="4" class="p-4 text-center text-gray-500">No open ports detected.</td></tr>`;
            return;
        }
        ports.forEach(p => {
            const row = `
                <tr>
                    <td class="px-4 py-3 text-sm">${p.port || 'N/A'}</td>
                    <td class="px-4 py-3 text-sm">${p.protocol || 'N/A'}</td>
                    <td class="px-4 py-3 text-sm">${p.service || 'N/A'}</td>
                    <td class="px-4 py-3 text-sm">${p.version || 'N/A'}</td>
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
            updateOpenPortsTable(data.open_ports);
        } catch (error) {
            appendLog('[x] Error fetching open ports.');
        }
    }

    /**
     * Loads the raw text content for a specific scan type.
     * @param {string} scanType The type of scan results to fetch (e.g., 'tcp', 'os').
     */
    async function loadScanResults(scanType) {
        elements.resultsContent.textContent = 'Loading...';
        elements.rawReportTitle.textContent = `Raw Report (${scanType.toUpperCase()})`;
        try {
            const response = await fetch(`${API_BASE_URL}/get_scan_results?type=${scanType}`);
            const data = await response.json();
            elements.resultsContent.textContent = response.ok ? data.content : data.message;
        } catch (error) {
            elements.resultsContent.textContent = 'Failed to load results.';
        }
    }

    /**
     * Initiates a network scan.
     * @param {string} protocolType 'TCP' or 'UDP'.
     * @param {string} scanType The specific type of scan (e.g., 'default', 'os').
     * @param {HTMLElement} button The button that triggered the scan.
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
        
        await apiPost('/scan', {
            target_ip: targetIp,
            protocol_type: protocolType,
            scan_type: scanType
        }, button);
    }
    
    // --- Server-Sent Events (SSE) for Live Log ---
    function initializeLogStream() {
        const eventSource = new EventSource(`${API_BASE_URL}/log_stream`);

        eventSource.onmessage = (event) => {
            const message = event.data;
            if (message.startsWith(':')) return; // Ignore keep-alive comments
            
            appendLog(message);

            // Check for completion messages to trigger data refresh
            if (message.includes("process completed") || message.includes("finished")) {
                setStatus('Action complete!', 'success');
                fetchAndDisplayOpenPorts();
                loadScanResults(lastScanType);
            }
        };

        eventSource.onerror = () => {
            appendLog('[!] Log stream connection failed. Please refresh.');
            setStatus('Log stream disconnected', 'error');
            eventSource.close();
        };
    }

    // --- Event Listeners ---
    
    function setupEventListeners() {
        elements.detectIpBtn.addEventListener('click', fetchAndDisplayLocalIp);

        elements.scanTcpBtn.addEventListener('click', () => initiateScan('TCP', 'default', elements.scanTcpBtn));
        elements.scanUdpBtn.addEventListener('click', () => initiateScan('UDP', 'default', elements.scanUdpBtn));

        elements.advancedScanToggle.addEventListener('click', () => {
            elements.advancedScanOptions.classList.toggle('hidden');
            elements.advancedScanArrow.classList.toggle('rotate-180');
        });

        elements.advancedScanOptions.addEventListener('click', (e) => {
            const button = e.target.closest('button[data-scan-type]');
            if (button) {
                const scanType = button.dataset.scanType;
                initiateScan('TCP', scanType, null); // Advanced scans are TCP-based
                elements.advancedScanOptions.classList.add('hidden'); // Hide dropdown after click
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
            if (await apiPost('/clear_log', {}, elements.clearLogBtn)) {
                elements.logOutput.innerHTML = '';
            }
        });

        elements.refreshResultsBtn.addEventListener('click', () => {
            setStatus('Refreshing data...', 'busy');
            Promise.all([
                fetchAndDisplayLocalIp(),
                fetchAndDisplayWhitelist(),
                fetchAndDisplayOpenPorts(),
                loadScanResults(lastScanType)
            ]).then(() => setStatus('Ready', 'ready'));
        });

        elements.copyResultsBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(elements.resultsContent.textContent).then(() => {
                const icon = elements.copyResultsBtn.querySelector('i');
                icon.className = 'fas fa-check text-green-500';
                setTimeout(() => { icon.className = 'far fa-copy text-sm'; }, 2000);
            });
        });
    }

    // --- Initialization ---
    function init() {
        appendLog('Initializing UI...');
        setupEventListeners();
        initializeLogStream();
        
        // Initial data fetch
        setStatus('Initializing...', 'busy');
        Promise.all([
            fetchAndDisplayLocalIp(),
            fetchAndDisplayWhitelist(),
            fetchAndDisplayOpenPorts(),
            loadScanResults(lastScanType)
        ]).then(() => {
            setStatus('Ready', 'ready');
            appendLog('Initialization complete. Ready for commands.');
        });
    }

    init();
});