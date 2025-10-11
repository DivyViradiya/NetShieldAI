// static/js/script.js

document.addEventListener('DOMContentLoaded', () => {
    // Base URL for all API endpoints
    const API_BASE_URL = '/network_scanner';

    const detectIpBtn = document.getElementById('detectIpBtn');
    const scanTcpBtn = document.getElementById('scanTcpBtn');
    const scanUdpBtn = document.getElementById('scanUdpBtn');
    const blockPortsBtn = document.getElementById('blockPortsBtn');
    const verifyPortsBtn = document.getElementById('verifyPortsBtn');
    const addWhitelistBtn = document.getElementById('addWhitelistBtn');
    const clearWhitelistBtn = document.getElementById('clearWhitelistBtn');
    const clearLogBtn = document.getElementById('clearLogBtn');
    const refreshResultsBtn = document.getElementById('refreshResultsBtn');
    const copyResultsBtn = document.getElementById('copyResultsBtn');
    const resultsContent = document.getElementById('resultsContent');
    const resultsTabs = document.getElementById('resultsTabs');
    const logOutput = document.getElementById('logOutput');
    const localIpDisplay = document.getElementById('localIpDisplay');
    const targetIpInput = document.getElementById('targetIp');
    const whitelistPortsInput = document.getElementById('whitelistPorts');
    const whitelistedPortsDisplay = document.getElementById('whitelistedPortsDisplay');
    const openPortsTableBody = document.getElementById('openPortsTableBody');
    const scanStatus = document.getElementById('scanStatus');

    // Current active tab
    let activeTab = 'tcp';

    // Helper function to toggle loading state on a button
    function toggleLoading(button, isLoading) {
        if (!button) return; // Skip if button doesn't exist
        const buttonText = button.querySelector('.button-text');
        const spinner = button.querySelector('.spinner');
        if (buttonText && spinner) {
            if (isLoading) {
                buttonText.classList.add('hidden');
                spinner.classList.remove('hidden');
                button.disabled = true;
            } else {
                buttonText.classList.remove('hidden');
                spinner.classList.add('hidden');
                button.disabled = false;
            }
        }
    }

    // Function to enable/disable all action buttons and inputs
    function setAllButtonsState(disabled) {
        const buttons = [
            detectIpBtn, scanTcpBtn, scanUdpBtn, blockPortsBtn,
            verifyPortsBtn, addWhitelistBtn, clearWhitelistBtn, clearLogBtn
        ].filter(btn => btn !== null); // Filter out any null buttons
        
        buttons.forEach(btn => {
            if (btn) {
                btn.disabled = disabled;
                // Ensure spinners are hidden when all buttons are disabled/enabled
                if (!disabled) {
                    toggleLoading(btn, false);
                }
            }
        });
        
        if (targetIpInput) targetIpInput.disabled = disabled;
        if (whitelistPortsInput) whitelistPortsInput.disabled = disabled;

        if (scanStatus) {
            if (disabled) {
                scanStatus.textContent = "Processing...";
                scanStatus.classList.remove('text-green-400', 'text-red-400');
                scanStatus.classList.add('text-yellow-400');
            } else {
                scanStatus.textContent = "Ready";
                scanStatus.classList.remove('text-yellow-400', 'text-red-400');
                scanStatus.classList.add('text-green-400');
            }
        }
    }

    // Function to append log messages
    function appendLog(message) {
        const p = document.createElement('p');
        p.textContent = message;
        logOutput.appendChild(p);
        logOutput.scrollTop = logOutput.scrollHeight; // Scroll to bottom
    }

    // Initialize log stream via Server-Sent Events (SSE)
    const eventSource = new EventSource(`${API_BASE_URL}/log_stream`);
    eventSource.onmessage = function(event) {
        // Handle standard log messages (event.data contains the log message)
        appendLog(event.data);
    };

    // Listen for custom 'ports_updated' event
    eventSource.addEventListener('ports_updated', function(event) {
        try {
            const updatedPorts = JSON.parse(event.data);
            appendLog("[*] Received 'ports_updated' event. Updating table...");
            updateOpenPortsTable(updatedPorts);
            // After ports are updated, if a scan was in progress, set status to ready
            if (scanStatus.textContent === "Scanning..." || scanStatus.textContent === "Processing...") {
                scanStatus.textContent = "Scan Complete";
                scanStatus.classList.remove('text-yellow-400');
                scanStatus.classList.add('text-green-400');
            }
            setAllButtonsState(false); // Re-enable all buttons after scan/update
        } catch (e) {
            console.error("Error parsing 'ports_updated' event data:", e);
            appendLog("[!] Error: Could not parse port update data.");
            setAllButtonsState(false); // Re-enable on error too
        }
    });

    eventSource.onerror = function(err) {
        console.error("EventSource failed:", err);
        appendLog("[!] Error: Log stream disconnected. Please refresh the page or check server.");
        eventSource.close(); // Close to prevent continuous error attempts
        setAllButtonsState(false); // Re-enable buttons if SSE fails
    };

    // Function to fetch open ports from the server
    function fetchOpenPorts() {
        console.log("Fetching open ports...");
        
        fetch('/network_scanner/open_ports')
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                console.log("Received open ports data:", data);
                
                if (data.status === 'success') {
                    console.log("Ports data structure:", {
                        hasTCP: Array.isArray(data.ports.TCP) && data.ports.TCP.length > 0,
                        hasUDP: Array.isArray(data.ports.UDP) && data.ports.UDP.length > 0,
                        tcpCount: data.ports.TCP ? data.ports.TCP.length : 0,
                        udpCount: data.ports.UDP ? data.ports.UDP.length : 0
                    });
                    
                    // Ensure we have valid arrays for TCP and UDP
                    if (!Array.isArray(data.ports.TCP)) {
                        console.warn("TCP ports is not an array, initializing empty array");
                        data.ports.TCP = [];
                    }
                    if (!Array.isArray(data.ports.UDP)) {
                        console.warn("UDP ports is not an array, initializing empty array");
                        data.ports.UDP = [];
                    }
                    
                    updateOpenPortsTable(data.ports);
                    console.log(`Updated ports table with ${data.ports.TCP.length} TCP and ${data.ports.UDP.length} UDP ports`);
                } else {
                    console.error("Error fetching open ports:", data.message || "Unknown error");
                    // Clear the table on error
                    openPortsTableBody.innerHTML = `
                        <tr>
                            <td colspan="6" class="px-4 py-2 whitespace-nowrap text-sm text-red-400 text-center">
                                Error fetching open ports: ${data.message || 'Unknown error'}
                            </td>
                        </tr>
                    `;
                }
            })
            .catch(error => {
                console.error("Error fetching open ports:", error);
                // Clear the table on error
                openPortsTableBody.innerHTML = `
                    <tr>
                        <td colspan="6" class="px-4 py-2 whitespace-nowrap text-sm text-red-400 text-center">
                            Failed to fetch open ports: ${error.message}
                        </td>
                    </tr>
                `;
            });
    }

    // Function to update the open ports table
    function updateOpenPortsTable(portsData) {
        console.log("Updating ports table with data:", portsData);
        
        // Clear existing rows
        openPortsTableBody.innerHTML = '';
        
        // Check if we have valid data
        if (!portsData || (Object.keys(portsData.TCP).length === 0 && Object.keys(portsData.UDP).length === 0)) {
            openPortsTableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="px-4 py-2 whitespace-nowrap text-sm text-gray-400 text-center">No open ports detected.</td>
                </tr>
            `;
            return;
        }
        
        // Combine TCP and UDP ports into a single array
        const allPorts = [];
        let rowNumber = 1;
        
        // Process TCP ports
        if (portsData.TCP && Array.isArray(portsData.TCP)) {
            portsData.TCP.forEach(port => {
                if (port && port.port) {
                    allPorts.push({
                        number: rowNumber++,
                        port: port.port,
                        protocol: 'TCP',
                        service: port.service || 'unknown',
                        version: port.version || '',
                        process: port.process_name || port.process || 'N/A'
                    });
                }
            });
        }
        
        // Process UDP ports
        if (portsData.UDP && Array.isArray(portsData.UDP)) {
            portsData.UDP.forEach(port => {
                if (port && port.port) {
                    allPorts.push({
                        number: rowNumber++,
                        port: port.port,
                        protocol: 'UDP',
                        service: port.service || 'unknown',
                        version: port.version || '',
                        process: port.process_name || port.process || 'N/A'
                    });
                }
            });
        }
        
        // If no valid ports were found
        if (allPorts.length === 0) {
            openPortsTableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="px-4 py-2 whitespace-nowrap text-sm text-gray-400 text-center">No open ports detected.</td>
                </tr>
            `;
            return;
        }
        
        // Sort all ports by port number
        allPorts.sort((a, b) => parseInt(a.port) - parseInt(b.port));
        
        // Update row numbers after sorting
        allPorts.forEach((port, index) => {
            port.number = index + 1;
            
            const row = document.createElement('tr');
            row.className = 'hover:bg-gray-700';
            row.innerHTML = `
                <td class="px-4 py-2 whitespace-nowrap text-sm font-medium text-gray-300">${port.number}</td>
                <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-300">${port.port}</td>
                <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-300">${port.protocol}</td>
                <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-300">${port.service}</td>
                <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-300">${port.version}</td>
                <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-300">${port.process}</td>
            `;
            
            openPortsTableBody.appendChild(row);
        });
        
        console.log(`Updated table with ${allPorts.length} ports`);
    }

    // Function to fetch and display whitelisted ports
    async function fetchWhitelistedPorts() {
        try {
            const response = await fetch(`${API_BASE_URL}/whitelisted_ports`);
            const data = await response.json();
            whitelistedPortsDisplay.textContent = data.whitelisted_ports.length > 0 ? data.whitelisted_ports.join(', ') : 'None';
        } catch (error) {
            console.error('Error fetching whitelisted ports:', error);
            appendLog(`[!] Error fetching whitelisted ports: ${error.message}`);
        }
    }

    // Function to load scan results
    async function loadScanResults(scanType) {
        try {
            resultsContent.textContent = 'Loading...';
            const response = await fetch(`${API_BASE_URL}/get_scan_results?type=${scanType}`);
            const data = await response.json();
            
            if (response.ok && data.content) {
                resultsContent.textContent = data.content;
            } else {
                resultsContent.textContent = data.message || 'No results available for this scan type.';
            }
        } catch (error) {
            console.error('Error loading scan results:', error);
            resultsContent.textContent = 'Error loading results. Please try again.';
        }
    }

    // Function to switch tabs
    function switchTab(tabType) {
        // Update active tab styling
        document.querySelectorAll('#resultsTabs button').forEach(tab => {
            tab.classList.remove('active', 'text-blue-400', 'border-blue-500');
            tab.classList.add('border-transparent');
            tab.setAttribute('aria-selected', 'false');
        });
        
        const activeTabElement = document.querySelector(`#${tabType}-tab`);
        if (activeTabElement) {
            activeTabElement.classList.add('active', 'text-blue-400', 'border-blue-500');
            activeTabElement.classList.remove('border-transparent');
            activeTabElement.setAttribute('aria-selected', 'true');
        }
        
        // Show/hide IP range controls
        const ipRangeControls = document.getElementById('ip-range-controls');
        if (tabType === 'ip_range') {
            ipRangeControls.classList.remove('hidden');
            resultsContent.textContent = 'Enter an IP range and click Start Scan to begin.';
        } else {
            ipRangeControls.classList.add('hidden');
            // Load the content for the selected tab
            loadScanResults(tabType);
        }
        
        activeTab = tabType;
    }

    // Function to start IP range scan
    async function startIpRangeScan() {
        const ipRangeInput = document.getElementById('ipRangeInput');
        const ipRange = ipRangeInput.value.trim();
        
        if (!ipRange) {
            appendLog('[!] Please enter an IP range');
            return;
        }
        
        try {
            // Show loading state
            const startButton = document.getElementById('startIpRangeScan');
            const originalText = startButton.innerHTML;
            startButton.disabled = true;
            startButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
            
            // Start the scan
            const response = await fetch(`${API_BASE_URL}/scan/range`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    target_range: ipRange,
                    scan_type: 'default' // or get from UI if you add scan type selection
                })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                appendLog(`[+] ${data.message}`);
                // Automatically switch to the results tab after a short delay
                setTimeout(() => {
                    switchTab('tcp');
                    loadScanResults('tcp');
                }, 1000);
            } else {
                appendLog(`[!] Error: ${data.message || 'Failed to start IP range scan'}`);
            }
        } catch (error) {
            console.error('Error starting IP range scan:', error);
            appendLog('[!] Failed to start IP range scan');
        } finally {
            // Reset button state
            const startButton = document.getElementById('startIpRangeScan');
            startButton.disabled = false;
            startButton.innerHTML = 'Start Scan';
        }
    }

    // Copy results to clipboard
    function copyResultsToClipboard() {
        const textToCopy = resultsContent.textContent;
        navigator.clipboard.writeText(textToCopy).then(() => {
            // Show feedback
            const originalText = copyResultsBtn.innerHTML;
            copyResultsBtn.innerHTML = '<i class="fas fa-check"></i>';
            copyResultsBtn.classList.remove('text-gray-400');
            copyResultsBtn.classList.add('text-green-400');
            
            // Reset button after 2 seconds
            setTimeout(() => {
                copyResultsBtn.innerHTML = originalText;
                copyResultsBtn.classList.remove('text-green-400');
                copyResultsBtn.classList.add('text-gray-400');
            }, 2000);
        }).catch(err => {
            console.error('Failed to copy text: ', err);
            appendLog('[!] Failed to copy results to clipboard');
        });
    }

    // Initial data load on page load
    async function initializeApp() {
        setAllButtonsState(true); // Disable buttons during initialization
        appendLog("[*] Initializing NetShield...");
        try {
            // Fetch local IP
            const ipResponse = await fetch(`${API_BASE_URL}/local_ip`);
            const ipData = await ipResponse.json();
            localIpDisplay.textContent = ipData.local_ip;
            targetIpInput.value = ipData.local_ip; // Pre-fill target with local IP
            appendLog(`[+] Local IP Detected: ${ipData.local_ip}`);

            // Fetch whitelisted ports
            await fetchWhitelistedPorts();

            // Fetch open ports (in case there were previous scans)
            await fetchOpenPorts();

        } catch (error) {
            console.error('Error during initialization:', error);
            appendLog(`[!] Initialization failed: ${error.message}`);
        } finally {
            setAllButtonsState(false); // Re-enable buttons
            appendLog("[*] NetShield ready.");
        }
    }

    // --- Event Listeners ---

    detectIpBtn.addEventListener('click', async () => {
        setAllButtonsState(true);
        toggleLoading(detectIpBtn, true);
        try {
            const response = await fetch(`${API_BASE_URL}/local_ip`);
            const data = await response.json();
            localIpDisplay.textContent = data.local_ip;
            targetIpInput.value = data.local_ip; // Pre-fill target with local IP
            appendLog(`[+] Local IP Detected: ${data.local_ip}`);
        } catch (error) {
            console.error('Error detecting IP:', error);
            appendLog(`[!] Error detecting IP: ${error.message}`);
        } finally {
            toggleLoading(detectIpBtn, false);
            setAllButtonsState(false);
        }
    });

    // Toggle advanced scan options
    if (advancedScanToggle) {
        advancedScanToggle.addEventListener('click', () => {
            const isExpanded = advancedScanOptions.classList.toggle('hidden');
            advancedScanArrow.style.transform = isExpanded ? 'rotate(0deg)' : 'rotate(180deg)';
        });
    }

    // Handle advanced scan option clicks
    if (advancedScanOptions) {
        advancedScanOptions.addEventListener('click', async (e) => {
            const button = e.target.closest('button[data-scan-type]');
            if (!button) return;

            const scanType = button.getAttribute('data-scan-type');
            const targetIp = targetIpInput.value.trim() || localIpDisplay.textContent;
            
            if (!targetIp || targetIp === 'Not detected') {
                appendLog("[!] Please detect your local IP or enter a target IP first.");
                return;
            }

            // Update UI
            setAllButtonsState(true);
            const buttonText = button.textContent.trim();
            appendLog(`[+] Starting ${buttonText}...`);
            scanStatus.textContent = `Running ${buttonText}...`;
            scanStatus.className = 'text-center text-xl font-bold mt-4 p-2 rounded-md bg-gray-700 text-yellow-400';

            try {
                const response = await fetch(`${API_BASE_URL}/scan/advanced`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        target_ip: targetIp,
                        scan_type: scanType
                    })
                });

                const data = await response.json();
                if (!response.ok) {
                    throw new Error(data.message || 'Failed to start advanced scan');
                }
                
                appendLog(`[+] ${data.message}`);
                // The actual results will be streamed via SSE
            } catch (error) {
                console.error('Advanced scan error:', error);
                appendLog(`[!] Error during ${buttonText}: ${error.message}`);
                scanStatus.textContent = 'Scan Failed';
                scanStatus.className = 'text-center text-xl font-bold mt-4 p-2 rounded-md bg-gray-700 text-red-400';
            } finally {
                setAllButtonsState(false);
            }
        });
    }

    // Update the scan buttons to use the scan_type parameter
    [scanTcpBtn, scanUdpBtn].forEach(btn => {
        if (!btn) return;
        
        btn.addEventListener('click', async () => {
            const protocol = btn === scanTcpBtn ? 'TCP' : 'UDP';
            const targetIp = targetIpInput.value.trim() || localIpDisplay.textContent;
            
            if (!targetIp || targetIp === 'Not detected') {
                appendLog("[!] Please detect your local IP or enter a target IP first.");
                return;
            }

            setAllButtonsState(true);
            toggleLoading(btn, true);
            appendLog(`[+] Starting ${protocol} scan...`);
            scanStatus.textContent = `Running ${protocol} Scan...`;
            scanStatus.className = 'text-center text-xl font-bold mt-4 p-2 rounded-md bg-gray-700 text-yellow-400';

            try {
                const response = await fetch(`${API_BASE_URL}/scan`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        target_ip: targetIp,
                        protocol_type: protocol,
                        scan_type: 'default'  // Explicitly set default scan type
                    })
                });

                const data = await response.json();
                if (!response.ok) {
                    throw new Error(data.message || 'Failed to start scan');
                }
                
                appendLog(`[+] ${data.message}`);
                // The actual results will be streamed via SSE
            } catch (error) {
                console.error('Scan error:', error);
                appendLog(`[!] Error during ${protocol} scan: ${error.message}`);
                scanStatus.textContent = 'Scan Failed';
                scanStatus.className = 'text-center text-xl font-bold mt-4 p-2 rounded-md bg-gray-700 text-red-400';
            } finally {
                setAllButtonsState(false);
                toggleLoading(btn, false);
            }
        });
    });

    scanUdpBtn.addEventListener('click', async () => {
        setAllButtonsState(true);
        toggleLoading(scanUdpBtn, true);
        const targetIp = targetIpInput.value.trim();
        try {
            const response = await fetch(`${API_BASE_URL}/scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_ip: targetIp, protocol_type: 'UDP' })
            });
            const data = await response.json();
            if (response.ok) {
                appendLog(`[+] ${data.message}`);
                // The ports_updated SSE event will trigger fetchOpenPorts and re-enable buttons
            } else {
                appendLog(`[!] Error initiating UDP scan: ${data.message}`);
                scanStatus.textContent = "Scan Failed";
                scanStatus.classList.remove('text-yellow-400', 'text-green-400');
                scanStatus.classList.add('text-red-400');
                toggleLoading(scanUdpBtn, false); // Turn off spinner on error
                setAllButtonsState(false); // Re-enable buttons on error
            }
        } catch (error) {
            console.error('Error during UDP scan initiation:', error);
            appendLog(`[!] Network error during UDP scan: ${error.message}`);
            scanStatus.textContent = "Scan Failed";
            scanStatus.classList.remove('text-yellow-400', 'text-green-400');
            scanStatus.classList.add('text-red-400');
            toggleLoading(scanUdpBtn, false); // Turn off spinner on error
            setAllButtonsState(false); // Re-enable buttons on error
        }
    });

    blockPortsBtn.addEventListener('click', async () => {
        setAllButtonsState(true);
        toggleLoading(blockPortsBtn, true);
        try {
            const response = await fetch(`${API_BASE_URL}/block_ports`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            const data = await response.json();
            if (response.ok) {
                appendLog(`[+] ${data.message}`);
            } else {
                appendLog(`[!] Error blocking ports: ${data.message}`);
            }
        } catch (error) {
            console.error('Error during port blocking:', error);
            appendLog(`[!] Network error during port blocking: ${error.message}`);
        } finally {
            toggleLoading(blockPortsBtn, false);
            setAllButtonsState(false);
        }
    });

    verifyPortsBtn.addEventListener('click', async () => {
        setAllButtonsState(true);
        toggleLoading(verifyPortsBtn, true);
        const targetIp = targetIpInput.value.trim();
        try {
            const response = await fetch(`${API_BASE_URL}/verify_ports`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_ip: targetIp })
            });
            const data = await response.json();
            if (response.ok) {
                appendLog(`[+] ${data.message}`);
            } else {
                appendLog(`[!] Error verifying ports: ${data.message}`);
            }
        } catch (error) {
            console.error('Error during port verification:', error);
            appendLog(`[!] Network error during port verification: ${error.message}`);
        } finally {
            toggleLoading(verifyPortsBtn, false);
            setAllButtonsState(false);
        }
    });

    addWhitelistBtn.addEventListener('click', async () => {
        setAllButtonsState(true);
        toggleLoading(addWhitelistBtn, true);
        const portsToAdd = whitelistPortsInput.value.trim();
        if (portsToAdd) {
            try {
                const response = await fetch(`${API_BASE_URL}/add_whitelist`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ports: portsToAdd })
                });
                const data = await response.json();
                if (response.ok) {
                    appendLog(`[+] ${data.message}`);
                    whitelistPortsInput.value = ''; // Clear input
                    fetchWhitelistedPorts(); // Update display
                } else {
                    appendLog(`[!] Error adding to whitelist: ${data.message}`);
                }
            } catch (error) {
                console.error('Error adding to whitelist:', error);
                appendLog(`[!] Network error adding to whitelist: ${error.message}`);
            }
        } else {
            appendLog("[*] Whitelist input is empty.");
        }
        toggleLoading(addWhitelistBtn, false);
        setAllButtonsState(false);
    });

    clearWhitelistBtn.addEventListener('click', async () => {
        setAllButtonsState(true);
        toggleLoading(clearWhitelistBtn, true);
        try {
            const response = await fetch(`${API_BASE_URL}/clear_whitelist`, {
                method: 'POST'
            });
            const data = await response.json();
            if (response.ok) {
                appendLog(`[+] ${data.message}`);
                fetchWhitelistedPorts(); // Update display to show 'None'
            } else {
                appendLog(`[!] Error clearing whitelist: ${data.message}`);
            }
        } catch (error) {
            console.error('Error clearing whitelist:', error);
            appendLog(`[!] Network error clearing whitelist: ${error.message}`);
        } finally {
            toggleLoading(clearWhitelistBtn, false);
            setAllButtonsState(false);
        }
    });

    clearLogBtn.addEventListener('click', async () => {
        setAllButtonsState(true);
        toggleLoading(clearLogBtn, true);
        try {
            const response = await fetch(`${API_BASE_URL}/clear_log`, {
                method: 'POST'
            });
            const data = await response.json();
            if (response.ok) {
                    logOutput.innerHTML = ''; // Clear log display
                appendLog(`[+] ${data.message}`);
            } else {
                appendLog(`[!] Error clearing log: ${data.message}`);
            }
        } catch (error) {
            console.error('Error clearing log:', error);
            appendLog(`[!] Network error clearing log: ${error.message}`);
        } finally {
            toggleLoading(clearLogBtn, false);
            setAllButtonsState(false);
        }
    });

    // Event Listeners for Results Section
    if (resultsTabs) {
        resultsTabs.addEventListener('click', (e) => {
            const tabButton = e.target.closest('button[data-tab]');
            if (tabButton) {
                const tabType = tabButton.getAttribute('data-tab');
                switchTab(tabType);
            }
        });
    }

    if (refreshResultsBtn) {
        refreshResultsBtn.addEventListener('click', () => {
            loadScanResults(activeTab);
        });
    }

    if (copyResultsBtn) {
        copyResultsBtn.addEventListener('click', copyResultsToClipboard);
    }

    // Add event listener for IP range scan button
    const startIpRangeScanBtn = document.getElementById('startIpRangeScan');
    if (startIpRangeScanBtn) {
        startIpRangeScanBtn.addEventListener('click', startIpRangeScan);
    }
    
    // Allow pressing Enter in the IP range input to start the scan
    const ipRangeInput = document.getElementById('ipRangeInput');
    if (ipRangeInput) {
        ipRangeInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                startIpRangeScan();
            }
        });
    }

    // Initialize the application state on page load
    initializeApp();
});
