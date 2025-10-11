document.addEventListener('DOMContentLoaded', function() {
    // --- Element References ---
    const targetHostInput = document.getElementById('targetHost');
    const initiateScanBtn = document.getElementById('initiateScanBtn');
    const scanStatus = document.getElementById('scanStatus');
    const clearLogBtn = document.getElementById('clearLogBtn');
    const logOutput = document.getElementById('logOutput');
    const resultsContent = document.getElementById('resultsContent');
    const copyResultsBtn = document.getElementById('copyResultsBtn');
    const refreshReportBtn = document.getElementById('refreshReportBtn');

    // Report-specific elements
    const summaryTarget = document.getElementById('summaryTarget');
    const summaryIp = document.getElementById('summaryIp');
    const summaryPort = document.getElementById('summaryPort');
    const serverConfigDetails = document.getElementById('serverConfigDetails');
    const certificateChainContainer = document.getElementById('certificateChainContainer');
    const protocolsTableBody = document.getElementById('protocolsTableBody');
    const ciphersTableBody = document.getElementById('ciphersTableBody');
    const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');

    let eventSource = null;

    // --- Core Functions ---

    /**
     * Toggles the loading state of a button.
     * @param {HTMLButtonElement} button The button element.
     * @param {boolean} isLoading True to show spinner, false to show text.
     */
    function updateButtonState(button, isLoading) {
        const buttonText = button.querySelector('.button-text');
        const spinner = button.querySelector('.spinner');
        button.disabled = isLoading;
        if (buttonText) buttonText.classList.toggle('hidden', isLoading);
        if (spinner) spinner.classList.toggle('hidden', !isLoading);
    }

    /**
     * Resets all report sections to their default "awaiting results" state.
     */
    function clearScanResults() {
        summaryTarget.textContent = 'N/A';
        summaryIp.textContent = 'N/A';
        summaryPort.textContent = 'N/A';
        serverConfigDetails.innerHTML = '<p class="text-gray-500">Awaiting scan results...</p>';
        certificateChainContainer.innerHTML = '<p class="text-gray-500 text-sm">Awaiting scan results...</p>';
        protocolsTableBody.innerHTML = '<tr><td colspan="2" class="p-4 text-center text-gray-500">Awaiting scan results...</td></tr>';
        ciphersTableBody.innerHTML = '<tr><td colspan="3" class="p-4 text-center text-gray-500">Awaiting scan results...</td></tr>';
        vulnerabilitiesList.innerHTML = '<li class="text-gray-500">Awaiting scan results...</li>';
        resultsContent.textContent = 'Raw JSON report will appear here after a scan.';
    }

    // --- Report Rendering Functions ---

    function renderVulnerabilities(vulnerabilities) {
        vulnerabilitiesList.innerHTML = '';
        if (!vulnerabilities || vulnerabilities.length === 0) {
            vulnerabilitiesList.innerHTML = '<li class="text-green-600 font-medium"><i class="fas fa-check-circle mr-2"></i>No vulnerabilities detected.</li>';
            return;
        }

        const severityClasses = {
            'Critical': 'text-red-700 bg-red-100 border-red-500',
            'High': 'text-orange-700 bg-orange-100 border-orange-500',
            'Medium': 'text-yellow-700 bg-yellow-100 border-yellow-500',
            'Low': 'text-blue-700 bg-blue-100 border-blue-500',
        };

        vulnerabilities.forEach(vuln => {
            const li = document.createElement('li');
            li.className = `p-3 rounded-md border-l-4 ${severityClasses[vuln.severity] || 'text-gray-700 bg-gray-100 border-gray-500'}`;
            li.innerHTML = `<strong class="font-semibold">${vuln.name}</strong> <span class="block text-sm">${vuln.description}</span>`;
            vulnerabilitiesList.appendChild(li);
        });
    }

    function renderServerConfig(configs) {
        serverConfigDetails.innerHTML = '';
        const details = [
            `<strong>TLS Compression:</strong> ${configs.tls_compression?.supported ? `<span class="font-bold text-red-500">Enabled (${configs.tls_compression.method})</span>` : '<span class="text-green-600">Disabled</span>'}`,
            `<strong>Secure Renegotiation:</strong> ${configs.renegotiation?.secure ? '<span class="text-green-600">Supported</span>' : '<span class="font-bold text-red-500">Not Supported</span>'}`,
            `<strong>OCSP Stapling:</strong> ${configs.ocsp_stapling?.supported ? '<span class="text-green-600">Supported</span>' : 'Not Supported'}`,
            `<strong>Fallback SCSV:</strong> ${configs.fallback_scsv_supported ? '<span class="text-green-600">Supported</span>' : 'Not Supported'}`
        ];
        serverConfigDetails.innerHTML = details.map(d => `<p>${d}</p>`).join('');
    }

    function renderCertificateChain(chain) {
        certificateChainContainer.innerHTML = '';
        if (!chain || chain.length === 0) {
            certificateChainContainer.innerHTML = '<p class="text-gray-500 text-sm">No certificate information found.</p>';
            return;
        }
        chain.forEach((cert, index) => {
            const isLeaf = index === 0;
            const card = document.createElement('div');
            card.className = 'bg-gray-50 p-4 rounded-lg border';
            card.innerHTML = `
                <h4 class="text-md font-semibold mb-2">${isLeaf ? 'Leaf Certificate' : `Intermediate #${index}`}</h4>
                <div class="space-y-1 text-sm">
                    <p><strong>Subject:</strong> <span class="font-medium text-gray-700">${cert.common_name}</span></p>
                    <p><strong>Issuer:</strong> <span class="font-medium text-gray-700">${cert.issuer}</span></p>
                    <p><strong>Validity:</strong> ${cert.not_before} to ${cert.not_after}</p>
                    <p><strong>Signature:</strong> ${cert.signature_algorithm} (${cert.key_size}-bit ${cert.key_type})</p>
                    <p><strong>Alt Names:</strong> ${cert.alt_names.length > 0 ? cert.alt_names.join(', ') : 'N/A'}</p>
                </div>
            `;
            certificateChainContainer.appendChild(card);
        });
    }

    function renderProtocols(protocols) {
        protocolsTableBody.innerHTML = '';
        if (!protocols || protocols.length === 0) {
            protocolsTableBody.innerHTML = '<tr><td colspan="2" class="p-4 text-center text-gray-500">No protocols detected.</td></tr>';
            return;
        }
        protocols.forEach(p => {
            const row = protocolsTableBody.insertRow();
            row.innerHTML = `
                <td class="px-4 py-2 whitespace-nowrap text-sm font-medium text-gray-800">${p.name}</td>
                <td class="px-4 py-2 whitespace-nowrap text-sm ${p.enabled ? 'text-green-600 font-semibold' : 'text-gray-500'}">${p.enabled ? 'Enabled' : 'Disabled'}</td>
            `;
        });
    }

    function renderCiphers(ciphers) {
        ciphersTableBody.innerHTML = '';
        if (!ciphers || ciphers.length === 0) {
            ciphersTableBody.innerHTML = '<tr><td colspan="3" class="p-4 text-center text-gray-500">No ciphers detected.</td></tr>';
            return;
        }
        ciphers.forEach(c => {
            const row = ciphersTableBody.insertRow();
            row.innerHTML = `
                <td class="px-4 py-2 whitespace-nowrap text-sm">${c.protocol}</td>
                <td class="px-4 py-2 whitespace-nowrap text-sm font-medium ${c.bits < 128 ? 'text-red-500' : 'text-gray-800'}">${c.bits}-bit</td>
                <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-600">${c.name}</td>
            `;
        });
    }

    /**
     * Fetches the report JSON from the backend and populates the entire UI.
     */
    async function fetchAndDisplayReport() {
        try {
            const response = await fetch('/ssl_scanner/report');
            const data = await response.json();

            if (data.status === 'success') {
                const report = data.content;
                
                // Populate all sections with the new JSON data
                summaryTarget.textContent = report.target || 'N/A';
                summaryIp.textContent = report.ip || 'N/A';
                summaryPort.textContent = report.port || 'N/A';

                renderVulnerabilities(report.vulnerabilities);
                renderServerConfig(report.server_configs);
                renderCertificateChain(report.certificate_chain);
                renderProtocols(report.protocols);
                renderCiphers(report.ciphers);

                // Display the raw JSON report, pretty-printed
                resultsContent.textContent = JSON.stringify(report, null, 2);
            } else {
                // Clear results if report loading fails (e.g., no report exists)
                clearScanResults();
                resultsContent.textContent = data.message;
            }
        } catch (error) {
            console.error('Error fetching/parsing SSL report:', error);
        }
    }

    // --- Event Listeners ---

    initiateScanBtn.addEventListener('click', async () => {
        const targetHost = targetHostInput.value.trim();
        if (!targetHost) {
            alert('Please enter a target host.'); // Simple alert as popup is removed
            return;
        }

        clearScanResults();
        logOutput.innerHTML = ''; // Use innerHTML to clear child elements
        updateButtonState(initiateScanBtn, true);
        scanStatus.textContent = 'Scanning...';
        scanStatus.className = 'text-center text-sm mt-4 p-2 rounded-md text-yellow-500 bg-yellow-100';

        try {
            const response = await fetch('/ssl_scanner/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_host: targetHost })
            });
            const data = await response.json();

            if (data.status !== 'success') {
                scanStatus.textContent = 'Scan Failed';
                scanStatus.className = 'text-center text-sm mt-4 p-2 rounded-md text-red-500 bg-red-100';
                updateButtonState(initiateScanBtn, false);
            }
            // On success, the SSE event will update the status
        } catch (error) {
            console.error('Error initiating SSL scan:', error);
            scanStatus.textContent = 'Scan Failed';
            scanStatus.className = 'text-center text-sm mt-4 p-2 rounded-md text-red-500 bg-red-100';
            updateButtonState(initiateScanBtn, false);
        }
    });

    clearLogBtn.addEventListener('click', async () => {
        updateButtonState(clearLogBtn, true);
        try {
            const response = await fetch('/ssl_scanner/clear_log', { method: 'POST' });
            const data = await response.json();
            if (data.status === 'success') {
                logOutput.innerHTML = ''; // Use innerHTML to clear child elements
            }
        } catch (error) {
            console.error('Error clearing log:', error);
        } finally {
            updateButtonState(clearLogBtn, false);
        }
    });

    copyResultsBtn.addEventListener('click', () => {
        const textToCopy = resultsContent.textContent;
        if (!textToCopy || textToCopy.includes('Awaiting scan results')) {
            return;
        }
        const textarea = document.createElement('textarea');
        textarea.value = textToCopy;
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
        } catch (err) {
            console.error('Failed to copy report.', err);
        } finally {
            document.body.removeChild(textarea);
        }
    });

    refreshReportBtn.addEventListener('click', fetchAndDisplayReport);

    // --- Server-Sent Events (SSE) Setup ---
    function setupLogStream() {
        if (eventSource) eventSource.close();
        eventSource = new EventSource('/ssl_scanner/log_stream');

        eventSource.onmessage = function(event) {
            const message = event.data;
            if (message) {
                const logLine = document.createElement('div');
                logLine.textContent = message;
                logOutput.appendChild(logLine);
                logOutput.scrollTop = logOutput.scrollHeight; // Auto-scroll to bottom
            }
        };

        eventSource.addEventListener('ssl_scan_complete', function(event) {
            const data = JSON.parse(event.data);
            scanStatus.textContent = 'Scan Complete';
            scanStatus.className = 'text-center text-sm mt-4 p-2 rounded-md text-green-500 bg-green-100';
            updateButtonState(initiateScanBtn, false);
            fetchAndDisplayReport(); // Automatically fetch the new report
        });

        eventSource.onerror = function(err) {
            console.error('EventSource failed:', err);
            eventSource.close();
            setTimeout(setupLogStream, 5000); // Reconnect after 5 seconds
        };
    }

    // --- Initial Page Load ---
    setupLogStream();
    clearScanResults();
    fetchAndDisplayReport(); // Load existing report if available
});
