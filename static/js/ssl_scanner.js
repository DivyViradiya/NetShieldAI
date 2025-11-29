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
    
    // --- Download & Analysis Elements ---
    const downloadReportBtn = document.getElementById('downloadReportBtn');
    const analyzeReportDropdown = document.getElementById('analyzeReportDropdown'); // 🚨 NEW
    const llmAnalysisOptions = document.getElementById('llmAnalysisOptions');     // 🚨 NEW
    const CHATBOT_REDIRECT_URL = '/chatbot';                                     // 🚨 NEW

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
    let reportDownloadUrl = null;

    // --- Core Functions ---

    /**
     * Toggles the loading state of a button.
     */
    function updateButtonState(button, isLoading) {
        const buttonText = button.querySelector('.button-text');
        const spinner = button.querySelector('.spinner');
        
        button.disabled = isLoading;
        if (buttonText) buttonText.classList.toggle('hidden', isLoading);
        if (spinner) spinner.classList.toggle('hidden', !isLoading);
        
        // Handle dropdown caret
        const caret = button.querySelector('.fa-caret-down');
        if (caret) caret.classList.toggle('hidden', isLoading);
    }

    /**
     * Resets all report sections.
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
        
        // Reset download and analysis buttons
        [downloadReportBtn, analyzeReportDropdown].forEach(btn => {
            if (btn) {
                btn.disabled = true;
                btn.classList.add('opacity-50', 'cursor-not-allowed');
                btn.classList.remove('hover:bg-red-500', 'hover:bg-indigo-500');
            }
        });
        reportDownloadUrl = null;
    }

    // --- Report Availability Check ---
    /**
     * Checks the server for available PDF report and updates the buttons.
     * 🚨 MODIFIED: Now manages the Analysis button state.
     */
    async function checkReportAvailability() {
        // Function to disable and reset a button
        const disableButton = (button, hoverClass) => {
            if (!button) return;
            button.disabled = true;
            button.classList.add('opacity-50', 'cursor-not-allowed');
            button.classList.remove(hoverClass);
        };

        // Disable both buttons initially
        disableButton(downloadReportBtn, 'hover:bg-red-500');
        disableButton(analyzeReportDropdown, 'hover:bg-indigo-500');

        try {
            const response = await fetch('/ssl_scanner/report_files');
            if (response.ok) {
                const data = await response.json();
                if (data.status === 'success' && data.pdf_report) {
                    reportDownloadUrl = data.pdf_report;
                    
                    // Enable Download Button
                    downloadReportBtn.disabled = false;
                    downloadReportBtn.classList.remove('opacity-50', 'cursor-not-allowed');
                    downloadReportBtn.classList.add('hover:bg-red-500');
                    
                    // Enable Analysis Button
                    analyzeReportDropdown.disabled = false;
                    analyzeReportDropdown.classList.remove('opacity-50', 'cursor-not-allowed');
                    analyzeReportDropdown.classList.add('hover:bg-indigo-500');
                    
                    return;
                }
            }
        } catch (error) {
            console.error('Error checking report availability:', error);
        }

        reportDownloadUrl = null;
    }
    
    /**
     * 🚨 NEW FUNCTION: Triggers the server-side proxy to upload the PDF for AI analysis.
     * @param {string} llmMode - The selected LLM mode ('local' or 'gemini').
     */
async function analyzeReport(llmMode) {
        const button = analyzeReportDropdown;
        if (button.disabled) return;
        
        logOutput.innerHTML += `<div>[*] Preparing SSL PDF for AI analysis (${llmMode})...</div>`;
        
        updateButtonState(button, true);
        downloadReportBtn.disabled = true;

        try {
            // 1. First, check local PDF availability via the local blueprint.
            let response = await fetch('/ssl_scanner/trigger_ai_analysis', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ llm_mode: llmMode })
            });
            let data = await response.json();
            
            if (data.status !== 'success') {
                throw new Error(data.message || 'PDF availability check failed.');
            }
            
            // 2. Now call the central proxy route on the chatbot blueprint.
            const CHATBOT_PROXY_URL = `${CHATBOT_REDIRECT_URL}/scanner_analysis`;
            response = await fetch(CHATBOT_PROXY_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ llm_mode: llmMode, scanner_type: data.scanner_type }) // Pass scanner_type
            });

            data = await response.json(); // Data now contains summary and llm_mode

            if (response.ok && data.status === 'success') {
                logOutput.innerHTML += `<div>[✓] AI analysis initiated. Summary received. Redirecting...</div>`;
                scanStatus.textContent = 'Analysis Complete';
                
                // 3. Redirect, passing summary and mode (from the server response)
                window.location.href = `${CHATBOT_REDIRECT_URL}?mode=${data.llm_mode}&summary=${encodeURIComponent(data.summary)}`;
                return;
            } else {
                throw new Error(data.message || `Analysis failed with status ${response.status}`);
            }
        } catch (error) {
            logOutput.innerHTML += `<div>[x] AI Analysis Error: ${error.message}</div>`;
            // Reset status color to error for the main status box
            scanStatus.textContent = 'Analysis Failed';
            scanStatus.className = 'text-center text-sm mt-4 p-2 rounded-md text-red-500 bg-red-100';
        } finally {
            // Only run cleanup if no redirect happened (i.e., if it failed)
            updateButtonState(button, false);
            checkReportAvailability(); 
        }
    }


    // --- Report Rendering Functions (Unchanged) ---
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
            `<strong>TLS Compression:</strong> ${configs.tls_compression?.supported ? `<span class="font-bold text-red-500">Enabled (CRIME risk)</span>` : '<span class="text-green-600">Disabled</span>'}`,
            `<strong>Secure Renegotiation:</strong> ${configs.renegotiation?.secure ? '<span class="text-green-600">Supported</span>' : '<span class="font-bold text-red-500">Not Secure</span>'}`,
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
            
            card.className = 'bg-slate-800 p-4 rounded-lg border border-slate-700';
            
            card.innerHTML = `
                <h4 class="text-md font-semibold mb-2 text-slate-100">${isLeaf ? 'Leaf Certificate' : `Intermediate #${index}`}</h4>
                <div class="space-y-1 text-sm text-slate-300">
                    <p><strong class="text-slate-400">Subject:</strong> <span class="font-medium text-slate-200">${cert.common_name}</span></p>
                    <p><strong class="text-slate-400">Issuer:</strong> <span class="font-medium text-slate-200">${cert.issuer}</span></p>
                    <p><strong class="text-slate-400">Validity:</strong> ${cert.not_before} to ${cert.not_after}</p>
                    <p><strong class="text-slate-400">Signature:</strong> ${cert.signature_algorithm} (${cert.key_size}-bit ${cert.key_type})</p>
                    <p><strong class="text-slate-400">Alt Names:</strong> ${cert.alt_names.length > 0 ? cert.alt_names.join(', ') : 'N/A'}</p>
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
                <td class="px-4 py-2 whitespace-nowrap text-sm font-medium text-slate-300">${p.name}</td>
                <td class="px-4 py-2 whitespace-nowrap text-sm ${p.enabled ? 'text-green-500 font-semibold' : 'text-red-500'}">${p.enabled ? 'Enabled' : 'Disabled'}</td>
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
                <td class="px-4 py-2 whitespace-nowrap text-sm text-slate-300">${c.protocol}</td>
                <td class="px-4 py-2 whitespace-nowrap text-sm font-medium ${c.bits < 128 ? 'text-red-500' : 'text-slate-300'}">${c.bits}-bit</td>
                <td class="px-4 py-2 whitespace-nowrap text-sm text-slate-400">${c.name}</td>
            `;
        });
    }

    /**
     * Fetches the report JSON from the backend.
     */
    async function fetchAndDisplayReport() {
        try {
            const response = await fetch('/ssl_scanner/report');
            const data = await response.json();

            if (data.status === 'success') {
                const report = data.content;
                
                summaryTarget.textContent = report.target || 'N/A';
                summaryIp.textContent = report.ip || 'N/A';
                summaryPort.textContent = report.port || 'N/A';

                renderVulnerabilities(report.vulnerabilities);
                renderServerConfig(report.server_configs);
                renderCertificateChain(report.certificate_chain);
                renderProtocols(report.protocols);
                renderCiphers(report.ciphers);

                resultsContent.textContent = JSON.stringify(report, null, 2);
                
                checkReportAvailability();
            } else {
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
            alert('Please enter a target host.');
            return;
        }

        clearScanResults();
        logOutput.innerHTML = '';
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
                logOutput.innerHTML = '';
            }
        } catch (error) {
            console.error('Error clearing log:', error);
        } finally {
            updateButtonState(clearLogBtn, false);
        }
    });

    if (copyResultsBtn) {
            const copyButtonText = copyResultsBtn.textContent;
            
            copyResultsBtn.addEventListener('click', () => {
                const textToCopy = resultsContent.textContent;
                
                if (!textToCopy || textToCopy.includes('Awaiting scan results')) {
                    console.log('No scan results to copy.');
                    return;
                }

                navigator.clipboard.writeText(textToCopy).then(() => {
                    const originalContent = copyResultsBtn.innerHTML;
                    copyResultsBtn.innerHTML = '<i class="fas fa-check text-green-500 mr-1"></i> COPIED!';
                    
                    setTimeout(() => { 
                        copyResultsBtn.innerHTML = originalContent; 
                    }, 2000);
                }).catch(err => {
                    console.error('Failed to copy text: ', err);
                    alert('Failed to copy to clipboard. Manual copy may be required.'); 
                });
            });
        }

    refreshReportBtn.addEventListener('click', () => {
        fetchAndDisplayReport();
        checkReportAvailability(); 
    });

    if (downloadReportBtn) {
        downloadReportBtn.addEventListener('click', () => {
            if (reportDownloadUrl) {
                window.location.href = reportDownloadUrl;
            } else {
                console.log('No report available to download.');
            }
        });
    }
    
    // 🚨 NEW: Analysis Dropdown Toggle
    if (analyzeReportDropdown) {
        analyzeReportDropdown.addEventListener('click', (e) => {
            if (!analyzeReportDropdown.disabled) {
                llmAnalysisOptions.classList.toggle('hidden');
                e.stopPropagation(); 
            }
        });
    }
    
    // 🚨 NEW: Analysis Option Selection
    if (llmAnalysisOptions) {
        llmAnalysisOptions.addEventListener('click', (e) => {
            e.preventDefault();
            const option = e.target.closest('a[data-llm-mode]');
            if (option) {
                const llmMode = option.dataset.llmMode;
                llmAnalysisOptions.classList.add('hidden'); 
                analyzeReport(llmMode); // Start the analysis and redirection
            }
        });
    }

    // Close dropdown when clicking outside
    document.addEventListener('click', (e) => {
        if (llmAnalysisOptions && analyzeReportDropdown && !analyzeReportDropdown.contains(e.target)) {
            llmAnalysisOptions.classList.add('hidden');
        }
    });

    // --- Server-Sent Events (SSE) Setup ---
    function setupLogStream() {
        if (eventSource) eventSource.close();
        eventSource = new EventSource('/ssl_scanner/log_stream');

        eventSource.onmessage = function(event) {
            const message = event.data;
            if (message && message !== ': keep-alive\n\n') {
                const logLine = document.createElement('div');
                logLine.textContent = message;
                logOutput.appendChild(logLine);
                logOutput.scrollTop = logOutput.scrollHeight;
                
                if (message.includes("PDF report generated successfully") || message.includes("SSL scan complete")) {
                    scanStatus.textContent = 'Scan Complete';
                    scanStatus.className = 'text-center text-sm mt-4 p-2 rounded-md text-green-500 bg-green-100';
                    updateButtonState(initiateScanBtn, false);
                    
                    fetchAndDisplayReport(); 
                    checkReportAvailability(); 
                }
            }
        };

        eventSource.onerror = function(err) {
            console.error('EventSource failed:', err);
            eventSource.close();
            setTimeout(setupLogStream, 5000); 
        };
    }

    // --- Initial Page Load ---
    setupLogStream();
    fetchAndDisplayReport(); 
    checkReportAvailability(); 
});