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
    const analyzeReportDropdown = document.getElementById('analyzeReportDropdown'); 
    const llmAnalysisOptions = document.getElementById('llmAnalysisOptions'); 
    const CHATBOT_REDIRECT_URL = '/chatbot'; 

    // Report-specific elements
    const summaryTarget = document.getElementById('summaryTarget');
    const summaryIp = document.getElementById('summaryIp');
    const summaryPort = document.getElementById('summaryPort');
    const summaryRenegotiation = document.getElementById('summaryRenegotiation'); // Added
    const serverConfigDetails = document.getElementById('serverConfigDetails');
    const certificateChainContainer = document.getElementById('certificateChainContainer');
    const protocolsTableBody = document.getElementById('protocolsTableBody');
    const ciphersTableBody = document.getElementById('ciphersTableBody');
    const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');

    let eventSource = null;
    let reportDownloadUrl = null;

    // --- Core Functions ---

    function toggleSpinner(button, isLoading) {
        if (!button) return;
        const spinner = button.querySelector('.spinner');
        const icon = button.querySelector('.material-symbols-outlined'); 
        const text = button.querySelector('.button-text'); 

        button.disabled = isLoading;

        if (isLoading) {
            button.classList.add('opacity-70', 'cursor-not-allowed');
            if (icon && !icon.classList.contains('expand_more')) icon.classList.add('hidden'); // Don't hide dropdown arrow
            if (spinner) spinner.classList.remove('hidden');
        } else {
            button.classList.remove('opacity-70', 'cursor-not-allowed');
            if (spinner) spinner.classList.add('hidden');
            if (icon) icon.classList.remove('hidden');
        }
    }

    function updateStatus(msg, type) {
        scanStatus.textContent = msg;
        scanStatus.style.color = '#a1a1aa';
        if (type === 'success') scanStatus.style.color = '#10b981';
        if (type === 'error') scanStatus.style.color = '#ef4444';
        if (type === 'busy') scanStatus.style.color = '#eab308';
    }

    /**
     * Resets all report sections.
     */
    function clearScanResults() {
        summaryTarget.textContent = '---';
        summaryIp.textContent = '---';
        summaryPort.textContent = '---';
        if(summaryRenegotiation) summaryRenegotiation.textContent = '---';
        
        serverConfigDetails.innerHTML = 'Waiting for scan...';
        certificateChainContainer.innerHTML = '<div style="text-align:center; color: #555; padding: 2rem;">Waiting for scan...</div>';
        protocolsTableBody.innerHTML = '<tr><td colspan="2" style="text-align:center; color: #555; padding: 2rem;">Waiting for scan...</td></tr>';
        ciphersTableBody.innerHTML = '<tr><td colspan="3" style="text-align:center; color: #555; padding: 2rem;">Waiting for scan...</td></tr>';
        vulnerabilitiesList.innerHTML = '<li style="color: #666;">Waiting for scan...</li>';
        resultsContent.textContent = '// Raw JSON report';
        
        [downloadReportBtn, analyzeReportDropdown].forEach(btn => {
            if (btn) {
                btn.disabled = true;
                btn.style.opacity = '0.7';
            }
        });
        reportDownloadUrl = null;
    }

    // --- Report Availability Check ---
    async function checkReportAvailability() {
        downloadReportBtn.disabled = true;
        downloadReportBtn.style.opacity = '0.7';
        analyzeReportDropdown.disabled = true;
        analyzeReportDropdown.style.opacity = '0.7';

        try {
            const response = await fetch('/ssl_scanner/report_files');
            if (response.ok) {
                const data = await response.json();
                if (data.status === 'success' && data.pdf_report) {
                    reportDownloadUrl = data.pdf_report;
                    
                    downloadReportBtn.disabled = false;
                    downloadReportBtn.style.opacity = '1';
                    
                    analyzeReportDropdown.disabled = false;
                    analyzeReportDropdown.style.opacity = '1';
                    return;
                }
            }
        } catch (error) {
            console.error('Error checking report availability:', error);
        }
        reportDownloadUrl = null;
    }
    
    async function analyzeReport(llmMode) {
        const button = analyzeReportDropdown;
        if (button.disabled) return;
        
        // append log manually
        const logLine = document.createElement('div');
        logLine.textContent = `[*] Preparing SSL PDF for AI analysis (${llmMode})...`;
        logLine.style.color = '#3b82f6';
        logOutput.appendChild(logLine);
        
        toggleSpinner(button, true);
        downloadReportBtn.disabled = true;

        try {
            // 1. Check local PDF
            let response = await fetch('/ssl_scanner/trigger_ai_analysis', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ llm_mode: llmMode })
            });
            let data = await response.json();
            
            if (data.status !== 'success') throw new Error(data.message);
            
            // 2. Call Proxy
            const CHATBOT_PROXY_URL = `${CHATBOT_REDIRECT_URL}/scanner_analysis`;
            response = await fetch(CHATBOT_PROXY_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ llm_mode: llmMode, scanner_type: data.scanner_type }) 
            });

            data = await response.json();

            if (response.ok && data.status === 'success') {
                updateStatus('Redirecting...', 'success');
                window.location.href = `${CHATBOT_REDIRECT_URL}?mode=${data.llm_mode}&summary=${encodeURIComponent(data.summary)}`;
                return;
            } else {
                throw new Error(data.message || `Analysis failed`);
            }
        } catch (error) {
            const errLine = document.createElement('div');
            errLine.textContent = `[x] AI Analysis Error: ${error.message}`;
            errLine.style.color = '#ef4444';
            logOutput.appendChild(errLine);
            updateStatus('Analysis Failed', 'error');
        } finally {
            toggleSpinner(button, false);
            checkReportAvailability(); 
        }
    }


    // --- Report Rendering Functions ---
    function renderVulnerabilities(vulnerabilities) {
        vulnerabilitiesList.innerHTML = '';
        if (!vulnerabilities || vulnerabilities.length === 0) {
            vulnerabilitiesList.innerHTML = '<li style="color: #10b981; font-weight: 500;">No vulnerabilities detected.</li>';
            return;
        }

        const riskColors = {
            'Critical': 'border-left: 3px solid #ef4444; color: #fca5a5;',
            'High': 'border-left: 3px solid #ef4444; color: #fca5a5;',
            'Medium': 'border-left: 3px solid #f97316; color: #fdba74;',
            'Low': 'border-left: 3px solid #eab308; color: #fde047;',
        };

        vulnerabilities.forEach(vuln => {
            const li = document.createElement('li');
            li.className = 'vuln-item';
            // Apply inline style based on severity
            const style = riskColors[vuln.severity] || 'border-left: 3px solid #3b82f6; color: #93c5fd;';
            li.style.cssText = style + ' padding: 0.75rem; background: rgba(255,255,255,0.05); margin-bottom: 0.5rem; list-style:none;';
            
            li.innerHTML = `
                <div style="font-size: 0.85rem; font-weight: 700; margin-bottom: 4px;">${vuln.name}</div>
                <div style="font-size: 0.8rem; opacity: 0.8;">${vuln.description}</div>
            `;
            vulnerabilitiesList.appendChild(li);
        });
    }

    function renderServerConfig(configs) {
        serverConfigDetails.innerHTML = '';
        
        const createItem = (label, val, isBad) => `
            <div style="display:flex; justify-content:space-between; padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.1);">
                <span>${label}</span>
                <span style="color: ${isBad ? '#ef4444' : '#10b981'}; font-weight:600;">${val}</span>
            </div>
        `;

        let html = '';
        html += createItem('TLS Compression', configs.tls_compression?.supported ? 'Enabled (Risk)' : 'Disabled', configs.tls_compression?.supported);
        html += createItem('Secure Renegotiation', configs.renegotiation?.secure ? 'Supported' : 'Insecure', !configs.renegotiation?.secure);
        html += createItem('OCSP Stapling', configs.ocsp_stapling?.supported ? 'Supported' : 'Not Supported', false); // Neutral
        html += createItem('Fallback SCSV', configs.fallback_scsv_supported ? 'Supported' : 'Not Supported', false);

        serverConfigDetails.innerHTML = html;
        
        // Update the top stat card for renegotiation
        if(summaryRenegotiation) {
            const secure = configs.renegotiation?.secure;
            summaryRenegotiation.textContent = secure ? "Secure" : "Insecure";
            summaryRenegotiation.style.color = secure ? "#10b981" : "#ef4444";
        }
    }

    function renderCertificateChain(chain) {
        certificateChainContainer.innerHTML = '';
        if (!chain || chain.length === 0) {
            certificateChainContainer.innerHTML = '<div style="text-align:center; color: #555;">No certificate info.</div>';
            return;
        }
        chain.forEach((cert, index) => {
            const isLeaf = index === 0;
            const card = document.createElement('div');
            card.className = 'cert-card';
            
            card.innerHTML = `
                <div style="color: ${isLeaf ? '#10b981' : '#a1a1aa'}; font-weight: 700; margin-bottom: 8px; font-size: 0.85rem; text-transform:uppercase;">
                    ${isLeaf ? 'Leaf Certificate' : `Intermediate #${index}`}
                </div>
                <div style="display: grid; gap: 4px;">
                    <div><span class="cert-label">Subject:</span><span class="cert-val">${cert.common_name}</span></div>
                    <div><span class="cert-label">Issuer:</span><span class="cert-val">${cert.issuer}</span></div>
                    <div><span class="cert-label">Validity:</span><span class="cert-val" style="font-size:0.75rem;">${cert.not_before} - ${cert.not_after}</span></div>
                    <div><span class="cert-label">Sig:</span><span class="cert-val" style="font-size:0.75rem;">${cert.signature_algorithm} (${cert.key_size}-bit)</span></div>
                </div>
            `;
            certificateChainContainer.appendChild(card);
        });
    }

    function renderProtocols(protocols) {
        protocolsTableBody.innerHTML = '';
        if (!protocols || protocols.length === 0) {
            protocolsTableBody.innerHTML = '<tr><td colspan="2" style="text-align:center; padding:1rem; color:#555;">None detected</td></tr>';
            return;
        }
        protocols.forEach(p => {
            const row = protocolsTableBody.insertRow();
            row.innerHTML = `
                <td>${p.name}</td>
                <td style="color: ${p.enabled ? '#10b981' : '#52525b'}; font-weight: ${p.enabled ? '600' : '400'}">
                    ${p.enabled ? 'Enabled' : 'Disabled'}
                </td>
            `;
        });
    }

    function renderCiphers(ciphers) {
        ciphersTableBody.innerHTML = '';
        if (!ciphers || ciphers.length === 0) {
            ciphersTableBody.innerHTML = '<tr><td colspan="3" style="text-align:center; padding:1rem; color:#555;">None detected</td></tr>';
            return;
        }
        ciphers.forEach(c => {
            const row = ciphersTableBody.insertRow();
            const weak = c.bits < 128;
            row.innerHTML = `
                <td style="color: #a1a1aa; font-size: 0.75rem;">${c.protocol}</td>
                <td style="color: ${weak ? '#ef4444' : '#10b981'};">${c.bits}</td>
                <td style="font-family: monospace; font-size: 0.75rem;">${c.name}</td>
            `;
        });
    }

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
        toggleSpinner(initiateScanBtn, true);
        updateStatus('Scanning...', 'busy');
        
        // Add initial log
        const initLog = document.createElement('div');
        initLog.textContent = `> Initiating SSL scan for ${targetHost}...`;
        initLog.style.color = '#a1a1aa';
        logOutput.appendChild(initLog);

        try {
            const response = await fetch('/ssl_scanner/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_host: targetHost })
            });
            const data = await response.json();

            if (data.status !== 'success') {
                updateStatus('Start Failed', 'error');
                toggleSpinner(initiateScanBtn, false);
            }
        } catch (error) {
            console.error('Error:', error);
            updateStatus('Conn Error', 'error');
            toggleSpinner(initiateScanBtn, false);
        }
    });

    clearLogBtn.addEventListener('click', async () => {
        logOutput.innerHTML = '';
        await fetch('/ssl_scanner/clear_log', { method: 'POST' });
    });

    copyResultsBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(resultsContent.textContent).then(() => {
            const original = copyResultsBtn.textContent;
            copyResultsBtn.textContent = 'COPIED!';
            setTimeout(() => copyResultsBtn.textContent = original, 2000);
        });
    });

    refreshReportBtn.addEventListener('click', () => {
        fetchAndDisplayReport();
    });

    if (downloadReportBtn) {
        downloadReportBtn.addEventListener('click', () => {
            if (reportDownloadUrl) window.location.href = reportDownloadUrl;
        });
    }
    
    if (analyzeReportDropdown) {
        analyzeReportDropdown.addEventListener('click', (e) => {
            if (!analyzeReportDropdown.disabled) {
                llmAnalysisOptions.classList.toggle('hidden');
                e.stopPropagation(); 
            }
        });
    }
    
    if (llmAnalysisOptions) {
        llmAnalysisOptions.addEventListener('click', (e) => {
            e.preventDefault();
            const option = e.target.closest('a[data-llm-mode]');
            if (option) {
                const llmMode = option.dataset.llmMode;
                llmAnalysisOptions.classList.add('hidden'); 
                analyzeReport(llmMode); 
            }
        });
    }

    document.addEventListener('click', (e) => {
        if (llmAnalysisOptions && analyzeReportDropdown && !analyzeReportDropdown.contains(e.target)) {
            llmAnalysisOptions.classList.add('hidden');
        }
    });

    // --- SSE ---
    function setupLogStream() {
        if (eventSource) eventSource.close();
        eventSource = new EventSource('/ssl_scanner/log_stream');

        eventSource.onmessage = function(event) {
            const message = event.data;
            if (message && message !== ': keep-alive\n\n') {
                const logLine = document.createElement('div');
                logLine.textContent = message;
                
                // Color coding
                if(message.includes('[!]')) logLine.style.color = '#ef4444';
                else if(message.includes('[+]')) logLine.style.color = '#10b981';
                else logLine.style.color = '#a1a1aa';

                logOutput.appendChild(logLine);
                logOutput.scrollTop = logOutput.scrollHeight;
                
                if (message.includes("PDF report generated") || message.includes("SSL scan complete")) {
                    updateStatus('Complete', 'success');
                    toggleSpinner(initiateScanBtn, false);
                    fetchAndDisplayReport(); 
                }
            }
        };
    }

    // --- Init ---
    setupLogStream();
    fetchAndDisplayReport(); 
    checkReportAvailability(); 
});