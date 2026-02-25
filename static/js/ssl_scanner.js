document.addEventListener('DOMContentLoaded', function() {
    // --- Element References ---
    var elements = {
        targetHostInput: document.getElementById('targetHost'),
        initiateScanBtn: document.getElementById('initiateScanBtn'),
        scanStatus: document.getElementById('scanStatus'),
        clearLogBtn: document.getElementById('clearLogBtn'),
        logOutput: document.getElementById('logOutput'),
        resultsContent: document.getElementById('resultsContent'),
        copyResultsBtn: document.getElementById('copyResultsBtn'),
        refreshReportBtn: document.getElementById('refreshReportBtn'),
        
        // Intelligence & Overlay
        downloadReportBtn: document.getElementById('downloadReportBtn'),
        analyzeReportDropdown: document.getElementById('analyzeReportDropdown'),
        llmAnalysisOptions: document.getElementById('llmAnalysisOptions'),
        aiProcessingOverlay: document.getElementById('aiProcessingOverlay'),
        aiProcessingText: document.getElementById('aiProcessingText'),

        // Report Data
        summaryTarget: document.getElementById('summaryTarget'),
        summaryIp: document.getElementById('summaryIp'),
        summaryPort: document.getElementById('summaryPort'),
        summaryRenegotiation: document.getElementById('summaryRenegotiation'),
        serverConfigDetails: document.getElementById('serverConfigDetails'),
        certificateChainContainer: document.getElementById('certificateChainContainer'),
        protocolsTableBody: document.getElementById('protocolsTableBody'),
        ciphersTableBody: document.getElementById('ciphersTableBody'),
        vulnerabilitiesList: document.getElementById('vulnerabilitiesList')
    };

    var CHATBOT_REDIRECT_URL = '/chatbot'; 
    var ANALYZE_ENDPOINT = '/ssl_scanner/trigger_ai_analysis';
    var REPORT_FILES_ENDPOINT = '/ssl_scanner/report_files';

    var eventSource = null;
    var reportDownloadUrl = null;

    // --- 🔒 CSRF TOKEN RETRIEVAL ---
    var csrfToken = document.querySelector('meta[name="csrf-token"]') 
        ? document.querySelector('meta[name="csrf-token"]').getAttribute('content') 
        : '';

    // --- Core Functions ---

    function toggleSpinner(button, isLoading) {
        if (!button) return;
        var spinner = button.querySelector('.spinner');
        var icon = button.querySelector('.material-symbols-outlined'); 
        
        button.disabled = isLoading;
        if (isLoading) {
            button.classList.add('opacity-70', 'cursor-not-allowed');
            if (icon && !icon.textContent.includes('expand_more')) icon.classList.add('hidden'); 
            if (spinner) spinner.classList.remove('hidden');
        } else {
            button.classList.remove('opacity-70', 'cursor-not-allowed');
            button.style.opacity = '1';
            if (spinner) spinner.classList.add('hidden');
            if (icon) icon.classList.remove('hidden');
        }
    }

    function updateStatus(msg, type) {
        if (!elements.scanStatus) return;
        elements.scanStatus.textContent = msg;
        elements.scanStatus.style.color = 'var(--neo-text-muted)';
        if (type === 'success') elements.scanStatus.style.color = '#10b981';
        if (type === 'error') elements.scanStatus.style.color = '#ef4444';
        if (type === 'busy') elements.scanStatus.style.color = '#eab308';
    }

    function appendLog(message) {
        if (!elements.logOutput) return;

        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });

        let cleanedMessage = message.replace(/\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s*/g, "");
        cleanedMessage = cleanedMessage.trim();

        let contentStyle = '';
        if (cleanedMessage.includes('[!]') || cleanedMessage.includes('Error')) {
            contentStyle = 'color:#ef4444';
        } else if (cleanedMessage.includes('[+]') || cleanedMessage.includes('Success')) {
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

    // --- State Management ---

    function clearScanResults() {
        if(elements.summaryTarget) elements.summaryTarget.textContent = '---';
        if(elements.summaryIp) elements.summaryIp.textContent = '---';
        if(elements.summaryPort) elements.summaryPort.textContent = '---';
        if(elements.summaryRenegotiation) elements.summaryRenegotiation.textContent = '---';
        
        if(elements.serverConfigDetails) elements.serverConfigDetails.innerHTML = 'Waiting for scan...';
        if(elements.certificateChainContainer) elements.certificateChainContainer.innerHTML = '<div style="text-align:center; color: var(--neo-text-muted); padding: 2rem; font-family: var(--font-mono); font-size: 0.8rem;">NO CERTIFICATE DATA AVAILABLE.</div>';
        if(elements.protocolsTableBody) elements.protocolsTableBody.innerHTML = '<tr><td colspan="2" style="text-align:center; color: #555; padding: 2rem; font-family: var(--font-mono);">---</td></tr>';
        if(elements.ciphersTableBody) elements.ciphersTableBody.innerHTML = '<tr><td colspan="3" style="text-align:center; color: #555; padding: 2rem; font-family: var(--font-mono);">---</td></tr>';
        if(elements.vulnerabilitiesList) elements.vulnerabilitiesList.innerHTML = '<div style="text-align:center; padding: 2rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.85rem;">WAITING FOR SCAN RESULTS...</div>';
        if(elements.resultsContent) elements.resultsContent.textContent = '// JSON OUTPUT';
        
        [elements.downloadReportBtn, elements.analyzeReportDropdown].forEach(function(btn) {
            if (btn) {
                btn.disabled = true;
                btn.style.opacity = '0.7';
            }
        });
        reportDownloadUrl = null;
    }

    async function checkReportAvailability() {
        var target = elements.targetHostInput.value.trim();
        try {
            var url = target ? REPORT_FILES_ENDPOINT + '?target=' + encodeURIComponent(target) : REPORT_FILES_ENDPOINT;
            var response = await fetch(url);
            if (response.ok) {
                var data = await response.json();
                if (data.status === 'success' && data.pdf_report) {
                    reportDownloadUrl = data.pdf_report;
                    
                    if (elements.downloadReportBtn) {
                        elements.downloadReportBtn.disabled = false;
                        elements.downloadReportBtn.style.opacity = '1';
                        elements.downloadReportBtn.classList.remove('opacity-70', 'cursor-not-allowed');
                    }
                    
                    if (elements.analyzeReportDropdown) {
                        elements.analyzeReportDropdown.disabled = false;
                        elements.analyzeReportDropdown.style.opacity = '1';
                        elements.analyzeReportDropdown.classList.remove('opacity-70', 'cursor-not-allowed');
                    }
                    return;
                }
            }
        } catch (error) {
            console.error('Error checking report availability:', error);
        }
        
        // If fail, disable buttons
        [elements.downloadReportBtn, elements.analyzeReportDropdown].forEach(function(btn) {
            if (btn) {
                btn.disabled = true;
                btn.style.opacity = '0.7';
            }
        });
        reportDownloadUrl = null;
    }

    // --- AI ANALYSIS LOGIC ---

    async function analyzeReport(llmMode) {
        if (elements.analyzeReportDropdown.disabled) return;
        var target = elements.targetHostInput.value.trim();

        if (!csrfToken) {
            appendLog('[!] Error: CSRF Token missing. Refresh page.');
            return;
        }

        // UI LOCKDOWN
        elements.llmAnalysisOptions.classList.add('hidden');
        elements.aiProcessingOverlay.classList.remove('hidden');
        elements.aiProcessingText.textContent = llmMode.includes('gemini') 
            ? 'CONTACTING GEMINI...' 
            : 'LOADING LOCAL MODEL...';
        
        toggleSpinner(elements.analyzeReportDropdown, true);
        updateStatus('AI Analysis (' + llmMode + ')...', 'busy');

        try {
            // 1. Trigger Context
            var response = await fetch(ANALYZE_ENDPOINT, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken 
                },
                body: JSON.stringify({ llm_mode: llmMode, target: target })
            });
            var data = await response.json();
            
            if (data.status !== 'success') throw new Error(data.message);
            
            // 2. Synthesize
            elements.aiProcessingText.textContent = 'SYNTHESIZING REPORT...';
            
            var CHATBOT_PROXY_URL = CHATBOT_REDIRECT_URL + '/scanner_analysis';
            response = await fetch(CHATBOT_PROXY_URL, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ 
                    llm_mode: llmMode, 
                    scanner_type: data.scanner_type,
                    target: data.target,
                    force_new_session: true // [NEW] Force a fresh chat
                }) 
            });

            data = await response.json();

            if (response.ok && data.status === 'success') {
                elements.aiProcessingText.textContent = 'REDIRECTING...';
                updateStatus('Redirecting...', 'success');
                setTimeout(function() {
                    const params = new URLSearchParams({
                        mode: data.llm_mode,
                        summary: data.summary,
                        session_id: data.session_id
                    });
                    window.location.href = CHATBOT_REDIRECT_URL + '?' + params.toString();
                }, 800);
            } else {
                throw new Error(data.message || 'Analysis failed');
            }
        } catch (error) {
            appendLog('[x] AI Analysis Error: ' + error.message);
            updateStatus('Analysis Failed', 'error');
            elements.aiProcessingOverlay.classList.add('hidden'); // Hide overlay to allow retry
        } finally {
            toggleSpinner(elements.analyzeReportDropdown, false);
            checkReportAvailability(); 
        }
    }

    // --- Rendering Helpers ---

    function getRiskColor(risk) {
        if (risk === 'Critical' || risk === 'High') return '#ef4444';
        if (risk === 'Medium') return '#f97316';
        if (risk === 'Low') return '#eab308';
        return '#3b82f6';
    }

    function createFindingCard(finding) {
        const risk = finding.severity || 'Info';
        const color = getRiskColor(risk);
        
        // [NEW] Risk Score Rendering
        const rawScore = finding.predicted_risk_score !== undefined ? finding.predicted_risk_score : 0;
        const displayScore = (rawScore * 10).toFixed(1);

        const card = document.createElement('div');
        card.className = 'finding-card';
        
        card.innerHTML = `
            <div class="finding-header" style="flex-wrap: wrap; gap: 1rem;">
                <div class="risk-indicator" style="color: ${color}; min-width: 80px;">
                    <div class="risk-dot" style="background: ${color};"></div>
                    <span>${risk}</span>
                </div>

                <div class="risk-indicator" style="color: var(--neo-text-muted); min-width: 100px;">
                    <span style="font-size: 0.6rem; opacity: 0.6; margin-right: 4px;">ML RISK:</span>
                    <span style="color: ${rawScore > 0.5 ? 'var(--neo-red)' : 'var(--neo-text-main)'}">${displayScore}</span>
                </div>
                
                <div class="finding-title" style="flex: 1; min-width: 200px;">${finding.name}</div>
                
                <span class="material-symbols-outlined expand-icon" style="font-size: 1.25rem;">expand_more</span>
            </div>
            
            <div class="finding-details">
                <div class="details-content">
                    <div class="detail-section">
                        <span class="detail-label">Vulnerability Analysis</span>
                        <div class="detail-text">${finding.description || 'Detailed vulnerability analysis is unavailable for this finding.'}</div>
                    </div>

                    ${finding.remediation ? `
                    <div class="detail-section">
                        <span class="detail-label">Remediation & Solution</span>
                        <div class="detail-text" style="border-left: 3px solid var(--neo-green); padding-left: 1rem; opacity: 1;">${finding.remediation}</div>
                    </div>` : ''}
                </div>
            </div>
        `;

        card.addEventListener('click', () => {
            card.classList.toggle('expanded');
        });

        return card;
    }

    function renderVulnerabilities(vulnerabilities) {
        elements.vulnerabilitiesList.innerHTML = '';
        if (!vulnerabilities || vulnerabilities.length === 0) {
            elements.vulnerabilitiesList.innerHTML = '<div style="text-align:center; padding: 2rem; color: #10b981; font-family: var(--font-mono); font-size: 0.85rem;">NO VULNERABILITIES DETECTED.</div>';
            return;
        }

        vulnerabilities.forEach(function(vuln) {
            const card = createFindingCard(vuln);
            elements.vulnerabilitiesList.appendChild(card);
        });
    }

    function renderServerConfig(configs) {
        elements.serverConfigDetails.innerHTML = '';
        
        function createItem(label, val, isBad) {
            var color = isBad ? 'var(--neo-red)' : 'var(--neo-green)';
            return '<div style="display:flex; justify-content:space-between; padding: 4px 0; border-bottom: 1px solid var(--neo-border);">' +
                   '<span>' + label + '</span>' +
                   '<span style="color: ' + color + '; font-weight:600;">' + val + '</span>' +
                   '</div>';
        }

        // --- FIXED: Replaced optional chaining (?.) with safe checks ---
        var tlsSupported = (configs.tls_compression && configs.tls_compression.supported);
        var renegotiationSecure = (configs.renegotiation && configs.renegotiation.secure);
        var ocspSupported = (configs.ocsp_stapling && configs.ocsp_stapling.supported);
        var fallbackSupported = (configs.fallback_scsv_supported);

        var html = '';
        html += createItem('TLS Compression', tlsSupported ? 'Enabled (Risk)' : 'Disabled', tlsSupported);
        html += createItem('Secure Renegotiation', renegotiationSecure ? 'Supported' : 'Insecure', !renegotiationSecure);
        html += createItem('OCSP Stapling', ocspSupported ? 'Supported' : 'Not Supported', false); 
        html += createItem('Fallback SCSV', fallbackSupported ? 'Supported' : 'Not Supported', false);

        elements.serverConfigDetails.innerHTML = html;
        
        if(elements.summaryRenegotiation) {
            elements.summaryRenegotiation.textContent = renegotiationSecure ? "Secure" : "Insecure";
            elements.summaryRenegotiation.style.color = renegotiationSecure ? "#10b981" : "#ef4444";
        }
    }

    function renderCertificateChain(chain) {
        elements.certificateChainContainer.innerHTML = '';
        if (!chain || chain.length === 0) {
            elements.certificateChainContainer.innerHTML = '<div style="text-align:center; color: var(--neo-text-muted);">No certificate info.</div>';
            return;
        }
        chain.forEach(function(cert, index) {
            var isLeaf = (index === 0);
            var card = document.createElement('div');
            card.className = 'cert-card';
            
            var titleColor = isLeaf ? 'var(--neo-green)' : 'var(--neo-text-muted)';
            var titleText = isLeaf ? 'Leaf Certificate' : 'Intermediate #' + index;

            card.innerHTML = 
                '<div style="color: ' + titleColor + '; font-weight: 700; margin-bottom: 8px; font-size: 0.85rem; text-transform:uppercase;">' +
                    titleText +
                '</div>' +
                '<div style="display: grid; gap: 4px;">' +
                    '<div><span class="cert-label">Subject:</span><span class="cert-val">' + cert.common_name + '</span></div>' +
                    '<div><span class="cert-label">Issuer:</span><span class="cert-val">' + cert.issuer + '</span></div>' +
                    '<div><span class="cert-label">Validity:</span><span class="cert-val" style="font-size:0.75rem;">' + cert.not_before + ' - ' + cert.not_after + '</span></div>' +
                    '<div><span class="cert-label">Sig:</span><span class="cert-val" style="font-size:0.75rem;">' + cert.signature_algorithm + ' (' + cert.key_size + '-bit)</span></div>' +
                '</div>';
            elements.certificateChainContainer.appendChild(card);
        });
    }

    function renderProtocols(protocols) {
        elements.protocolsTableBody.innerHTML = '';
        if (!protocols || protocols.length === 0) {
            elements.protocolsTableBody.innerHTML = '<tr><td colspan="2" style="text-align:center; padding:1rem; color:var(--neo-text-muted);">None detected</td></tr>';
            return;
        }
        protocols.forEach(function(p) {
            var row = elements.protocolsTableBody.insertRow();
            row.className = "hover:bg-slate-800/50 transition-colors";
            
            var color = p.enabled ? 'var(--neo-green)' : 'var(--neo-text-muted)';
            var weight = p.enabled ? '600' : '400';
            var status = p.enabled ? 'Enabled' : 'Disabled';

            row.innerHTML = 
                '<td style="color: var(--neo-text-main);">' + p.name + '</td>' +
                '<td style="color: ' + color + '; font-weight: ' + weight + '">' + status + '</td>';
        });
    }

    function renderCiphers(ciphers) {
        elements.ciphersTableBody.innerHTML = '';
        if (!ciphers || ciphers.length === 0) {
            elements.ciphersTableBody.innerHTML = '<tr><td colspan="3" style="text-align:center; padding:1rem; color:var(--neo-text-muted);">None detected</td></tr>';
            return;
        }
        ciphers.forEach(function(c) {
            var row = elements.ciphersTableBody.insertRow();
            var weak = c.bits < 128;
            row.className = "hover:bg-slate-800/50 transition-colors";
            
            var color = weak ? 'var(--neo-red)' : 'var(--neo-green)';

            row.innerHTML = 
                '<td style="color: var(--neo-text-muted); font-size: 0.75rem;">' + c.protocol + '</td>' +
                '<td style="color: ' + color + '; font-weight: 600;">' + c.bits + '</td>' +
                '<td style="font-family: monospace; font-size: 0.75rem; color: var(--neo-text-main);">' + c.name + '</td>';
        });
    }

    async function fetchAndDisplayReport() {
        try {
            var response = await fetch('/ssl_scanner/report');
            var data = await response.json();

            if (data.status === 'success') {
                var report = data.content;
                
                if(elements.summaryTarget) elements.summaryTarget.textContent = report.target || 'N/A';
                if(elements.summaryIp) elements.summaryIp.textContent = report.ip || 'N/A';
                if(elements.summaryPort) elements.summaryPort.textContent = report.port || 'N/A';

                renderVulnerabilities(report.vulnerabilities);
                renderServerConfig(report.server_configs);
                renderCertificateChain(report.certificate_chain);
                renderProtocols(report.protocols);
                renderCiphers(report.ciphers);

                elements.resultsContent.textContent = JSON.stringify(report, null, 2);
                checkReportAvailability();
            } else {
                clearScanResults();
                elements.resultsContent.textContent = data.message;
            }
        } catch (error) {
            console.error('Error fetching/parsing SSL report:', error);
        }
    }

    // --- Event Listeners ---

    if(elements.initiateScanBtn) {
        elements.initiateScanBtn.addEventListener('click', async function() {
            var targetHost = elements.targetHostInput.value.trim();
            if (!targetHost) {
                alert('Please enter a target host.');
                return;
            }
            if (!csrfToken) {
                elements.logOutput.innerHTML = '';
                appendLog('[!] Error: CSRF Token missing. Refresh page.');
                return;
            }

            clearScanResults();
            elements.logOutput.innerHTML = '';
            toggleSpinner(elements.initiateScanBtn, true);
            updateStatus('Scanning...', 'busy');
            
            appendLog('> Initiating SSL scan for ' + targetHost + '...');

            try {
                var response = await fetch('/ssl_scanner/scan', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken 
                    },
                    body: JSON.stringify({ target_host: targetHost })
                });
                var data = await response.json();

                if (data.status !== 'success') {
                    updateStatus('Start Failed', 'error');
                    toggleSpinner(elements.initiateScanBtn, false);
                    appendLog('[!] Error: ' + data.message);
                }
            } catch (error) {
                console.error('Error:', error);
                updateStatus('Conn Error', 'error');
                toggleSpinner(elements.initiateScanBtn, false);
            }
        });
    }

    if(elements.clearLogBtn) {
        elements.clearLogBtn.addEventListener('click', async function() {
            if (!csrfToken) return;
            elements.logOutput.innerHTML = '';
            await fetch('/ssl_scanner/clear_log', { 
                method: 'POST',
                headers: { 'X-CSRFToken': csrfToken }
            });
        });
    }

    if(elements.copyResultsBtn) {
        elements.copyResultsBtn.addEventListener('click', function() {
            navigator.clipboard.writeText(elements.resultsContent.textContent).then(function() {
                var original = elements.copyResultsBtn.innerHTML;
                elements.copyResultsBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 1rem; margin-right: 4px;">check</span> Copied!';
                setTimeout(function() { elements.copyResultsBtn.innerHTML = original; }, 2000);
            });
        });
    }

    if(elements.refreshReportBtn) {
        elements.refreshReportBtn.addEventListener('click', function() {
            fetchAndDisplayReport();
        });
    }

    if (elements.downloadReportBtn) {
        elements.downloadReportBtn.addEventListener('click', function() {
            if (reportDownloadUrl) window.location.href = reportDownloadUrl;
        });
    }
    
    // Dropdown Handling
    if (elements.analyzeReportDropdown) {
        elements.analyzeReportDropdown.addEventListener('click', function(e) {
            if (!elements.analyzeReportDropdown.disabled) {
                elements.llmAnalysisOptions.classList.toggle('hidden');
                e.stopPropagation(); 
                
                var closeAiMenu = function(docEvent) {
                    if (!elements.llmAnalysisOptions.contains(docEvent.target) && docEvent.target !== elements.analyzeReportDropdown) {
                        elements.llmAnalysisOptions.classList.add('hidden');
                        document.removeEventListener('click', closeAiMenu);
                    }
                };
                document.addEventListener('click', closeAiMenu);
            }
        });
    }
    
    if (elements.llmAnalysisOptions) {
        elements.llmAnalysisOptions.addEventListener('click', function(e) {
            e.preventDefault();
            var option = e.target.closest('a[data-llm-mode]');
            if (option) {
                var llmMode = option.dataset.llmMode;
                elements.llmAnalysisOptions.classList.add('hidden'); 
                analyzeReport(llmMode); 
            }
        });
    }

    // --- Log Streaming ---
    function setupLogStream() {
        if (eventSource) eventSource.close();
        eventSource = new EventSource('/ssl_scanner/log_stream');

        eventSource.onmessage = function(event) {
            var message = event.data;
            if (message && message !== ': keep-alive\n\n') {
                
                if (message.includes("PDF report generated") || message.includes("SSL scan complete")) {
                    updateStatus('Complete', 'success');
                    toggleSpinner(elements.initiateScanBtn, false);
                    fetchAndDisplayReport(); 
                }

                if (message.includes("EVENT:") || message.startsWith("EVENT:")) return;
                appendLog(message);
            }
        };
    }

    // --- Init ---
    setTimeout(function() { appendLog('System Ready. Initializing SSL Scanner...'); }, 100);
    setupLogStream();
    fetchAndDisplayReport(); 
    checkReportAvailability(); 
});