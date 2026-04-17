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
        execSummaryBtn: document.getElementById('execSummaryBtn'),
        execSummaryLabel: document.getElementById('execSummaryLabel'),
        execSummaryIcon: document.getElementById('execSummaryIcon'),
        execSummarySpinner: document.getElementById('execSummarySpinner'),
        
        analyzeReportDropdown: document.getElementById('analyzeReportDropdown'),
        llmAnalysisOptions: document.getElementById('llmAnalysisOptions'),
        aiProcessingOverlay: document.getElementById('aiProcessingOverlay'),
        aiProcessingText: document.getElementById('aiProcessingText'),

        // History
        sslHistoryBtn: document.getElementById('sslHistoryBtn'),
        historyModal: document.getElementById('historyModal'),
        closeHistoryModal: document.getElementById('closeHistoryModal'),
        historyTableBody: document.getElementById('historyTableBody'),

        // Report Data
        summaryTarget: document.getElementById('summaryTarget'),
        summaryIp: document.getElementById('summaryIp'),
        summaryPort: document.getElementById('summaryPort'),
        summaryRenegotiation: document.getElementById('summaryRenegotiation'),
        vulnCountDisplay: document.getElementById('vulnCountDisplay'),
        serverConfigDetails: document.getElementById('serverConfigDetails'),
        certificateChainContainer: document.getElementById('certificateChainContainer'),
        protocolsTableBody: document.getElementById('protocolsTableBody'),
        ciphersTableBody: document.getElementById('ciphersTableBody'),
        vulnerabilitiesList: document.getElementById('vulnerabilitiesList')
    };

    var CHATBOT_REDIRECT_URL = '/chatbot'; 
    var ANALYZE_ENDPOINT = '/ssl_scanner/trigger_ai_analysis';
    var REPORT_FILES_ENDPOINT = '/ssl_scanner/report_files';
    var API_BASE_URL = '/ssl_scanner';

    var eventSource = null;
    var reportDownloadUrl = null;
    var lastScanLogId = null;

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
        cleanedMessage = cleanedMessage.replace(/^\[?\d{1,2}:\d{2}:\d{2}\]?\s*/, '');
        cleanedMessage = cleanedMessage.replace(/(\[[A-Z]+\])\s*\1/g, '$1');
        cleanedMessage = cleanedMessage.trim();

        if (!cleanedMessage || cleanedMessage === '|' || cleanedMessage.includes('deprecated method')) return;

        // Professional Log Formatting
        const logMap = {
            '[!]': { color: '#ef4444', icon: 'error' },
            '[x]': { color: '#ef4444', icon: 'cancel' },
            '[✓]': { color: '#10b981', icon: 'check_circle' },
            '[+]': { color: '#10b981', icon: 'add_circle' },
            '[*]': { color: '#3b82f6', icon: 'info' }
        };

        let activeIcon = 'radio_button_checked';
        let activeColor = '#999';

        for (const key in logMap) {
            if (cleanedMessage.includes(key)) {
                activeIcon = logMap[key].icon;
                activeColor = logMap[key].color;
                cleanedMessage = cleanedMessage.replace(key, '').trim();
                break;
            }
        }

        const line = document.createElement('div');
        line.className = 'log-line';
        
        line.innerHTML = `
            <div class="log-time">${timeStr}</div>
            <div class="log-content" style="color: ${activeColor}; display: flex; align-items: center; gap: 8px;">
                <span class="material-symbols-outlined" style="font-size: 0.9rem; opacity: 0.6;">${activeIcon}</span>
                <span>${cleanedMessage.toUpperCase()}</span>
            </div>
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
        if(elements.vulnCountDisplay) elements.vulnCountDisplay.textContent = '0';
        
        if(elements.serverConfigDetails) elements.serverConfigDetails.innerHTML = '<div class="flex items-center gap-2"><span class="spinner-sm"></span><span>Waiting for scan...</span></div>';
        if(elements.certificateChainContainer) elements.certificateChainContainer.innerHTML = '<div style="text-align:center; color: var(--neo-text-muted); padding: 2rem; font-family: var(--font-mono); font-size: 0.8rem;">NO DATA.</div>';
        if(elements.protocolsTableBody) elements.protocolsTableBody.innerHTML = '<tr><td colspan="2" style="text-align:center; color: var(--neo-text-muted); padding: 2rem; font-family: var(--font-mono);">---</td></tr>';
        if(elements.ciphersTableBody) elements.ciphersTableBody.innerHTML = '<tr><td colspan="3" style="text-align:center; color: var(--neo-text-muted); padding: 2rem; font-family: var(--font-mono);">---</td></tr>';
        if(elements.vulnerabilitiesList) elements.vulnerabilitiesList.innerHTML = `
            <div class="w-full flex flex-col items-center justify-center" style="grid-column: 1 / -1; padding: 6rem 2rem;">
                <div class="ai-pulse-container" style="opacity: 0.3;">
                  <div class="ai-pulse-ring"></div>
                  <span class="material-symbols-outlined" style="font-size: 3rem; color: var(--neo-text-muted);">radar</span>
                </div>
                <div style="font-family: var(--font-mono); font-size: 0.9rem; color: var(--neo-text-muted); text-transform: uppercase; letter-spacing: 0.2em; text-align: center;">
                  INITIATE A SCAN TO VIEW RESULTS...
                </div>
            </div>
        `;
        if(elements.resultsContent) elements.resultsContent.textContent = '// JSON OUTPUT';
        
        [elements.downloadReportBtn, elements.analyzeReportDropdown, elements.execSummaryBtn].forEach(function(btn) {
            if (btn) {
                btn.disabled = true;
                btn.style.opacity = '0.5';
            }
        });
        reportDownloadUrl = null;
    }

    function updateExecSummaryButton(state, downloadUrl = null) {
        if (!elements.execSummaryBtn) return;

        elements.execSummaryBtn.dataset.state = state;
        elements.execSummaryBtn.classList.remove('btn-intel-processing', 'btn-intel-success-glass', 'btn-intel-premium');
        elements.execSummaryBtn.disabled = false;
        elements.execSummaryBtn.style.opacity = "1";

        if (state === 'ready') {
            elements.execSummaryBtn.classList.add('btn-intel-premium');
            elements.execSummaryLabel.textContent = 'GENERATE BRIEF';
            elements.execSummaryIcon.classList.remove('hidden');
            elements.execSummarySpinner.classList.add('hidden');
            elements.execSummaryBtn.dataset.downloadUrl = '';
        } 
        else if (state === 'generating') {
            elements.execSummaryBtn.classList.add('btn-intel-processing');
            elements.execSummaryLabel.textContent = 'SYNTHESIZING...';
            elements.execSummaryIcon.classList.add('hidden');
            elements.execSummarySpinner.classList.remove('hidden');
            elements.execSummaryBtn.disabled = true;
        } 
        else if (state === 'download') {
            elements.execSummaryBtn.classList.add('btn-intel-success-glass');
            elements.execSummaryLabel.textContent = 'DOWNLOAD BRIEF';
            elements.execSummaryIcon.textContent = 'file_download';
            elements.execSummaryIcon.classList.remove('hidden');
            elements.execSummarySpinner.classList.add('hidden');
            elements.execSummaryBtn.dataset.downloadUrl = downloadUrl;
        }
        else {
            // Disabled state
            elements.execSummaryBtn.classList.add('btn-intel-premium');
            elements.execSummaryBtn.style.opacity = "0.5";
            elements.execSummaryBtn.disabled = true;
            elements.execSummaryLabel.textContent = 'SSL SEC BRIEF';
        }
    }

    async function generateExecutiveSummary() {
        if (!lastScanLogId) {
            appendLog("[!] SCAN LOG ID MISSING. CANNOT GENERATE BRIEF.");
            return;
        }

        updateExecSummaryButton('generating');
        appendLog("[*] INITIATING EXECUTIVE BRIEF SYNTHESIS...");

        try {
            const target = elements.targetHostInput.value.trim();
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
                appendLog("[✓] EXECUTIVE BRIEF SYNTHESIZED SUCCESSFULLY.");
                updateExecSummaryButton('download', data.download_url);
            } else {
                throw new Error(data.message || "SYNTHESIS FAILED");
            }
        } catch (err) {
            appendLog(`[x] BRIEF ERROR: ${err.message.toUpperCase()}`);
            updateExecSummaryButton('ready');
        }
    }

    async function checkReportAvailability() {
        const target = elements.targetHostInput.value.trim();
        try {
            const url = target ? `${REPORT_FILES_ENDPOINT}?target=${encodeURIComponent(target)}` : REPORT_FILES_ENDPOINT;
            const response = await fetch(url);
            if (response.ok) {
                const data = await response.json();
                if (data.status === 'success') {
                    // Technical Report
                    if (data.pdf_report) {
                        reportDownloadUrl = data.pdf_report;
                        if (elements.downloadReportBtn) {
                            elements.downloadReportBtn.disabled = false;
                            elements.downloadReportBtn.style.opacity = '1';
                        }
                        if (elements.analyzeReportDropdown) {
                            elements.analyzeReportDropdown.disabled = false;
                            elements.analyzeReportDropdown.style.opacity = '1';
                        }
                    }

                    // AI Executive Summary
                    lastScanLogId = data.scan_log_id;
                    if (data.exec_summary_report) {
                        updateExecSummaryButton('download', data.exec_summary_report);
                    } else if (lastScanLogId) {
                        updateExecSummaryButton('ready');
                    } else {
                        updateExecSummaryButton('disabled');
                    }
                    return;
                }
            }
            updateExecSummaryButton('disabled');
        } catch (error) { 
            console.error(error); 
            updateExecSummaryButton('disabled');
        }
    }
    // --- HISTORY LOGIC ---

    async function fetchHistory() {
        if (!elements.historyTableBody) return;
        elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-text-muted);">LOADING HISTORY...</td></tr>';
        
        try {
            const res = await fetch(`${API_BASE_URL}/report_history`);
            const data = await res.json();
            
            if (data.status === 'success' && data.history) {
                if (data.history.length === 0) {
                    elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-text-muted);">NO PRIOR SCANS FOUND</td></tr>';
                    return;
                }
                
                elements.historyTableBody.innerHTML = '';
                data.history.forEach(item => {
                    const row = document.createElement('tr');
                    // Extract target from filename (ssl_report_target.pdf)
                    let target = item.filename.split('_').slice(2).join('_').replace('.pdf', '');                    target = target.replace(/_\d{8}_\d{6}$/, '');
                    if (!target) target = 'Previous Scan';
                    
                    row.innerHTML = `
                        <td>${item.created_at}</td>
                        <td class="font-mono text-blue-400">${target}</td>
                        <td style="text-align: right;">
                            <a href="${API_BASE_URL}/download_pdf?filename=${item.filename}" class="btn-dash btn-secondary" style="display: inline-flex; height: 32px; padding: 0 10px;">
                                <span class="material-symbols-outlined" style="font-size: 1.1rem;">download</span>
                            </a>
                        </td>
                    `;
                    elements.historyTableBody.appendChild(row);
                });
            } else {
                elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-red);">FAILED TO LOAD HISTORY</td></tr>';
            }
        } catch (e) {
            console.error('History fetch failed:', e);
            elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-red);">ERROR LOADING HISTORY</td></tr>';
        }
    }

    if (elements.sslHistoryBtn) {
        elements.sslHistoryBtn.addEventListener('click', () => {
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

    // --- AI ANALYSIS LOGIC ---

    async function analyzeReport(llmMode) {
        var target = elements.targetHostInput.value.trim();
        if (!target) {
            alert("Please perform a scan or enter a target host first.");
            return;
        }

        if (!csrfToken) {
            appendLog('[!] Error: CSRF Token missing. Refresh page.');
            return;
        }

        // UI LOCKDOWN
        elements.llmAnalysisOptions.classList.add('hidden');
        elements.llmAnalysisOptions.classList.remove('show');
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
            appendLog('[x] AI ANALYSIS ERROR: ' + error.message.toUpperCase());
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

    function createFindingCard(finding, index) {
        const severity = (finding.severity || 'Info').toLowerCase();
        const score = finding.predicted_risk_score !== undefined ? finding.predicted_risk_score : 0;
        const displayScore = (score * 10).toFixed(1);
        
        let riskClass = 'risk-safe';
        let riskLabel = 'LOW';
        if (severity === 'critical') { riskClass = 'risk-critical'; riskLabel = 'CRITICAL'; }
        else if (severity === 'high') { riskClass = 'risk-high'; riskLabel = 'HIGH'; }
        else if (severity === 'medium') { riskClass = 'risk-medium'; riskLabel = 'MEDIUM'; }
        else if (severity === 'low') { riskClass = 'risk-low'; riskLabel = 'LOW'; }
        else { riskClass = 'risk-info'; riskLabel = 'INFO'; }

        const card = document.createElement('div');
        card.className = `discovery-card ${riskClass} animate-card`;
        card.style.animationDelay = (index * 0.05) + 's';
        
        card.innerHTML = `
            <div class="card-header">
                <div class="finding-main">
                    <span class="finding-severity">${severity.toUpperCase()}</span>
                    <h4 class="finding-title">${finding.name}</h4>
                </div>
                <div class="risk-badge">
                    <span class="risk-val">${displayScore}</span>
                    <span class="risk-label">ML RISK</span>
                </div>
            </div>

            <div class="risk-section">
                <div class="risk-header">
                    <div class="flex items-center gap-2">
                        <span class="risk-tag" style="--card-accent-rgb: ${riskClass === 'risk-critical' ? '239, 68, 68' : '150, 150, 150'}">${riskLabel}</span>
                        <span style="color: var(--card-accent); font-weight: 700;">RISK LEVEL</span>
                    </div>
                    <span>${displayScore}/10</span>
                </div>
                <div class="risk-score-bar">
                    <div class="risk-score-fill" style="width: ${score * 100}%"></div>
                </div>
            </div>
            
            <div class="analysis-footer">
                <div style="font-weight: 800; font-size: 0.6rem; color: var(--card-accent); margin-bottom: 0.25rem;">[AI ANALYSIS]</div>
                ${finding.description || 'No detailed analysis available.'}
            </div>

            <div class="finding-details">
                ${finding.remediation ? `
                <div style="margin-top: 0.5rem;">
                    <span style="font-size: 0.6rem; font-weight: 800; color: var(--neo-text-muted); text-transform: uppercase; display: block; margin-bottom: 4px;">REMEDIATION</span>
                    <p style="margin: 0; line-height: 1.4; color: var(--neo-text-main);">${finding.remediation}</p>
                </div>
                ` : ''}
            </div>
        `;

        card.addEventListener('click', () => {
            card.classList.toggle('expanded');
        });

        return card;
    }

    function renderVulnerabilities(vulnerabilities) {
        if (!elements.vulnerabilitiesList) return;
        elements.vulnerabilitiesList.innerHTML = '';
        
        if (elements.vulnCountDisplay) {
            elements.vulnCountDisplay.textContent = vulnerabilities ? vulnerabilities.length : 0;
        }

        if (!vulnerabilities || vulnerabilities.length === 0) {
            elements.vulnerabilitiesList.innerHTML = `
                <div class="w-full flex flex-col items-center justify-center" style="grid-column: 1 / -1; padding: 6rem 2rem;">
                    <div class="ai-pulse-container" style="opacity: 0.3;">
                      <div class="ai-pulse-ring"></div>
                      <span class="material-symbols-outlined" style="font-size: 3rem; color: var(--neo-text-muted);">verified_user</span>
                    </div>
                    <div style="font-family: var(--font-mono); font-size: 0.9rem; color: var(--neo-text-muted); text-transform: uppercase; letter-spacing: 0.2em; text-align: center;">
                      NO VULNERABILITIES DETECTED
                    </div>
                </div>
            `;
            return;
        }

        vulnerabilities.forEach((vuln, index) => {
            const card = createFindingCard(vuln, index);
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

            // Handle potential string vs object data
            const subject = typeof cert.common_name === 'object' ? JSON.stringify(cert.common_name) : cert.common_name;
            const issuer = typeof cert.issuer === 'object' ? JSON.stringify(cert.issuer) : cert.issuer;

            card.innerHTML = 
                '<div style="color: ' + titleColor + '; font-weight: 700; margin-bottom: 8px; font-size: 0.85rem; text-transform:uppercase;">' +
                    titleText +
                '</div>' +
                '<div style="display: grid; gap: 4px;">' +
                    '<div><span class="cert-label">Subject:</span><span class="cert-val">' + (subject || 'N/A') + '</span></div>' +
                    '<div><span class="cert-label">Issuer:</span><span class="cert-val">' + (issuer || 'N/A') + '</span></div>' +
                    '<div><span class="cert-label">Validity:</span><span class="cert-val" style="font-size:0.75rem;">' + cert.not_before + ' - ' + cert.not_after + '</span></div>' +
                    '<div><span class="cert-label">Sig:</span><span class="cert-val" style="font-size:0.75rem;">' + (cert.signature_algorithm || 'N/A') + ' (' + (cert.key_size || '0') + '-bit)</span></div>' +
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
            var targetHost = elements.targetHostInput ? elements.targetHostInput.value.trim() : '';
            var url = targetHost ? '/ssl_scanner/report?target=' + encodeURIComponent(targetHost) : '/ssl_scanner/report';
            var response = await fetch(url);
            var data = await response.json();

            if (data.status === 'success') {
                var report = data.content;
                
                if(elements.summaryTarget) elements.summaryTarget.textContent = report.target || 'N/A';
                if(elements.targetHostInput && !elements.targetHostInput.value) {
                    elements.targetHostInput.value = report.target || '';
                }
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
            toggleSpinner(elements.initiateScanBtn, false);
            updateStatus('Ready');
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
            toggleSpinner(elements.initiateScanBtn, false);
            updateStatus('Ready');
        };
    }

    async function handleScanInitiation(userConfirmedAuth = false) {
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

        if (!userConfirmedAuth) {
            appendLog('> Initiating SSL scan for ' + targetHost + '...');
            
            if(elements.serverConfigDetails) elements.serverConfigDetails.innerHTML = '<div class="flex items-center gap-2" style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--neo-text-muted);"><div class="spinner-sm"></div><span>SCANNING TARGET...</span></div>';
            if(elements.vulnerabilitiesList) {
                elements.vulnerabilitiesList.innerHTML = `
                    <div class="w-full flex flex-col items-center justify-center animate-card" style="grid-column: 1 / -1; padding: 6rem 2rem;">
                        <div class="ai-pulse-container" style="opacity: 0.8;">
                          <div class="ai-pulse-ring"></div>
                          <span class="material-symbols-outlined" style="font-size: 3rem; color: var(--neo-blue);">radar</span>
                        </div>
                        <div style="font-family: var(--font-mono); font-size: 0.9rem; color: var(--neo-blue); text-transform: uppercase; letter-spacing: 0.2em; text-align: center; margin-top: 1rem;">
                          SCANNING TARGET...
                        </div>
                    </div>
                `;
            }
        }

        toggleSpinner(elements.initiateScanBtn, true);
        updateStatus('Scanning...', 'busy');

        try {
            var response = await fetch('/ssl_scanner/scan', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken 
                },
                body: JSON.stringify({ 
                    target_host: targetHost,
                    user_confirmed_auth: userConfirmedAuth
                })
            });
            var data = await response.json();

            if (response.ok) {
                if (data.status !== 'success') {
                    updateStatus('Start Failed', 'error');
                    toggleSpinner(elements.initiateScanBtn, false);
                    appendLog('[!] Error: ' + data.message);
                }
            } else {
                if (data.status === 'auth_required') {
                    showAuthModal(data.message, () => handleScanInitiation(true));
                    return;
                }
                if (data.status === 'blocked') {
                    showBlockedModal(data.message);
                    return;
                }
                updateStatus('Start Failed', 'error');
                toggleSpinner(elements.initiateScanBtn, false);
                appendLog('[!] Error: ' + (data.message || 'Scan failed to start.'));
            }
        } catch (error) {
            console.error('Error:', error);
            updateStatus('Conn Error', 'error');
            toggleSpinner(elements.initiateScanBtn, false);
        }
    }

    if(elements.initiateScanBtn) {
        elements.initiateScanBtn.addEventListener('click', () => handleScanInitiation(false));
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

    if (elements.refreshReportBtn) {
        elements.refreshReportBtn.addEventListener('click', function() {
            var icon = elements.refreshReportBtn.querySelector('.material-symbols-outlined');
            if (icon) icon.classList.add('animate-spin');
            
            Promise.all([
                fetchAndDisplayReport(),
                checkReportAvailability()
            ]).finally(function() {
                setTimeout(function() {
                    if (icon) icon.classList.remove('animate-spin');
                }, 800);
            });
        });
    }

    if (elements.downloadReportBtn) {
        elements.downloadReportBtn.addEventListener('click', function() {
            if (reportDownloadUrl) window.location.href = reportDownloadUrl;
        });
    }

    if (elements.execSummaryBtn) {
        elements.execSummaryBtn.addEventListener('click', function() {
            var state = elements.execSummaryBtn.dataset.state || 'ready';
            if (state === 'ready') {
                generateExecutiveSummary();
            } else if (state === 'download') {
                var downloadUrl = elements.execSummaryBtn.dataset.downloadUrl;
                if (downloadUrl) {
                    window.location.href = downloadUrl;
                    appendLog('[✓] DOWNLOADING EXECUTIVE BRIEF...');
                }
            }
        });
    }

    if (elements.analyzeReportDropdown) {
        elements.analyzeReportDropdown.addEventListener('click', function(e) {
            if (!elements.analyzeReportDropdown.disabled) {
                if (elements.llmAnalysisOptions) elements.llmAnalysisOptions.classList.toggle('hidden');
                e.stopPropagation();
            }
        });
    }

    // Dropdown Selection Handling (delegated to items)
    if (elements.llmAnalysisOptions) {
        elements.llmAnalysisOptions.addEventListener('click', function(e) {
            e.preventDefault();
            var option = e.target.closest('[data-llm-mode]');
            if (option) {
                var llmMode = option.dataset.llmMode;
                elements.llmAnalysisOptions.classList.add('hidden'); 
                elements.llmAnalysisOptions.classList.remove('show');
                analyzeReport(llmMode); 
            }
        });
    }

    document.addEventListener('click', function(e) {
        if (elements.llmAnalysisOptions && elements.analyzeReportDropdown && !elements.analyzeReportDropdown.contains(e.target)) {
            elements.llmAnalysisOptions.classList.add('hidden');
        }
    });

    // --- Log Streaming ---
    function setupLogStream() {
        if (eventSource) eventSource.close();
        eventSource = new EventSource('/ssl_scanner/log_stream');

        eventSource.onmessage = function(event) {
            var message = event.data;
            if (message && message !== ': keep-alive\n\n') {
                
                if (message.includes("SSLScan report parsed successfully") || message.includes("SSL_SCAN_FINALIZED_SUCCESSFULLY")) {
                    updateStatus('Complete', 'success');
                    toggleSpinner(elements.initiateScanBtn, false);
                    appendLog('[✓] Scan complete. Finalizing results...');
                    fetchAndDisplayReport(); 
                }

                if (message.includes("EVENT:") || message.startsWith("EVENT:")) return;
                appendLog(message);
            }
        };
    }

    // --- Init ---
    async function init() {
        appendLog('[*] SYSTEM READY. INITIALIZING SSL/TLS VULNERABILITY AUDIT...');
        
        // Active Scan Check
        try {
            const res = await fetch(`${API_BASE_URL}/check_active_scan`);
            const data = await res.json();
            if (data.status === 'active') {
                toggleSpinner(elements.initiateScanBtn, true);
                updateStatus('Scanning...', 'busy');
                appendLog('[*] DETECTED ACTIVE SSL/TLS AUDIT. RE-ATTACHING...');
                if (elements.targetHostInput) elements.targetHostInput.value = data.target || '';
            }
        } catch(e) {}

        setupLogStream();
        fetchAndDisplayReport(); 
    }

    init();
});

// --- Mobile Helper Functions (Global for compatibility) ---
window.toggleMobileDropdown = function(id) {
    var el = document.getElementById(id);
    if (!el) return;
    var menu = el.querySelector('.dropdown-menu');
    if (!menu) return;
    
    var isShow = menu.classList.contains('show');
    
    // Close others
    document.querySelectorAll('.dropdown-menu').forEach(function(m) {
        m.classList.remove('show');
        m.classList.add('hidden');
    });

    if (!isShow) {
        menu.classList.add('show');
        menu.classList.remove('hidden');
    } else {
        menu.classList.remove('show');
        menu.classList.add('hidden');
    }

    var closeDropdown = function(e) {
        if (!el.contains(e.target)) {
            menu.classList.remove('show');
            menu.classList.add('hidden');
            document.removeEventListener('click', closeDropdown);
        }
    };
    setTimeout(function() { document.addEventListener('click', closeDropdown); }, 10);
}

window.toggleDashPanel = function(id) {
    var el = document.getElementById(id);
    if (el) el.classList.toggle('open');
}

window.toggleTerminal = function() {
    const sheet = document.getElementById('terminalSheet');
    if (sheet) sheet.classList.toggle('open');
}

window.copyRawLogs = function() {
    const content = document.getElementById('resultsContent');
    if (content) {
        navigator.clipboard.writeText(content.innerText).then(() => {
            const btn = event.currentTarget;
            const originalIcon = btn.innerHTML;
            btn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 1.1rem;">check</span>';
            setTimeout(() => { btn.innerHTML = originalIcon; }, 2000);
        });
    }
}