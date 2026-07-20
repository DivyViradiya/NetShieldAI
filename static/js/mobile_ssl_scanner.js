document.addEventListener('DOMContentLoaded', function() {
    // --- Element References ---
    var elements = {
        targetHostInput: document.getElementById('targetHost'),
        initiateScanBtn: document.getElementById('initiateScanBtn'),
        scanStatus: document.getElementById('scanStatus'),
        logOutput: document.getElementById('logOutput'),
        resultsContent: document.getElementById('resultsContent'),
        
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
        vulnCountDisplay: document.getElementById('vulnCountDisplay'),
        serverConfigDetails: document.getElementById('serverConfigDetails'),
        certificateChainContainer: document.getElementById('certificateChainContainer'),
        protocolsTableBody: document.getElementById('protocolsTableBody'),
        ciphersTableBody: document.getElementById('ciphersTableBody'),
        vulnerabilitiesList: document.getElementById('vulnerabilitiesList'),

        // History Modal
        sslHistoryBtn: document.getElementById('sslHistoryBtn'),
        historyModal: document.getElementById('historyModal'),
        closeHistoryModal: document.getElementById('closeHistoryModal'),
        historyTableBody: document.getElementById('historyTableBody'),
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

    // --- Mobile UI Helpers ---

    window.switchTab = function(panelId) {
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
            if (btn.getAttribute('onclick') && btn.getAttribute('onclick').includes(panelId)) btn.classList.add('active');
        });
        document.querySelectorAll('.tab-panel').forEach(panel => {
            panel.classList.remove('active');
        });
        const targetPanel = document.getElementById(panelId);
        if (targetPanel) targetPanel.classList.add('active');
        
        const nav = document.querySelector('.tabs-nav');
        if (nav) window.scrollTo({ top: nav.offsetTop - 80, behavior: 'smooth' });
    };

    window.toggleMobileDropdown = function(id) {
        const el = document.getElementById(id);
        if (!el) return;
        const menu = el.querySelector('.dropdown-menu');
        if (!menu) return;
        
        const isShow = menu.classList.contains('show') && !menu.classList.contains('hidden') && menu.style.display !== 'none';
        
        document.querySelectorAll('.dropdown-menu').forEach(m => {
            m.classList.remove('show');
            m.classList.add('hidden');
            m.style.display = 'none';
        });
        
        if (!isShow) {
            menu.classList.remove('hidden');
            menu.classList.add('show');
            menu.style.display = 'flex';
        }
        
        const closeDropdown = (e) => {
            if (!el.contains(e.target)) {
                menu.classList.remove('show');
                menu.classList.add('hidden');
                menu.style.display = 'none';
                document.removeEventListener('click', closeDropdown);
            }
        };
        setTimeout(() => document.addEventListener('click', closeDropdown), 10);
    };

    window.toggleDashPanel = function(id) {
        var el = document.getElementById(id);
        if (el) el.classList.toggle('open');
    };

    window.toggleTerminal = function() {
        const sheet = document.getElementById('terminalSheet');
        if (sheet) sheet.classList.toggle('open');
    };

    window.copyRawLogs = function() {
        const content = document.getElementById('resultsContent');
        if (content) {
            navigator.clipboard.writeText(content.innerText).then(() => {
                const btn = document.getElementById('copyResultsBtn');
                if (!btn) return;
                const originalIcon = btn.innerHTML;
                btn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 1.1rem;">check</span>';
                setTimeout(() => { btn.innerHTML = originalIcon; }, 2000);
            });
        }
    };

    window.loadRawScanResults = function() {
        fetchAndDisplayReport();
    };

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
            if (spinner) spinner.classList.add('hidden');
            if (icon) icon.classList.remove('hidden');
        }
    }

    function updateStatus(msg, type) {
        if (!elements.scanStatus) return;
        elements.scanStatus.textContent = msg;
        elements.scanStatus.style.color = '#a1a1aa';
        if (type === 'success') elements.scanStatus.style.color = '#10b981';
        if (type === 'error') elements.scanStatus.style.color = '#ef4444';
        if (type === 'busy') elements.scanStatus.style.color = '#eab308';
    }

    function appendLog(message) {
        if (!elements.logOutput) return;

        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });

        let cleanedMessage = message.replace(/\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s*/g, "").trim();

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

    function getRiskColor(risk) {
        if (risk === 'Critical' || risk === 'High') return '#ef4444';
        if (risk === 'Medium') return '#f97316';
        if (risk === 'Low') return '#eab308';
        return '#3b82f6';
    }

    function renderVulnerabilities(vulnerabilities) {
        elements.vulnerabilitiesList.innerHTML = '';
        if (elements.vulnCountDisplay) elements.vulnCountDisplay.textContent = vulnerabilities ? vulnerabilities.length : 0;

        if (!vulnerabilities || vulnerabilities.length === 0) {
            elements.vulnerabilitiesList.innerHTML = '<div style="text-align:center; padding: 2rem; color: #10b981; font-family: var(--font-mono); font-size: 0.85rem;">NO VULNERABILITIES DETECTED.</div>';
            return;
        }

        vulnerabilities.forEach(function(vuln) {
            const rawScore = vuln.predicted_risk_score !== undefined ? vuln.predicted_risk_score : 0;
            const displayScore = (rawScore * 10).toFixed(1);
            const color = getRiskColor(vuln.severity || 'Info');
            
            const item = `
                <div class="discovery-item" style="border-left: 3px solid ${color};">
                    <div class="port-box">
                        <span class="port-id" style="color: ${color}; font-size: 0.7rem;">${(vuln.severity || 'INFO').toUpperCase()}</span>
                        <span class="port-tag">SSL_FINDING</span>
                    </div>
                    <div class="service-info">
                        <span class="service-name">${vuln.name}</span>
                    </div>
                    <div class="risk-indicator" style="color: ${color}">
                        <span class="risk-val">${displayScore}</span>
                        <div class="risk-bar"><div class="risk-fill" style="width: ${rawScore * 100}%;"></div></div>
                    </div>
                    <div class="vuln-detail-row">
                        <span style="color: var(--neo-blue); opacity: 0.8;">[ADVISORY]</span> ${vuln.description || 'N/A'}
                    </div>
                </div>`;
            elements.vulnerabilitiesList.insertAdjacentHTML('beforeend', item);
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

        var tlsSupported = (configs.tls_compression && configs.tls_compression.supported);
        var renegotiationSecure = (configs.renegotiation && configs.renegotiation.secure);
        var html = '';
        html += createItem('TLS Compression', tlsSupported ? 'Enabled (Risk)' : 'Disabled', tlsSupported);
        html += createItem('Secure Renegotiation', renegotiationSecure ? 'Supported' : 'Insecure', !renegotiationSecure);
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

            const subject = typeof cert.common_name === 'object' ? JSON.stringify(cert.common_name) : cert.common_name;
            const issuer = typeof cert.issuer === 'object' ? JSON.stringify(cert.issuer) : cert.issuer;

            card.innerHTML = 
                '<div style="color: ' + titleColor + '; font-weight: 700; margin-bottom: 8px; font-size: 0.85rem; text-transform:uppercase;">' + titleText + '</div>' +
                '<div style="display: grid; gap: 4px;">' +
                    '<div><span class="cert-label">Subject:</span><span class="cert-val">' + (subject || 'N/A') + '</span></div>' +
                    '<div><span class="cert-label">Issuer:</span><span class="cert-val">' + (issuer || 'N/A') + '</span></div>' +
                    '<div><span class="cert-label">Validity:</span><span class="cert-val" style="font-size:0.75rem;">' + (cert.not_before || 'N/A') + ' - ' + (cert.not_after || 'N/A') + '</span></div>' +
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
            var status = p.enabled ? 'Enabled' : 'Disabled';
            row.innerHTML = '<td>' + p.name + '</td><td style="color:' + (p.enabled ? 'var(--neo-green)' : 'var(--neo-text-muted)') + '">' + status + '</td>';
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
            row.innerHTML = '<td>' + c.protocol + '</td><td>' + c.bits + '</td><td style="font-family:monospace; font-size:0.7rem;">' + c.name + '</td>';
        });
    }

    async function fetchHistory() {
        if (!elements.historyTableBody) return;
        elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-text-muted);">LOADING HISTORY...</td></tr>';
        
        try {
            const res = await fetch(`/ssl_scanner/report_history`);
            const data = await res.json();
            
            if (data.status === 'success' && data.history) {
                if (data.history.length === 0) {
                    elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-text-muted);">NO PRIOR SCANS FOUND</td></tr>';
                    return;
                }
                
                elements.historyTableBody.innerHTML = '';
                data.history.forEach(item => {
                    const row = document.createElement('tr');
                    // Extract target from filename (scanner_target.pdf)
                    let target = item.filename.split('_').slice(1).join('_').replace('.pdf', '');                    target = target.replace(/_\d{8}_\d{6}$/, '');
                    if (!target || target === 'report') target = 'Previous Scan';
                    
                    row.innerHTML = `
                        <td style="padding: 1rem; font-size: 0.7rem; color: var(--neo-text-main); font-family: var(--font-mono);">${item.created_at}</td>
                        <td style="padding: 1rem; font-size: 0.7rem; color: var(--neo-blue); font-family: var(--font-mono);">${target}</td>
                        <td style="padding: 1rem; text-align: right;">
                            <a href="/ssl_scanner/download_pdf?filename=${item.filename}" class="btn-dash btn-secondary" style="display: inline-flex; height: 36px; padding: 0 12px; border-radius: 8px;">
                                <span class="material-symbols-outlined" style="font-size: 1.1rem;">download</span>
                            </a>
                        </td>
                    `;
                    elements.historyTableBody.appendChild(row);
                });
            } else {
                elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-red);">FAILED TO LOAD HISTORY</td></tr>';
            }
        } catch (e) {
            console.error('History fetch failed:', e);
            elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-red);">ERROR LOADING HISTORY</td></tr>';
        }
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

                if(elements.targetHostInput && !elements.targetHostInput.value) {
                    elements.targetHostInput.value = report.target || '';
                }
                elements.resultsContent.textContent = JSON.stringify(report, null, 2);
                checkReportAvailability();
            }
        } catch (error) { console.error(error); }
    }

    async function checkReportAvailability() {
        var target = elements.targetHostInput.value.trim().toLowerCase();
        try {
            var url = target ? REPORT_FILES_ENDPOINT + '?target=' + encodeURIComponent(target) : REPORT_FILES_ENDPOINT;
            var response = await fetch(url);
            if (response.ok) {
                var data = await response.json();
                if (data.status === 'success' && data.pdf_report) {
                    reportDownloadUrl = data.pdf_report;
                    if (elements.downloadReportBtn) elements.downloadReportBtn.disabled = false;
                    if (elements.analyzeReportDropdown) elements.analyzeReportDropdown.disabled = false;
                    return;
                }
            }
        } catch (error) {}
        if (elements.downloadReportBtn) elements.downloadReportBtn.disabled = true;
        reportDownloadUrl = null;
    }

    async function analyzeReport(llmMode) {
        var target = elements.targetHostInput.value.trim().toLowerCase();
        if (!target) return;
        elements.aiProcessingOverlay.classList.remove('hidden');
        elements.aiProcessingText.textContent = 'INITIATING AI...';
        toggleSpinner(elements.analyzeReportDropdown, true);
        try {
            var res = await fetch(ANALYZE_ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                body: JSON.stringify({ llm_mode: llmMode, target: target })
            });
            var data = await res.json();
            if (data.status !== 'success') throw new Error(data.message);
            
            res = await fetch(CHATBOT_REDIRECT_URL + '/scanner_analysis', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                body: JSON.stringify({ llm_mode: llmMode, scanner_type: 'ssl_scanner', target: data.target, force_new_session: true }) 
            });
            data = await res.json();
            if (res.ok && data.status === 'success') {
                setTimeout(function() {
                    window.location.href = CHATBOT_REDIRECT_URL + '?mode=' + data.llm_mode + '&summary=' + data.summary + '&session_id=' + data.session_id;
                }, 800);
            }
        } catch (error) {
            appendLog('[x] AI Error: ' + error.message);
            elements.aiProcessingOverlay.classList.add('hidden');
        } finally {
            toggleSpinner(elements.analyzeReportDropdown, false);
            checkReportAvailability();
        }
    }

    // --- Logging ---
    function setupLogStream() {
        if (eventSource) eventSource.close();
        eventSource = new EventSource('/ssl_scanner/log_stream');
        eventSource.onmessage = function(event) {
            var message = event.data;
            if (message && !message.startsWith(':')) {
                if (message.includes("SSLScan report parsed successfully")) {
                    updateStatus('Complete', 'success');
                    toggleSpinner(elements.initiateScanBtn, false);
                    fetchAndDisplayReport(); 
                }
                if (message.includes("EVENT:") || message.startsWith("EVENT:")) return;
                appendLog(message);
            }
        };
    }

    // --- Event Listeners ---
    if(elements.initiateScanBtn) {
        elements.initiateScanBtn.addEventListener('click', async function() {
            var target = elements.targetHostInput.value.trim().toLowerCase();
            if (!target) return;
            toggleSpinner(elements.initiateScanBtn, true);
            updateStatus('Scanning...', 'busy');
            appendLog('> Initiating SSL scan for ' + target + '...');
            if(elements.serverConfigDetails) elements.serverConfigDetails.innerHTML = '<div style="display:flex; align-items:center; gap:8px;"><span class="spinner-sm"></span><span style="color:var(--neo-blue)">SCANNING...</span></div>';
            if(elements.vulnerabilitiesList) elements.vulnerabilitiesList.innerHTML = '<div style="text-align:center; padding: 2rem; color: var(--neo-blue);"><span class="spinner-sm"></span> ANALYZING...</div>';
            
            try {
                await fetch('/ssl_scanner/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                    body: JSON.stringify({ target_host: target })
                });
            } catch (e) { toggleSpinner(elements.initiateScanBtn, false); }
        });
    }

    if (elements.llmAnalysisOptions) {
        elements.llmAnalysisOptions.addEventListener('click', function(e) {
            e.preventDefault();
            var opt = e.target.closest('[data-llm-mode]');
            if (opt) analyzeReport(opt.dataset.llmMode);
        });
    }

    if (elements.downloadReportBtn) {
        elements.downloadReportBtn.addEventListener('click', function() {
            if (reportDownloadUrl) window.location.href = reportDownloadUrl;
        });
    }

    if (elements.sslHistoryBtn) {
        elements.sslHistoryBtn.addEventListener('click', function() {
            elements.historyModal.classList.remove('hidden');
            fetchHistory();
        });
    }

    if (elements.closeHistoryModal) {
        elements.closeHistoryModal.addEventListener('click', function() {
            elements.historyModal.classList.add('hidden');
        });
    }

    if (elements.historyModal) {
        elements.historyModal.addEventListener('click', function(e) {
            if (e.target === elements.historyModal) {
                elements.historyModal.classList.add('hidden');
            }
        });
    }

    // --- Init ---
    setupLogStream();
    fetchAndDisplayReport();
    checkReportAvailability();
    appendLog('SSL Scanner Mobile Interface Active.');
});
