document.addEventListener('DOMContentLoaded', function() {
    // --- API Endpoints ---
    const API_BASE_URL = '/semgrep_scanner';
    const SCAN_ENDPOINT = `${API_BASE_URL}/scan`;
    const REPORT_ENDPOINT = `${API_BASE_URL}/report`;
    const CLEAR_LOG_ENDPOINT = `${API_BASE_URL}/clear_log`;
    const LOG_STREAM_ENDPOINT = `${API_BASE_URL}/log_stream`;
    const REPORT_FILES_ENDPOINT = `${API_BASE_URL}/report_files`; 
    const ANALYZE_ENDPOINT = `${API_BASE_URL}/trigger_ai_analysis`; 
    const STATUS_ENDPOINT = `${API_BASE_URL}/status`;
    const CHATBOT_REDIRECT_URL = '/chatbot';

    // --- 🔒 CSRF TOKEN ---
    const csrfToken = document.querySelector('meta[name="csrf-token"]') 
        ? document.querySelector('meta[name="csrf-token"]').getAttribute('content') 
        : '';

    // --- DOM Elements ---
    const elements = {
        // Inputs & Controls
        gitUrlInput: document.getElementById('gitUrlInput'),
        fileUploadInput: document.getElementById('fileUploadInput'),
        triggerUploadBtn: document.getElementById('triggerUploadBtn'),
        resetScanBtn: document.getElementById('resetScanBtn'),
        initiateScanBtn: document.getElementById('initiateScanBtn'),
        scanCategorySelect: document.getElementById('scanCategory'), // hidden select
        
        // Status & Metrics
        scanStatus: document.getElementById('scanStatus'),
        metricTotal: document.getElementById('metricTotal'),
        metricHigh: document.getElementById('metricHigh'),
        metricDuration: document.getElementById('metricDuration'),
        
        // Logs & Raw Data
        clearLogBtn: document.getElementById('clearLogBtn'),
        logOutput: document.getElementById('logOutput'),
        resultsContent: document.getElementById('resultsContent'),
        copyResultsBtn: document.getElementById('copyResultsBtn'),
        
        // Intelligence & Overlay
        refreshReportBtn: document.getElementById('refreshReportBtn'),
        downloadReportBtn: document.getElementById('downloadReportBtn'),
        analyzeReportDropdown: document.getElementById('analyzeReportDropdown'),
        llmAnalysisOptions: document.getElementById('llmAnalysisOptions'),
        aiProcessingOverlay: document.getElementById('aiProcessingOverlay'),
        aiProcessingText: document.getElementById('aiProcessingText'),
        semgrepHistoryBtn: document.getElementById('semgrepHistoryBtn'),

        // Dynamic Content Areas
        findingsListSide: document.getElementById('findingsListSide'),
        findingsTableBody: document.getElementById('findingsTableBody'), // Severity table
        serverConfigDetails: document.getElementById('serverConfigDetails'),
        findingsSearch: document.getElementById('findingsSearch'),
        filteredCountBadge: document.getElementById('filteredCountBadge'),

        // History Modal
        historyModal: document.getElementById('historyModal'),
        closeHistoryModal: document.getElementById('closeHistoryModal'),
        historyTableBody: document.getElementById('historyTableBody'),
    };

    let eventSource = null;
    let reportDownloadUrl = null;
    let selectedFile = null; 
    let currentFilter = 'all';

    // --- Mobile UI Helpers ---

    window.toggleMobileDropdown = function(id) {
        const el = document.getElementById(id);
        if (!el) return;
        const menu = el.querySelector('.dropdown-menu');
        if (!menu) return;
        
        const isShow = menu.classList.contains('show');
        
        document.querySelectorAll('.dropdown-menu').forEach(m => {
            m.classList.remove('show');
            m.style.display = 'none';
        });
        
        if (!isShow) {
            menu.classList.add('show');
            menu.style.display = 'flex';
        }
        
        const closeDropdown = (e) => {
            if (!el.contains(e.target)) {
                menu.classList.remove('show');
                menu.style.display = 'none';
                document.removeEventListener('click', closeDropdown);
            }
        };
        setTimeout(() => document.addEventListener('click', closeDropdown), 10);
    };

    window.selectDropdownItem = function(dropdownId, value, text) {
        const dropdown = document.getElementById(dropdownId);
        if (!dropdown) return;
        const triggerText = dropdown.querySelector('.trigger-text');
        const items = dropdown.querySelectorAll('.dropdown-item');
        const menu = dropdown.querySelector('.dropdown-menu');
        
        if (triggerText) triggerText.textContent = text;
        items.forEach(item => item.classList.toggle('active', item.dataset.value === value));
        
        if (dropdownId === 'profileDropdown' && elements.scanCategorySelect) {
            elements.scanCategorySelect.value = value;
        }

        // AI Dropdown
        if (dropdownId === 'aiDropdown') {
            analyzeReport(value);
        }
        
        if (menu) {
            menu.classList.remove('show');
            menu.style.display = 'none';
        }
    };

    window.toggleTerminal = function() {
        const sheet = document.getElementById('terminalSheet');
        if (sheet) sheet.classList.toggle('open');
    };

    window.switchTab = function(tabName) {
        const tabs = ["findings", "severity", "config", "raw"];
        tabs.forEach((t) => {
            const contentEl = document.getElementById(`content${t.charAt(0).toUpperCase() + t.slice(1)}`);
            if (contentEl) {
                contentEl.classList.add("hidden");
                contentEl.classList.remove("active");
                contentEl.style.display = 'none';
            }
            const pillEl = document.getElementById(`tab${t.charAt(0).toUpperCase() + t.slice(1)}Btn`);
            if (pillEl) pillEl.classList.remove("active");
        });

        const targetContent = document.getElementById(`content${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`);
        if (targetContent) {
            targetContent.classList.remove("hidden");
            targetContent.classList.add("active");
            targetContent.style.display = tabName === 'findings' ? 'flex' : 'block';
        }
        const targetPill = document.getElementById(`tab${tabName.charAt(0).toUpperCase() + tabName.slice(1)}Btn`);
        if (targetPill) targetPill.classList.add("active");
    };

    // --- Core Functions ---

    function toggleSpinner(button, isLoading) {
        if (!button) return;
        const spinner = button.querySelector('.spinner');
        const icon = button.querySelector('.material-symbols-outlined'); 
        const text = button.querySelector('.button-text');
        
        button.disabled = isLoading;
        if (isLoading) {
            button.classList.add('opacity-70', 'cursor-not-allowed');
            if (icon) icon.classList.add('hidden'); 
            if (spinner) spinner.classList.remove('hidden');
            if (text && button.id === 'initiateScanBtn') text.textContent = 'SCANNING...';
        } else {
            button.classList.remove('opacity-70', 'cursor-not-allowed');
            if (spinner) spinner.classList.add('hidden');
            if (icon) icon.classList.remove('hidden');
            if (text && button.id === 'initiateScanBtn') text.textContent = 'START SCAN';
        }
    }

    function updateStatus(msg, type) {
        if (!elements.scanStatus) return;
        elements.scanStatus.textContent = msg.toUpperCase();
        
        if (type === 'success') elements.scanStatus.style.color = 'var(--neo-green)';
        else if (type === 'error') elements.scanStatus.style.color = 'var(--neo-red)';
        else if (type === 'busy') elements.scanStatus.style.color = 'var(--neo-amber)';
        else elements.scanStatus.style.color = 'var(--neo-text-main)';
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

        let contentStyle = '';
        if (cleanedMessage.includes('[!]') || cleanedMessage.includes('Error')) {
            contentStyle = 'color: var(--neo-red)';
        } else if (cleanedMessage.includes('[+]') || cleanedMessage.includes('Success')) {
            contentStyle = 'color: var(--neo-green)';
        } else if (cleanedMessage.includes('[*]')) {
            contentStyle = 'color: var(--neo-blue)';
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

    function clearScanResults() {
        if(elements.metricTotal) elements.metricTotal.textContent = '0';
        if(elements.metricHigh) elements.metricHigh.textContent = '0';
        if(elements.metricDuration) elements.metricDuration.textContent = '---';
        
        if(elements.serverConfigDetails) elements.serverConfigDetails.innerHTML = 'Waiting for scan metadata...';
        if(elements.findingsTableBody) elements.findingsTableBody.innerHTML = '<tr><td colspan="3" style="text-align:center; color: #555; padding: 2rem; font-family: var(--font-mono);">---</td></tr>';
        
        if(elements.findingsListSide) {
            elements.findingsListSide.innerHTML = '<div style="text-align:center; padding: 4rem 1rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.75rem;">WAITING FOR CODE SCAN...</div>';
        }
        if(elements.resultsContent) elements.resultsContent.textContent = '// JSON OUTPUT';
        if(elements.filteredCountBadge) elements.filteredCountBadge.textContent = '0';
        
        [elements.downloadReportBtn, elements.analyzeReportDropdown].forEach(function(btn) {
            if (btn) {
                btn.disabled = true;
                btn.style.opacity = '0.5';
            }
        });
        reportDownloadUrl = null;
        window.currentSemgrepReport = null;
    }

    // --- Input Handling ---
    
    if(elements.triggerUploadBtn) {
        elements.triggerUploadBtn.addEventListener('click', function() {
            elements.fileUploadInput.click();
        });
    }

    if(elements.fileUploadInput) {
        elements.fileUploadInput.addEventListener('change', function(e) {
            if (this.files && this.files[0]) {
                selectedFile = this.files[0];
                appendLog('[*] Selected archive: ' + selectedFile.name + ' (' + (selectedFile.size / 1024).toFixed(1) + ' KB)');
                elements.gitUrlInput.value = "[FILE] " + selectedFile.name;
                elements.gitUrlInput.disabled = true; 
                elements.triggerUploadBtn.classList.add('highlight');
            }
        });
    }

    if(elements.resetScanBtn) {
        elements.resetScanBtn.addEventListener('click', function() {
            elements.gitUrlInput.value = '';
            elements.gitUrlInput.disabled = false;
            elements.fileUploadInput.value = '';
            selectedFile = null;
            elements.triggerUploadBtn.classList.remove('highlight');
            updateStatus('READY', 'info');
            clearScanResults();
            appendLog('[*] Scan parameters and dashboard cleared.');
        });
    }

    // --- Data Fetching & Rendering ---

    async function checkReportAvailability() {
        var target = selectedFile ? selectedFile.name : elements.gitUrlInput.value.trim();
        try {
            var url = target ? `${REPORT_FILES_ENDPOINT}?target=${encodeURIComponent(target)}` : REPORT_FILES_ENDPOINT;
            var response = await fetch(url);
            if (response.ok) {
                var data = await response.json();
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
                }
            }
        } catch (error) {
            console.error('Error checking report:', error);
        }
    }

    async function fetchAndDisplayReport() {
        try {
            var response = await fetch(REPORT_ENDPOINT);
            var data = await response.json();

            if (data.status === 'success' && data.content) {
                var report = data.content;
                window.currentSemgrepReport = report; 
                
                if (elements.metricTotal) elements.metricTotal.textContent = report.total_findings !== undefined ? report.total_findings : 0;
                if (elements.metricHigh) elements.metricHigh.textContent = (report.severity_counts && report.severity_counts.ERROR) !== undefined ? report.severity_counts.ERROR : 0;
                if (report.scan_duration && elements.metricDuration) elements.metricDuration.textContent = parseFloat(report.scan_duration).toFixed(1) + 's';

                renderMetadata(report);
                renderSeverityTable(report.severity_counts);
                renderFindingsCards(report.findings || []);

                if (elements.resultsContent) elements.resultsContent.textContent = JSON.stringify(report, null, 2);
                checkReportAvailability();
            } else {
                if (elements.findingsListSide) elements.findingsListSide.innerHTML = `<div style="text-align:center; padding: 4rem 1rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.75rem;">${data.message || 'NO DATA'}</div>`;
            }
        } catch (error) {
            console.error('Error fetching SAST report:', error);
        }
    }

    function renderMetadata(data) {
        var html = '<div style="display: flex; flex-direction: column; gap: 0.75rem;">';
        var createItem = function(label, val, highlight) {
            return `<div style="display:flex; justify-content:space-between; align-items:center; padding-bottom: 0.5rem; border-bottom: 1px solid var(--neo-border);">
                        <span style="font-size:0.65rem; font-weight:800; color:var(--neo-text-muted); text-transform:uppercase;">${label}</span>
                        <span style="font-family:var(--font-mono); font-size:0.75rem; color:${highlight ? 'var(--neo-blue)' : 'var(--neo-text-main)'}; text-align:right; word-break:break-all; max-width:60%;">${val}</span>
                    </div>`;
        };

        html += createItem("Analysis Engine", data.tool || "Semgrep OSS", false);
        html += createItem("Target Source", data.target || "Unknown", true);
        html += createItem("Rulesets Executed", "Security, Secrets, Config", false);
        html += createItem("Generation Date", data.scan_date || new Date().toISOString().split('T')[0], false);
        html += '</div>';
        
        if(elements.serverConfigDetails) elements.serverConfigDetails.innerHTML = html;
    }

    function renderSeverityTable(counts) {
        if(!elements.findingsTableBody) return;
        elements.findingsTableBody.innerHTML = '';
        if (!counts) return;

        var order = ['ERROR', 'WARNING', 'INFO'];
        var mapping = { 'ERROR': 'High', 'WARNING': 'Medium', 'INFO': 'Low' };
        var colors = { 'ERROR': 'var(--neo-red)', 'WARNING': 'var(--neo-amber)', 'INFO': 'var(--neo-blue)' };

        order.forEach(function(key) {
            var count = counts[key] || 0;
            var row = elements.findingsTableBody.insertRow();
            row.innerHTML = `
                <td style="color: ${colors[key]}; font-weight: 800;">${mapping[key]}</td>
                <td style="font-family: var(--font-mono);">${count}</td>
                <td>
                    <span class="badge-pill" style="color: ${count > 0 ? colors[key] : 'var(--neo-text-muted)'}; border-color: ${count > 0 ? colors[key] : 'var(--neo-border)'}; background: transparent;">
                        ${count > 0 ? 'DETECTED' : 'CLEAN'}
                    </span>
                </td>`;
        });
    }

    function renderFindingsCards(findings) {
        if(!elements.findingsListSide) return;
        elements.findingsListSide.innerHTML = '';
        
        var filterText = elements.findingsSearch ? elements.findingsSearch.value.toLowerCase() : '';
        
        var filteredFindings = (findings || []).filter(function(f) {
            var matchesTabFilter = currentFilter === 'all' || (f.severity || 'INFO') === currentFilter;
            var matchesText = (f.check_id || '').toLowerCase().includes(filterText) || 
                              (f.path || '').toLowerCase().includes(filterText) || 
                              (f.message || '').toLowerCase().includes(filterText);
            return matchesTabFilter && matchesText;
        });

        if(elements.filteredCountBadge) {
            elements.filteredCountBadge.textContent = filteredFindings.length;
            elements.filteredCountBadge.style.display = 'inline-flex';
        }

        if (filteredFindings.length === 0) {
            elements.findingsListSide.innerHTML = `<div style="text-align:center; padding: 4rem 1rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.75rem;">${filterText ? 'NO MATCHES FOUND.' : 'CODEBASE IS SECURE.'}</div>`;
            return;
        }

        filteredFindings.forEach(function(f) {
            var severity = f.severity || 'INFO';
            var severityColor = severity === 'ERROR' ? 'var(--neo-red)' : (severity === 'WARNING' ? 'var(--neo-amber)' : 'var(--neo-blue)');
            var riskClass = severity === 'ERROR' ? 'risk-high' : (severity === 'WARNING' ? 'risk-medium' : 'risk-low');
            
            var path = f.path || 'Unknown Path';
            var cleanPath = path.includes("source_code_temp") ? path.split("source_code_temp")[1].replace(/^[\\/]/, "") : path;

            // Gauge calculations
            const rawScore = f.predicted_risk_score !== undefined ? f.predicted_risk_score : 0;
            const displayScore = (rawScore * 10).toFixed(1);
            const radius = 16;
            const circumference = 2 * Math.PI * radius;
            const offset = circumference - (rawScore * circumference);
            
            let gaugeClass = 'gauge-low';
            if (rawScore > 0.7) gaugeClass = 'gauge-critical';
            else if (rawScore > 0.5) gaugeClass = 'gauge-high';
            else if (rawScore > 0.3) gaugeClass = 'gauge-medium';

            var card = document.createElement('div');
            card.className = `finding-card animate-mobile-card ${riskClass}`;
            card.style.setProperty('--accent-gradient', severityColor);

            card.innerHTML = `
                <div class="finding-header">
                    <div class="risk-indicator" style="color: ${severityColor};">
                        <div class="risk-dot" style="background: ${severityColor};"></div>
                        <span>${severity === 'ERROR' ? 'HIGH' : (severity === 'WARNING' ? 'MED' : 'LOW')}</span>
                    </div>
                    
                    <div class="finding-title">
                        <div style="font-size: 0.85rem; font-weight: 600; color: var(--neo-text-main); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${f.check_id || 'Unknown Rule'}</div>
                        <div style="font-family: var(--font-mono); font-size: 0.65rem; color: var(--neo-text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 2px;">${cleanPath} : L${f.line || '?'}</div>
                    </div>
                    
                    <div style="display: flex; align-items: center; gap: 0.5rem; flex-shrink: 0;">
                        <div class="risk-score-gauge">
                            <svg class="gauge-svg" viewBox="0 0 40 40">
                                <circle class="gauge-bg" cx="20" cy="20" r="${radius}"></circle>
                                <circle class="gauge-fill ${gaugeClass}" cx="20" cy="20" r="${radius}" style="stroke-dasharray: ${circumference}; stroke-dashoffset: ${offset};"></circle>
                            </svg>
                            <span class="gauge-val">${displayScore}</span>
                        </div>
                    </div>
                    <span class="material-symbols-outlined expand-icon">expand_more</span>
                </div>
                
                <div class="finding-details">
                    <div class="details-content">
                        <div class="detail-section">
                            <span class="detail-label">Issue Analysis</span>
                            <div class="detail-text">${f.message || 'No description available.'}</div>
                        </div>

                        <div class="detail-section">
                            <span class="detail-label mb-1">Source Code Evidence</span>
                            <div class="detail-text-mono">${f.code_snippet || 'No code evidence available.'}</div>
                        </div>

                        ${f.fix_suggestion && f.fix_suggestion !== 'N/A' ? `
                        <div class="detail-section" style="border-bottom: none;">
                            <span class="detail-label" style="color: var(--neo-green);">Remediation</span>
                            <div class="detail-text" style="border-left: 2px solid var(--neo-green); padding-left: 0.75rem;">${f.fix_suggestion}</div>
                        </div>` : ''}
                    </div>
                </div>
            `;

            card.querySelector('.finding-header').addEventListener('click', () => {
                card.classList.toggle('expanded');
            });

            elements.findingsListSide.appendChild(card);
        });
    }

    // --- Search & Filter Logic ---
    if (elements.findingsSearch) {
        elements.findingsSearch.addEventListener('input', function() {
            if(window.currentSemgrepReport && window.currentSemgrepReport.findings) {
                renderFindingsCards(window.currentSemgrepReport.findings);
            }
        });
    }

    document.querySelectorAll('.filter-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
            chip.classList.add('active');
            currentFilter = chip.dataset.filter;
            if(window.currentSemgrepReport && window.currentSemgrepReport.findings) {
                renderFindingsCards(window.currentSemgrepReport.findings);
            }
        });
    });

    // --- Core Action: Start Scan ---

    if(elements.initiateScanBtn) {
        elements.initiateScanBtn.addEventListener('click', async function() {
            var targetInput = "";
            var isFile = false;

            if (selectedFile) {
                isFile = true;
                targetInput = selectedFile.name;
            } else {
                targetInput = elements.gitUrlInput.value.trim();
            }

            if (!targetInput) {
                appendLog('[!] Error: Please provide a Git URL or upload a file.');
                toggleTerminal();
                return;
            }
            if (!csrfToken) {
                appendLog('[!] Error: CSRF Token missing. Refresh page.');
                return;
            }

            clearScanResults();
            toggleSpinner(elements.initiateScanBtn, true);
            updateStatus('Scanning...', 'busy');
            appendLog('[*] Initiating SAST Engine on: ' + targetInput);

            try {
                var formData = new FormData();
                if (isFile) formData.append('file', selectedFile);
                else formData.append('git_url', targetInput);
                
                if(elements.scanCategorySelect) formData.append('ruleset', elements.scanCategorySelect.value);

                setupLogStream(); // Attach before request

                var response = await fetch(SCAN_ENDPOINT, {
                    method: 'POST',
                    headers: { 'X-CSRFToken': csrfToken }, 
                    body: formData
                });
                
                var data = await response.json();

                if (data.status !== 'success') {
                    updateStatus('Failed', 'error');
                    toggleSpinner(elements.initiateScanBtn, false);
                    appendLog('[!] Error: ' + data.message);
                    if(eventSource) { eventSource.close(); eventSource = null; }
                }
            } catch (error) {
                console.error('Error:', error);
                updateStatus('Network Error', 'error');
                toggleSpinner(elements.initiateScanBtn, false);
                if(eventSource) { eventSource.close(); eventSource = null; }
            }
        });
    }

    function setupLogStream() {
        if (eventSource) eventSource.close();
        eventSource = new EventSource(LOG_STREAM_ENDPOINT);

        eventSource.onmessage = function(event) {
            var message = event.data;
            if (message && message !== ': keep-alive\n\n') {
                
                if (message.includes("SYSTEM_EVENT: READY_FOR_ANALYSIS")) {
                    checkReportAvailability();
                }

                if (message.toLowerCase().includes("pdf report generated") || 
                    message.toLowerCase().includes("semgrep scan complete") || 
                    message.includes("READY_FOR_ANALYSIS")) {
                    
                    updateStatus('Complete', 'success');
                    toggleSpinner(elements.initiateScanBtn, false);
                    setTimeout(fetchAndDisplayReport, 1000); 
                    eventSource.close();
                    eventSource = null;
                }

                if (message.includes("EVENT:") || message.startsWith("EVENT:")) return;
                appendLog(message);
            }
        };
        
        eventSource.onerror = function() {
            if(eventSource) eventSource.close();
        };
    }

    // --- AI Analysis Logic ---
    async function analyzeReport(llmMode) {
        if (elements.analyzeReportDropdown.disabled) return;
        var target = selectedFile ? selectedFile.name : elements.gitUrlInput.value.trim();

        if (!csrfToken) return appendLog('[!] Error: CSRF Token missing.');

        elements.aiProcessingOverlay.classList.remove('hidden');
        elements.aiProcessingText.textContent = llmMode.includes('gemini') ? 'CONTACTING GEMINI...' : 'LOADING LOCAL MODEL...';
        
        updateStatus('AI Analysis...', 'busy');
        elements.analyzeReportDropdown.disabled = true;

        try {
            var response = await fetch(ANALYZE_ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                body: JSON.stringify({ llm_mode: llmMode, target: target })
            });
            var data = await response.json();
            if (data.status !== 'success') throw new Error(data.message);
            
            elements.aiProcessingText.textContent = 'ANALYZING CODE...';
            
            var CHATBOT_PROXY_URL = CHATBOT_REDIRECT_URL + '/scanner_analysis';
            response = await fetch(CHATBOT_PROXY_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                body: JSON.stringify({ 
                    llm_mode: llmMode, 
                    scanner_type: data.scanner_type,
                    target: data.target,
                    force_new_session: true 
                }) 
            });

            data = await response.json();

            if (response.ok && data.status === 'success') {
                elements.aiProcessingText.textContent = 'REDIRECTING...';
                updateStatus('Redirecting...', 'success');
                setTimeout(function() {
                    const params = new URLSearchParams({ mode: data.llm_mode, summary: data.summary, session_id: data.session_id });
                    window.location.href = CHATBOT_REDIRECT_URL + '?' + params.toString();
                }, 800);
            } else {
                throw new Error(data.message || 'Analysis failed');
            }
        } catch (error) {
            appendLog('[!] AI Analysis Error: ' + error.message);
            updateStatus('Analysis Failed', 'error');
            elements.aiProcessingOverlay.classList.add('hidden');
        } finally {
            elements.analyzeReportDropdown.disabled = false;
            checkReportAvailability(); 
        }
    }

    // --- History Logic ---
    async function fetchHistory() {
        if (!elements.historyTableBody) return;
        elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.8rem;">LOADING HISTORY...</td></tr>';
        
        try {
            const res = await fetch(`${API_BASE_URL}/report_history`);
            const data = await res.json();
            
            if (data.status === 'success' && data.history && data.history.length > 0) {
                elements.historyTableBody.innerHTML = '';
                data.history.forEach(item => {
                    const row = document.createElement('tr');
                    let target = item.filename.split('_').slice(1).join('_').replace('.pdf', '');
                    if (!target) target = 'Previous Scan';
                    
                    row.innerHTML = `
                        <td>${item.created_at}</td>
                        <td style="color: var(--neo-blue);">${target}</td>
                        <td style="text-align: right;">
                            <a href="${API_BASE_URL}/download_pdf?filename=${item.filename}" class="btn-dash" style="display: inline-flex; height: 32px; width: 32px; padding: 0;">
                                <span class="material-symbols-outlined" style="font-size: 1.1rem;">download</span>
                            </a>
                        </td>
                    `;
                    elements.historyTableBody.appendChild(row);
                });
            } else {
                elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.8rem;">NO PRIOR SCANS FOUND</td></tr>';
            }
        } catch (e) {
            elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-red); font-family: var(--font-mono); font-size: 0.8rem;">ERROR LOADING HISTORY</td></tr>';
        }
    }

    // --- General Event Listeners ---
    
    if(elements.clearLogBtn) {
        elements.clearLogBtn.addEventListener('click', async function() {
            if (!csrfToken) return;
            elements.logOutput.innerHTML = '';
            await fetch(CLEAR_LOG_ENDPOINT, { method: 'POST', headers: { 'X-CSRFToken': csrfToken } });
        });
    }

    if(elements.copyResultsBtn) {
        elements.copyResultsBtn.addEventListener('click', function() {
            if (elements.resultsContent.textContent !== '// Buffer Empty') {
                navigator.clipboard.writeText(elements.resultsContent.textContent).then(function() {
                    var icon = elements.copyResultsBtn.querySelector('span');
                    icon.textContent = 'check';
                    setTimeout(function() { icon.textContent = 'content_copy'; }, 2000);
                });
            }
        });
    }

    if(elements.refreshReportBtn) {
        elements.refreshReportBtn.addEventListener('click', fetchAndDisplayReport);
    }

    if (elements.downloadReportBtn) {
        elements.downloadReportBtn.addEventListener('click', function() {
            if (reportDownloadUrl) window.location.href = reportDownloadUrl;
        });
    }

    if (elements.analyzeReportDropdown) {
        elements.analyzeReportDropdown.addEventListener('click', function(e) {
            if (!elements.analyzeReportDropdown.disabled) {
                elements.llmAnalysisOptions.classList.toggle('hidden');
                e.stopPropagation(); 
            }
        });
    }
    
    if (elements.llmAnalysisOptions) {
        elements.llmAnalysisOptions.addEventListener('click', function(e) {
            e.preventDefault();
            var option = e.target.closest('a[data-llm-mode]');
            if (option) {
                elements.llmAnalysisOptions.classList.add('hidden'); 
                analyzeReport(option.dataset.llmMode); 
            }
        });
    }

    document.addEventListener('click', function(e) {
        if (elements.llmAnalysisOptions && !elements.analyzeReportDropdown.contains(e.target)) {
            elements.llmAnalysisOptions.classList.add('hidden');
        }
    });

    if (elements.semgrepHistoryBtn) {
        elements.semgrepHistoryBtn.addEventListener('click', function() {
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
            if (e.target === elements.historyModal) elements.historyModal.classList.add('hidden');
        });
    }

    async function checkActiveScan() {
        try {
            const res = await fetch(STATUS_ENDPOINT);
            const data = await res.json();
            if (data.status === 'success' && data.is_running) {
                appendLog('[*] Resuming active scan...');
                updateStatus('Scanning...', 'busy');
                toggleSpinner(elements.initiateScanBtn, true);
                if (elements.findingsListSide) {
                    elements.findingsListSide.innerHTML = '<div style="text-align:center; padding: 4rem 1rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.8rem;">SCANNING IN PROGRESS...</div>';
                }
                setupLogStream();
            }
        } catch (e) {
            console.error('Failed to check active scan:', e);
        }
    }

    // --- Init ---
    setTimeout(function() { appendLog('System Ready. Initializing SAST Engine...'); }, 100);
    checkActiveScan();
    fetchAndDisplayReport(); 
    checkReportAvailability(); 
});