document.addEventListener('DOMContentLoaded', function() {
    // --- Element References ---
    var elements = {
        // Inputs & Controls
        gitUrlInput: document.getElementById('gitUrlInput'),
        fileUploadInput: document.getElementById('fileUploadInput'),
        triggerUploadBtn: document.getElementById('triggerUploadBtn'),
        resetScanBtn: document.getElementById('resetScanBtn'), 
        initiateScanBtn: document.getElementById('initiateScanBtn'),
        scanStatus: document.getElementById('scanStatus'),
        
        // Logs & Raw Data
        clearLogBtn: document.getElementById('clearLogBtn'),
        logOutput: document.getElementById('logOutput'),
        resultsContent: document.getElementById('resultsContent'),
        copyResultsBtn: document.getElementById('copyResultsBtn'),
        refreshReportBtn: document.getElementById('refreshReportBtn'),
        
        // Intelligence & Overlay (Shared Logic)
        downloadReportBtn: document.getElementById('downloadReportBtn'),
        execSummaryBtn: document.getElementById('execSummaryBtn'),
        execSummaryLabel: document.getElementById('execSummaryLabel'),
        execSummaryIcon: document.getElementById('execSummaryIcon'),
        execSummarySpinner: document.getElementById('execSummarySpinner'),
        
        analyzeReportDropdown: document.getElementById('analyzeReportDropdown'),
        llmAnalysisOptions: document.getElementById('llmAnalysisOptions'),
        aiProcessingOverlay: document.getElementById('aiProcessingOverlay'),
        aiProcessingText: document.getElementById('aiProcessingText'),

        // Metrics & Containers
        metricTarget: document.getElementById('metricTarget'),
        metricTotal: document.getElementById('metricTotal'),
        metricHigh: document.getElementById('metricHigh'),
        metricDuration: document.getElementById('metricDuration'),
        
        // Dynamic Content Areas
        findingsListSide: document.getElementById('findingsListSide'),
        findingsDetailSide: document.getElementById('findingsDetailSide'),
        findingsTableBody: document.getElementById('findingsTableBody'),
        serverConfigDetails: document.getElementById('serverConfigDetails'),

        // History
        semgrepHistoryBtn: document.getElementById('semgrepHistoryBtn'),
        historyModal: document.getElementById('historyModal'),
        closeHistoryModal: document.getElementById('closeHistoryModal'),
        historyTableBody: document.getElementById('historyTableBody'),
    };

    var lastScanLogId = null;

    var CHATBOT_REDIRECT_URL = '/chatbot'; 
    var ANALYZE_ENDPOINT = '/semgrep_scanner/trigger_ai_analysis';
    var REPORT_FILES_ENDPOINT = '/semgrep_scanner/report_files';
    
    var eventSource = null;
    var reportDownloadUrl = null;
    var selectedFile = null; // Track selected file state

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
        elements.scanStatus.style.color = '#fff'; // Default white
        if (type === 'success') elements.scanStatus.style.color = '#10b981';
        if (type === 'error') elements.scanStatus.style.color = '#ef4444';
        if (type === 'busy') elements.scanStatus.style.color = '#eab308';
        if (type === 'ready') elements.scanStatus.style.color = '#fff';
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

        for (const [key, val] of Object.entries(logMap)) {
            if (cleanedMessage.includes(key)) {
                activeIcon = val.icon;
                activeColor = val.color;
                cleanedMessage = cleanedMessage.replace(key, '').trim();
                break;
            }
        }

        const line = document.createElement('div');
        line.className = 'log-line';
        
        line.innerHTML = `
            <div class="log-time">${timeStr}</div>
            <div class="log-content" style="color: ${activeColor === '#999' ? '' : activeColor}; display: flex; align-items: center; gap: 8px;">
                <span class="material-symbols-outlined" style="font-size: 0.9rem; opacity: 0.6;">${activeIcon}</span>
                <span>${escapeHtml(cleanedMessage).toUpperCase()}</span>
            </div>
        `;
        
        elements.logOutput.appendChild(line);
        elements.logOutput.scrollTop = elements.logOutput.scrollHeight;
    }

    // --- State Management ---

    function clearScanResults() {
        if(elements.metricTarget) elements.metricTarget.textContent = '---';
        if(elements.metricTotal) elements.metricTotal.textContent = '0';
        if(elements.metricHigh) elements.metricHigh.textContent = '0';
        if(elements.metricDuration) elements.metricDuration.textContent = '---';
        
        if(elements.serverConfigDetails) elements.serverConfigDetails.innerHTML = 'Waiting for scan...';
        
        if(elements.findingsTableBody) elements.findingsTableBody.innerHTML = '<tr><td colspan="3" style="text-align:center; color: #555; padding: 2rem; font-family: var(--font-mono);">---</td></tr>';
        
        if(elements.findingsListSide) {
            elements.findingsListSide.innerHTML = '<div style="text-align:center; padding: 4rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.8rem;">WAITING FOR CODE SCAN...</div>';
        }

        resetDetailView();

        if(elements.resultsContent) elements.resultsContent.textContent = '// JSON OUTPUT';
        
        [elements.downloadReportBtn, elements.analyzeReportDropdown, elements.execSummaryBtn].forEach(function(btn) {
            if (btn) {
                btn.disabled = true;
                btn.style.opacity = '0.5';
            }
        });
        updateExecSummaryButton('disabled');
        reportDownloadUrl = null;
    }

    // --- Input Handling (File vs Git vs Reset) ---
    
    // 1. Trigger File Dialog
    if(elements.triggerUploadBtn) {
        elements.triggerUploadBtn.addEventListener('click', function() {
            elements.fileUploadInput.click();
        });
    }

    // 2. Handle File Selection
    if(elements.fileUploadInput) {
        elements.fileUploadInput.addEventListener('change', function(e) {
            if (this.files && this.files[0]) {
                selectedFile = this.files[0];
                appendLog('[*] Selected file: ' + selectedFile.name + ' (' + (selectedFile.size / 1024).toFixed(1) + ' KB)');
                // Update UI to show file selected
                elements.gitUrlInput.value = "[FILE] " + selectedFile.name;
                elements.gitUrlInput.disabled = true; // Lock text input
                elements.triggerUploadBtn.classList.add('btn-primary'); // Highlight button
                elements.triggerUploadBtn.classList.remove('btn-secondary');
            }
        });
    }

    // 3. NEW: Reset Button Logic
    if(elements.resetScanBtn) {
        elements.resetScanBtn.addEventListener('click', function() {
            // A. Reset Inputs
            elements.gitUrlInput.value = '';
            elements.gitUrlInput.disabled = false;
            elements.fileUploadInput.value = '';
            selectedFile = null;

            // B. Reset Upload Button Style
            elements.triggerUploadBtn.classList.remove('btn-primary');
            elements.triggerUploadBtn.classList.add('btn-secondary');

            // C. Reset Status Text
            updateStatus('READY', 'ready');

            // D. Clear all Dashboard Data
            clearScanResults();

            // E. Optional Log
            appendLog('[*] Dashboard inputs and results cleared.');
        });
    }

    // --- Data Fetching & Rendering ---

    // --- Report & Button Management ---

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
            elements.execSummaryLabel.textContent = 'SAST BRIEF';
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
            var target = selectedFile ? selectedFile.name : elements.gitUrlInput.value.trim();
            const response = await fetch('/semgrep_scanner/trigger_executive_summary', {
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
        var target = selectedFile ? selectedFile.name : elements.gitUrlInput.value.trim();
        try {
            var url = target ? REPORT_FILES_ENDPOINT + '?target=' + encodeURIComponent(target) : REPORT_FILES_ENDPOINT;
            var response = await fetch(url);
            if (response.ok) {
                var data = await response.json();
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
            console.error('Error checking report availability:', error);
            updateExecSummaryButton('disabled');
        }
    }

    // --- HISTORY LOGIC ---

    async function fetchHistory() {
        if (!elements.historyTableBody) return;
        elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-text-muted);">LOADING HISTORY...</td></tr>';
        
        try {
            const res = await fetch('/semgrep_scanner/report_history');
            const data = await res.json();
            
            if (data.status === 'success' && data.history) {
                if (data.history.length === 0) {
                    elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-text-muted);">NO PRIOR SCANS FOUND</td></tr>';
                    return;
                }
                
                elements.historyTableBody.innerHTML = '';
                data.history.forEach(item => {
                    const row = document.createElement('tr');
                    // Extract target from filename (scanner_target.pdf)
                    let target = item.filename.split('_').slice(1).join('_').replace('.pdf', '');                    target = target.replace(/_\d{8}_\d{6}$/, '');
                    if (!target) target = 'Previous Scan';
                    
                    row.innerHTML = `
                        <td>${item.created_at}</td>
                        <td class="font-mono text-blue-400">${target}</td>
                        <td style="text-align: right;">
                            <a href="/semgrep_scanner/download_pdf?filename=${item.filename}" class="btn-dash btn-secondary" style="display: inline-flex; height: 32px; padding: 0 10px;">
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
            if (e.target === elements.historyModal) {
                elements.historyModal.classList.add('hidden');
            }
        });
    }

    function renderMetadata(data) {
        if (elements.metricTarget && data.target) {
            elements.metricTarget.textContent = data.target;
        }

        var html = '';
        var createItem = function(label, val, color) {
            return '<div style="display:flex; justify-content:space-between; padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.1);">' +
                   '<span>' + label + '</span><span style="color: ' + (color || '#fff') + ';">' + val + '</span></div>';
        };

        html += createItem("Tool", data.tool || "Semgrep OSS");
        html += createItem("Target", data.target || "Unknown Source");
        html += createItem("Rulesets", "Security, Secrets, Python", "#10b981");
        html += createItem("Scan Date", data.scan_date || "Just now");
        
        elements.serverConfigDetails.innerHTML = html;
    }

    function renderSeverityTable(counts) {
        elements.findingsTableBody.innerHTML = '';
        if (!counts) return;

        var order = ['ERROR', 'WARNING', 'INFO'];
        var mapping = { 'ERROR': 'High', 'WARNING': 'Medium', 'INFO': 'Low' };
        var colors = { 'ERROR': '#ef4444', 'WARNING': '#f97316', 'INFO': '#3b82f6' };

        order.forEach(function(key) {
            var count = counts[key] || 0;
            var row = elements.findingsTableBody.insertRow();
            row.className = "hover:bg-slate-800/50 transition-colors";
            
            row.innerHTML = 
                '<td style="color: ' + colors[key] + '; font-weight: 700;">' + mapping[key] + '</td>' +
                '<td style="font-family: monospace;">' + count + '</td>' +
                '<td>' + (count > 0 ? 'Detected' : 'Clean') + '</td>';
        });
    }

    function renderFindingsCards(findings) {
        if(!elements.findingsListSide) return;

        elements.findingsListSide.innerHTML = '';
        var filterText = document.getElementById('findingsSearch')?.value.toLowerCase() || '';
        
        var filteredFindings = (findings || []).filter(function(f) {
            return (f.check_id || '').toLowerCase().includes(filterText) || 
                   (f.path || '').toLowerCase().includes(filterText) || 
                   (f.message || '').toLowerCase().includes(filterText);
        });

        var countBadge = document.getElementById('filteredCountBadge');
        if(countBadge) countBadge.textContent = filteredFindings.length + ' FINDING' + (filteredFindings.length !== 1 ? 'S' : '');

        if (filteredFindings.length === 0) {
            elements.findingsListSide.innerHTML = '<div style="text-align:center; padding: 3rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.75rem;">' + (filterText ? 'NO MATCHES.' : 'NO VULNERABILITIES.') + '</div>';
            resetDetailView();
            return;
        }

        filteredFindings.forEach(function(f, index) {
            var severity = f.severity || 'INFO';
            var color = severity === 'ERROR' ? '#ef4444' : (severity === 'WARNING' ? '#f97316' : '#3b82f6');
            
            var path = f.path || 'Unknown Path';
            var cleanPath = path.includes("source_code_temp") ? path.split("source_code_temp")[1].replace(/^[\\/]/, "") : path;

            var item = document.createElement('div');
            item.style.cssText = 'padding: 1rem; border-bottom: 1px solid var(--neo-border); cursor: pointer; transition: background 0.2s;';
            if (window.selectedFindingIndex === index) item.style.background = 'rgba(59, 130, 246, 0.1)';

            item.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 4px;">
                    <div style="font-size: 0.7rem; color: ${color}; font-weight: 800; text-transform: uppercase;">${severity}</div>
                </div>
                <div style="font-size: 0.85rem; color: var(--neo-text-main); font-weight: 600; margin-bottom: 2px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${f.check_id || 'Unknown Rule'}</div>
                <div style="font-size: 0.7rem; color: var(--neo-text-muted); font-family: var(--font-mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${cleanPath}</div>
            `;

            item.onclick = function() {
                document.querySelectorAll('#findingsListSide > div').forEach(el => el.style.background = 'transparent');
                item.style.background = 'rgba(59, 130, 246, 0.1)';
                window.selectedFindingIndex = index;
                renderDetailView(f, cleanPath);
            };

            elements.findingsListSide.appendChild(item);
        });

        if (window.selectedFindingIndex === undefined && filteredFindings.length > 0) {
            elements.findingsListSide.firstChild.click();
        }
    }

    function resetDetailView() {
        if(!elements.findingsDetailSide) return;
        elements.findingsDetailSide.innerHTML = `
            <div style="height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center; opacity: 0.2;">
                <span class="material-symbols-outlined" style="font-size: 4rem; margin-bottom: 1rem;">data_exploration</span>
                <div style="font-family: var(--font-mono); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.1em;">Select a finding to view analysis</div>
            </div>
        `;
    }

    function renderDetailView(f, cleanPath) {
        if(!elements.findingsDetailSide) return;

        // Derive severity display vars from the finding
        var severity = f.severity || 'INFO';
        var severityColor = severity === 'ERROR' ? '#ef4444' : (severity === 'WARNING' ? '#f97316' : '#3b82f6');

        elements.findingsDetailSide.innerHTML = `
            <div style="margin-bottom: 2rem; border-bottom: 1px solid var(--neo-border); padding-bottom: 1.5rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <div style="font-size: 0.7rem; color: ${severityColor}; font-weight: 800; text-transform: uppercase; letter-spacing: 0.1em;">${severity} FINDING</div>
                </div>
                <h2 style="font-size: 1.25rem; font-weight: 700; color: var(--neo-text-main); margin-bottom: 0.5rem;">${f.check_id || 'Unknown Rule'}</h2>
                <div style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--neo-text-muted); word-break: break-all;">${cleanPath || 'Unknown Path'}</div>
                <div style="margin-top: 1rem; display: flex; gap: 1rem;">
                    <span class="badge-pill" style="color: ${severityColor}; border-color: ${severityColor}44; background: ${severityColor}11;">Line ${f.line || '?'}</span>
                </div>
            </div>

            <div class="flex flex-col gap-6">
                <div class="detail-section">
                    <span class="detail-label">Issue Description</span>
                    <div class="detail-text">${f.message || 'No description available.'}</div>
                </div>

                <div class="detail-section">
                    <span class="detail-label">Code Evidence</span>
                    <div style="background: #000; padding: 1rem; border-radius: 4px; border: 1px solid #222; overflow-x: auto; margin-top: 0.5rem;">
                        <pre style="font-family: var(--font-mono); font-size: 0.75rem; color: #a1a1aa; margin: 0;">${f.code_snippet || 'No code evidence available.'}</pre>
                    </div>
                </div>

                ${f.fix_suggestion && f.fix_suggestion !== 'N/A' ? `
                    <div class="detail-section" style="border-bottom: none;">
                        <span class="detail-label" style="color: #10b981;">Remediation Guidance</span>
                        <div class="detail-text" style="color: #10b981; opacity: 1; border-left: 2px solid #10b981; padding-left: 1rem;">${f.fix_suggestion}</div>
                    </div>
                ` : ''}

                <!-- Bottom spacer to prevent clipping -->
                <div style="height: 4rem;"></div>
            </div>
        `;
    }

    // --- Tab Switching ---
    (function setupTabs() {
        var findingsBtn = document.getElementById('findingsTabBtn');
        var rawBtn = document.getElementById('rawTabBtn');
        var findingsContent = document.getElementById('findingsContent');
        var rawContent = document.getElementById('rawContent');
        var searchBar = document.getElementById('findingsSearchBar');
        var copyBtn = document.getElementById('copyResultsBtn');
        var countBadge = document.getElementById('filteredCountBadge');

        if (!findingsBtn || !rawBtn) return;

        findingsBtn.addEventListener('click', function() {
            findingsBtn.classList.add('active');
            rawBtn.classList.remove('active');
            if (findingsContent) findingsContent.style.display = 'flex';
            if (rawContent) rawContent.classList.add('hidden');
            if (searchBar) searchBar.style.display = '';
            if (copyBtn) copyBtn.classList.add('hidden');
            if (countBadge) countBadge.style.display = '';
        });

        rawBtn.addEventListener('click', function() {
            rawBtn.classList.add('active');
            findingsBtn.classList.remove('active');
            if (rawContent) rawContent.classList.remove('hidden');
            if (findingsContent) findingsContent.style.display = 'none';
            if (searchBar) searchBar.style.display = 'none';
            if (copyBtn) copyBtn.classList.remove('hidden');
            if (countBadge) countBadge.style.display = 'none';
        });
    })();

    // Add search listener
    var searchInput = document.getElementById('findingsSearch');
    if(searchInput) {
        searchInput.addEventListener('input', function() {
            if(window.currentSemgrepReport && window.currentSemgrepReport.findings) {
                window.selectedFindingIndex = undefined; // Reset selection on search
                renderFindingsCards(window.currentSemgrepReport.findings);
            }
        });
    }

    async function fetchAndDisplayReport() {
        try {
            var response = await fetch('/semgrep_scanner/report');
            var data = await response.json();

            if (data.status === 'success' && data.content) {
                var report = data.content;
                window.currentSemgrepReport = report; // Store globally for filtering
                
                // Update Metrics (ensure UI doesn't say --- if we have data)
                if (elements.metricTotal) elements.metricTotal.textContent = report.total_findings !== undefined ? report.total_findings : 0;
                if (elements.metricHigh) elements.metricHigh.textContent = (report.severity_counts && report.severity_counts.ERROR) !== undefined ? report.severity_counts.ERROR : 0;
                
                if (report.scan_duration) {
                     if (elements.metricDuration) elements.metricDuration.textContent = parseFloat(report.scan_duration).toFixed(1) + 's';
                }

                // Render
                renderMetadata(report);
                renderSeverityTable(report.severity_counts);
                renderFindingsCards(report.findings || []);

                if (elements.resultsContent) elements.resultsContent.textContent = JSON.stringify(report, null, 2);
                checkReportAvailability();
            } else {
                // If no report exists, keep "Waiting" state but don't error out
                if (elements.resultsContent) elements.resultsContent.textContent = data.message || "// No scan data yet";
            }
        } catch (error) {
            console.error('Error fetching Semgrep report:', error);
        }
    }

    // --- AI Analysis Logic ---
    async function analyzeReport(llmMode) {
        if (elements.analyzeReportDropdown.disabled) return;
        var target = selectedFile ? selectedFile.name : elements.gitUrlInput.value.trim();

        if (!csrfToken) {
            appendLog('[!] Error: CSRF Token missing. Refresh page.');
            return;
        }

        elements.llmAnalysisOptions.classList.add('hidden');
        elements.aiProcessingOverlay.classList.remove('hidden');
        elements.aiProcessingText.textContent = llmMode.includes('gemini') ? 'CONTACTING GEMINI...' : 'LOADING LOCAL MODEL...';
        
        toggleSpinner(elements.analyzeReportDropdown, true);
        updateStatus('AI Analysis...', 'busy');

        try {
            // 1. Context
            var response = await fetch(ANALYZE_ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                body: JSON.stringify({ llm_mode: llmMode, target: target })
            });
            var data = await response.json();
            if (data.status !== 'success') throw new Error(data.message);
            
            // 2. Synthesize
            elements.aiProcessingText.textContent = 'ANALYZING CODE...';
            
            var CHATBOT_PROXY_URL = CHATBOT_REDIRECT_URL + '/scanner_analysis';
            response = await fetch(CHATBOT_PROXY_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
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
            appendLog('[x] AI ANALYSIS ERROR: ' + error.message);
            updateStatus('Analysis Failed', 'error');
            elements.aiProcessingOverlay.classList.add('hidden');
        } finally {
            toggleSpinner(elements.analyzeReportDropdown, false);
            checkReportAvailability(); 
        }
    }

    // --- Main Scan Event Listener ---
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
        appendLog('[*] Start Scan triggered.');
        var targetInput = "";
        var isFile = false;

        if (selectedFile) {
            isFile = true;
            targetInput = selectedFile.name;
        } else {
            targetInput = elements.gitUrlInput.value.trim();
        }

        if (!targetInput) {
            alert('Please provide a Git URL or upload a file.');
            return;
        }
        if (!csrfToken) {
            appendLog('[!] Error: CSRF Token missing.');
            return;
        }

        if (!userConfirmedAuth) {
            elements.resultsContent.textContent = "// Scanning...";
            elements.findingsTableBody.innerHTML = '<tr><td colspan="3" style="text-align:center; padding:2rem;">Scanning...</td></tr>';
            
            if(elements.findingsListSide) {
                elements.findingsListSide.innerHTML = '<div style="text-align:center; padding:2rem; font-family: var(--font-mono); font-size: 0.8rem; color: var(--neo-text-muted);">SCANNING IN PROGRESS...</div>';
            }
            resetDetailView();
        }

        toggleSpinner(elements.initiateScanBtn, true);
        updateStatus('Scanning...', 'busy');
        
        appendLog('> Initiating Semgrep scan on: ' + targetInput);
        if(elements.metricTarget) elements.metricTarget.textContent = targetInput;

        try {
            var formData = new FormData();
            if (isFile) {
                formData.append('file', selectedFile);
            } else {
                formData.append('git_url', targetInput);
                formData.append('user_confirmed_auth', userConfirmedAuth);
            }

            var response = await fetch('/semgrep_scanner/scan', {
                method: 'POST',
                headers: { 'X-CSRFToken': csrfToken },
                body: formData
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

    // --- Generic Listeners (Log Clear, Copy, Refresh, Download) ---
    if(elements.clearLogBtn) {
        elements.clearLogBtn.addEventListener('click', async function() {
            if (!csrfToken) return;
            elements.logOutput.innerHTML = '';
            await fetch('/semgrep_scanner/clear_log', { 
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
                if (elements.llmAnalysisOptions) {
                    elements.llmAnalysisOptions.classList.toggle('hidden');
                    e.stopPropagation();
                }
            }
        });
    }
    
    document.addEventListener('click', function(e) {
        if (elements.llmAnalysisOptions && elements.analyzeReportDropdown && !elements.analyzeReportDropdown.contains(e.target)) {
            elements.llmAnalysisOptions.classList.add('hidden');
        }
    });
    
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
        eventSource = new EventSource('/semgrep_scanner/log_stream');

        eventSource.onmessage = function(event) {
            var message = event.data;
            if (message && message !== ': keep-alive\n\n') {
                if (message.includes("SYSTEM_EVENT: READY_FOR_ANALYSIS")) {
                    checkReportAvailability();
                }

                // Check keywords for completion
                if (message.includes("PDF report generated") || 
                    message.includes("Semgrep scan complete") || 
                    message.includes("Scan complete") ||
                    message.includes("READY_FOR_ANALYSIS")) {
                    
                    updateStatus('Complete', 'success');
                    toggleSpinner(elements.initiateScanBtn, false);
                    setTimeout(fetchAndDisplayReport, 1000); // Small delay to ensure file write
                }

                if (message.includes("EVENT:") || message.startsWith("EVENT:")) return;
                appendLog(message);
            }
        };
    }

    // --- Initialization ---
    async function init() {
        appendLog('[*] SYSTEM READY. INITIALIZING STATIC ANALYSIS SECURITY AUDIT...');
        checkReportAvailability();
        fetchAndDisplayReport();
        
        // Setup status check loop if needed, or initial check
        try {
            const res = await fetch('/semgrep_scanner/status');
            const data = await res.json();
            if (data.is_running) {
                toggleSpinner(elements.initiateScanBtn, true);
                updateStatus('Scanning...', 'busy');
                appendLog('[*] DETECTED ACTIVE SEMGREP SCAN. RE-ATTACHING...');
                if (elements.metricTarget) elements.metricTarget.textContent = data.target;
                
                // Show "Scanning" in findings list
                if (elements.findingsListSide) {
                    elements.findingsListSide.innerHTML = '<div style="text-align:center; padding:2rem; font-family: var(--font-mono); font-size: 0.8rem; color: var(--neo-text-muted);">SCANNING IN PROGRESS...</div>';
                }
            }
        } catch (e) {
            console.error('Failed to check active scan:', e);
        }
    }

    // --- Init ---
    setTimeout(function() { appendLog('System Ready. Initializing Semgrep SAST Engine...'); }, 100);
    setupLogStream();
    checkActiveScan(); // [NEW] Check if a scan is already running
    fetchAndDisplayReport(); 
    checkReportAvailability(); 
}); 