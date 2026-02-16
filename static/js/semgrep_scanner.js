document.addEventListener('DOMContentLoaded', function() {
    // --- Element References ---
    var elements = {
        // Inputs & Controls
        gitUrlInput: document.getElementById('gitUrlInput'),
        fileUploadInput: document.getElementById('fileUploadInput'),
        triggerUploadBtn: document.getElementById('triggerUploadBtn'),
        resetScanBtn: document.getElementById('resetScanBtn'), // <--- ADDED THIS
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
        serverConfigDetails: document.getElementById('serverConfigDetails') 
    };

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

        var now = new Date();
        var timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });
        var cleanedMessage = message.replace(/\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s*/g, "").trim();

        var contentStyle = 'color:var(--neo-text-muted)';
        var lowerMsg = cleanedMessage.toLowerCase();
        
        if (cleanedMessage.includes('[!]') || lowerMsg.includes('error') || lowerMsg.includes('failed')) {
            contentStyle = 'color:#ef4444'; 
        } else if (cleanedMessage.includes('[+]') || cleanedMessage.includes('[✓]') || lowerMsg.includes('success') || lowerMsg.includes('complete')) {
            contentStyle = 'color:#10b981'; 
        } else if (cleanedMessage.includes('[*]') || lowerMsg.includes('initiating')) {
            contentStyle = 'color:#3b82f6'; 
        }

        var line = document.createElement('div');
        line.className = 'log-line';
        line.innerHTML = 
            '<div class="log-time">' + timeStr + '</div>' +
            '<div class="log-content" style="' + contentStyle + '">' + cleanedMessage + '</div>';
        
        elements.logOutput.appendChild(line);
        elements.logOutput.scrollTop = elements.logOutput.scrollHeight;
    }

    // --- State Management ---

    function clearScanResults() {
        if(elements.metricTarget) elements.metricTarget.textContent = '---';
        if(elements.metricTotal) elements.metricTotal.textContent = '0';
        if(elements.metricHigh) elements.metricHigh.textContent = '0';
        if(elements.metricDuration) elements.metricDuration.textContent = '---';
        
        if(elements.serverConfigDetails) elements.serverConfigDetails.innerHTML = '<div style="display:flex; justify-content:space-between; padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.1);"><span>Tool</span><span style="color: #fff;">Semgrep OSS</span></div><div style="display:flex; justify-content:space-between; padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.1);"><span>Rulesets</span><span style="color: var(--neo-green);">Security, Secrets, Flask</span></div>';
        
        if(elements.findingsTableBody) elements.findingsTableBody.innerHTML = '<tr><td colspan="3" style="text-align:center; color: #555; padding: 2rem; font-family: monospace;">---</td></tr>';
        
        if(elements.findingsListSide) {
            elements.findingsListSide.innerHTML = '<div style="text-align:center; padding: 3rem; color: #444; font-family: var(--font-mono); font-size: 0.8rem;">WAITING FOR CODE SCAN...</div>';
        }

        resetDetailView();

        if(elements.resultsContent) elements.resultsContent.textContent = '// JSON OUTPUT';
        
        [elements.downloadReportBtn, elements.analyzeReportDropdown].forEach(function(btn) {
            if (btn) {
                btn.disabled = true;
                btn.style.opacity = '0.7';
            }
        });
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

    async function checkReportAvailability() {
        try {
            var response = await fetch(REPORT_FILES_ENDPOINT);
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
    }

    function renderMetadata(data) {
        var html = '';
        var createItem = function(label, val, color) {
            return '<div style="display:flex; justify-content:space-between; padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.1);">' +
                   '<span>' + label + '</span><span style="color: ' + (color || '#fff') + ';">' + val + '</span></div>';
        };

        html += createItem("Tool", data.tool || "Semgrep OSS");
        html += createItem("Rulesets", "Security, Secrets, Flask", "#10b981");
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
        
        var filteredFindings = findings.filter(function(f) {
            return f.check_id.toLowerCase().includes(filterText) || 
                   f.path.toLowerCase().includes(filterText) || 
                   f.message.toLowerCase().includes(filterText);
        });

        var countBadge = document.getElementById('filteredCountBadge');
        if(countBadge) countBadge.textContent = filteredFindings.length + ' FINDING' + (filteredFindings.length !== 1 ? 'S' : '');

        if (!filteredFindings || filteredFindings.length === 0) {
            elements.findingsListSide.innerHTML = '<div style="text-align:center; padding: 3rem; color: #444; font-family: var(--font-mono); font-size: 0.75rem;">' + (filterText ? 'NO MATCHES.' : 'NO VULNERABILITIES.') + '</div>';
            resetDetailView();
            return;
        }

        // Helper for severity styles
        var getColors = function(sev) {
            if (sev === 'ERROR') return { dot: '#ef4444', text: '#ef4444' };
            if (sev === 'WARNING') return { dot: '#f97316', text: '#f97316' };
            return { dot: '#3b82f6', text: '#3b82f6' };
        };

        filteredFindings.forEach(function(f, index) {
            var colors = getColors(f.severity);
            var cleanPath = f.path.includes("source_code_temp") ? f.path.split("source_code_temp")[1].replace(/^[\\/]/, "") : f.path;

            var item = document.createElement('div');
            item.className = 'finding-item-compact';
            if (window.selectedFindingIndex === index) item.classList.add('active');

            item.innerHTML = `
                <div class="compact-rule-id">${f.check_id}</div>
                <div class="compact-file-info" title="${cleanPath}">${cleanPath}</div>
                <div class="compact-meta">
                    <span><span class="severity-dot" style="background: ${colors.dot}"></span>${f.severity}</span>
                    <span>Line ${f.line}</span>
                </div>
            `;

            item.onclick = function() {
                // Update active state
                document.querySelectorAll('.finding-item-compact').forEach(el => el.classList.remove('active'));
                item.classList.add('active');
                window.selectedFindingIndex = index;
                renderDetailView(f, cleanPath);
            };

            elements.findingsListSide.appendChild(item);
        });

        // Automatically select the first finding if none selected
        if (window.selectedFindingIndex === undefined && filteredFindings.length > 0) {
            elements.findingsListSide.firstChild.click();
        }
    }

    function resetDetailView() {
        if(!elements.findingsDetailSide) return;
        elements.findingsDetailSide.innerHTML = `
            <div class="empty-detail-state">
                <span class="material-symbols-outlined" style="font-size: 4rem; opacity: 0.1;">data_exploration</span>
                <div style="font-family: var(--font-mono); font-size: 0.8rem; opacity: 0.3; letter-spacing: 0.1em;">SELECT A FINDING TO VIEW ANALYSIS</div>
            </div>
        `;
    }

    function renderDetailView(f, cleanPath) {
        if(!elements.findingsDetailSide) return;

        var severityColor = f.severity === 'ERROR' ? '#ef4444' : (f.severity === 'WARNING' ? '#f97316' : '#3b82f6');

        elements.findingsDetailSide.innerHTML = `
            <div class="detail-header">
                <div class="detail-rule-id">${f.check_id}</div>
                <div class="detail-title">${cleanPath}</div>
                <div style="display:flex; gap: 1rem; margin-top: 1rem; align-items:center;">
                    <span class="badge-pill" style="color: ${severityColor}; border-color: ${severityColor}44; background: ${severityColor}11;">
                        ${f.severity}
                    </span>
                    <span style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--neo-text-muted);">
                        Line ${f.line}:${f.column}
                    </span>
                </div>
            </div>

            <div class="flex flex-col gap-2">
                <div class="detail-section-label">
                    <span class="material-symbols-outlined" style="font-size: 1rem;">description</span>
                    Issue Description
                </div>
                <div class="detail-box">
                    <div class="vuln-message">${f.message}</div>
                </div>
            </div>

            <div class="flex flex-col gap-2">
                <div class="detail-section-label">
                    <span class="material-symbols-outlined" style="font-size: 1rem;">code</span>
                    Code Evidence
                </div>
                <div class="code-view-wrapper">
                    <div class="code-view-header">
                        <span>SOURCE CODE</span>
                        <span>READ-ONLY</span>
                    </div>
                    <div class="code-view-content">${f.code_snippet || 'N/A'}</div>
                </div>
            </div>

            ${f.fix_suggestion && f.fix_suggestion !== 'N/A' ? `
                <div class="flex flex-col gap-2">
                    <div class="detail-section-label">
                        <span class="material-symbols-outlined" style="font-size: 1rem; color: #10b981;">lightbulb</span>
                        Remediation Guidance
                    </div>
                    <div class="fix-suggestion-box">
                        <div style="font-size: 0.85rem; color: #10b981; font-family: var(--font-mono); line-height: 1.6;">${f.fix_suggestion}</div>
                    </div>
                </div>
            ` : ''}
        `;
    }

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

            if (data.status === 'success') {
                var report = data.content;
                window.currentSemgrepReport = report; // Store globally for filtering
                
                // Update Metrics
                elements.metricTotal.textContent = report.total_findings;
                elements.metricHigh.textContent = report.severity_counts.ERROR || 0;
                
                // Render
                renderMetadata(report);
                renderSeverityTable(report.severity_counts);
                renderFindingsCards(report.findings);

                elements.resultsContent.textContent = JSON.stringify(report, null, 2);
                checkReportAvailability();
            } else {
                // If no report exists, keep "Waiting" state but don't error out
                elements.resultsContent.textContent = data.message || "// No scan data yet";
            }
        } catch (error) {
            console.error('Error fetching Semgrep report:', error);
        }
    }

    // --- AI Analysis Logic ---
    async function analyzeReport(llmMode) {
        if (elements.analyzeReportDropdown.disabled) return;
        if (!csrfToken) {
            appendLog('[!] Error: CSRF Token missing. Refresh page.');
            return;
        }

        elements.llmAnalysisOptions.classList.add('hidden');
        elements.aiProcessingOverlay.classList.remove('hidden');
        elements.aiProcessingText.textContent = llmMode === 'gemini' ? 'CONTACTING GEMINI...' : 'LOADING LOCAL MODEL...';
        
        toggleSpinner(elements.analyzeReportDropdown, true);
        updateStatus('AI Analysis...', 'busy');

        try {
            // 1. Context
            var response = await fetch(ANALYZE_ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                body: JSON.stringify({ llm_mode: llmMode })
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
            elements.aiProcessingOverlay.classList.add('hidden');
        } finally {
            toggleSpinner(elements.analyzeReportDropdown, false);
            checkReportAvailability(); 
        }
    }

    // --- Main Scan Event Listener ---
    if(elements.initiateScanBtn) {
        elements.initiateScanBtn.addEventListener('click', async function() {
            appendLog('[*] Start Scan button clicked.');
            var targetInput = "";
            var isFile = false;

            // Determine Input Type
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

            // Clean UI before start
            elements.resultsContent.textContent = "// Scanning...";
            elements.findingsTableBody.innerHTML = '<tr><td colspan="3" style="text-align:center; padding:2rem;">Scanning...</td></tr>';
            
            if(elements.findingsListSide) {
                elements.findingsListSide.innerHTML = '<div style="text-align:center; padding:2rem; font-family: var(--font-mono); font-size: 0.8rem; color: var(--neo-text-muted);">SCANNING IN PROGRESS...</div>';
            }
            resetDetailView();

            toggleSpinner(elements.initiateScanBtn, true);
            updateStatus('Scanning...', 'busy');
            
            appendLog('> Initiating Semgrep scan on: ' + targetInput);
            if(elements.metricTarget) elements.metricTarget.textContent = targetInput;

            try {
                // Construct FormData for File Upload
                var formData = new FormData();
                if (isFile) {
                    formData.append('file', selectedFile);
                } else {
                    formData.append('git_url', targetInput);
                }

                var response = await fetch('/semgrep_scanner/scan', {
                    method: 'POST',
                    headers: { 'X-CSRFToken': csrfToken }, // Do NOT set Content-Type for FormData
                    body: formData
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
        eventSource = new EventSource('/semgrep_scanner/log_stream');

        eventSource.onmessage = function(event) {
            var message = event.data;
            if (message && message !== ': keep-alive\n\n') {
                appendLog(message);
                
                // Check keywords for completion
                if (message.includes("PDF report generated") || message.includes("Semgrep scan complete") || message.includes("Scan complete")) {
                    updateStatus('Complete', 'success');
                    toggleSpinner(elements.initiateScanBtn, false);
                    fetchAndDisplayReport(); 
                }
            }
        };
    }

    // --- Init ---
    setTimeout(function() { appendLog('System Ready. Initializing Semgrep SAST Engine...'); }, 100);
    setupLogStream();
    fetchAndDisplayReport(); 
    checkReportAvailability(); 
}); 