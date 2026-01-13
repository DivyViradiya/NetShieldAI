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
        vulnerabilitiesContainer: document.getElementById('vulnerabilitiesContainer'), 
        vulnerabilitiesList: document.getElementById('vulnerabilitiesList'),
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

        var contentStyle = 'color:#d4d4d8';
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
        
        // Reset container to initial list
        if(elements.vulnerabilitiesContainer) {
            elements.vulnerabilitiesContainer.innerHTML = '<ul id="vulnerabilitiesList" style="list-style: none; padding: 0;"><li style="color: #9ca3af; font-size: 0.8rem; font-family: \'JetBrains Mono\', monospace; text-align: center; padding: 2rem;">WAITING FOR CODE SCAN...</li></ul>';
        }

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
        elements.vulnerabilitiesContainer.innerHTML = '';
        
        if (!findings || findings.length === 0) {
            elements.vulnerabilitiesContainer.innerHTML = '<div style="text-align:center; padding: 2rem; color: #10b981;">No vulnerabilities found. Code looks clean!</div>';
            return;
        }

        // Helper for severity styles
        var getStyles = function(sev) {
            if (sev === 'ERROR') return { border: '#ef4444', badgeBg: '#fee2e2', badgeCol: '#be123c' };
            if (sev === 'WARNING') return { border: '#f97316', badgeBg: '#ffedd5', badgeCol: '#c2410c' };
            return { border: '#3b82f6', badgeBg: '#e0f2fe', badgeCol: '#0369a1' };
        };

        findings.forEach(function(f) {
            var styles = getStyles(f.severity);
            
            // Clean path
            var cleanPath = f.path;
            if (cleanPath.includes("source_code_temp")) {
                cleanPath = cleanPath.split("source_code_temp")[1].replace(/^[\\/]/, "");
            }

            var card = document.createElement('div');
            card.className = 'vuln-item'; // Reuse base class for some padding
            card.style.cssText = `border-left: 3px solid ${styles.border}; background: rgba(255,255,255,0.03); border-radius: 6px; padding: 0; margin-bottom: 1rem; overflow: hidden;`;

            var headerHtml = `
                <div style="padding: 10px 15px; background: rgba(255,255,255,0.05); display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(255,255,255,0.05);">
                    <div style="font-family: monospace; font-size: 0.75rem; color: #e4e4e7; font-weight: 600;">${f.check_id}</div>
                    <span style="background: ${styles.badgeBg}; color: ${styles.badgeCol}; padding: 2px 8px; border-radius: 4px; font-size: 0.65rem; font-weight: 700;">${f.severity}</span>
                </div>
            `;

            var bodyHtml = `
                <div style="padding: 15px;">
                    <div style="margin-bottom: 10px; font-size: 0.8rem; color: #a1a1aa;">
                        <span style="color: #fff; font-weight: 600;">${cleanPath}</span> : Line ${f.line}
                    </div>
                    <div style="margin-bottom: 10px; font-size: 0.85rem; color: #d4d4d8;">${f.message}</div>
                    
                    ${f.code_snippet !== 'N/A' ? `
                        <div style="background: #0f0f11; padding: 10px; border-radius: 4px; border: 1px solid #27272a; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #e4e4e7; white-space: pre-wrap; overflow-x: auto;">${f.code_snippet}</div>
                    ` : ''}
                </div>
            `;

            card.innerHTML = headerHtml + bodyHtml;
            elements.vulnerabilitiesContainer.appendChild(card);
        });
    }

    async function fetchAndDisplayReport() {
        try {
            var response = await fetch('/semgrep_scanner/report');
            var data = await response.json();

            if (data.status === 'success') {
                var report = data.content;
                
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
                body: JSON.stringify({ llm_mode: llmMode, scanner_type: data.scanner_type }) 
            });

            data = await response.json();

            if (response.ok && data.status === 'success') {
                elements.aiProcessingText.textContent = 'REDIRECTING...';
                updateStatus('Redirecting...', 'success');
                setTimeout(function() {
                    window.location.href = CHATBOT_REDIRECT_URL + '?mode=' + data.llm_mode + '&summary=' + encodeURIComponent(data.summary);
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
            elements.vulnerabilitiesContainer.innerHTML = '<div style="text-align:center; padding:2rem;">Scanning in progress...</div>';

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