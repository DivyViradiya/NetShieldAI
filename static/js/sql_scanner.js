document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Element Selectors ---
    const elements = {
        // Inputs & Controls
        targetUrlInput: document.getElementById('targetUrl'),
        startScanBtn: document.getElementById('startScanBtn'),
        scanOptionsBtn: document.getElementById('scanOptionsBtn'),
        scanOptionsDropdown: document.getElementById('scanOptionsDropdown'),
        scanMode: document.getElementById('scanMode'),
        checkWaf: document.getElementById('checkWaf'),
        
        // Metrics / Status
        scanStatus: document.getElementById('scanStatus'),
        targetDisplay: document.getElementById('targetDisplay'),
        hostStatusDisplay: document.getElementById('hostStatusDisplay'),
        vulnCountDisplay: document.getElementById('vulnCountDisplay'),
        dbmsDisplay: document.getElementById('dbmsDisplay'),
        strengthDisplay: document.getElementById('strengthDisplay'), // Used as Risk Score display
        
        // Intelligence & Insights
        refreshResultsBtn: document.getElementById('refreshResultsBtn'),
        analyzeReportDropdown: document.getElementById('analyzeReportDropdown'),
        llmAnalysisOptions: document.getElementById('llmAnalysisOptions'),
        downloadReportBtn: document.getElementById('downloadReportBtn'),
        avgRiskScore: document.getElementById('avgRiskScore'),
        topVectorsList: document.getElementById('topVectorsList'),
        metaTarget: document.getElementById('metaTarget'),
        metaDuration: document.getElementById('metaDuration'),
        
        // AI Animation Elements
        aiProcessingOverlay: document.getElementById('aiProcessingOverlay'),
        aiProcessingText: document.getElementById('aiProcessingText'),

        // Findings List
        findingsList: document.getElementById('findingsList'),
        findingsCountDisplay: document.getElementById('findingsCountDisplay'),
        findingsSearch: document.getElementById('findingsSearch'),
        filterChips: document.querySelectorAll('.filter-chip'),
        
        // Live Terminal
        clearLogBtn: document.getElementById('clearLogBtn'),
        logOutput: document.getElementById('logOutput'),
    };

    // --- State Variables ---
    const API_BASE_URL = '/sql_scanner';
    const CHATBOT_REDIRECT_URL = '/chatbot'; 
    let isActionInProgress = false;
    let reportDownloadUrl = null;
    let currentFindings = [];
    let activeFilter = 'all';

    // --- 🔒 CSRF TOKEN RETRIEVAL ---
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

    // --- Helper Functions ---
    
    function setButtonsDisabled(isDisabled) {
        const controlBtns = [
            elements.startScanBtn,
            elements.scanOptionsBtn,
            elements.refreshResultsBtn
        ];

        controlBtns.forEach(btn => {
            if (btn) {
                btn.disabled = isDisabled;
                btn.style.opacity = isDisabled ? '0.5' : '1';
                btn.classList.toggle('cursor-not-allowed', isDisabled);
            }
        });

        if (elements.targetUrlInput) {
            elements.targetUrlInput.disabled = isDisabled;
        }
    }

    function toggleSpinner(button, isLoading) {
        if (!button) return;
        const spinner = button.querySelector('.spinner');
        const icon = button.querySelector('.material-symbols-outlined'); 
        
        if (isLoading) {
            button.classList.add('opacity-70', 'cursor-not-allowed');
            if (icon) icon.classList.add('hidden'); 
            if (spinner) spinner.classList.remove('hidden');
        } else {
            button.classList.remove('opacity-70', 'cursor-not-allowed');
            if (spinner) spinner.classList.add('hidden');
            if (icon) icon.classList.remove('hidden');
        }
    }
    
    function appendLog(message) {
        if (!elements.logOutput) return;

        // Cleanup timestamps from message
        message = message.replace(/^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s*/, '');
        message = message.replace(/\[\d{2}:\d{2}:\d{2}\]\s*/g, '');
        message = message.replace(/\s\s+/g, ' ');

        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });

        let contentStyle = 'color:#999';
        if (message.includes('[!]') || message.toLowerCase().includes('error')) contentStyle = 'color:var(--neo-red)'; 
        else if (message.includes('[+]') || message.toLowerCase().includes('success')) contentStyle = 'color:var(--neo-green)'; 
        else if (message.includes('[*]') || message.includes('[STAGE]')) contentStyle = 'color:var(--neo-blue)';
        else if (message.includes('[DATA]')) contentStyle = 'color:var(--neo-amber)';

        const line = document.createElement('div');
        line.className = 'log-line';
        line.innerHTML = `
            <div class="log-time">${timeStr}</div>
            <div class="log-prompt">></div>
            <div class="log-content" style="${contentStyle}">${message}</div>
        `;
        
        elements.logOutput.appendChild(line);
        elements.logOutput.scrollTop = elements.logOutput.scrollHeight;
    }

    function setStatus(text, type = 'ready') {
        if (!elements.scanStatus) return;
        elements.scanStatus.textContent = text.toUpperCase();
        
        const badge = elements.scanStatus.parentElement;
        if (type === 'busy') badge.style.color = 'var(--neo-amber)';
        else if (type === 'error') badge.style.color = 'var(--neo-red)';
        else badge.style.color = 'var(--neo-green)';
    }

    // --- Findings Management ---

    function getRiskColor(type) {
        const t = (type || '').toLowerCase();
        if (t.includes('stacked') || t.includes('union') || t.includes('time-based blind')) return 'var(--risk-high)';
        if (t.includes('error-based') || t.includes('boolean-based')) return 'var(--risk-med)';
        return 'var(--risk-low)';
    }

    function getRiskLabel(type) {
        const t = (type || '').toLowerCase();
        if (t.includes('stacked') || t.includes('union') || t.includes('time-based blind')) return 'High';
        if (t.includes('error-based') || t.includes('boolean-based')) return 'Medium';
        return 'Low';
    }

    function renderFindings(findings) {
        if (!elements.findingsList) return;
        
        const searchTerm = (elements.findingsSearch?.value || '').toLowerCase();
        
        const filtered = findings.filter(f => {
            const risk = getRiskLabel(f.type);
            const matchesFilter = activeFilter === 'all' || risk === activeFilter;
            const matchesSearch = !searchTerm || 
                f.title.toLowerCase().includes(searchTerm) || 
                f.type.toLowerCase().includes(searchTerm) ||
                f.parameter.toLowerCase().includes(searchTerm);
            return matchesFilter && matchesSearch;
        });

        elements.findingsCountDisplay.textContent = filtered.length;

        if (filtered.length === 0) {
            elements.findingsList.innerHTML = `
                <div style="text-align:center; padding: 4rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.85rem;">
                    <span class="material-symbols-outlined" style="font-size: 3rem; opacity: 0.2; margin-bottom: 1rem; display: block;">search_off</span>
                    ${findings.length === 0 ? 'INITIATE A SCAN TO VIEW RESULTS...' : 'NO FINDINGS MATCH YOUR FILTERS.'}
                </div>`;
            return;
        }

        elements.findingsList.innerHTML = filtered.map((f, index) => {
            const riskLabel = getRiskLabel(f.type);
            const riskColor = getRiskColor(f.type);
            const score = riskLabel === 'High' ? '8.5' : (riskLabel === 'Medium' ? '6.0' : '3.5');

            return `
                <div class="finding-card" data-index="${index}">
                    <div class="finding-header">
                        <div class="risk-indicator" style="color: ${riskColor}">
                            <div class="risk-dot" style="background: ${riskColor}"></div>
                            ${riskLabel}
                        </div>
                        <div class="finding-title">${f.type} on parameter '${f.parameter}'</div>
                        <div class="score-container">
                            <span class="score-label">Risk Score</span>
                            <span class="score-val">${score}</span>
                        </div>
                        <span class="material-symbols-outlined expand-icon">expand_more</span>
                    </div>
                    <div class="finding-details">
                        <div class="details-content">
                            <div class="detail-section">
                                <span class="detail-label">Vulnerability Details</span>
                                <p class="detail-text">${f.title || 'SQL Injection detected on target parameter.'}</p>
                            </div>
                            <div class="detail-section">
                                <span class="detail-label">Confirmed Payload</span>
                                <div class="detail-text-mono" style="background: var(--neo-input); padding: 1rem; border-radius: 6px; word-break: break-all;">${f.payload}</div>
                            </div>
                            <div class="detail-section">
                                <span class="detail-label">Affected Parameter</span>
                                <span class="detail-text-mono">${f.parameter}</span>
                            </div>
                            <div class="detail-section">
                                <span class="detail-label">Target URL</span>
                                <a href="${f.url}" target="_blank" class="finding-url-link">${f.url}</a>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        // Re-attach expand listeners
        elements.findingsList.querySelectorAll('.finding-card').forEach(card => {
            card.addEventListener('click', () => {
                const isExpanded = card.classList.contains('expanded');
                // Close others
                elements.findingsList.querySelectorAll('.finding-card.expanded').forEach(c => c.classList.remove('expanded'));
                if (!isExpanded) card.classList.add('expanded');
            });
        });
    }

    // --- API & Data Functions ---

    async function fetchReportData() {
        try {
            const response = await fetch(`${API_BASE_URL}/report`);
            if (response.ok) {
                const data = await response.json();
                if(data.status === 'success') {
                    updateDashboard(data.content);
                }
            }
            await checkReportAvailability();
        } catch (error) {
            console.error('Error fetching report:', error);
        }
    }

    function updateDashboard(data) {
        currentFindings = data.vulnerabilities || [];
        
        // Update Metrics
        if(elements.targetDisplay) elements.targetDisplay.textContent = data.target || '---';
        if(elements.metaTarget) elements.metaTarget.textContent = (data.target || '---').split('?')[0];
        
        const dbms = data.database_info?.dbms || '---';
        elements.dbmsDisplay.textContent = dbms;
        elements.dbmsDisplay.title = dbms;
        
        elements.vulnCountDisplay.textContent = currentFindings.length;
        
        if(data.scan_time) {
            elements.hostStatusDisplay.textContent = "SCANNED";
            elements.hostStatusDisplay.style.color = 'var(--neo-green)';
        }

        // Calculate avg risk score
        const highCount = currentFindings.filter(f => getRiskLabel(f.type) === 'High').length;
        const medCount = currentFindings.filter(f => getRiskLabel(f.type) === 'Medium').length;
        const avgScore = currentFindings.length > 0 
            ? ((highCount * 8.5 + medCount * 6.0 + (currentFindings.length - highCount - medCount) * 3.5) / currentFindings.length).toFixed(1)
            : "0.0";
        
        if (elements.strengthDisplay) elements.strengthDisplay.textContent = avgScore;
        if (elements.avgRiskScore) elements.avgRiskScore.textContent = avgScore;

        // Render Attack Vectors
        if (elements.topVectorsList) {
            const vectors = {};
            currentFindings.forEach(f => {
                vectors[f.type] = (vectors[f.type] || 0) + 1;
            });
            const sortedVectors = Object.entries(vectors).sort((a,b) => b[1] - a[1]).slice(0, 3);
            
            if (sortedVectors.length > 0) {
                elements.topVectorsList.innerHTML = sortedVectors.map(([name, count]) => `
                    <div class="vector-item">
                        <span class="vector-name" title="${name}">${name}</span>
                        <span class="vector-count">${count}</span>
                    </div>
                `).join('');
            } else {
                elements.topVectorsList.innerHTML = `<div style="text-align:center; padding: 1rem; color: var(--neo-text-muted); font-size: 0.7rem; font-family: var(--font-mono);">NO VECTORS DETECTED</div>`;
            }
        }

        renderFindings(currentFindings);
    }

    async function checkReportAvailability() {
        const target = elements.targetUrlInput.value.trim();
        try {
            const url = target ? `${API_BASE_URL}/report_files?target=${encodeURIComponent(target)}` : `${API_BASE_URL}/report_files`;
            const response = await fetch(url);
            if (response.ok) {
                const data = await response.json();
                if (data.status === 'success' && data.pdf_report) {
                    reportDownloadUrl = data.pdf_report;
                    [elements.downloadReportBtn, elements.analyzeReportDropdown].forEach(btn => {
                        if (btn) {
                            btn.disabled = false;
                            btn.style.opacity = '1';
                        }
                    });
                    return;
                }
            }
        } catch (error) { console.error(error); }

        reportDownloadUrl = null;
        [elements.downloadReportBtn, elements.analyzeReportDropdown].forEach(btn => {
            if (btn) {
                btn.disabled = true;
                btn.style.opacity = '0.7';
            }
        });
    }

    async function initiateScan() {
        const targetUrl = elements.targetUrlInput.value.trim();
        if (!targetUrl) {
            appendLog('[!] Error: Target URL is required.');
            return;
        }
        
        setButtonsDisabled(true);
        setStatus('Scanning...', 'busy');
        toggleSpinner(elements.startScanBtn, true);

        try {
            const response = await fetch(`${API_BASE_URL}/scan`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken 
                },
                body: JSON.stringify({
                    target_url: targetUrl,
                    scan_mode: elements.scanMode.value,
                    check_waf: elements.checkWaf.checked
                }),
            });
            const data = await response.json();
            if (response.ok) {
                appendLog(`[✓] ${data.message}`);
            } else {
                throw new Error(data.message);
            }
        } catch (error) {
            appendLog(`[!] Error: ${error.message}`);
            setStatus('Error', 'error');
            setButtonsDisabled(false);
            toggleSpinner(elements.startScanBtn, false);
        }
    }

    async function analyzeReport(llmMode) {
        const overlay = elements.aiProcessingOverlay;
        const processingText = elements.aiProcessingText;
        const target = elements.targetUrlInput.value.trim();

        if (overlay) overlay.classList.remove('hidden');
        if (processingText) processingText.textContent = 'PREPARING ANALYSIS...';

        try {
            let response = await fetch(`${API_BASE_URL}/trigger_ai_analysis`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                body: JSON.stringify({ target: target })
            });
            let data = await response.json();
            if (data.status !== 'success') throw new Error(data.message);
            
            if (processingText) processingText.textContent = 'RUNNING AI ENGINE...';

            response = await fetch(`${CHATBOT_REDIRECT_URL}/scanner_analysis`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                body: JSON.stringify({ 
                    llm_mode: llmMode, 
                    scanner_type: 'sql',
                    target: data.target,
                    force_new_session: true
                })
            });

            data = await response.json();
            if (response.ok && data.status === 'success') {
                window.location.href = `${CHATBOT_REDIRECT_URL}?mode=${data.llm_mode}&summary=${data.summary}&session_id=${data.session_id}`;
            } else {
                throw new Error(data.message);
            }
        } catch (error) {
            appendLog(`[!] AI Analysis Error: ${error.message}`);
            if (overlay) overlay.classList.add('hidden');
        } 
    }

    // --- SSE Log Stream ---
    function initializeLogStream() {
        const eventSource = new EventSource(`${API_BASE_URL}/log_stream`);
        eventSource.onmessage = (event) => {
            const message = event.data;
            if (message.startsWith(':')) return;
            
            if (message.includes("SYSTEM_EVENT: READY_FOR_ANALYSIS")) {
                checkReportAvailability();
            }

            if (message.toLowerCase().includes("scan complete") || message.toLowerCase().includes("finished")) {
                setStatus('Ready', 'success');
                fetchReportData().then(() => {
                    setButtonsDisabled(false);
                    toggleSpinner(elements.startScanBtn, false);
                });
            }

            if (!message.includes("EVENT:")) appendLog(message);
        };
    }

    // --- Event Listeners ---
    function setupEventListeners() {
        elements.startScanBtn?.addEventListener('click', initiateScan);
        
        elements.scanOptionsBtn?.addEventListener('click', (e) => {
            e.stopPropagation();
            elements.scanOptionsDropdown.classList.toggle('hidden');
        });

        document.addEventListener('click', (e) => {
            if (elements.scanOptionsDropdown && !elements.scanOptionsDropdown.contains(e.target)) {
                elements.scanOptionsDropdown.classList.add('hidden');
            }
            if (elements.llmAnalysisOptions && !elements.llmAnalysisOptions.contains(e.target)) {
                elements.llmAnalysisOptions.classList.add('hidden');
            }
        });

        elements.refreshResultsBtn?.addEventListener('click', () => {
            toggleSpinner(elements.refreshResultsBtn, true);
            fetchReportData().then(() => setTimeout(() => toggleSpinner(elements.refreshResultsBtn, false), 500));
        });

        elements.clearLogBtn?.addEventListener('click', () => {
            elements.logOutput.innerHTML = '';
            fetch(`${API_BASE_URL}/clear_log`, { method: 'POST', headers: { 'X-CSRFToken': csrfToken } });
        });

        elements.downloadReportBtn?.addEventListener('click', () => {
            if (reportDownloadUrl) window.location.href = reportDownloadUrl;
        });

        elements.analyzeReportDropdown?.addEventListener('click', (e) => {
            e.stopPropagation();
            elements.llmAnalysisOptions.classList.toggle('hidden');
        });

        elements.llmAnalysisOptions?.addEventListener('click', (e) => {
            const opt = e.target.closest('a[data-llm-mode]');
            if (opt) analyzeReport(opt.dataset.llmMode);
        });

        elements.findingsSearch?.addEventListener('input', () => renderFindings(currentFindings));

        elements.filterChips.forEach(chip => {
            chip.addEventListener('click', () => {
                elements.filterChips.forEach(c => c.classList.remove('active'));
                chip.classList.add('active');
                activeFilter = chip.dataset.filter;
                renderFindings(currentFindings);
            });
        });
    }

    // --- Init ---
    setupEventListeners();
    initializeLogStream();
    
    // Initial Check
    fetchReportData().then(() => {
        if (currentFindings.length > 0) {
            renderFindings(currentFindings);
        }
    });
    
    setTimeout(() => appendLog('SQLMap Engine Initialized. Awaiting target...'), 100);
});
