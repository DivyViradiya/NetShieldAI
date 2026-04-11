document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Element Selectors ---
    const elements = {
        // Inputs & Controls
        targetUrlInput: document.getElementById('targetUrl'),
        startScanBtn: document.getElementById('startScanBtn'),
        scanOptionsBtn: document.getElementById('scanOptionsBtn'),
        scanOptionsDropdown: document.getElementById('scanOptionsDropdown'),
        scanMode: document.getElementById('scanMode'),
        scanTiming: document.getElementById('scanTiming'),
        scanLevel: document.getElementById('scanLevel'),
        tamperScript: document.getElementById('tamperScript'),
        scanTechnique: document.getElementById('scanTechnique'),
        toggleOptionsBtn: document.getElementById('toggleAdvancedOptionsBtn'),
        advancedOptionsArea: document.getElementById('advancedScanOptions'),
        checkWaf: document.getElementById('checkWaf'),
        
        // Metrics / Status
        scanStatus: document.getElementById('scanStatus'),
        lastScannedUrlDisplay: document.getElementById('lastScannedUrlDisplay'),
        targetDisplay: document.getElementById('targetDisplay'),
        hostStatusDisplay: document.getElementById('hostStatusDisplay'),
        findingsCountDisplay: document.getElementById('findingsCountDisplay'),
        threatLevelDisplay: document.getElementById('threatLevelDisplay'),
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
        resultsContent: document.getElementById('resultsContent'),
        rawContent: document.getElementById('rawContent'),
        copyJsonBtn: document.getElementById('copyJsonBtn'),

        // History
        sqlHistoryBtn: document.getElementById('sqlHistoryBtn'),
        historyModal: document.getElementById('historyModal'),
        closeHistoryModal: document.getElementById('closeHistoryModal'),
        historyTableBody: document.getElementById('historyTableBody'),
    };

    // --- State Variables ---
    const API_BASE_URL = '/sql_scanner';
    const CHATBOT_REDIRECT_URL = '/chatbot'; 
    let isActionInProgress = false;
    let isFetchingReport = false;
    let reportDownloadUrl = null;
    let currentFindings = [];
    let activeFilter = 'all';

    // --- 🔒 CSRF TOKEN RETRIEVAL ---
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

    // Tab Switching
    const findingsTabBtn = document.getElementById('findingsTabBtn');
    const rawTabBtn = document.getElementById('rawTabBtn');
    const findingsContent = document.getElementById('findingsContent');
    const rawContent = document.getElementById('rawContent');

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
        message = message.replace(/^\[?\d{1,2}:\d{2}:\d{2}\]?\s*/, '');
        message = message.replace(/(\[[A-Z]+\])\s*\1/g, '$1');
        message = message.replace(/\s\s+/g, ' ');
        message = message.trim();

        if (!message || message === '|' || message.includes('deprecated method')) return;

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
            <div class="log-content" style="${contentStyle}">${message}</div>
        `;
        
        if (elements.logOutput) {
            elements.logOutput.appendChild(line);
            elements.logOutput.scrollTop = elements.logOutput.scrollHeight;
        }
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
            
            // [NEW] Risk Score Rendering
            const rawScore = f.predicted_risk_score !== undefined ? f.predicted_risk_score : 0;
            const score = (rawScore * 10).toFixed(1);

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

    async function fetchReportData(specificTarget = null) {
        if (isFetchingReport) return;
        isFetchingReport = true;
        
        const target = specificTarget || elements.targetUrlInput?.value.trim();
        try {
            const url = target ? `${API_BASE_URL}/report?target=${encodeURIComponent(target)}` : `${API_BASE_URL}/report`;
            const response = await fetch(url);
            if (response.ok) {
                const data = await response.json();
                if(data.status === 'success') {
                    updateDashboard(data.content);
                }
            } else {
                const errorData = await response.json();
                appendLog(`[!] Failed to load findings: ${errorData.message || 'Unknown error'}`);
            }
        } catch (error) {
            console.error('Error fetching report:', error);
            appendLog(`[!] Connection error while fetching results.`);
        } finally {
            isFetchingReport = false;
        }
    }

    function updateDashboard(data) {
        if (!data) return;
        currentFindings = data.vulnerabilities || [];
        
        // Update Metrics
        if(elements.targetDisplay) elements.targetDisplay.textContent = data.target || '---';
        if(elements.metaTarget) elements.metaTarget.textContent = (data.target || '---').split('?')[0];
        
        const dbms = data.database_info?.dbms || '---';
        if (elements.dbmsDisplay) {
            elements.dbmsDisplay.textContent = dbms;
            elements.dbmsDisplay.title = dbms;
        }
        
        if (elements.findingsCountDisplay) elements.findingsCountDisplay.textContent = currentFindings.length;
        if (elements.dbCountDisplay) elements.dbCountDisplay.textContent = data.database_info?.db_count || '0';
        
        if (elements.lastScannedUrlDisplay) elements.lastScannedUrlDisplay.textContent = data.target || '---';

        if (elements.threatLevelDisplay) {
            const count = currentFindings.length;
            if (count > 5) {
                elements.threatLevelDisplay.textContent = 'CRITICAL';
                elements.threatLevelDisplay.style.color = 'var(--neo-red)';
            } else if (count > 0) {
                elements.threatLevelDisplay.textContent = 'HIGH';
                elements.threatLevelDisplay.style.color = 'var(--neo-amber)';
            } else {
                elements.threatLevelDisplay.textContent = 'LOW';
                elements.threatLevelDisplay.style.color = 'var(--neo-green)';
            }
        }
        
        if(data.scan_time && elements.hostStatusDisplay) {
            elements.hostStatusDisplay.textContent = "SCANNED";
            elements.hostStatusDisplay.style.color = 'var(--neo-green)';
        }

        // Calculate avg risk score
        const totalScore = currentFindings.reduce((acc, f) => acc + (f.predicted_risk_score || 0), 0);
        const avgScore = currentFindings.length > 0 
            ? (totalScore / currentFindings.length * 10).toFixed(1)
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

        // Update JSON View
        if (elements.resultsContent) {
            elements.resultsContent.textContent = JSON.stringify(data, null, 4);
        }
    }

    async function checkReportAvailability() {
        const target = elements.targetUrlInput?.value.trim();
        try {
            // If target is empty, we still want to check for the MOST RECENT report to enable buttons
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
                    // Extract target from filename (scanner_target.pdf)
                    let target = item.filename.split('_').slice(1).join('_').replace('.pdf', '');                    target = target.replace(/_\d{8}_\d{6}$/, '');
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

    if (elements.sqlHistoryBtn) {
        elements.sqlHistoryBtn.addEventListener('click', () => {
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
    function showAuthModal(message, onConfirm) {
        const modal = document.getElementById('authModal');
        const msgEl = document.getElementById('authModalMessage');
        const confirmBtn = document.getElementById('confirmAuthBtn');
        const cancelBtn = document.getElementById('cancelAuthBtn');

        if (msgEl) msgEl.textContent = message;
        if (modal) modal.classList.remove('hidden');

        // Clean up any old listener
        const newConfirmBtn = confirmBtn.cloneNode(true);
        confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);

        newConfirmBtn.addEventListener('click', () => {
            if (modal) modal.classList.add('hidden');
            if (onConfirm) onConfirm();
        });

        cancelBtn.onclick = () => {
            if (modal) modal.classList.add('hidden');
            setButtonsDisabled(false);
            toggleSpinner(elements.startScanBtn, false);
            setStatus('Ready');
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
            setButtonsDisabled(false);
            toggleSpinner(elements.startScanBtn, false);
            setStatus('Ready');
        };
    }

    async function initiateScan(userConfirmedAuth = false) {
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
                    check_waf: elements.checkWaf.checked,
                    user_confirmed_auth: userConfirmedAuth,
                    risk_level: elements.scanTiming ? elements.scanTiming.value : '3',
                    scan_level: elements.scanLevel ? elements.scanLevel.value : '3',
                    tamper: elements.tamperScript ? elements.tamperScript.value : '',
                    technique: elements.scanTechnique ? elements.scanTechnique.value : 'BEUSTQ'
                }),
            });
            const data = await response.json();
            if (response.ok) {
                appendLog(`[✓] ${data.message}`);
            } else {
                if (data.status === 'auth_required') {
                    showAuthModal(data.message, () => initiateScan(true));
                    return;
                }
                if (data.status === 'blocked') {
                    showBlockedModal(data.message);
                    return;
                }
                if (response.status === 403) {
                    showBlockedModal(data.message || 'Access is blocked.');
                    return;
                }
                throw new Error(data.message || 'Scan failed');
            }
        } catch (error) {
            appendLog(`[!] Error: ${error.message}`);
            setStatus('Error', 'error');
            setButtonsDisabled(false);
            toggleSpinner(elements.startScanBtn, false);
        }
    }

    async function analyzeReport(llmMode) {
        if (!elements.analyzeReportDropdown || elements.analyzeReportDropdown.disabled) return;
        const target = elements.targetUrlInput?.value.trim() || elements.targetDisplay?.textContent.trim();

        if (!csrfToken) {
            appendLog('[!] Error: CSRF Token missing. Refresh page.');
            return;
        }

        // 1. LOCK UI & SHOW OVERLAY
        if (elements.llmAnalysisOptions) elements.llmAnalysisOptions.classList.add('hidden');
        if (elements.aiProcessingOverlay) {
            elements.aiProcessingOverlay.classList.remove('hidden');
            if (elements.aiProcessingText) {
                elements.aiProcessingText.textContent = llmMode.includes('gemini') 
                    ? 'CONTACTING GEMINI...' 
                    : 'LOADING LOCAL MODEL...';
            }
        }

        setStatus(`AI Analysis (${llmMode})...`, 'busy');
        
        // Disable dropdown interactions
        elements.analyzeReportDropdown.disabled = true;

        try {
            // 2. Trigger Context Preparation (Backend loads Scan Data)
            let response = await fetch(`${API_BASE_URL}/trigger_ai_analysis`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ llm_mode: llmMode, target: target })
            });
            let data = await response.json();
            
            if (data.status !== 'success') throw new Error(data.message || 'Check failed.');
            
            // 3. Synthesize Report (Backend calls LLM)
            if (elements.aiProcessingText) elements.aiProcessingText.textContent = 'SYNTHESIZING REPORT...';

            response = await fetch(`${CHATBOT_REDIRECT_URL}/scanner_analysis`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ 
                    llm_mode: llmMode, 
                    scanner_type: 'sql',
                    target: data.target,
                    force_new_session: true
                })
            });

            data = await response.json();

            if (response.ok && data.status === 'success') {
                if (elements.aiProcessingText) elements.aiProcessingText.textContent = 'REDIRECTING...';
                setStatus('Redirecting...', 'success');
                
                // Brief delay to let the user see the "Redirecting" state
                setTimeout(() => {
                    const params = new URLSearchParams({
                        mode: data.llm_mode,
                        summary: data.summary,
                        session_id: data.session_id
                    });
                    window.location.href = `${CHATBOT_REDIRECT_URL}?${params.toString()}`;
                }, 800);
            } else {
                throw new Error(data.message || `Analysis failed`);
            }
        } catch (error) {
            appendLog(`[!] AI Analysis Error: ${error.message}`);
            setStatus('Analysis failed', 'error');
            
            // Hide overlay to allow retry
            if (elements.aiProcessingOverlay) elements.aiProcessingOverlay.classList.add('hidden');
            elements.analyzeReportDropdown.disabled = false;
        } finally {
            checkReportAvailability(); 
        }
    }

    // --- SSE Log Stream ---
    function initializeLogStream() {
        const eventSource = new EventSource(`${API_BASE_URL}/log_stream`);
        eventSource.onmessage = (event) => {
            const message = event.data;
            if (message.startsWith(':')) return;
            
            // 1. Structured Completion Event (Highest Priority)
            if (message.includes("EVENT: scan_complete")) {
                try {
                    const payloadStr = message.split('| PAYLOAD: ')[1];
                    const payload = JSON.parse(payloadStr);
                    
                    setStatus('Ready', 'success');
                    setButtonsDisabled(false);
                    toggleSpinner(elements.startScanBtn, false);
                    
                    // Controlled Refresh
                    fetchReportData(payload.target);
                    checkReportAvailability();
                } catch (e) { console.error("Error parsing scan_complete event:", e); }
                return;
            }

            // 2. Report Availability Signal
            if (message.includes("SYSTEM_EVENT: READY_FOR_ANALYSIS")) {
                checkReportAvailability();
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

        elements.toggleOptionsBtn?.addEventListener('click', () => {
            elements.advancedOptionsArea?.classList.toggle('hidden');
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
            const icon = elements.refreshResultsBtn.querySelector('.material-symbols-outlined');
            if (icon) icon.classList.add('animate-spin');
            
            Promise.all([
                fetchReportData(),
                checkReportAvailability()
            ]).then(() => {
                setTimeout(() => {
                    if (icon) icon.classList.remove('animate-spin');
                }, 800);
            });
        });

        elements.clearLogBtn?.addEventListener('click', () => {
            if (elements.logOutput) elements.logOutput.innerHTML = '';
            if (elements.resultsContent) elements.resultsContent.textContent = '// Buffer Empty';
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

        // --- Tab Switching Logic ---
        if (findingsTabBtn && rawTabBtn && findingsContent && rawContent) {
            findingsTabBtn.addEventListener('click', () => {
                findingsTabBtn.classList.add('active');
                rawTabBtn.classList.remove('active');
                findingsContent.classList.remove('hidden');
                rawContent.classList.add('hidden');
            });

            rawTabBtn.addEventListener('click', () => {
                rawTabBtn.classList.add('active');
                findingsTabBtn.classList.remove('active');
                rawContent.classList.remove('hidden');
                findingsContent.classList.add('hidden');
            });
        }

        elements.copyJsonBtn?.addEventListener('click', () => {
            const content = elements.resultsContent?.textContent;
            if (!content || content.includes('// Buffer Empty')) return;

            navigator.clipboard.writeText(content).then(() => {
                const icon = elements.copyJsonBtn.querySelector('.material-symbols-outlined');
                const text = elements.copyJsonBtn.querySelector('span:not(.material-symbols-outlined)');
                
                const originalIcon = icon.textContent;
                const originalText = text.textContent;

                icon.textContent = 'check';
                text.textContent = 'COPIED';
                elements.copyJsonBtn.style.color = 'var(--neo-green)';

                setTimeout(() => {
                    if (icon) icon.textContent = originalIcon;
                    if (text) text.textContent = originalText;
                    if (elements.copyJsonBtn) elements.copyJsonBtn.style.color = '';
                }, 2000);
            });
        });
    }

    // --- Init ---
    setupEventListeners();
    initializeLogStream();
    
    // Initial Check
    Promise.all([
        fetchReportData(),
        checkReportAvailability()
    ]).then(() => {
        if (currentFindings.length > 0) {
            renderFindings(currentFindings);
        }
    });
    
    setTimeout(() => appendLog('SQLMap Engine Initialized. Awaiting target...'), 100);
});
