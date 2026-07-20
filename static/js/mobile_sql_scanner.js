document.addEventListener('DOMContentLoaded', () => {
    // --- API Endpoints ---
    const API_BASE_URL = '/sql_scanner';
    const CHATBOT_REDIRECT_URL = '/chatbot'; 

    // --- 🔒 CSRF TOKEN ---
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

    // --- DOM Elements ---
    const elements = {
        // Inputs & Controls
        targetUrlInput: document.getElementById('targetUrl'),
        startScanBtn: document.getElementById('startScanBtn'),
        scanMode: document.getElementById('scanMode'),
        scanTiming: document.getElementById('scanTiming'),
        checkWaf: document.getElementById('checkWaf'),
        
        // Metrics / Status
        scanStatus: document.getElementById('scanStatus'),
        lastScannedUrlDisplay: document.getElementById('lastScannedUrlDisplay'),
        targetDisplay: document.getElementById('targetDisplay'), // Hidden hook if needed
        hostStatusDisplay: document.getElementById('hostStatusDisplay'),
        dbCountDisplay: document.getElementById('dbCountDisplay'),
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
        findingsSearch: document.getElementById('findingsSearch'),
        filterChips: document.querySelectorAll('.filter-chip'),
        
        // Live Terminal & Raw Data
        clearLogBtn: document.getElementById('clearLogBtn'),
        logOutput: document.getElementById('logOutput'),
        resultsContent: document.getElementById('resultsContent'),
        copyJsonBtn: document.getElementById('copyJsonBtn'),

        // History
        sqlHistoryBtn: document.getElementById('sqlHistoryBtn'),
        historyModal: document.getElementById('historyModal'),
        closeHistoryModal: document.getElementById('closeHistoryModal'),
        historyTableBody: document.getElementById('historyTableBody'),

        // Tabs
        findingsTabBtn: document.getElementById('findingsTabBtn'),
        intelTabBtn: document.getElementById('intelTabBtn'),
        rawTabBtn: document.getElementById('rawTabBtn'),
        findingsContent: document.getElementById('findingsContent'),
        intelContent: document.getElementById('intelContent'),
        rawContent: document.getElementById('rawContent')
    };

    // --- State Variables ---
    let reportDownloadUrl = null;
    let currentFindings = [];
    let activeFilter = 'all';

    // --- Mobile UI Helper Functions (Global for inline onclicks) ---

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

    window.selectDropdownItem = function(dropdownId, value, text) {
        const dropdown = document.getElementById(dropdownId);
        const triggerText = dropdown.querySelector('.trigger-text');
        const items = dropdown.querySelectorAll('.dropdown-item');
        const menu = dropdown.querySelector('.dropdown-menu');
        
        triggerText.textContent = text;
        items.forEach(item => item.classList.toggle('active', item.dataset.value === value));
        
        // Sync with hidden select
        if (dropdownId === 'scanModeDropdown' && elements.scanMode) elements.scanMode.value = value;
        if (dropdownId === 'timingDropdown' && elements.scanTiming) elements.scanTiming.value = value;
        
        menu.classList.remove('show');
        menu.style.display = 'none';
    };

    window.toggleTerminal = function() {
        const sheet = document.getElementById('terminalSheet');
        if (sheet) sheet.classList.toggle('open');
    };

    window.switchTab = function(tabName) {
        const tabs = ['findings', 'intel', 'raw'];
        tabs.forEach(t => {
            const btn = elements[t + 'TabBtn'] || document.getElementById(t + 'TabBtn');
            const panel = elements[t + 'Content'] || document.getElementById(t + 'Content');
            if (btn) btn.classList.toggle('active', t === tabName);
            if (panel) {
                if (t === tabName) {
                    panel.classList.add('active');
                    panel.style.display = (t === 'findings' || t === 'intel') ? 'flex' : 'block';
                } else {
                    panel.classList.remove('active');
                    panel.style.display = 'none';
                }
            }
        });
    };

    // --- UI Control Functions ---
    
    function setButtonsDisabled(isDisabled) {
        const controlBtns = [elements.startScanBtn, elements.refreshResultsBtn];
        controlBtns.forEach(btn => {
            if (btn) {
                btn.disabled = isDisabled;
                btn.style.opacity = isDisabled ? '0.5' : '1';
                btn.classList.toggle('cursor-not-allowed', isDisabled);
            }
        });
        if (elements.targetUrlInput) elements.targetUrlInput.disabled = isDisabled;
    }

    function toggleSpinner(button, isLoading) {
        if (!button) return;
        const spinner = button.querySelector('.spinner');
        const icon = button.querySelector('.material-symbols-outlined'); 
        const text = button.querySelector('.button-text');

        if (isLoading) {
            button.classList.add('opacity-70', 'cursor-not-allowed');
            if (icon) icon.classList.add('hidden'); 
            if (spinner) spinner.classList.remove('hidden');
            if (text && button.id === 'startScanBtn') text.textContent = 'SCANNING...';
        } else {
            button.classList.remove('opacity-70', 'cursor-not-allowed');
            if (spinner) spinner.classList.add('hidden');
            if (icon) icon.classList.remove('hidden');
            if (text && button.id === 'startScanBtn') text.textContent = 'START SCAN';
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

        let contentStyle = 'color: var(--neo-text-muted)';
        if (message.includes('[!]') || message.toLowerCase().includes('error')) contentStyle = 'color: var(--neo-red)'; 
        else if (message.includes('[+]') || message.toLowerCase().includes('success')) contentStyle = 'color: var(--neo-green)'; 
        else if (message.includes('[*]') || message.includes('[STAGE]')) contentStyle = 'color: var(--neo-blue)';
        else if (message.includes('[DATA]')) contentStyle = 'color: var(--neo-amber)';

        const line = document.createElement('div');
        line.className = 'log-line';
        line.innerHTML = `
            <div class="log-time">${timeStr}</div>
            <div class="log-content" style="${contentStyle}">${message}</div>
        `;
        
        elements.logOutput.appendChild(line);
        elements.logOutput.scrollTop = elements.logOutput.scrollHeight;
    }

    function setStatus(text, type = 'ready') {
        if (!elements.scanStatus) return;
        elements.scanStatus.textContent = text.toUpperCase();
        
        const badge = elements.scanStatus.parentElement;
        if (type === 'busy') { badge.style.color = 'var(--neo-amber)'; badge.style.borderColor = 'rgba(245, 158, 11, 0.3)'; badge.style.background = 'rgba(245, 158, 11, 0.1)'; }
        else if (type === 'error') { badge.style.color = 'var(--neo-red)'; badge.style.borderColor = 'rgba(239, 68, 68, 0.3)'; badge.style.background = 'rgba(239, 68, 68, 0.1)'; }
        else { badge.style.color = 'var(--neo-green)'; badge.style.borderColor = 'rgba(16, 185, 129, 0.3)'; badge.style.background = 'rgba(16, 185, 129, 0.1)'; }
    }

    // --- Findings Management ---

    function getRiskColor(type) {
        const t = (type || '').toLowerCase();
        if (t.includes('stacked') || t.includes('union') || t.includes('time-based blind')) return 'var(--neo-red)';
        if (t.includes('error-based') || t.includes('boolean-based')) return 'var(--neo-amber)';
        return 'var(--neo-blue)';
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

        if (elements.findingsCountDisplay) elements.findingsCountDisplay.textContent = filtered.length;

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
            
            const rawScore = f.predicted_risk_score !== undefined ? f.predicted_risk_score : 0;
            const score = (rawScore * 10).toFixed(1);
            
            const radius = 16;
            const circumference = 2 * Math.PI * radius;
            const offset = circumference - (rawScore * circumference);
            let gaugeClass = 'gauge-low';
            if (rawScore > 0.7) gaugeClass = 'gauge-critical';
            else if (rawScore > 0.5) gaugeClass = 'gauge-high';
            else if (rawScore > 0.3) gaugeClass = 'gauge-medium';

            const riskClass = riskLabel === 'High' ? 'risk-high' : (riskLabel === 'Medium' ? 'risk-medium' : 'risk-low');

            return `
                <div class="finding-card animate-mobile-card ${riskClass}" data-index="${index}" style="--accent-gradient: ${riskColor};">
                    <div class="finding-header">
                        <div class="risk-indicator" style="color: ${riskColor}">
                            <div class="risk-dot" style="background: ${riskColor}; box-shadow: 0 0 8px ${riskColor};"></div>
                            ${riskLabel.toUpperCase()}
                        </div>
                        <div class="finding-title" style="white-space: normal;">${f.type} on param '${f.parameter}'</div>
                        
                        <div style="display: flex; align-items: center; gap: 0.5rem; flex-shrink: 0;">
                            <div class="risk-score-gauge">
                                <svg class="gauge-svg" viewBox="0 0 40 40">
                                    <circle class="gauge-bg" cx="20" cy="20" r="${radius}"></circle>
                                    <circle class="gauge-fill ${gaugeClass}" cx="20" cy="20" r="${radius}" style="stroke-dasharray: ${circumference}; stroke-dashoffset: ${offset};"></circle>
                                </svg>
                                <span class="gauge-val">${score}</span>
                            </div>
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
                                <span class="detail-label">Affected Parameter</span>
                                <span class="badge-pill" style="background: rgba(255,255,255,0.05); border: 1px solid var(--neo-border); color: var(--neo-text-main); font-family: var(--font-mono); width: fit-content;">${f.parameter}</span>
                            </div>
                            <div class="detail-section">
                                <span class="detail-label mb-1">Confirmed Payload</span>
                                <div class="detail-text-mono">${f.payload}</div>
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

        elements.findingsList.querySelectorAll('.finding-card').forEach(card => {
            card.querySelector('.finding-header').addEventListener('click', () => {
                const isExpanded = card.classList.contains('expanded');
                elements.findingsList.querySelectorAll('.finding-card.expanded').forEach(c => c.classList.remove('expanded'));
                if (!isExpanded) card.classList.add('expanded');
            });
        });
    }

    // --- API & Data Functions ---

    async function fetchReportData(specificTarget = null) {
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
            await checkReportAvailability();
        } catch (error) {
            console.error('Error fetching report:', error);
            appendLog(`[!] Connection error while fetching results.`);
        }
    }

    function updateDashboard(data) {
        if (!data) return;
        currentFindings = data.vulnerabilities || [];
        
        // Update Metrics
        if(elements.targetDisplay) elements.targetDisplay.textContent = data.target || '---';
        if(elements.metaTarget) elements.metaTarget.textContent = (data.target || '---').split('?')[0];
        
        const dbms = data.database_info?.dbms || '---';
        if (elements.dbmsDisplay) elements.dbmsDisplay.textContent = dbms;
        
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
        if (elements.avgRiskScore) {
            elements.avgRiskScore.textContent = avgScore;
            elements.avgRiskScore.style.color = avgScore > 7 ? 'var(--neo-red)' : (avgScore > 4 ? 'var(--neo-amber)' : 'var(--neo-blue)');
        }

        // Render Attack Vectors
        if (elements.topVectorsList) {
            const vectors = {};
            currentFindings.forEach(f => { vectors[f.type] = (vectors[f.type] || 0) + 1; });
            const sortedVectors = Object.entries(vectors).sort((a,b) => b[1] - a[1]).slice(0, 3);
            
            if (sortedVectors.length > 0) {
                elements.topVectorsList.innerHTML = sortedVectors.map(([name, count]) => `
                    <div style="display: flex; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 4px; margin-bottom: 4px;">
                        <span style="color: var(--neo-text-main);">${name}</span>
                        <span style="color: var(--neo-text-muted);">${count}</span>
                    </div>
                `).join('');
            } else {
                elements.topVectorsList.innerHTML = `<div style="text-align:center; padding: 1rem; color: var(--neo-text-muted); font-size: 0.7rem; font-family: var(--font-mono);">NO VECTORS DETECTED</div>`;
            }
        }

        renderFindings(currentFindings);

        if (elements.resultsContent) elements.resultsContent.textContent = JSON.stringify(data, null, 4);
    }

    async function checkReportAvailability() {
        const target = elements.targetUrlInput?.value.trim();
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

    async function fetchHistory() {
        if (!elements.historyTableBody) return;
        elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.8rem;">LOADING HISTORY...</td></tr>';
        
        try {
            const res = await fetch(`${API_BASE_URL}/report_history`);
            const data = await res.json();
            
            if (data.status === 'success' && data.history) {
                if (data.history.length === 0) {
                    elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.8rem;">NO PRIOR SCANS FOUND</td></tr>';
                    return;
                }
                
                elements.historyTableBody.innerHTML = '';
                data.history.forEach(item => {
                    const row = document.createElement('tr');
                    let target = item.filename.split('_').slice(1).join('_').replace('.pdf', '');                    target = target.replace(/_\d{8}_\d{6}$/, '');
                    if (!target) target = 'Previous Scan';
                    
                    row.innerHTML = `
                        <td>${item.created_at}</td>
                        <td style="color: var(--neo-blue);">${target}</td>
                        <td style="text-align: right;">
                            <a href="${API_BASE_URL}/download_pdf?filename=${item.filename}" class="btn-dash" style="display: inline-flex; height: 32px; width: 32px; padding: 0; background: rgba(255,255,255,0.05); border: none;">
                                <span class="material-symbols-outlined" style="font-size: 1.1rem;">download</span>
                            </a>
                        </td>
                    `;
                    elements.historyTableBody.appendChild(row);
                });
            } else {
                elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-red); font-family: var(--font-mono); font-size: 0.8rem;">FAILED TO LOAD HISTORY</td></tr>';
            }
        } catch (e) {
            console.error('History fetch failed:', e);
            elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-red); font-family: var(--font-mono); font-size: 0.8rem;">ERROR LOADING HISTORY</td></tr>';
        }
    }

    async function initiateScan() {
        const targetUrl = elements.targetUrlInput.value.trim();
        if (!targetUrl) {
            appendLog('[!] Error: Target URL is required.');
            toggleTerminal();
            return;
        }
        
        setButtonsDisabled(true);
        setStatus('Scanning...', 'busy');
        toggleSpinner(elements.startScanBtn, true);
        if (elements.lastScannedUrlDisplay) elements.lastScannedUrlDisplay.textContent = targetUrl;
        
        // Reset findings view
        if (elements.findingsList) {
            elements.findingsList.innerHTML = `<div style="text-align:center; padding: 4rem 1rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.75rem;">SCAN IN PROGRESS...</div>`;
        }

        try {
            const response = await fetch(`${API_BASE_URL}/scan`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken 
                },
                body: JSON.stringify({
                    target_url: targetUrl,
                    scan_mode: elements.scanMode ? elements.scanMode.value : 'quick',
                    check_waf: elements.checkWaf ? elements.checkWaf.checked : false,
                    risk_level: elements.scanTiming ? elements.scanTiming.value : '3'
                }),
            });
            const data = await response.json();
            if (response.ok) {
                appendLog(`[✓] ${data.message}`);
                // Stream handles completion event
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
        if (!elements.analyzeReportDropdown || elements.analyzeReportDropdown.disabled) return;
        const target = elements.targetUrlInput?.value.trim() || elements.lastScannedUrlDisplay?.textContent.trim();

        if (!csrfToken) {
            appendLog('[!] Error: CSRF Token missing.');
            return;
        }

        if (elements.llmAnalysisOptions) elements.llmAnalysisOptions.classList.add('hidden');
        if (elements.aiProcessingOverlay) {
            elements.aiProcessingOverlay.classList.remove('hidden');
            if (elements.aiProcessingText) {
                elements.aiProcessingText.textContent = llmMode.includes('gemini') ? 'CONTACTING GEMINI...' : 'LOADING LOCAL MODEL...';
            }
        }

        setStatus(`AI Analysis...`, 'busy');
        elements.analyzeReportDropdown.disabled = true;

        try {
            let response = await fetch(`${API_BASE_URL}/trigger_ai_analysis`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                body: JSON.stringify({ llm_mode: llmMode, target: target })
            });
            let data = await response.json();
            
            if (data.status !== 'success') throw new Error(data.message || 'Check failed.');
            
            if (elements.aiProcessingText) elements.aiProcessingText.textContent = 'SYNTHESIZING REPORT...';

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
                if (elements.aiProcessingText) elements.aiProcessingText.textContent = 'REDIRECTING...';
                setStatus('Redirecting...', 'success');
                
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
            if (elements.aiProcessingOverlay) elements.aiProcessingOverlay.classList.add('hidden');
            elements.analyzeReportDropdown.disabled = false;
        } finally {
            checkReportAvailability(); 
        }
    }

    function initializeLogStream() {
        const eventSource = new EventSource(`${API_BASE_URL}/log_stream`);
        eventSource.onmessage = (event) => {
            const message = event.data;
            if (message.startsWith(':')) return;
            
            if (message.includes("EVENT: scan_complete")) {
                try {
                    const payloadStr = message.split('| PAYLOAD: ')[1];
                    const payload = JSON.parse(payloadStr);
                    setStatus('Ready', 'success');
                    fetchReportData(payload.target).then(() => {
                        setButtonsDisabled(false);
                        toggleSpinner(elements.startScanBtn, false);
                    });
                } catch (e) { console.error("Error parsing scan_complete:", e); }
                return;
            }

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

    // --- Event Listeners Setup ---
    function setupEventListeners() {
        elements.startScanBtn?.addEventListener('click', initiateScan);

        document.addEventListener('click', (e) => {
            if (elements.llmAnalysisOptions && !elements.analyzeReportDropdown?.contains(e.target)) {
                elements.llmAnalysisOptions.classList.add('hidden');
            }
        });

        elements.refreshResultsBtn?.addEventListener('click', () => {
            fetchReportData();
            checkReportAvailability();
        });

        elements.clearLogBtn?.addEventListener('click', () => {
            if (elements.logOutput) elements.logOutput.innerHTML = '';
            if (elements.resultsContent) elements.resultsContent.textContent = '// Buffer Empty';
            if (csrfToken) fetch(`${API_BASE_URL}/clear_log`, { method: 'POST', headers: { 'X-CSRFToken': csrfToken } });
        });

        elements.downloadReportBtn?.addEventListener('click', () => {
            if (reportDownloadUrl) window.location.href = reportDownloadUrl;
        });

        elements.analyzeReportDropdown?.addEventListener('click', (e) => {
            e.stopPropagation();
            elements.llmAnalysisOptions?.classList.toggle('hidden');
        });

        elements.llmAnalysisOptions?.addEventListener('click', (e) => {
            const opt = e.target.closest('a[data-llm-mode], div[data-llm-mode]');
            if (opt) analyzeReport(opt.dataset.llmMode);
        });

        elements.findingsSearch?.addEventListener('input', () => renderFindings(currentFindings));

        elements.filterChips?.forEach(chip => {
            chip.addEventListener('click', () => {
                elements.filterChips.forEach(c => c.classList.remove('active'));
                chip.classList.add('active');
                activeFilter = chip.dataset.filter;
                renderFindings(currentFindings);
            });
        });

        elements.copyJsonBtn?.addEventListener('click', () => {
            const content = elements.resultsContent?.textContent;
            if (!content || content.includes('// Buffer Empty')) return;
            navigator.clipboard.writeText(content).then(() => {
                const icon = elements.copyJsonBtn.querySelector('.material-symbols-outlined');
                const text = elements.copyJsonBtn.querySelector('span:not(.material-symbols-outlined)');
                const originalIcon = icon ? icon.textContent : '';
                const originalText = text ? text.textContent : '';
                if(icon) icon.textContent = 'check';
                if(text) text.textContent = 'COPIED';
                elements.copyJsonBtn.style.color = 'var(--neo-green)';
                setTimeout(() => {
                    if (icon) icon.textContent = originalIcon;
                    if (text) text.textContent = originalText;
                    elements.copyJsonBtn.style.color = '';
                }, 2000);
            });
        });

        if (elements.sqlHistoryBtn) {
            elements.sqlHistoryBtn.addEventListener('click', () => {
                elements.historyModal?.classList.remove('hidden');
                fetchHistory();
            });
        }

        if (elements.closeHistoryModal) {
            elements.closeHistoryModal.addEventListener('click', () => {
                elements.historyModal?.classList.add('hidden');
            });
        }

        if (elements.historyModal) {
            elements.historyModal.addEventListener('click', (e) => {
                if (e.target === elements.historyModal) elements.historyModal.classList.add('hidden');
            });
        }
    }

    async function checkActiveScan() {
        try {
            const response = await fetch(`${API_BASE_URL}/status`);
            const data = await response.json();
            if (data.status === 'success' && data.is_running) {
                setButtonsDisabled(true);
                setStatus(`Scanning: ${data.target}...`, 'busy');
                toggleSpinner(elements.startScanBtn, true);
                if (elements.targetUrlInput) elements.targetUrlInput.value = data.target;
                if (elements.lastScannedUrlDisplay) elements.lastScannedUrlDisplay.textContent = data.target;
                if (elements.findingsList) {
                    elements.findingsList.innerHTML = `<div style="text-align:center; padding: 4rem 1rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.75rem;">SCAN IN PROGRESS...</div>`;
                }
                appendLog(`[*] Detected active SQL scan on ${data.target}. Attaching stream...`);
            }
        } catch (error) { console.error(error); }
    }

    // --- Init ---
    setupEventListeners();
    initializeLogStream();
    
    fetchReportData().then(() => {
        if (currentFindings.length > 0) renderFindings(currentFindings);
    });
    checkActiveScan();
    
    setTimeout(() => appendLog('System Ready. Initializing SQLMap Engine...'), 100);
});