document.addEventListener('DOMContentLoaded', () => {
    // --- API Endpoints ---
    const API_BASE_URL = '/api_scanner';
    const SCAN_ENDPOINT = `${API_BASE_URL}/scan`;
    const RESULTS_ENDPOINT = `${API_BASE_URL}/scan_results`;
    const CLEAR_LOG_ENDPOINT = `${API_BASE_URL}/clear_log`;
    const LOG_STREAM_ENDPOINT = `${API_BASE_URL}/log_stream`;
    const REPORT_FILES_ENDPOINT = `${API_BASE_URL}/report_files`; 
    const ANALYZE_ENDPOINT = `${API_BASE_URL}/trigger_ai_analysis`; 
    const STATUS_ENDPOINT = `${API_BASE_URL}/status`;
    const CHATBOT_REDIRECT_URL = '/chatbot'; 

    // --- DOM Elements ---
    const targetUrlInput = document.getElementById('targetUrl');
    const definitionUrlInput = document.getElementById('definitionUrl'); 
    const authTokenInput = document.getElementById('authToken');
    const startScanBtn = document.getElementById('startScanBtn'); 
    
    const scanStatus = document.getElementById('scanStatus');
    const logOutput = document.getElementById('logOutput');
    const clearLogBtn = document.getElementById('clearLogBtn');

    // Metrics
    const lastScannedUrlDisplay = document.getElementById('lastScannedUrlDisplay');
    const totalAlertsDisplay = document.getElementById('totalAlertsDisplay');
    const highAlertsDisplay = document.getElementById('highAlertsDisplay');
    const mediumAlertsDisplay = document.getElementById('mediumAlertsDisplay');
    const lowAlertsDisplay = document.getElementById('lowAlertsDisplay');
    const infoAlertsDisplay = document.getElementById('infoAlertsDisplay');
    
    // New Elements
    const findingsList = document.getElementById('findingsList');
    const findingsSearch = document.getElementById('findingsSearch');
    const filterChips = document.querySelectorAll('.filter-chip');
    const findingsCountDisplay = document.getElementById('findingsCountDisplay');

    // Insights Panel
    const avgRiskScore = document.getElementById('avgRiskScore');
    const topVectorsList = document.getElementById('topVectorsList');
    const metaTarget = document.getElementById('metaTarget');
    const metaDuration = document.getElementById('metaDuration');

    let allFindings = [];
    let currentFilter = 'all';
    let scanStartTime = null;
    let resolvedTarget = ''; // Set when any report is found (from input or fallback)

    // Actions
    const refreshResultsBtn = document.getElementById('refreshResultsBtn');
    const downloadPdfBtn = document.getElementById('downloadReportBtn'); 
    
    // AI Analysis & Overlay Elements
    const analyzeReportDropdown = document.getElementById('analyzeReportDropdown');
    const llmAnalysisOptions = document.getElementById('llmAnalysisOptions');
    const aiProcessingOverlay = document.getElementById('aiProcessingOverlay');
    const aiProcessingText = document.getElementById('aiProcessingText');

    // History
    const apiHistoryBtn = document.getElementById('apiHistoryBtn') || document.getElementById('nmapHistoryBtn');
    const historyModal = document.getElementById('historyModal');
    const closeHistoryModal = document.getElementById('closeHistoryModal');
    const historyTableBody = document.getElementById('historyTableBody');

    // Tab Switching
    const findingsTabBtn = document.getElementById('findingsTabBtn');
    const rawTabBtn = document.getElementById('rawTabBtn');
    const findingsContent = document.getElementById('findingsContent');
    const rawContent = document.getElementById('rawContent');

    let logEventSource = null;

    // --- 🔒 CSRF TOKEN RETRIEVAL ---
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

    // --- Utility Functions ---

    function toggleButtonLoading(button, isLoading) {
        if (!button) return;
        const spinner = button.querySelector('.spinner');
        const icon = button.querySelector('.material-symbols-outlined');
        const text = button.querySelector('.button-text');
        
        button.disabled = isLoading;

        if (isLoading) {
            button.style.opacity = '0.7';
            button.style.cursor = 'not-allowed';
            if (spinner) spinner.classList.remove('hidden');
            if (icon && !icon.textContent.includes('expand_more')) icon.style.display = 'none';
            if (text && button.id === 'startScanBtn') text.textContent = 'SCANNING...';
        } else {
            button.style.opacity = '1';
            button.style.cursor = 'pointer';
            if (spinner) spinner.classList.add('hidden');
            if (icon) icon.style.display = 'inline-block';
            if (text && button.id === 'startScanBtn') text.textContent = 'START SCAN';
        }
    }

    function updateScanStatus(message, type = 'info') {
        if (!scanStatus) return;
        scanStatus.textContent = message;
        
        const isLight = document.body.classList.contains("light-mode");
        scanStatus.style.color = isLight ? '#64748b' : '#a1a1aa'; 
        
        if (type === 'success') scanStatus.style.color = '#10b981'; 
        else if (type === 'error') scanStatus.style.color = '#ef4444'; 
        else if (type === 'busy') scanStatus.style.color = '#eab308'; 
    }

    function appendLog(message) {
        if (!logOutput) return;

        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });

        let cleanedMessage = message.replace(/\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s*/g, "");
        cleanedMessage = cleanedMessage.replace(/^\[?\d{1,2}:\d{2}:\d{2}\]?\s*/, '');
        cleanedMessage = cleanedMessage.replace(/(\[[A-Z]+\])\s*\1/g, '$1');
        cleanedMessage = cleanedMessage.trim();

        // --- NEW FILTERING RULES ---
        // Hide spammy and non-essential ZAP Java internal logs
        if (
            cleanedMessage.includes('Starting ZAP Engine...') ||
            cleanedMessage.includes('org.parosproxy.paros.') ||
            cleanedMessage.includes('org.zaproxy.addon.') ||
            cleanedMessage.includes('org.zaproxy.zap.extension.') ||
            cleanedMessage.includes('WARNING: sun.misc.Unsafe') ||
            cleanedMessage.includes('WARNING: Please consider reporting this to the maintainers of class') ||
            cleanedMessage.includes('java.sql.SQLException') ||
            cleanedMessage.includes('at java.base') ||
            cleanedMessage.includes('Caused by:') ||
            cleanedMessage.includes('Host info:') ||
            cleanedMessage.includes('Build info:') ||
            cleanedMessage.includes('System info:') ||
            cleanedMessage.includes('Driver info:') ||
            cleanedMessage.includes('Command: [null,') ||
            cleanedMessage.includes('file:[FILE_PATH]') || // Common in Java warnings printed
            (cleanedMessage.startsWith('...') && cleanedMessage.includes('more'))
        ) {
            return;
        }

        if (!cleanedMessage || cleanedMessage === '|' || cleanedMessage.includes('deprecated method')) return;

        const isProgressBar = cleanedMessage.startsWith('[PROGRESS]') || (cleanedMessage.startsWith('[') && cleanedMessage.includes('%'));
        if (isProgressBar) {
            const lastLine = logOutput.lastElementChild;
            if (lastLine) {
                const logContent = lastLine.querySelector('.log-content');
                if (logContent && logContent.getAttribute('data-is-progress') === 'true') {
                    lastLine.querySelector('.log-time').textContent = timeStr;
                    logContent.textContent = cleanedMessage;
                    return;
                }
            }
        }
        
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
        const dataAttr = isProgressBar ? ' data-is-progress="true"' : '';
        
        line.innerHTML = `
            <div class="log-time">${timeStr}</div>
            <div class="log-content" style="${contentStyle}"${dataAttr}>${cleanedMessage}</div>
        `;
        
        logOutput.appendChild(line);
        logOutput.scrollTop = logOutput.scrollHeight;
    }

    // --- Report & Button Management ---

    async function checkReportStatus() {
        const target = targetUrlInput.value.trim();
        if (downloadPdfBtn) {
            downloadPdfBtn.disabled = true;
            downloadPdfBtn.style.opacity = '0.5';
        }
        if (analyzeReportDropdown) {
            analyzeReportDropdown.disabled = true;
            analyzeReportDropdown.style.opacity = '0.5';
        }

        try {
            const url = target ? `${REPORT_FILES_ENDPOINT}?target=${encodeURIComponent(target)}` : REPORT_FILES_ENDPOINT;
            const response = await fetch(url);
            if (!response.ok) return;
            const data = await response.json();
    
            if (data.status === "success" && data.pdf_report) {
                // Track the resolved target for AI analysis
                resolvedTarget = target || '';

                if (downloadPdfBtn) {
                    downloadPdfBtn.disabled = false;
                    downloadPdfBtn.style.opacity = '1';
                    downloadPdfBtn.onclick = () => window.open(data.pdf_report, '_blank');
                }
                
                if (analyzeReportDropdown) {
                    analyzeReportDropdown.disabled = false;
                    analyzeReportDropdown.style.opacity = '1';
                }
            }
        } catch (error) {
            console.error("Error checking report status:", error);
        }
    }

    // --- HISTORY LOGIC ---

    async function fetchHistory() {
        if (!historyTableBody) return;
        historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-text-muted);">LOADING HISTORY...</td></tr>';
        
        try {
            const res = await fetch(`${API_BASE_URL}/report_history`);
            const data = await res.json();
            
            if (data.status === 'success' && data.history) {
                if (data.history.length === 0) {
                    historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-text-muted);">NO PRIOR SCANS FOUND</td></tr>';
                    return;
                }
                
                historyTableBody.innerHTML = '';
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
                    historyTableBody.appendChild(row);
                });
            } else {
                historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-red);">FAILED TO LOAD HISTORY</td></tr>';
            }
        } catch (e) {
            console.error('History fetch failed:', e);
            historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-red);">ERROR LOADING HISTORY</td></tr>';
        }
    }

    if (apiHistoryBtn) {
        apiHistoryBtn.addEventListener('click', () => {
            historyModal.classList.remove('hidden');
            fetchHistory();
        });
    }

    if (closeHistoryModal) {
        closeHistoryModal.addEventListener('click', () => {
            historyModal.classList.add('hidden');
        });
    }

    if (historyModal) {
        historyModal.addEventListener('click', (e) => {
            if (e.target === historyModal) {
                historyModal.classList.add('hidden');
            }
        });
    }
    
    async function analyzeReport(llmMode) {
        if (analyzeReportDropdown.disabled) return;
        // Use the typed target first; fall back to whatever the backend resolved
        const target = targetUrlInput.value.trim() || resolvedTarget;
        
        if (!csrfToken) {
            appendLog('[!] Error: CSRF Token missing. Refresh page.');
            return;
        }

        if (llmAnalysisOptions) llmAnalysisOptions.classList.add('hidden');
        if (aiProcessingOverlay) {
            aiProcessingOverlay.classList.remove('hidden');
            if (aiProcessingText) {
                aiProcessingText.textContent = llmMode.includes('gemini') 
                    ? 'CONTACTING GEMINI AI...' 
                    : 'LOADING LOCAL MODEL...';
            }
        }

        updateScanStatus(`AI Analysis (${llmMode})...`, 'busy');
        analyzeReportDropdown.disabled = true;

        try {
            let response = await fetch(ANALYZE_ENDPOINT, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ llm_mode: llmMode, target: target })
            });
            let data = await response.json();
            
            if (data.status !== 'success') throw new Error(data.message || 'Check failed.');
            
            if (aiProcessingText) aiProcessingText.textContent = 'ANALYZING ENDPOINTS...';

            const CHATBOT_PROXY_URL = `${CHATBOT_REDIRECT_URL}/scanner_analysis`;
            response = await fetch(CHATBOT_PROXY_URL, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ 
                    llm_mode: llmMode, 
                    scanner_type: "api",
                    target: data.target,
                    force_new_session: true 
                })
            });

            data = await response.json();

            if (response.ok && data.status === 'success') {
                if (aiProcessingText) aiProcessingText.textContent = 'REDIRECTING...';
                updateScanStatus('Redirecting...', 'success');
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
            updateScanStatus('Analysis failed', 'error');
            if (aiProcessingOverlay) aiProcessingOverlay.classList.add('hidden');
            analyzeReportDropdown.disabled = false;
        } finally {
            checkReportStatus(); 
        }
    }

    // --- Main Rendering Logic ---

    async function fetchAndDisplayResults() {
        if (!findingsList) return;
        findingsList.innerHTML = `<div style="text-align:center; padding: 4rem; color: #555; font-family: monospace;">LOADING SCAN DATA...</div>`;

        try {
            const response = await fetch(RESULTS_ENDPOINT);
            
            if (!response.ok) {
                if (response.status === 404) {
                    findingsList.innerHTML = `<div style="text-align:center; padding: 4rem; color: #64748b; font-family: var(--font-mono); letter-spacing: 0.1em;">NO SCAN DATA FOUND. START A NEW SCAN.</div>`;
                    return;
                }
                if (response.status === 401 || response.status === 403) {
                    findingsList.innerHTML = `<div style="text-align:center; padding: 4rem; color: #f97316; font-family: monospace;">SESSION EXPIRED.</div>`;
                    return;
                }
                throw new Error(`HTTP ${response.status}`);
            }

            const contentType = response.headers.get("content-type");
            if (!contentType || !contentType.includes("application/json")) {
                findingsList.innerHTML = `<div style="text-align:center; padding: 4rem; color: #f97316; font-family: monospace;">UNEXPECTED RESPONSE FROM SERVER.</div>`;
                return;
            }

            const result = await response.json();

            if (result.status === 'success' && result.data) {
                const report = result.data;
                updateSummaryDisplay(report.summary, report.target_url);
                allFindings = report.findings || report.alerts || [];
                renderFindings();
                updateInsightsDisplay(report);

                // Populate Raw JSON tab
                const resultsContent = document.getElementById('resultsContent');
                if (resultsContent) {
                    resultsContent.textContent = JSON.stringify(report, null, 2);
                }
            } else {
                findingsList.innerHTML = `<div style="text-align:center; padding: 4rem; color: #555; font-family: monospace;">NO RESULTS AVAILABLE.</div>`;
            }
        } catch (error) {
            console.error(error);
            findingsList.innerHTML = `<div style="text-align:center; padding: 4rem; color: #ef4444; font-family: monospace;">CONNECTION ERROR.</div>`;
        } finally {
            await checkReportStatus();
        }
    }
    
    function updateSummaryDisplay(summary, targetUrl) {
        if (!summary) return;
        if (lastScannedUrlDisplay) lastScannedUrlDisplay.textContent = targetUrl || '---';
        if (totalAlertsDisplay) totalAlertsDisplay.textContent = summary.Total || summary.total || '0';
        if (highAlertsDisplay) highAlertsDisplay.textContent = summary.High || summary.high || '0';
        if (mediumAlertsDisplay) mediumAlertsDisplay.textContent = summary.Medium || summary.medium || '0';
        if (lowAlertsDisplay) lowAlertsDisplay.textContent = summary.Low || summary.low || '0';
        if (infoAlertsDisplay) infoAlertsDisplay.textContent = summary.Info || summary.info || '0';
    }

    function updateInsightsDisplay(report) {
        if (!report) return;

        // 1. Target & Metadata
        if (metaTarget) metaTarget.textContent = report.target_url || '---';
        if (scanStartTime && metaDuration) {
            const duration = Math.floor((Date.now() - scanStartTime) / 1000);
            metaDuration.textContent = `${duration}s`;
        }

        // 2. Risk Index (Average of Predicted Scores)
        const scores = allFindings
            .map(f => parseFloat(f.predicted_risk_score))
            .filter(s => !isNaN(s));
        
        if (scores.length > 0 && avgRiskScore) {
            const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
            avgRiskScore.textContent = (avg * 10).toFixed(1);
            
            if (avg > 15) avgRiskScore.style.color = '#ef4444';
            else if (avg > 8) avgRiskScore.style.color = '#f97316';
            else avgRiskScore.style.color = '#3b82f6';
        }

        // 3. Top Attack Vectors
        const vectorMap = {};
        allFindings.forEach(f => {
            const name = f.name || f.alert;
            vectorMap[name] = (vectorMap[name] || 0) + 1;
        });

        const sortedVectors = Object.entries(vectorMap)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 3);

        if (topVectorsList) {
            topVectorsList.innerHTML = '';
            if (sortedVectors.length > 0) {
                sortedVectors.forEach(([name, count]) => {
                    const item = document.createElement('div');
                    item.className = 'vector-item';
                    item.innerHTML = `
                        <span class="vector-name" title="${name}">${name}</span>
                        <span class="vector-count">${count}x</span>
                    `;
                    topVectorsList.appendChild(item);
                });
            } else {
                topVectorsList.innerHTML = `<div style="text-align:center; padding: 1rem; color: #444; font-size: 0.7rem;">NO VECTORS IDENTIFIED</div>`;
            }
        }
    }

    function getRiskColor(risk) {
        if (risk === 'High') return '#ef4444';
        if (risk === 'Medium') return '#f97316';
        if (risk === 'Low') return '#eab308';
        return '#3b82f6';
    }

    function renderFindings() {
        const searchTerm = findingsSearch.value.toLowerCase();
        findingsList.innerHTML = '';
        
        const filtered = allFindings.filter(f => {
            const matchesFilter = currentFilter === 'all' || f.risk === currentFilter;
            const matchesSearch = (f.name || f.alert || '').toLowerCase().includes(searchTerm) || 
                                  (f.url || '').toLowerCase().includes(searchTerm);
            return matchesFilter && matchesSearch;
        });

        if (findingsCountDisplay) findingsCountDisplay.textContent = filtered.length;

        if (filtered.length === 0) {
            findingsList.innerHTML = `<div style="text-align:center; padding: 4rem; color: #555; font-family: monospace;">NO FINDINGS MATCHING CRITERIA.</div>`;
            return;
        }

        filtered.forEach(finding => {
            const card = createFindingCard(finding);
            findingsList.appendChild(card);
        });
    }

    function createFindingCard(finding) {
        const risk = finding.risk || 'Info';
        const rawScore = parseFloat(finding.predicted_risk_score || 0);
        const scoreVal = (rawScore * 10).toFixed(1);
        const color = getRiskColor(risk);

        // SVG Gauge
        const radius = 20;
        const circumference = 2 * Math.PI * radius;
        const offset = circumference - (rawScore * circumference);
        let gaugeClass = 'gauge-low';
        if (rawScore > 0.7) gaugeClass = 'gauge-critical';
        else if (rawScore > 0.5) gaugeClass = 'gauge-high';
        else if (rawScore > 0.3) gaugeClass = 'gauge-medium';

        // priority_level comes as "P3 (Low)" — extract badge "P3" and label "Low"
        const rawPriority = finding.priority_level || 'P3 (Low)';
        const priorityBadge = rawPriority.split(' ')[0]; // "P3"
        const priorityLabel = rawPriority.replace(priorityBadge, '').replace(/[()]/g, '').trim(); // "Low"
        const priorityColor = priorityBadge === 'P0' ? '#ef4444'
                            : priorityBadge === 'P1' ? '#f59e0b'
                            : priorityBadge === 'P2' ? '#3b82f6'
                            : '#10b981';

        const tctrScore = typeof finding.tctr_priority === 'number'
            ? finding.tctr_priority.toFixed(4) : (finding.tctr_priority || '—');
        const baseScore = typeof finding.base_score === 'number'
            ? finding.base_score.toFixed(1) : (finding.base_score || '—');

        const card = document.createElement('div');
        card.className = 'finding-card';
        card.setAttribute('data-priority', priorityBadge);
        card.style.setProperty('--accent-gradient', color);

        card.innerHTML = `
            <div class="finding-header">
                <div class="risk-indicator" style="color: ${color};">
                    <div class="risk-dot" style="background: ${color};"></div>
                    <span>${risk}</span>
                </div>

                <div class="finding-title" title="${finding.name || finding.alert}">${finding.name || finding.alert}</div>

                <div style="display: flex; align-items: center; gap: 0.5rem; flex-shrink: 0;">
                    <span class="badge-pill" style="background: ${priorityColor}22; border-color: ${priorityColor}55; color: ${priorityColor}; font-size: 0.65rem; font-weight: 800; padding: 2px 8px;">${priorityBadge}</span>
                    <div class="risk-score-gauge">
                        <svg class="gauge-svg" viewBox="0 0 48 48">
                            <circle class="gauge-bg" cx="24" cy="24" r="${radius}"></circle>
                            <circle class="gauge-fill ${gaugeClass}" cx="24" cy="24" r="${radius}"
                                style="stroke-dasharray: ${circumference}; stroke-dashoffset: ${offset};"></circle>
                        </svg>
                        <span class="gauge-val">${scoreVal}</span>
                    </div>
                </div>

                <span class="material-symbols-outlined expand-icon" style="margin-left: 0.5rem; font-size: 1.25rem;">expand_more</span>
            </div>

            <div class="finding-details">
                <div class="details-content">

                    <div class="detail-section">
                        <span class="detail-label">Vulnerable Endpoint</span>
                        <div class="flex items-center gap-3" style="flex-wrap: wrap;">
                            <div class="badge-pill" style="background: var(--neo-input); border: 1px solid var(--neo-border); color: var(--neo-text-main); font-family: var(--font-mono); font-size: 0.7rem; padding: 4px 8px;">${finding.method || 'GET'}</div>
                            <a href="${finding.url || '#'}" target="_blank" class="finding-url-link" style="font-family: var(--font-mono); font-size: 0.75rem; word-break: break-all;">${finding.url || 'N/A'}</a>
                        </div>
                        ${finding.param ? `<div class="detail-text" style="font-size: 0.75rem; margin-top: 4px; color: var(--neo-text-muted);">PARAMETER: <span style="color: var(--neo-text-main);">${finding.param}</span></div>` : ''}
                    </div>

                    <div class="detail-section">
                        <span class="detail-label">Vulnerability Description</span>
                        <div class="detail-text" style="line-height: 1.7;">${finding.description || 'No description available.'}</div>
                    </div>

                    ${finding.solution ? `
                    <div class="detail-section">
                        <span class="detail-label">Remediation &amp; Solution</span>
                        <div class="detail-text" style="border-left: 3px solid var(--neo-green); padding-left: 1rem;">${finding.solution}</div>
                    </div>` : ''}

                    <div class="detail-section">
                        <span class="detail-label">TCTR Analyst Metrics</span>
                        <div class="flex flex-col gap-2 mt-2" style="background: rgba(0,0,0,0.25); padding: 1.25rem; border-radius: 8px; border: 1px solid var(--neo-border);">
                            <div class="flex justify-between items-center">
                                <span style="font-size: 0.7rem; color: var(--neo-text-muted); font-weight: 800; letter-spacing: 0.05em;">ANALYST PRIORITY</span>
                                <div style="display: flex; align-items: center; gap: 0.5rem;">
                                    <span class="badge-pill" style="background: ${priorityColor}22; border-color: ${priorityColor}44; color: ${priorityColor}; font-size: 0.7rem; font-weight: 800;">${priorityBadge}</span>
                                    <span style="font-size: 0.7rem; color: var(--neo-text-muted);">${priorityLabel}</span>
                                </div>
                            </div>
                            <div class="flex justify-between items-center">
                                <span style="font-size: 0.7rem; color: var(--neo-text-muted); font-weight: 800; letter-spacing: 0.05em;">TCTR SCORE</span>
                                <span style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--neo-text-main); font-weight: 600;">${tctrScore}</span>
                            </div>
                            <div class="flex justify-between items-center">
                                <span style="font-size: 0.7rem; color: var(--neo-text-muted); font-weight: 800; letter-spacing: 0.05em;">BASE RISK SCORE</span>
                                <span style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--neo-text-main); font-weight: 600;">${baseScore}</span>
                            </div>
                            <div class="flex justify-between items-center">
                                <span style="font-size: 0.7rem; color: var(--neo-text-muted); font-weight: 800; letter-spacing: 0.05em;">ZAP RISK LEVEL</span>
                                <span style="font-family: var(--font-mono); font-size: 0.8rem; font-weight: 600; color: ${color};">${risk.toUpperCase()}</span>
                            </div>
                            <div style="margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid rgba(255,255,255,0.06);">
                                <span style="font-size: 0.7rem; color: var(--neo-text-muted); font-weight: 800; display: block; margin-bottom: 6px; letter-spacing: 0.05em;">RISK JUSTIFICATION</span>
                                <p style="font-size: 0.8rem; color: var(--neo-text-main); line-height: 1.6; opacity: 0.9; margin: 0;">${finding.risk_justification || 'Automated risk assessment performed by TCTR Engine.'}</p>
                            </div>
                        </div>
                    </div>

                    ${finding.confidence || finding.cweid ? `
                    <div class="detail-section">
                        <span class="detail-label">Additional Details</span>
                        <div class="flex gap-4 flex-wrap">
                            ${finding.confidence ? `<span style="font-size: 0.7rem; color: var(--neo-text-muted); font-weight: 700;">CONFIDENCE: <span style="color: var(--neo-text-main);">${finding.confidence}</span></span>` : ''}
                            ${finding.cweid ? `<span style="font-size: 0.7rem; color: var(--neo-text-muted); font-weight: 700;">CWE: <span style="color: var(--neo-blue); cursor: pointer;" onclick="window.open('https://cwe.mitre.org/data/definitions/${finding.cweid}.html','_blank')">${finding.cweid}</span></span>` : ''}
                        </div>
                    </div>` : ''}

                    ${finding.evidence ? `
                    <div class="detail-section">
                        <span class="detail-label">Evidence</span>
                        <div class="detail-text detail-text-mono" style="color: #a1a1aa; background: #000; padding: 1rem; border-radius: 6px; border: 1px solid #222; white-space: pre-wrap;">${finding.evidence}</div>
                    </div>` : ''}

                    ${finding.reference ? `
                    <div class="detail-section" style="border-bottom: none; padding-bottom: 0;">
                        <span class="detail-label">References</span>
                        <div class="detail-text" style="font-size: 0.75rem; line-height: 1.8; color: var(--neo-blue);">${finding.reference.split('\n').map(ref => ref.trim() ? `<a href="${ref.trim()}" target="_blank" style="color: inherit; display: block;">${ref.trim()}</a>` : '').join('')}</div>
                    </div>` : ''}

                </div>
            </div>
        `;

        card.addEventListener('click', () => {
            card.classList.toggle('expanded');
        });

        return card;
    }

    // --- Filter &amp; Search Listeners ---
    filterChips.forEach(chip => {
        chip.addEventListener('click', () => {
            filterChips.forEach(c => c.classList.remove('active'));
            chip.classList.add('active');
            currentFilter = chip.dataset.filter;
            renderFindings();
        });
    });

    if (findingsSearch) findingsSearch.addEventListener('input', renderFindings);

    // --- Core Action: Start Scan ---

    async function handleScanButtonClick() {
        const targetUrl = targetUrlInput.value.trim();
        const definitionUrl = definitionUrlInput.value.trim();
        const authToken = authTokenInput ? authTokenInput.value.trim() : null;

        if (!targetUrl) {
            alert("Please enter the API Base URL.");
            return;
        }
        if (!definitionUrl) {
            alert("Please enter the OpenAPI/Swagger Definition URL.");
            return;
        }

        if (!csrfToken) {
            appendLog('[!] Error: CSRF Token missing. Refresh page.');
            return;
        }

        // Start/Restart SSE stream for this new session
        setupLogStream();

        toggleButtonLoading(startScanBtn, true);
        const authMsg = authToken ? 'Authenticated' : 'Anonymous';
        updateScanStatus(`Scanning (${authMsg})...`, 'busy');
        logOutput.innerHTML = ''; 
        appendLog(`Initiating API Scan on ${targetUrl} (${authMsg})...`);
        appendLog(`Loading Definition: ${definitionUrl}`);
        scanStartTime = Date.now();

        try {
            const response = await fetch(SCAN_ENDPOINT, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ 
                    target_url: targetUrl,
                    definition_url: definitionUrl,
                    auth_token: authToken
                })
            });
            const data = await response.json();

            if (!response.ok || data.status !== 'success') {
                appendLog(`[!] Error: ${data.message}`);
                updateScanStatus('Failed', 'error');
                toggleButtonLoading(startScanBtn, false);
            }
        } catch (error) {
            appendLog(`[!] Network error: ${error.message}`);
            toggleButtonLoading(startScanBtn, false);
        }
    }

    // --- SSE & Event Listeners ---
    
    // Toggle Scan Options Dropdown
    const scanOptionsBtn = document.getElementById('scanOptionsBtn');
    const scanOptionsDropdown = document.getElementById('scanOptionsDropdown');

    if (scanOptionsBtn && scanOptionsDropdown) {
        scanOptionsBtn.addEventListener('click', (e) => {
            scanOptionsDropdown.classList.toggle('hidden');
            e.stopPropagation();
        });

        document.addEventListener('click', (e) => {
            if (!scanOptionsBtn.contains(e.target) && !scanOptionsDropdown.contains(e.target)) {
                scanOptionsDropdown.classList.add('hidden');
            }
        });
    }

    function setupLogStream() {
        // Close existing stream if active
        if (logEventSource) {
            logEventSource.close();
            logEventSource = null;
        }

        logEventSource = new EventSource(LOG_STREAM_ENDPOINT);
        
        logEventSource.onmessage = function(event) {
            if (event.data === ': keep-alive') return;

            const lowerData = event.data.toLowerCase();

            if (lowerData.includes("scan complete") || lowerData.includes("api scan complete")) { 
                updateScanStatus('Complete', 'success');
                toggleButtonLoading(startScanBtn, false);
                scanStartTime = null;
                fetchAndDisplayResults();
            }

            if (lowerData.includes("failed") || lowerData.includes("error:")) {
                updateScanStatus('Failed', 'error');
                toggleButtonLoading(startScanBtn, false);
                scanStartTime = null;
            }
            
            if (event.data.includes("SYSTEM_EVENT: READY_FOR_ANALYSIS")) {
                checkReportStatus();
            }

            if (event.data.includes("EVENT:") || event.data.startsWith("EVENT:")) return;
            appendLog(event.data);
        };

        logEventSource.onerror = function(err) {
            console.error("SSE Stream Error:", err);
            // Optional: Handle reconnection or state cleanup
        };
    }

    startScanBtn.addEventListener('click', handleScanButtonClick);

    clearLogBtn.addEventListener('click', async () => {
        if (!csrfToken) return;
        logOutput.innerHTML = '';
        await fetch(CLEAR_LOG_ENDPOINT, { 
            method: 'POST',
            headers: { 'X-CSRFToken': csrfToken }
        });
        appendLog("[*] Log cleared.");
    });

    if (refreshResultsBtn) {
        refreshResultsBtn.addEventListener('click', () => {
            fetchAndDisplayResults();
        });
    }
    
    if (analyzeReportDropdown) {
        analyzeReportDropdown.addEventListener('click', (e) => {
            if (!analyzeReportDropdown.disabled) {
                llmAnalysisOptions.classList.toggle('hidden');
                e.stopPropagation(); 
            }
        });
    }
    
    if (llmAnalysisOptions) {
        llmAnalysisOptions.addEventListener('click', (e) => {
            e.preventDefault();
            const option = e.target.closest('a[data-llm-mode]');
            if (option) {
                const llmMode = option.dataset.llmMode;
                llmAnalysisOptions.classList.add('hidden'); 
                analyzeReport(llmMode);
            }
        });
    }

    document.addEventListener('click', (e) => {
        if (llmAnalysisOptions && !analyzeReportDropdown.contains(e.target)) {
            llmAnalysisOptions.classList.add('hidden');
        }
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

    async function checkScanStatus() {
        try {
            const response = await fetch(STATUS_ENDPOINT);
            const data = await response.json();
            
            if (data.status === 'success' && data.is_running) {
                toggleButtonLoading(startScanBtn, true);
                updateScanStatus(`Scanning: ${data.target}...`, 'busy');
                if (targetUrlInput) targetUrlInput.value = data.target;
                appendLog(`[*] Detected active API scan on ${data.target}. Re-attaching...`);
                return true;
            } else {
                // Ensure UI is enabled if no scan is running
                toggleButtonLoading(startScanBtn, false);
                updateScanStatus('READY', 'info');
                return false;
            }
        } catch (error) {
            console.error("Error checking scan status:", error);
            toggleButtonLoading(startScanBtn, false);
            return false;
        }
    }

    // Initialize — match ZAP scanner pattern exactly
    async function init() {
        setTimeout(() => appendLog('System Ready. Initializing API Security Scanner...'), 100);
        checkReportStatus();
        fetchAndDisplayResults();
        checkScanStatus();
        setupLogStream();
    }

    init();
});