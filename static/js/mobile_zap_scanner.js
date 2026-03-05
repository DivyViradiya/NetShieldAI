document.addEventListener('DOMContentLoaded', () => {
    // --- API Endpoints ---
    const API_BASE_URL = '/zap_scanner';
    const SCAN_ENDPOINT = `${API_BASE_URL}/scan`;
    const RESULTS_ENDPOINT = `${API_BASE_URL}/scan_results`;
    const CLEAR_LOG_ENDPOINT = `${API_BASE_URL}/clear_log`;
    const LOG_STREAM_ENDPOINT = `${API_BASE_URL}/log_stream`;
    const REPORT_FILES_ENDPOINT = `${API_BASE_URL}/report_files`; 
    const ANALYZE_ENDPOINT = `${API_BASE_URL}/trigger_ai_analysis`; 
    const STATUS_ENDPOINT = `${API_BASE_URL}/status`;
    const CHATBOT_REDIRECT_URL = '/chatbot'; 

    // --- 🔒 CSRF TOKEN ---
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

    // --- DOM Elements ---
    const targetUrlInput = document.getElementById('targetUrl');
    const startScanBtn = document.getElementById('scanBtn');
    const scanCategorySelect = document.getElementById('scanCategory'); // Hidden native select
    
    // Advanced Config
    const useAjaxCheckbox = document.getElementById('useAjax');
    const loginUrlInput = document.getElementById('loginUrl');
    const userFieldInput = document.getElementById('userField');
    const passFieldInput = document.getElementById('passField');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');

    // UI Status & Metrics
    const scanStatus = document.getElementById('scanStatus');
    const localIpDisplay = document.getElementById('localIpDisplay');
    const threatLevelDisplay = document.getElementById('threatLevelDisplay');
    const totalAlertsDisplay = document.getElementById('totalAlertsDisplay');
    const highAlertsDisplay = document.getElementById('highAlertsDisplay');
    const mediumAlertsDisplay = document.getElementById('mediumAlertsDisplay');
    const lowAlertsDisplay = document.getElementById('lowAlertsDisplay');
    const findingsCountDisplay = document.getElementById('findingsCountDisplay');
    
    // Intel
    const avgRiskScore = document.getElementById('avgRiskScore');
    const metaTarget = document.getElementById('metaTarget');
    const metaDuration = document.getElementById('metaDuration');
    const topVectorsList = document.getElementById('topVectorsList');

    // Action Buttons
    const downloadPdfBtn = document.getElementById('downloadReportBtn'); 
    const analyzeReportDropdown = document.getElementById('analyzeReportDropdown');
    const llmAnalysisOptions = document.getElementById('llmAnalysisOptions');
    const refreshResultsBtn = document.getElementById('refreshResultsBtn');
    const zapHistoryBtn = document.getElementById('nmapHistoryBtn'); // Mapped to the HTML ID

    // AI Overlay
    const aiProcessingOverlay = document.getElementById('aiProcessingOverlay');
    const aiProcessingText = document.getElementById('aiProcessingText');

    // Tabs & Content
    const findingsTabBtn = document.getElementById('findingsTabBtn');
    const rawTabBtn = document.getElementById('rawTabBtn');
    const findingsContent = document.getElementById('findingsContent');
    const rawContent = document.getElementById('rawContent');
    const findingsList = document.getElementById('openPortsTableBody'); // Using the ID from HTML
    const findingsSearch = document.getElementById('findingsSearch');
    const filterChips = document.querySelectorAll('.filter-chip');
    const copyResultsBtn = document.getElementById('copyResultsBtn');
    const resultsContent = document.getElementById('resultsContent');

    // Terminal & Logs
    const logOutput = document.getElementById('logOutput');
    const clearLogBtn = document.getElementById('clearLogBtn');

    // History Modal
    const historyModal = document.getElementById('historyModal');
    const closeHistoryModal = document.getElementById('closeHistoryModal');
    const historyTableBody = document.getElementById('historyTableBody');

    // --- State ---
    let allFindings = [];
    let currentFilter = 'all';
    let scanStartTime = null;
    let eventSource = null;

    // --- Mobile UI Helper Functions (Global for inline onclicks) ---

    window.toggleMobileDropdown = function(id) {
        const el = document.getElementById(id);
        if (!el) return;
        const menu = el.querySelector('.dropdown-menu');
        if (!menu) return;
        
        const isShow = menu.classList.contains('show');
        
        // Close others
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
        
        // Sync with hidden select or state
        if (dropdownId === 'profileDropdown' && scanCategorySelect) {
            scanCategorySelect.value = value;
        } else if (dropdownId === 'aiDropdown') {
            // Trigger AI analysis with selected mode
            triggerAIAnalysis(value);
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

    // --- Utility Functions ---

    function toggleButtonLoading(button, isLoading) {
        if (!button) return;
        const spinner = button.querySelector('.spinner');
        const icon = button.querySelector('.material-symbols-outlined');
        
        button.disabled = isLoading;

        if (isLoading) {
            button.style.opacity = '0.7';
            button.style.cursor = 'not-allowed';
            if (spinner) spinner.classList.remove('hidden');
            if (icon) icon.classList.add('hidden');
        } else {
            button.style.opacity = '1';
            button.style.cursor = 'pointer';
            if (spinner) spinner.classList.add('hidden');
            if (icon) icon.classList.remove('hidden');
        }
    }

    function updateScanStatus(message, type = 'info') {
        if (!scanStatus) return;
        scanStatus.textContent = message.toUpperCase();
        
        if (type === 'busy') {
            scanStatus.style.color = 'var(--neo-amber)';
        } else if (type === 'success') {
            scanStatus.style.color = 'var(--neo-green)';
        } else if (type === 'error') {
            scanStatus.style.color = 'var(--neo-red)';
        } else {
            scanStatus.style.color = 'var(--neo-text-muted)';
        }
    }

    function appendLog(message) {
        if (!logOutput) return;

        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });

        // Clean up ZAP logs for readability
        let cleanedMessage = message.replace(/\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s*/g, "");
        cleanedMessage = cleanedMessage.replace(/^\[?\d{1,2}:\d{2}:\d{2}\]?\s*/, '');
        cleanedMessage = cleanedMessage.replace(/\[(?:ZAP Daemon|ZAP-daemon|ZAP-IO-[^\]]+)\]\s*/gi, '');
        cleanedMessage = cleanedMessage.replace(/^\d+\s+\[main\]\s+(?:INFO|WARN|ERROR)\s+org\.[\w\.]+\s+-\s+/, '');
        cleanedMessage = cleanedMessage.trim();

        let contentStyle = '';
        if (cleanedMessage.includes('[!]') || cleanedMessage.includes('Error')) {
            contentStyle = 'color: var(--neo-red)';
        } else if (cleanedMessage.includes('[+]') || cleanedMessage.includes('Success') || cleanedMessage.includes('[✓]')) {
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
        
        logOutput.appendChild(line);
        logOutput.scrollTop = logOutput.scrollHeight;
    }

    // --- Action: Start Scan ---

    async function handleScanButtonClick() {
        const targetUrl = targetUrlInput.value.trim();
        const scanMode = scanCategorySelect ? scanCategorySelect.value : 'default';
        const useAjax = useAjaxCheckbox ? useAjaxCheckbox.checked : false;

        let authConfig = null;
        if (loginUrlInput && loginUrlInput.value.trim() && usernameInput.value.trim() && passwordInput.value.trim()) {
            authConfig = {
                login_url: loginUrlInput.value.trim(),
                username_field: userFieldInput.value.trim() || 'username',
                password_field: passFieldInput.value.trim() || 'password',
                username: usernameInput.value.trim(),
                password: passwordInput.value.trim()
            };
        }

        if (!targetUrl) {
            appendLog('[!] Error: Target URL is required.');
            toggleTerminal(); // Pop open terminal to show error
            return;
        }

        if (!csrfToken) {
            appendLog('[!] Error: CSRF Token missing. Refresh page.');
            return;
        }

        toggleButtonLoading(startScanBtn, true);
        const authMsg = authConfig ? 'Authenticated' : 'Anonymous';
        updateScanStatus(`Scanning (${scanMode})...`, 'busy');
        
        if (localIpDisplay) localIpDisplay.textContent = targetUrl;
        logOutput.innerHTML = ''; 
        appendLog(`[*] Initiating ZAP ${scanMode.toUpperCase()} on ${targetUrl} (AJAX: ${useAjax}, Auth: ${authMsg})...`);
        scanStartTime = Date.now();

        // Reset UI metrics
        if (threatLevelDisplay) { threatLevelDisplay.textContent = '---'; threatLevelDisplay.style.color = 'var(--neo-text-muted)'; }
        if (totalAlertsDisplay) totalAlertsDisplay.textContent = '0';
        if (highAlertsDisplay) highAlertsDisplay.textContent = '0';
        if (mediumAlertsDisplay) mediumAlertsDisplay.textContent = '0';
        if (lowAlertsDisplay) lowAlertsDisplay.textContent = '0';
        if (findingsList) findingsList.innerHTML = `<div style="text-align:center; padding: 4rem 1rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.75rem;">SCAN IN PROGRESS...</div>`;

        try {
            const response = await fetch(SCAN_ENDPOINT, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ target_url: targetUrl, scan_mode: scanMode, use_ajax: useAjax, auth_config: authConfig })
            });
            const data = await response.json();

            if (!response.ok || data.status !== 'success') {
                throw new Error(data.message || 'Scan initiation failed');
            }
            // Stream handles completion, do not re-enable button yet
        } catch (error) {
            appendLog(`[!] Network error: ${error.message}`);
            updateScanStatus('Failed', 'error');
            toggleButtonLoading(startScanBtn, false);
        }
    }

    // --- SSE Stream ---
    
    function setupLogStream() {
        if (eventSource) eventSource.close();
        eventSource = new EventSource(LOG_STREAM_ENDPOINT);
        
        eventSource.onmessage = function(event) {
            if (event.data === ': keep-alive') return;

            if (event.data.includes("Scan, analysis, and prediction complete") || event.data.includes("SYSTEM_EVENT: READY_FOR_ANALYSIS")) {
                updateScanStatus('Complete', 'success');
                toggleButtonLoading(startScanBtn, false);
                fetchAndDisplayResults();
                checkReportStatus();
                appendLog('[✓] Scan sequence completed successfully.');
                return;
            }

            if (event.data.includes("[!] ZAP scan failed") || event.data.includes("ZAP Scan Error:")) {
                updateScanStatus('Failed', 'error');
                toggleButtonLoading(startScanBtn, false);
            }

            if (event.data.includes("EVENT:") || event.data.startsWith("EVENT:")) return;
            appendLog(event.data);
        };
    }

    // --- Results & Rendering ---

    async function fetchAndDisplayResults() {
        try {
            const response = await fetch(RESULTS_ENDPOINT);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            
            const result = await response.json();
            if (result.status === 'success' && result.data) {
                const report = result.data;
                updateSummaryDisplay(report.summary, report.target_url);
                allFindings = report.findings || report.alerts || [];
                renderFindings();
                updateInsightsDisplay(report);
            }
        } catch (error) {
            console.error(error);
            if (findingsList) findingsList.innerHTML = `<div style="text-align:center; padding: 4rem 1rem; color: var(--neo-red); font-family: var(--font-mono); font-size: 0.75rem;">ERROR LOADING DATA.</div>`;
        }
    }

    function updateSummaryDisplay(summary, targetUrl) {
        if (!summary) return;
        if (localIpDisplay && targetUrl) localIpDisplay.textContent = targetUrl;
        if (totalAlertsDisplay) totalAlertsDisplay.textContent = summary.Total || summary.total || '0';
        if (highAlertsDisplay) highAlertsDisplay.textContent = summary.High || summary.high || '0';
        if (mediumAlertsDisplay) mediumAlertsDisplay.textContent = summary.Medium || summary.medium || '0';
        if (lowAlertsDisplay) lowAlertsDisplay.textContent = summary.Low || summary.low || '0';
        
        if (threatLevelDisplay) {
            let topRisk = (summary.High || summary.high) > 0 ? 'High' : ((summary.Medium || summary.medium) > 0 ? 'Medium' : ((summary.Low || summary.low) > 0 ? 'Low' : 'Info'));
            threatLevelDisplay.textContent = topRisk.toUpperCase();
            threatLevelDisplay.style.color = getRiskColor(topRisk);
        }
    }

    function updateInsightsDisplay(report) {
        if (!report) return;
        if (metaTarget) metaTarget.textContent = report.target_url || '---';
        if (scanStartTime && metaDuration) {
            const duration = Math.floor((Date.now() - scanStartTime) / 1000);
            metaDuration.textContent = `${duration}s`;
        }

        const scores = allFindings.map(f => parseFloat(f.predicted_risk_score)).filter(s => !isNaN(s));
        if (scores.length > 0 && avgRiskScore) {
            const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
            avgRiskScore.textContent = avg.toFixed(1);
            avgRiskScore.style.color = avg > 0.7 ? 'var(--neo-red)' : (avg > 0.4 ? 'var(--neo-amber)' : 'var(--neo-blue)');
        }

        const vectorMap = {};
        allFindings.forEach(f => {
            const name = f.name || f.alert;
            vectorMap[name] = (vectorMap[name] || 0) + 1;
        });

        const sortedVectors = Object.entries(vectorMap).sort((a, b) => b[1] - a[1]).slice(0, 3);
        if (topVectorsList) {
            topVectorsList.innerHTML = '';
            if (sortedVectors.length > 0) {
                sortedVectors.forEach(([name, count]) => {
                    topVectorsList.innerHTML += `
                        <div style="display: flex; justify-content: space-between; margin-bottom: 4px; padding-bottom: 4px; border-bottom: 1px solid rgba(255,255,255,0.05);">
                            <span style="color: var(--neo-text-main); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 80%;">${name}</span>
                            <span style="color: var(--neo-text-muted);">${count}x</span>
                        </div>`;
                });
            } else {
                topVectorsList.innerHTML = `<span style="color: var(--neo-text-muted); font-size: 0.7rem;">NO VECTORS IDENTIFIED</span>`;
            }
        }
    }

    function getRiskColor(risk) {
        if (risk === 'High') return 'var(--neo-red)';
        if (risk === 'Medium') return 'var(--neo-amber)';
        if (risk === 'Low') return '#eab308';
        return 'var(--neo-blue)';
    }

    function renderFindings() {
        if (!findingsList) return;
        const searchTerm = findingsSearch ? findingsSearch.value.toLowerCase() : '';
        findingsList.innerHTML = '';
        
        const filtered = allFindings.filter(f => {
            const matchesFilter = currentFilter === 'all' || f.risk === currentFilter;
            const matchesSearch = (f.name || f.alert || '').toLowerCase().includes(searchTerm) || (f.url || '').toLowerCase().includes(searchTerm);
            return matchesFilter && matchesSearch;
        });

        if (findingsCountDisplay) findingsCountDisplay.textContent = filtered.length;

        if (filtered.length === 0) {
            findingsList.innerHTML = `<div style="text-align:center; padding: 4rem 1rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.75rem;">NO FINDINGS MATCHING CRITERIA.</div>`;
            return;
        }

        filtered.forEach(finding => findingsList.appendChild(createFindingCard(finding)));
    }

    function createFindingCard(finding) {
        const risk = finding.risk || 'Info';
        const rawScore = parseFloat(finding.predicted_risk_score || 0);
        const scoreVal = (rawScore * 10).toFixed(1);
        const color = getRiskColor(risk);
        
        const radius = 16;
        const circumference = 2 * Math.PI * radius;
        const offset = circumference - (rawScore * circumference);
        
        let gaugeClass = 'gauge-low';
        if (rawScore > 0.7) gaugeClass = 'gauge-critical';
        else if (rawScore > 0.5) gaugeClass = 'gauge-high';
        else if (rawScore > 0.3) gaugeClass = 'gauge-medium';

        const priorityLevel = finding.priority_level || 'P3';
        const priorityColor = priorityLevel === 'P0' ? 'var(--neo-red)' : (priorityLevel === 'P1' ? 'var(--neo-amber)' : 'var(--neo-blue)');

        const card = document.createElement('div');
        card.className = 'finding-card animate-mobile-card';
        card.style.setProperty('--accent-gradient', color);
        
        card.innerHTML = `
            <div class="finding-header">
                <div class="risk-indicator" style="color: ${color};">
                    <div class="risk-dot" style="background: ${color};"></div>
                    <span>${risk}</span>
                </div>
                
                <div class="finding-title" title="${finding.name || finding.alert}">${finding.name || finding.alert}</div>
                
                <div class="score-container">
                    <div class="risk-score-gauge">
                        <svg class="gauge-svg" viewBox="0 0 40 40">
                            <circle class="gauge-bg" cx="20" cy="20" r="${radius}"></circle>
                            <circle class="gauge-fill ${gaugeClass}" cx="20" cy="20" r="${radius}" style="stroke-dasharray: ${circumference}; stroke-dashoffset: ${offset};"></circle>
                        </svg>
                        <span class="gauge-val">${scoreVal}</span>
                    </div>
                </div>
                <span class="material-symbols-outlined expand-icon">expand_more</span>
            </div>
            
            <div class="finding-details">
                <div class="details-content">
                    <div class="detail-section">
                        <span class="detail-label">Endpoint</span>
                        <div class="flex items-center gap-2 mt-1">
                            <div class="badge-pill" style="background: rgba(255,255,255,0.05); color: var(--neo-text-main); border: 1px solid var(--neo-border);">${finding.method || 'GET'}</div>
                            <span style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--neo-blue); word-break: break-all;">${finding.url || 'N/A'}</span>
                        </div>
                    </div>

                    <div class="detail-section">
                        <span class="detail-label">Analysis</span>
                        <div class="detail-text">${finding.description || 'No description available.'}</div>
                    </div>

                    <div class="detail-section">
                        <span class="detail-label">Remediation</span>
                        <div class="detail-text" style="border-left: 2px solid var(--neo-green); padding-left: 0.75rem;">${finding.solution || 'Consult security best practices.'}</div>
                    </div>

                    <div class="detail-section" style="background: rgba(0,0,0,0.2);">
                        <div class="flex justify-between items-center mb-2">
                            <span class="detail-label">TCTR Intelligence</span>
                            <span class="badge-pill" style="background: ${priorityColor}22; border-color: ${priorityColor}44; color: ${priorityColor};">${priorityLevel}</span>
                        </div>
                        <div class="intel-row" style="padding: 0.25rem 0; border: none;">
                            <span class="intel-label" style="font-size: 0.6rem;">TCTR Score</span>
                            <span class="intel-val">${finding.tctr_priority || '0.00'}</span>
                        </div>
                        <div class="intel-row" style="padding: 0.25rem 0; border: none;">
                            <span class="intel-label" style="font-size: 0.6rem;">Justification</span>
                            <span class="intel-val" style="color: var(--neo-text-muted); font-size: 0.65rem;">${finding.risk_justification || 'Automated assessment'}</span>
                        </div>
                    </div>

                    <div class="detail-section">
                        <span class="detail-label mb-1">Evidence</span>
                        <div class="detail-text-mono">${finding.evidence || 'NO RAW EVIDENCE CAPTURED'}</div>
                    </div>
                </div>
            </div>
        `;

        card.querySelector('.finding-header').addEventListener('click', () => {
            card.classList.toggle('expanded');
        });

        return card;
    }

    async function loadRawScanResults() {
        if (!resultsContent) return;
        resultsContent.textContent = '// LOADING RAW DATA...';
        try {
            const response = await fetch(RESULTS_ENDPOINT);
            const result = await response.json();
            if (result.status === 'success' && result.data) {
                resultsContent.textContent = JSON.stringify(result.data, null, 4);
            } else {
                resultsContent.textContent = '// NO RAW DATA AVAILABLE.';
            }
        } catch (error) {
            resultsContent.textContent = '// FAILED TO LOAD RESULTS.';
        }
    }

    async function checkReportStatus() {
        if (downloadPdfBtn) { downloadPdfBtn.disabled = true; downloadPdfBtn.style.opacity = '0.5'; }
        if (analyzeReportDropdown) { analyzeReportDropdown.disabled = true; analyzeReportDropdown.style.opacity = '0.5'; }

        try {
            const target = targetUrlInput.value.trim();
            const url = target ? `${REPORT_FILES_ENDPOINT}?target=${encodeURIComponent(target)}` : REPORT_FILES_ENDPOINT;
            const response = await fetch(url);
            if (!response.ok) return;
            const data = await response.json();
    
            if (data.status === "success" && data.pdf_report) {
                if (downloadPdfBtn) {
                    downloadPdfBtn.disabled = false;
                    downloadPdfBtn.style.opacity = '1';
                    downloadPdfBtn.onclick = () => {
                        const a = document.createElement('a');
                        a.href = data.pdf_report;
                        a.download = `zap_report_${target.replace(/[^a-z0-9]/gi, '_')}.pdf`;
                        a.click();
                    };
                }
                if (analyzeReportDropdown) {
                    analyzeReportDropdown.disabled = false;
                    analyzeReportDropdown.style.opacity = '1';
                }
            }
        } catch (error) { console.error("Error checking report status:", error); }
    }

    // --- AI Analysis ---
    
    async function analyzeReport(llmMode) {
        const target = targetUrlInput.value.trim();
        if (!csrfToken) return appendLog('[!] Error: CSRF Token missing.');

        if (aiProcessingOverlay) aiProcessingOverlay.classList.remove('hidden');
        if (aiProcessingText) aiProcessingText.textContent = llmMode.includes('gemini') ? 'CONTACTING GEMINI...' : 'LOADING LOCAL MODEL...';
        
        updateScanStatus(`AI Analysis...`, 'busy');
        if (analyzeReportDropdown) analyzeReportDropdown.disabled = true;

        try {
            let response = await fetch(ANALYZE_ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                body: JSON.stringify({ llm_mode: llmMode, target: target })
            });
            let data = await response.json();
            
            if (data.status !== 'success') throw new Error(data.message || 'Check failed.');
            
            if (aiProcessingText) aiProcessingText.textContent = 'SYNTHESIZING REPORT...';

            response = await fetch(`${CHATBOT_REDIRECT_URL}/scanner_analysis`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                body: JSON.stringify({ 
                    llm_mode: llmMode, scanner_type: data.scanner_type, target: data.target, force_new_session: true 
                })
            });

            data = await response.json();

            if (response.ok && data.status === 'success') {
                if (aiProcessingText) aiProcessingText.textContent = 'REDIRECTING...';
                updateScanStatus('Redirecting...', 'success');
                setTimeout(() => {
                    const params = new URLSearchParams({ mode: data.llm_mode, summary: data.summary, session_id: data.session_id });
                    window.location.href = `${CHATBOT_REDIRECT_URL}?${params.toString()}`;
                }, 800);
            } else {
                throw new Error(data.message || `Analysis failed`);
            }
        } catch (error) {
            appendLog(`[!] AI Analysis Error: ${error.message}`);
            updateScanStatus('Analysis failed', 'error');
            if (aiProcessingOverlay) aiProcessingOverlay.classList.add('hidden');
            if (analyzeReportDropdown) analyzeReportDropdown.disabled = false;
        } finally {
            checkReportStatus(); 
        }
    }

    // --- History Modal ---
    
    async function fetchHistory() {
        if (!historyTableBody) return;
        historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.8rem;">LOADING HISTORY...</td></tr>';
        
        try {
            const res = await fetch(`${API_BASE_URL}/report_history`);
            const data = await res.json();
            
            if (data.status === 'success' && data.history && data.history.length > 0) {
                historyTableBody.innerHTML = '';
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
                    historyTableBody.appendChild(row);
                });
            } else {
                historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.8rem;">NO PRIOR SCANS FOUND</td></tr>';
            }
        } catch (e) {
            historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-red); font-family: var(--font-mono); font-size: 0.8rem;">ERROR LOADING HISTORY</td></tr>';
        }
    }

    // --- Event Listeners Initialization ---
    
    if (startScanBtn) startScanBtn.addEventListener('click', handleScanButtonClick);
    
    if (refreshResultsBtn) refreshResultsBtn.addEventListener('click', fetchAndDisplayResults);
    
    if (zapHistoryBtn && historyModal && closeHistoryModal) {
        zapHistoryBtn.addEventListener('click', () => { historyModal.classList.remove('hidden'); fetchHistory(); });
        closeHistoryModal.addEventListener('click', () => historyModal.classList.add('hidden'));
        historyModal.addEventListener('click', (e) => { if (e.target === historyModal) historyModal.classList.add('hidden'); });
    }

    if (llmAnalysisOptions) {
        llmAnalysisOptions.addEventListener('click', (e) => {
            e.preventDefault();
            const option = e.target.closest('[data-llm-mode]');
            if (option) {
                analyzeReport(option.dataset.llmMode);
            }
        });
    }

    // Tabs & Filters
    if (findingsTabBtn && rawTabBtn && findingsContent && rawContent) {
        findingsTabBtn.addEventListener('click', () => {
            findingsTabBtn.classList.add('active'); rawTabBtn.classList.remove('active');
            findingsContent.classList.add('active'); rawContent.classList.remove('active');
            findingsContent.style.display = 'flex'; rawContent.style.display = 'none';
        });
        rawTabBtn.addEventListener('click', () => {
            rawTabBtn.classList.add('active'); findingsTabBtn.classList.remove('active');
            rawContent.classList.add('active'); findingsContent.classList.remove('active');
            rawContent.style.display = 'block'; findingsContent.style.display = 'none';
            loadRawScanResults();
        });
    }

    if (filterChips && filterChips.length > 0) {
        filterChips.forEach(chip => {
            chip.addEventListener('click', () => {
                filterChips.forEach(c => c.classList.remove('active'));
                chip.classList.add('active');
                currentFilter = chip.dataset.filter;
                renderFindings();
            });
        });
    }

    if (findingsSearch) findingsSearch.addEventListener('input', renderFindings);

    if (copyResultsBtn && resultsContent) {
        copyResultsBtn.addEventListener('click', () => {
            if (resultsContent.textContent !== '// Buffer Empty') {
                navigator.clipboard.writeText(resultsContent.textContent).then(() => {
                    const txt = copyResultsBtn.querySelector('span:last-child');
                    txt.textContent = 'COPIED!';
                    setTimeout(() => txt.textContent = 'COPY', 2000);
                });
            }
        });
    }

    if (clearLogBtn) {
        clearLogBtn.addEventListener('click', async () => {
            if (!csrfToken) return;
            logOutput.innerHTML = '';
            await fetch(CLEAR_LOG_ENDPOINT, { method: 'POST', headers: { 'X-CSRFToken': csrfToken } });
            appendLog("[*] Log cleared.");
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
                if (localIpDisplay) localIpDisplay.textContent = data.target;
                appendLog(`[*] Detected active scan on ${data.target}. Attaching stream...`);
            }
        } catch (error) { console.error(error); }
    }

    // --- On Load ---
    setTimeout(() => appendLog('System Ready. Initializing Web App Scanner interface...'), 100);
    checkReportStatus();
    fetchAndDisplayResults();
    checkScanStatus();
    setupLogStream();
});