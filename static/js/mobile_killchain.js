document.addEventListener("DOMContentLoaded", () => {
    // --- STATE ---
    const API_BASE = "/killchain";
    const CHATBOT_REDIRECT_URL = "/chatbot";
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content");

    let currentScanId = null;
    let currentQueueId = null; 
    let eventSource = null;
    let isScanning = false;

    // --- ELEMENTS ---
    const els = {
        targetInput: document.getElementById("targetInput"),
        profileSelect: document.getElementById("profileSelect"),
        aggressionSelect: document.getElementById("aggressionSelect"),
        startBtn: document.getElementById("startScanBtn"),
        clearLogBtn: document.getElementById("clearLogBtn"),

        // Progress & Status
        targetDisplay: document.getElementById("targetDisplay"),
        scanStatusBadge: document.getElementById("scanStatusBadge"),
        statusText: document.getElementById("scanStatusText"),
        progressBar: document.getElementById("scanProgressBar"),
        progressPercent: document.getElementById("scanProgressPercent"),
        phaseText: document.getElementById("scanPhaseText"),

        logOutput: document.getElementById("logOutput"),

        // Metrics
        metricCritical: document.getElementById("metricCritical"),
        metricHigh: document.getElementById("metricHigh"),
        metricSubdomains: document.getElementById("metricSubdomains"),
        metricPorts: document.getElementById("metricPorts"),

        // Intel & Actions
        aiAnalysisDropdown: document.getElementById("aiAnalysisDropdown"),
        aiAnalysisOptions: document.getElementById("aiAnalysisOptions"),
        downloadPdfBtn: document.getElementById("downloadPdfBtn"),
        refreshReportBtn: document.getElementById("refreshReportBtn"),
        killchainHistoryBtn: document.getElementById("killchainHistoryBtn"),

        aiOverlay: document.getElementById("aiProcessingOverlay"),
        aiText: document.getElementById("aiProcessingText"),

        copyJsonBtn: document.getElementById("copyJsonBtn"),
        jsonOutput: document.getElementById("jsonOutput"),

        // Tab Contents
        vulnTableBody: document.getElementById("vulnTableBody"),
        reconTableBody: document.getElementById("reconTableBody"),
        networkTableBody: document.getElementById("networkTableBody"),
        techStackContainer: document.getElementById("techStackContainer"),
        
        // History Modal
        historyModal: document.getElementById('historyModal'),
        closeHistoryModal: document.getElementById('closeHistoryModal'),
        historyTableBody: document.getElementById('historyTableBody'),
    };

    // --- MOBILE UI HELPERS (Global) ---

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
        const triggerText = dropdown.querySelector('.trigger-text');
        const items = dropdown.querySelectorAll('.dropdown-item');
        const menu = dropdown.querySelector('.dropdown-menu');
        
        triggerText.textContent = text;
        items.forEach(item => item.classList.toggle('active', item.dataset.value === value));
        
        // Sync with hidden native select
        if (dropdownId === 'profileDropdown' && els.profileSelect) els.profileSelect.value = value;
        if (dropdownId === 'aggressionDropdown' && els.aggressionSelect) els.aggressionSelect.value = value;
        
        menu.classList.remove('show');
        menu.style.display = 'none';
    };

    window.toggleTerminal = function() {
        const sheet = document.getElementById('terminalSheet');
        if (sheet) sheet.classList.toggle('open');
    };

    window.switchTab = function(tabName) {
        const tabs = ["vulns", "recon", "network", "tech", "raw"];
        tabs.forEach((t) => {
            const contentEl = document.getElementById(`content${t.charAt(0).toUpperCase() + t.slice(1)}`);
            if (contentEl) {
                contentEl.classList.add("hidden");
                contentEl.classList.remove("active");
            }
            const pillEl = document.getElementById(`tab${t.charAt(0).toUpperCase() + t.slice(1)}`);
            if (pillEl) pillEl.classList.remove("active");
        });

        const targetContent = document.getElementById(`content${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`);
        if (targetContent) {
            targetContent.classList.remove("hidden");
            targetContent.classList.add("active");
        }
        const targetPill = document.getElementById(`tab${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`);
        if (targetPill) targetPill.classList.add("active");
    };

    // --- LOGGING & STATUS LOGIC ---

    function appendLog(msg) {
        if (!msg || !els.logOutput) return;

        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

        let cleanedMessage = msg.replace(/^\[?\d{1,2}:\d{2}:\d{2}\]?\s*/, '').trim();
        cleanedMessage = cleanedMessage.replace(/^\[\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\]\s*/, '').trim();
        cleanedMessage = cleanedMessage.replace(/(\[[A-Z]+\])\s*\1/g, '$1');
        cleanedMessage = cleanedMessage.replace(/\[(?:ZAP Daemon|ZAP-daemon|ZAP-IO-[^\]]+)\]\s*/gi, '');
        cleanedMessage = cleanedMessage.replace(/^\d+\s+\[main\]\s+(?:INFO|WARN|ERROR)\s+org\.[\w\.]+\s+-\s+/, '');
        cleanedMessage = cleanedMessage.replace(/\[ZAP-CLI\]\s*/g, '').replace(/\[ZAP\]\s*/g, '').trim();

        if (!cleanedMessage || cleanedMessage === '|' || cleanedMessage.includes('deprecated method')) return;

        const isProgress = cleanedMessage.startsWith('[') && (cleanedMessage.includes('%') || cleanedMessage.includes('==='));
        if (isProgress) {
            const lastLine = els.logOutput.lastElementChild;
            if (lastLine && lastLine.querySelector('.log-content').getAttribute('data-is-progress') === 'true') {
                lastLine.querySelector('.log-content').textContent = cleanedMessage;
                return;
            }
        }

        let contentStyle = '';
        if (cleanedMessage.includes('[x]') || cleanedMessage.includes('CRITICAL') || cleanedMessage.includes('ERROR')) {
            contentStyle = 'color: var(--neo-red)';
        } else if (cleanedMessage.includes('[+]') || cleanedMessage.includes('SUCCESS') || cleanedMessage.includes('Complete')) {
            contentStyle = 'color: var(--neo-green)';
        } else if (cleanedMessage.includes('[*]') || cleanedMessage.includes('PHASE')) {
            contentStyle = 'color: var(--neo-blue)';
        }

        const line = document.createElement("div");
        line.className = "log-line";
        line.innerHTML = `
            <div class="log-time">${timeStr}</div>
            <div class="log-content" style="${contentStyle}" ${isProgress ? 'data-is-progress="true"' : ''}>${cleanedMessage}</div>
        `;
        
        els.logOutput.appendChild(line);
        els.logOutput.scrollTop = els.logOutput.scrollHeight;
    }

    function updateStatus(text, type = "idle") {
        if (els.scanStatusBadge) {
            els.scanStatusBadge.textContent = text.toUpperCase();
            if (type === "busy") els.scanStatusBadge.style.color = 'var(--neo-amber)';
            else if (type === "success") els.scanStatusBadge.style.color = 'var(--neo-green)';
            else if (type === "error") els.scanStatusBadge.style.color = 'var(--neo-red)';
            else els.scanStatusBadge.style.color = 'var(--neo-text-muted)';
        }

        if (els.statusText) {
            els.statusText.textContent = text.toUpperCase();
            if (type === "busy") els.statusText.style.color = 'var(--neo-amber)';
            else if (type === "success") els.statusText.style.color = 'var(--neo-green)';
            else if (type === "error") els.statusText.style.color = 'var(--neo-red)';
            else els.statusText.style.color = 'var(--neo-text-main)';
        }
    }

    function updateProgress(percent, phase) {
        if (els.progressBar) els.progressBar.style.width = `${percent}%`;
        if (els.progressPercent) els.progressPercent.textContent = `${percent}%`;
        if (phase && els.phaseText) els.phaseText.textContent = `PHASE: ${phase.toUpperCase()}`;
    }

    function toggleButtons(scanActive) {
        if (!els.startBtn) return;
        els.startBtn.disabled = scanActive;
        
        const btnText = els.startBtn.querySelector(".button-text");
        const playIcon = els.startBtn.querySelector(".material-symbols-outlined");
        const spinner = els.startBtn.querySelector(".spinner");
        
        if (scanActive) {
            if (spinner) spinner.classList.remove("hidden");
            if (btnText) btnText.textContent = "SCANNING...";
            if (playIcon) playIcon.classList.add("hidden");
            els.startBtn.style.opacity = "0.7";
            els.startBtn.style.cursor = "not-allowed";
        } else {
            if (spinner) spinner.classList.add("hidden");
            if (btnText) btnText.textContent = "START SCAN";
            if (playIcon) playIcon.classList.remove("hidden");
            els.startBtn.style.opacity = "1";
            els.startBtn.style.cursor = "pointer";
        }

        const reportButtonsEnabled = !scanActive && currentScanId !== null;
        const opacity = reportButtonsEnabled ? "1" : "0.5";
        const cursor = reportButtonsEnabled ? "pointer" : "not-allowed";

        [els.aiAnalysisDropdown, els.downloadPdfBtn].forEach(btn => {
            if (btn) {
                btn.disabled = !reportButtonsEnabled;
                btn.style.opacity = opacity;
                btn.style.cursor = cursor;
            }
        });
    }

    // --- MAIN SCANNING LOGIC ---

    async function startScan() {
        if (isScanning) return;

        const target = els.targetInput.value.trim();
        if (!target) {
            appendLog("[!] Error: Target required");
            toggleTerminal();
            return;
        }

        isScanning = true;
        toggleButtons(true); 

        if (els.targetDisplay) els.targetDisplay.textContent = target;

        const emptyState = (msg) => `<div style="text-align:center; padding: 4rem 1rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.75rem;">${msg}</div>`;

        els.vulnTableBody.innerHTML = emptyState("SCANNING FOR VULNERABILITIES...");
        els.reconTableBody.innerHTML = emptyState("GATHERING RECON DATA...");
        els.networkTableBody.innerHTML = emptyState("SCANNING NETWORK...");
        els.techStackContainer.innerHTML = emptyState("ANALYZING TECH STACK...");
        els.jsonOutput.textContent = "// Scan in progress...";
        els.logOutput.innerHTML = "";

        updateProgress(0, "Initializing");
        updateStatus("Running", "busy");

        try {
            const res = await fetch(`${API_BASE}/dispatch`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": csrfToken,
                },
                body: JSON.stringify({
                    target: target,
                    profile: els.profileSelect ? els.profileSelect.value : "Full Scan",
                    aggression: els.aggressionSelect ? els.aggressionSelect.value : "Normal",
                }),
            });
            const data = await res.json();

            if (data.status === "success") {
                currentScanId = data.scan_id;
                currentQueueId = data.queue_id; 
                initLogStream(data.queue_id);
            } else {
                throw new Error(data.message);
            }
        } catch (e) {
            appendLog(`[!] ERROR: Failed to start scan: ${e.message}`);
            isScanning = false;
            toggleButtons(false); 
            updateStatus("Failed", "error");
        }
    }

    function initLogStream(queueId) {
        if (eventSource) eventSource.close(); 
        eventSource = null;

        if (!queueId) {
            appendLog("[!] Error: Invalid queue ID for log stream.");
            return;
        }

        let messageReceived = false;
        const staleTimer = setTimeout(() => {
            if (!messageReceived && eventSource) {
                appendLog("[!] Log stream timed out (no data). Closing connection.");
                eventSource.close();
                eventSource = null;
                isScanning = false;
                toggleButtons(false);
                updateStatus("Idle", "idle");
            }
        }, 30000);

        eventSource = new EventSource(`${API_BASE}/log_stream?queue_id=${queueId}`);

        eventSource.onmessage = (e) => {
            const msg = e.data;
            if (msg.startsWith(":")) return;
            
            messageReceived = true;
            clearTimeout(staleTimer);
            appendLog(msg);

            if (msg.includes("SYSTEM_EVENT: READY_FOR_ANALYSIS")) {
                fetchReportData();
            }
        };

        eventSource.addEventListener("progress_update", (e) => {
            try {
                const data = JSON.parse(e.data);
                updateProgress(data.percent, data.phase);
            } catch (err) {
                console.error("Progress parsing error", err);
            }
        });

        eventSource.addEventListener("scan_complete", () => {
            clearTimeout(staleTimer);
            messageReceived = true;
            appendLog("[*] Scan Finished. Fetching report...");
            eventSource.close();
            eventSource = null;
            isScanning = false;
            toggleButtons(false);
            updateStatus("Complete", "success");
            updateProgress(100, "Done");
            fetchReportData();
        });

        eventSource.addEventListener("scan_failed", (e) => {
            clearTimeout(staleTimer);
            messageReceived = true;
            const data = JSON.parse(e.data);
            appendLog(`[!] Scan Aborted: ${data.message}`);
            eventSource.close();
            eventSource = null;
            isScanning = false;
            toggleButtons(false);
            updateStatus("Error", "error");
        });
        
        eventSource.onerror = (err) => {
            console.error("EventSource failed:", err);
            if (!isScanning) {
                eventSource.close();
                eventSource = null;
                return;
            }
            if (eventSource && eventSource.readyState === EventSource.CLOSED) {
                appendLog("[*] Log stream closed unexpectedly. Browser will retry...");
            }
        };
    }

    // --- RESUME / RESTORE LOGIC ---

    async function checkActiveScan() {
        try {
            const res = await fetch(`${API_BASE}/check_active_scan`);
            const data = await res.json();

            if (data.status === "active") {
                isScanning = true;
                currentScanId = data.scan_id;
                currentQueueId = data.queue_id;
                
                if (els.targetInput) els.targetInput.value = data.target;
                if (els.targetDisplay) els.targetDisplay.textContent = data.target;
                
                // Update dropdown texts
                if (els.profileSelect) {
                    els.profileSelect.value = data.profile;
                    const triggerText = document.getElementById('profileTriggerText');
                    if (triggerText) triggerText.textContent = data.profile.toUpperCase();
                }
                if (els.aggressionSelect) {
                    els.aggressionSelect.value = data.aggression;
                    const triggerText = document.getElementById('aggressionTriggerText');
                    if (triggerText) triggerText.textContent = data.aggression.toUpperCase();
                }

                toggleButtons(true); 
                updateStatus("Resuming Scan", "busy");
                appendLog(`[*] Resuming active scan for ${data.target}...`);
                
                initLogStream(data.queue_id);
                fetchReportData(); 
            } else {
                toggleButtons(false);
                fetchHistory();        
                fetchLatestReport();  
            }
        } catch (e) {
            console.error("Error checking active scan:", e);
            toggleButtons(false); 
            fetchHistory(); 
        }
    }

    async function fetchReportData() {
        const target = els.targetInput.value.trim();
        if (!target && !currentScanId) return;

        try {
            const url = target ? `${API_BASE}/report_files?target=${encodeURIComponent(target)}` : `${API_BASE}/report_files?scan_id=${currentScanId}`;
            const checkRes = await fetch(url);
            const checkData = await checkRes.json();

            if (checkData.status === "success") {
                toggleButtons(false); 
                const jsonUrl = target ? `${API_BASE}/get_json_report?target=${encodeURIComponent(target)}` : `${API_BASE}/get_json_report?scan_id=${currentScanId}`;
                const jsonRes = await fetch(jsonUrl);
                const report = await jsonRes.json();
                renderReport(report);
            } else if (checkData.status === "pending") {
                if (isScanning) toggleButtons(true);
            }
        } catch (e) {
            appendLog(`[!] Failed to load report: ${e.message}`);
        }
    }

    async function fetchLatestReport() {
        try {
            const jsonRes = await fetch(`${API_BASE}/get_json_report`);
            if (!jsonRes.ok) return; 
            const report = await jsonRes.json();
            if (report.status === 'error') return;

            if (report.target && els.targetInput) {
                els.targetInput.value = report.target;
                if (els.targetDisplay) els.targetDisplay.textContent = report.target;
            }

            currentScanId = 'latest';
            updateStatus("Ready", "success");
            toggleButtons(false); 
            renderReport(report);
        } catch (e) {
            console.warn('[killchain] No previous report to restore');
        }
    }

    // --- RENDER LOGIC (MOBILE OPTIMIZED) ---

    function renderReport(data) {
        const allFindings = data.all_findings || [];
        const crit = allFindings.filter((v) => v.severity && v.severity.toLowerCase() === "critical").length;
        const high = allFindings.filter((v) => v.severity && v.severity.toLowerCase() === "high").length;
        const subs = data.recon && data.recon.subdomains ? data.recon.subdomains.length : 0;
        const openPorts = data.network && data.network.nmap_scan && data.network.nmap_scan.ports ? data.network.nmap_scan.ports.length : 0;

        if (els.metricCritical) els.metricCritical.textContent = crit;
        if (els.metricHigh) els.metricHigh.textContent = high;
        if (els.metricSubdomains) els.metricSubdomains.textContent = subs;
        if (els.metricPorts) els.metricPorts.textContent = openPorts;

        // 1. Vulnerabilities
        if (els.vulnTableBody) {
            els.vulnTableBody.innerHTML = "";
            if (allFindings.length === 0) {
                els.vulnTableBody.innerHTML = '<div style="text-align:center; padding: 4rem 1rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.75rem;">No vulnerabilities found.</div>';
            } else {
                allFindings.forEach((v) => {
                    const sev = (v.severity || v.risk || "info").toLowerCase(); 
                    let riskClass = 'risk-low';
                    let score = "0.0";
                    if (sev === 'critical') { riskClass = 'risk-critical'; score = "9.5"; }
                    else if (sev === 'high') { riskClass = 'risk-high'; score = "7.5"; }
                    else if (sev === 'medium') { riskClass = 'risk-medium'; score = "5.5"; }
                    else if (sev === 'info') { riskClass = 'risk-safe'; score = "0.0"; }

                    const title = v.type || v.name || "Unknown Vulnerability";
                    const evidence = v.evidence || v.url || v.location || "N/A";
                    const desc = v.description || "No description provided.";
                    const solution = v.solution || "No remediation provided.";

                    const radius = 16;
                    const circumference = 2 * Math.PI * radius;
                    const offset = circumference - ((parseFloat(score)/10) * circumference);
                    let gaugeClass = 'gauge-low';
                    if (parseFloat(score) > 7.0) gaugeClass = 'gauge-critical';
                    else if (parseFloat(score) > 5.0) gaugeClass = 'gauge-high';
                    else if (parseFloat(score) > 3.0) gaugeClass = 'gauge-medium';

                    const card = document.createElement('div');
                    card.className = `finding-card ${riskClass}`;
                    card.innerHTML = `
                        <div class="finding-header">
                            <div class="risk-indicator ${riskClass}">
                                <div class="risk-dot"></div>
                                <span>${sev.toUpperCase()}</span>
                            </div>
                            <div class="finding-title" title="${title}">${title}</div>
                            <div class="score-container">
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
                                    <span class="detail-label">Location / Evidence</span>
                                    <span class="detail-text-mono">${evidence}</span>
                                </div>
                                <div class="detail-section">
                                    <span class="detail-label">Description</span>
                                    <div class="detail-text">${desc}</div>
                                </div>
                                <div class="detail-section">
                                    <span class="detail-label">Remediation</span>
                                    <div class="detail-text" style="border-left: 2px solid var(--neo-green); padding-left: 0.75rem;">${solution}</div>
                                </div>
                            </div>
                        </div>
                    `;
                    card.querySelector('.finding-header').addEventListener('click', () => card.classList.toggle('expanded'));
                    els.vulnTableBody.appendChild(card);
                });
            }
        }

        // 2. Recon
        if (els.reconTableBody) {
            els.reconTableBody.innerHTML = "";
            const reconDataItems = [];
            if (data.recon && data.recon.subdomains && data.recon.subdomains.length > 0) {
                data.recon.subdomains.forEach(sub => reconDataItems.push({type: "SUBDOMAIN", item: sub, details: "Discovered via OSINT"}));
            }
            if (data.recon && data.recon.resolved_hosts && data.recon.resolved_hosts.length > 0) {
                data.recon.resolved_hosts.forEach(host => reconDataItems.push({type: "HOST IP", item: host.domain, details: host.ip}));
            }
            if (data.web_audit && data.web_audit.crawled_urls && data.web_audit.crawled_urls.length > 0) {
                data.web_audit.crawled_urls.slice(0, 10).forEach(url => reconDataItems.push({type: "CRAWLED URL", item: url, details: "Entry Point"}));
            }
            if (data.web_audit && data.web_audit.api_endpoints && data.web_audit.api_endpoints.length > 0) {
                data.web_audit.api_endpoints.slice(0, 5).forEach(endpoint => reconDataItems.push({type: "API ENDPOINT", item: endpoint, details: "JS Discovered"}));
            }

            if (reconDataItems.length > 0) {
                reconDataItems.forEach((item) => {
                    const titleText = item.item;
                    const iconMap = {"SUBDOMAIN": "dns", "HOST IP": "router", "CRAWLED URL": "link", "API ENDPOINT": "api"};
                    const icon = iconMap[item.type] || "radar";
                    
                    const cardHtml = `
                        <div class="discovery-card animate-card">
                            <div class="card-header">
                                <div style="display: flex; align-items: center; gap: 6px;">
                                    <span class="material-symbols-outlined" style="font-size: 1.1rem;">${icon}</span>
                                    ${item.type}
                                </div>
                            </div>
                            <div class="service-main">
                                <div class="service-title">${titleText}</div>
                                <div class="service-ver">${item.details || "Discovered asset"}</div>
                            </div>
                        </div>`;
                    els.reconTableBody.insertAdjacentHTML("beforeend", cardHtml);
                });
            } else {
                els.reconTableBody.innerHTML = '<div style="text-align:center; padding: 4rem 1rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size:0.75rem;">No recon data found.</div>';
            }
        }

        // 3. Network
        if (els.networkTableBody) {
            els.networkTableBody.innerHTML = "";
            if (data.network && data.network.nmap_scan && data.network.nmap_scan.ports && data.network.nmap_scan.ports.length > 0) {
                data.network.nmap_scan.ports.forEach((p) => {
                    const cardHtml = `
                        <div class="discovery-card animate-card">
                            <div class="card-header" style="justify-content: flex-start;">
                                <div class="port-badge">
                                    <span class="port-num">${p.port}</span>
                                    <span class="protocol-label">${p.protocol}</span>
                                </div>
                            </div>
                            <div class="service-main">
                                <div class="service-title" title="${p.service}">${p.service}</div>
                                <div class="service-ver">${p.version || p.product || "Unknown Version"}</div>
                            </div>
                            <div class="analysis-footer">Active listener detected</div>
                        </div>`;
                    els.networkTableBody.insertAdjacentHTML("beforeend", cardHtml);
                });
            } else {
                els.networkTableBody.innerHTML = '<div style="text-align:center; padding: 4rem 1rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size:0.75rem;">No open ports found.</div>';
            }
        }

        // 4. Tech Stack
        if (els.techStackContainer) {
            els.techStackContainer.innerHTML = "";
            if (data.tech && data.tech.technologies && Object.keys(data.tech.technologies).length > 0) {
                let techHtml = '<div style="display: flex; flex-direction: column; gap: 1rem;">';
                for (const category in data.tech.technologies) {
                    techHtml += `<div>
                        <h4 style="color: var(--neo-blue); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0.5rem;">${category}</h4>
                        <div style="display: flex; flex-wrap: wrap;">`;
                    data.tech.technologies[category].forEach(tech => {
                        techHtml += `<span class="tech-tag">${tech}</span>`;
                    });
                    techHtml += `</div></div>`;
                }
                
                if (data.tech.versions && Object.keys(data.tech.versions).length > 0) {
                    techHtml += `<div>
                        <h4 style="color: var(--neo-blue); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0.5rem; margin-top: 1rem;">VERSIONS</h4>
                        <div style="display: flex; flex-wrap: wrap;">`;
                    for (const software in data.tech.versions) {
                        techHtml += `<span class="tech-tag">${software} <span style="opacity:0.5; margin-left:4px;">v${data.tech.versions[software]}</span></span>`;
                    }
                    techHtml += `</div></div>`;
                }
                techHtml += '</div>';
                els.techStackContainer.innerHTML = techHtml;
            } else {
                els.techStackContainer.innerHTML = '<div style="text-align:center; padding: 4rem 1rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size:0.75rem;">No technologies detected.</div>';
            }
        }

        // 5. JSON
        if (data && els.jsonOutput) {
            els.jsonOutput.textContent = JSON.stringify(data, null, 2);
        }
    }

    // --- ACTIONS & AI ---

    async function analyzeReport(llmMode) {
        const target = els.targetInput.value.trim();
        if (!target && !currentScanId) return;

        if (els.aiOverlay) els.aiOverlay.classList.remove("hidden");
        if (els.aiText) els.aiText.textContent = llmMode.startsWith("gemini") ? "CONTACTING GEMINI..." : "LOADING LOCAL LLM...";

        try {
            const res = await fetch(`${API_BASE}/trigger_ai_analysis`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": csrfToken,
                },
                body: JSON.stringify({ scan_id: currentScanId, target: target }),
            });
            const data = await res.json();

            if (data.status === "success") {
                if (els.aiText) els.aiText.textContent = "SYNTHESIZING REPORT...";
                const chatRes = await fetch(`${CHATBOT_REDIRECT_URL}/scanner_analysis`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRFToken": csrfToken,
                    },
                    body: JSON.stringify({
                        llm_mode: llmMode,
                        scanner_type: "killchain",
                        target: data.target,
                        force_new_session: true 
                    }),
                });
                const chatData = await chatRes.json();

                if (chatRes.ok && chatData.status === "success") {
                    if (els.aiText) els.aiText.textContent = "REDIRECTING...";
                    setTimeout(() => {
                        window.location.href = `${CHATBOT_REDIRECT_URL}?mode=${chatData.llm_mode}&summary=${encodeURIComponent(chatData.summary)}&session_id=${chatData.session_id}`;
                    }, 800);
                } else {
                    throw new Error(chatData.message || "Chatbot handshake failed");
                }
            } else {
                throw new Error(data.message);
            }
        } catch (e) {
            alert("Analysis failed: " + e.message);
            if (els.aiOverlay) els.aiOverlay.classList.add("hidden");
        }
    }

    async function fetchHistory() {
        if (!els.historyTableBody) return;
        els.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.75rem;">LOADING HISTORY...</td></tr>';
        
        try {
            const res = await fetch(`${API_BASE}/report_history`);
            const data = await res.json();
            
            if (data.status === 'success' && data.history) {
                if (data.history.length === 0) {
                    els.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.75rem;">NO PRIOR SCANS FOUND</td></tr>';
                    return;
                }
                
                els.historyTableBody.innerHTML = '';
                data.history.forEach(item => {
                    const row = document.createElement('tr');
                    let target = item.filename.split('_').slice(1).join('_').replace('.pdf', '');                    target = target.replace(/_\d{8}_\d{6}$/, '');
                    if (!target) target = 'Previous Scan';
                    
                    row.innerHTML = `
                        <td>${item.created_at}</td>
                        <td style="color: var(--neo-blue);">${target}</td>
                        <td style="text-align: right;">
                            <a href="${API_BASE}/download_pdf?filename=${item.filename}" class="btn-dash" style="display: inline-flex; height: 32px; width: 32px; padding: 0;">
                                <span class="material-symbols-outlined" style="font-size: 1.1rem;">download</span>
                            </a>
                        </td>
                    `;
                    els.historyTableBody.appendChild(row);
                });
            } else {
                els.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-red); font-family: var(--font-mono); font-size: 0.75rem;">FAILED TO LOAD HISTORY</td></tr>';
            }
        } catch (e) {
            els.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-red); font-family: var(--font-mono); font-size: 0.75rem;">ERROR LOADING HISTORY</td></tr>';
        }
    }

    // --- EVENT LISTENERS ---

    if (els.startBtn) els.startBtn.addEventListener("click", startScan);

    if (els.refreshReportBtn) {
        els.refreshReportBtn.addEventListener("click", () => {
            if (els.targetInput.value.trim() || currentScanId || isScanning) {
                fetchReportData();
            } else {
                fetchLatestReport();
            }
        });
    }
    
    if (els.clearLogBtn) {
        els.clearLogBtn.addEventListener('click', () => {
            if (els.logOutput) els.logOutput.innerHTML = '';
        });
    }

    if (els.copyJsonBtn) {
        els.copyJsonBtn.addEventListener("click", () => {
            const text = els.jsonOutput.textContent;
            if (!text || text.startsWith("//")) return;

            navigator.clipboard.writeText(text).then(() => {
                const originalText = els.copyJsonBtn.textContent;
                els.copyJsonBtn.textContent = "COPIED";
                els.copyJsonBtn.style.color = "var(--neo-green)";
                setTimeout(() => {
                    els.copyJsonBtn.textContent = originalText;
                    els.copyJsonBtn.style.color = "";
                }, 2000);
            });
        });
    }

    if (els.downloadPdfBtn) {
        els.downloadPdfBtn.addEventListener("click", () => {
            const target = els.targetInput.value.trim();
            const downloadIdentifier = target || currentScanId;

            if (!downloadIdentifier) {
                appendLog("[!] Error: Cannot download PDF. No target or scan ID available.");
                return;
            }
            const url = `${API_BASE}/download_pdf?target=${encodeURIComponent(downloadIdentifier)}`;
            window.location.href = url;
        });
    }

    // AI Dropdown
    if (els.aiAnalysisDropdown) {
        els.aiAnalysisDropdown.addEventListener("click", (e) => {
            if (els.aiAnalysisDropdown.disabled) return;
            e.stopPropagation();
            els.aiAnalysisOptions.classList.toggle("hidden");
        });
    }

    if (els.aiAnalysisOptions) {
        els.aiAnalysisOptions.addEventListener("click", (e) => {
            e.preventDefault();
            const link = e.target.closest("a[data-llm-mode]");
            if (link) {
                const mode = link.dataset.llmMode;
                els.aiAnalysisOptions.classList.add("hidden");
                analyzeReport(mode);
            }
        });
    }

    // History
    if (els.killchainHistoryBtn) {
        els.killchainHistoryBtn.addEventListener('click', () => {
            els.historyModal.classList.remove('hidden');
            fetchHistory();
        });
    }
    if (els.closeHistoryModal) {
        els.closeHistoryModal.addEventListener('click', () => {
            els.historyModal.classList.add('hidden');
        });
    }
    if (els.historyModal) {
        els.historyModal.addEventListener('click', (e) => {
            if (e.target === els.historyModal) {
                els.historyModal.classList.add('hidden');
            }
        });
    }

    // --- INIT ---
    updateStatus("Ready");
    checkActiveScan(); 
});