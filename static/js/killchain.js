document.addEventListener("DOMContentLoaded", () => {
  // --- STATE ---
  const API_BASE = "/killchain";
  const CHATBOT_REDIRECT_URL = "/chatbot";
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content");

  let currentScanId = null;
  let currentQueueId = null; // New state variable for queue ID
  let eventSource = null;
  let isScanning = false;

  // --- ELEMENTS ---
  const els = {
    targetInput: document.getElementById("targetInput"),
    profileSelect: document.getElementById("profileSelect"),
    aggressionSelect: document.getElementById("aggressionSelect"),
    startBtn: document.getElementById("startScanBtn"),
    clearLogBtn: document.getElementById("clearLogBtn"),

    statusText: document.getElementById("scanStatusText"),
    progressBar: document.getElementById("scanProgressBar"),
    progressPercent: document.getElementById("scanProgressPercent"),
    phaseText: document.getElementById("scanPhaseText"),

    logOutput: document.getElementById("logOutput"),

    metricCritical: document.getElementById("metricCritical"),
    metricHigh: document.getElementById("metricHigh"),
    metricSubdomains: document.getElementById("metricSubdomains"),
    metricPorts: document.getElementById("metricPorts"),

    aiAnalysisDropdown: document.getElementById("aiAnalysisDropdown"),
    aiAnalysisOptions: document.getElementById("aiAnalysisOptions"),
    downloadPdfBtn: document.getElementById("downloadPdfBtn"),
    refreshReportBtn: document.getElementById("refreshReportBtn"),

    aiOverlay: document.getElementById("aiProcessingOverlay"),
    aiText: document.getElementById("aiProcessingText"),

    copyJsonBtn: document.getElementById("copyJsonBtn"),
    jsonOutput: document.getElementById("jsonOutput"),

    vulnTableBody: document.getElementById("vulnTableBody"),
    reconTableBody: document.getElementById("reconTableBody"),
    networkTableBody: document.getElementById("networkTableBody"),
    techStackContainer: document.getElementById("techStackContainer"),
    
    // History
    killchainHistoryBtn: document.getElementById('killchainHistoryBtn'),
    historyModal: document.getElementById('historyModal'),
    closeHistoryModal: document.getElementById('closeHistoryModal'),
    historyTableBody: document.getElementById('historyTableBody'),
  };

  // --- LOGGING LOGIC ---
  function appendLog(msg) {
    if (!msg) return;

    // Filter out verbose scanner/dependency noise
    const isImportant = msg.includes("ERROR") || msg.includes("CRITICAL") || msg.includes("FAIL") || 
                        msg.includes("[STAGE]") || msg.includes("[PHASE]") || msg.includes("[INFO] [+]") || 
                        msg.includes("[*]") || msg.includes("[SYSTEM]");
                        
    if (!isImportant) {
      if (
        /org\.(zaproxy|parosproxy|flywaydb|openqa)/i.test(msg) ||
        /^[A-Za-z]:\\[^>]*>/.test(msg.trim()) || 
        /java\s+-Xmx/i.test(msg) || 
        /sun\.misc\.unsafe/i.test(msg) ||
        /platformdependent/i.test(msg) ||
        /\b(?:Creating directory|Copying default configuration|Setting config|Installed add-ons|Loading extensions|Extensions loaded)\b/i.test(msg)
      ) {
        return; 
      }
    }

    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });

    let cleanedMessage = msg.replace(/^\[?\d{1,2}:\d{2}:\d{2}\]?\s*/, '').trim();
    
    // 1. Remove the standard backend timestamp brackets, e.g., "[2026-03-04 15:29:11]"
    cleanedMessage = cleanedMessage.replace(/^\[\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\]\s*/, '').trim();

    // 2. Remove redundant repeating tags like "[START] [START]" -> "[START]"
    cleanedMessage = cleanedMessage.replace(/(\[[A-Z]+\])\s*\1/g, '$1');

    // 3. Remove internal ZAP Daemon Java noise and thread tags
    cleanedMessage = cleanedMessage.replace(/\[(?:ZAP Daemon|ZAP-daemon|ZAP-IO-[^\]]+)\]\s*/gi, '');
    cleanedMessage = cleanedMessage.replace(/^\d+\s+\[main\]\s+(?:INFO|WARN|ERROR)\s+org\.[\w\.]+\s+-\s+/, '');
    
    // 4. Remove standard Python wrapper noise prefix
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
        contentStyle = 'color:#ef4444';
    } else if (cleanedMessage.includes('[+]') || cleanedMessage.includes('SUCCESS') || cleanedMessage.includes('Complete')) {
        contentStyle = 'color:#10b981';
    } else if (cleanedMessage.includes('[*]') || cleanedMessage.includes('PHASE')) {
        contentStyle = 'color:#3b82f6';
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
    if (!els.statusText) return;
    
    els.statusText.textContent = text.toUpperCase();
    
    const isLight = document.body.classList.contains("light-mode");
    els.statusText.style.color = isLight ? '#64748b' : '#a1a1aa';

    if (type === "busy") els.statusText.style.color = '#eab308';
    else if (type === "success") els.statusText.style.color = '#10b981';
    else if (type === "error") els.statusText.style.color = '#ef4444';
  }

  function updateProgress(percent, phase) {
    if (els.progressBar) els.progressBar.style.width = `${percent}%`;
    if (els.progressPercent) els.progressPercent.textContent = `${percent}%`;

    if (phase && els.phaseText) {
      els.phaseText.textContent = `PHASE: ${phase.toUpperCase()}`;
    }
  }

  function toggleButtons(scanActive) {
    els.startBtn.disabled = scanActive;
    
    // UI updates for START SCAN button
    const btnText = els.startBtn.querySelector(".button-text");
    const playIcon = els.startBtn.querySelector(".material-symbols-outlined");
    
    if (scanActive) {
      els.startBtn.querySelector(".spinner").classList.remove("hidden");
      if (btnText) btnText.textContent = "SCANNING...";
      if (playIcon) playIcon.classList.add("hidden");
      els.startBtn.style.opacity = "0.7";
      els.startBtn.style.cursor = "not-allowed";
    } else {
      els.startBtn.querySelector(".spinner").classList.add("hidden");
      if (btnText) btnText.textContent = "START SCAN";
      if (playIcon) playIcon.classList.remove("hidden");
      els.startBtn.style.opacity = "1";
      els.startBtn.style.cursor = "pointer";
    }

    const reportButtonsEnabled = !scanActive && currentScanId !== null;
    const opacity = reportButtonsEnabled ? "1" : "0.7";
    const cursor = reportButtonsEnabled ? "pointer" : "not-allowed";

    [els.aiAnalysisDropdown, els.downloadPdfBtn, els.copyJsonBtn].forEach(
      (btn) => {
        if (btn) {
          btn.disabled = !reportButtonsEnabled;
          btn.style.opacity = opacity;
          btn.style.cursor = cursor;
        }
      }
    );
  }

  function setSelectedOption(selectId, valueToSelect) {
    const select = document.getElementById(selectId);
    if (!select) return;
    select.value = valueToSelect;
  }

  // --- MAIN SCANNING LOGIC ---
  async function startScan() {
    if (isScanning) return;

    const target = els.targetInput.value.trim();
    if (!target) {
      appendLog("[frontend] Error: Target required");
      return;
    }

    isScanning = true;
    toggleButtons(true); // Disable start button, enable spinner, disable report/AI buttons initially

    // Reset Tables (Updated empty message styling)
    const emptyState = (msg) =>
      `<tr><td colspan="3" style="text-align:center; padding: 3rem; color: #555;">${msg}</td></tr>`;

    els.vulnTableBody.innerHTML = emptyState("Scanning for vulnerabilities...");
    els.reconTableBody.innerHTML = emptyState("Gathering recon data...");
    els.networkTableBody.innerHTML = emptyState("Scanning network...");
    els.techStackContainer.innerHTML = '<span style="color: #a1a1aa;">Scanning...</span>';
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
          profile: els.profileSelect.value,
          aggression: els.aggressionSelect.value,
        }),
      });
      const data = await res.json();

      if (data.status === "success") {
        currentScanId = data.scan_id;
        currentQueueId = data.queue_id; // Store queue ID
        initLogStream(data.queue_id);
      } else {
        throw new Error(data.message);
      }
    } catch (e) {
      appendLog(`[frontend] ERROR: Failed to start scan: ${e.message}`);
      isScanning = false;
      toggleButtons(false); // Re-enable start button, disable report buttons
      updateStatus("Failed", "error");
    }
  }

  function initLogStream(queueId) {
    if (eventSource) eventSource.close(); // Close any existing connection
    eventSource = null;

    // Only establish EventSource if queueId is valid
    if (!queueId) {
        appendLog("[frontend] Error: Invalid queue ID for log stream.");
        return;
    }

    // Stale-queue guard: if no message arrives within 30s, assume the queue
    // is dead (e.g. server restart / stale resumed scan) and stop reconnecting.
    let messageReceived = false;
    const staleTimer = setTimeout(() => {
        if (!messageReceived && eventSource) {
            appendLog("[SYSTEM] Log stream timed out (no data). Closing connection.");
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
      // Cancel stale-queue timeout on first real message
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
      appendLog("[SYSTEM] Scan Finished. Fetching report...");
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
      appendLog(`[ERROR] Scan Aborted: ${data.message}`);
      eventSource.close();
      eventSource = null;
      isScanning = false;
      toggleButtons(false);
      updateStatus("Error", "error");
    });
    
    eventSource.onerror = (err) => {
        console.error("EventSource failed:", err);

        if (!isScanning) {
            // No active scan — explicitly close so the browser does NOT auto-reconnect
            eventSource.close();
            eventSource = null;
            return;
        }

        // isScanning === true: let the browser's native SSE auto-reconnect handle it
        // (browser reconnects automatically after a few seconds per SSE spec)
        if (eventSource && eventSource.readyState === EventSource.CLOSED) {
            appendLog("[SYSTEM] Log stream closed unexpectedly. Browser will retry...");
        }
    };
  }

  // --- RESUME SCAN LOGIC ---
  async function checkActiveScan() {
    try {
        const res = await fetch(`${API_BASE}/check_active_scan`);
        const data = await res.json();

        if (data.status === "active") {
            isScanning = true;
            currentScanId = data.scan_id;
            currentQueueId = data.queue_id;
            
            els.targetInput.value = data.target;
            // Restore native select values
            setSelectedOption('profileSelect', data.profile);
            setSelectedOption('aggressionSelect', data.aggression);

            toggleButtons(true); // Disable start button, enable spinner
            updateStatus("Resuming Scan", "busy");
            // No progress here, as we don't know it from backend yet
            // updateProgress(data.progress_percent, data.current_phase); 

            appendLog(`[SYSTEM] Resuming active scan for ${data.target} (ID: ${data.scan_id}, Profile: ${data.profile}, Aggression: ${data.aggression})...`);
            initLogStream(data.queue_id);
            fetchReportData(); // Fetch existing report data to update tables if partial report exists
        } else {
            // No active scan — restore last report and load history modal data in parallel
            toggleButtons(false);
            fetchHistory();        // populates the modal
            fetchLatestReport();  // populates the main dashboard tables/metrics/telemetry
        }
    } catch (e) {
        console.error("Error checking active scan:", e);
        appendLog(`[frontend] Error checking for active scan: ${e.message}`);
        toggleButtons(false); // Ensure buttons are functional even on error
        fetchHistory(); // Attempt to load history anyway
    }
  }


  async function fetchReportData() {
    // Prioritize currentQueueId's target or use els.targetInput
    const target = els.targetInput.value.trim();
    if (!target && !currentScanId) return;

    try {
      const url = target ? `${API_BASE}/report_files?target=${encodeURIComponent(target)}` : `${API_BASE}/report_files?scan_id=${currentScanId}`;
      const checkRes = await fetch(url);
      const checkData = await checkRes.json();

      if (checkData.status === "success") {
        toggleButtons(false); // Enable report buttons if reports exist

        const jsonUrl = target ? `${API_BASE}/get_json_report?target=${encodeURIComponent(target)}` : `${API_BASE}/get_json_report?scan_id=${currentScanId}`;
        const jsonRes = await fetch(jsonUrl);
        const report = await jsonRes.json();
        renderReport(report);
      } else if (checkData.status === "pending") {
          // Reports not ready yet — only lock the start button if a scan is actively running
          if (isScanning) {
            toggleButtons(true);
          }
      }
    } catch (e) {
      appendLog(`[ERROR] Failed to load report: ${e.message}`);
    }
  }

  /**
   * Fetches the latest saved report without requiring a target in the input.
   * Called on page load when no scan is active to restore the last session's data.
   */
  async function fetchLatestReport() {
    try {
      // No target param → backend falls back to the newest file in the user's reports dir
      const jsonRes = await fetch(`${API_BASE}/get_json_report`);
      if (!jsonRes.ok) return; // 404 = no previous report, silently stay on empty state
      const report = await jsonRes.json();
      if (report.status === 'error') return;

      // Restore target input so subsequent actions (PDF download, AI analysis) work
      if (report.target && els.targetInput) {
        els.targetInput.value = report.target;
        if (document.getElementById('targetDisplay')) {
          document.getElementById('targetDisplay').textContent = report.target;
        }
      }

      // Mark currentScanId so report buttons are unlocked
      currentScanId = 'latest';

      updateStatus("Last Scan Loaded", "success");
      toggleButtons(false); // enable PDF / AI buttons
      renderReport(report);
    } catch (e) {
      // Silently ignore — no previous report is perfectly fine on first run
      console.warn('[killchain] No previous report to restore:', e.message);
    }
  }

  // --- REPORT RENDERING (MATCHING ZAP SCANNER STYLE) ---
  function renderReport(data) {
    // 1. Metrics
    // Use data.all_findings for metrics now
    const allFindings = data.all_findings || [];
    const crit = allFindings.filter((v) => v.severity && v.severity.toLowerCase() === "critical").length;
    const high = allFindings.filter((v) => v.severity && v.severity.toLowerCase() === "high").length;
    
    // Subdomains and Ports from specific sections
    const subs = data.recon && data.recon.subdomains ? data.recon.subdomains.length : 0;
    const openPorts = data.network && data.network.nmap_scan && data.network.nmap_scan.ports ? data.network.nmap_scan.ports.length : 0;

    els.metricCritical.textContent = crit;
    els.metricHigh.textContent = high;
    els.metricSubdomains.textContent = subs;
    els.metricPorts.textContent = openPorts;

    // 2. Vulnerabilities Table (Using data.all_findings)
    els.vulnTableBody.innerHTML = "";
    if (allFindings.length === 0) {
      els.vulnTableBody.innerHTML = '<div style="text-align:center; padding: 4rem; color: var(--neo-text-muted); font-family: var(--font-mono);">No vulnerabilities found.</div>';
    } else {
      allFindings.forEach((v) => {
        const sev = (v.severity || v.risk || "info").toLowerCase(); // Normalize severity
        let riskClass = 'risk-low';
        let score = "0.0";
        let color = '#3b82f6'; // low / info color by default
        
        if (sev === 'critical') { riskClass = 'risk-critical'; score = "9.5"; color = '#ef4444'; }
        else if (sev === 'high') { riskClass = 'risk-high'; score = "7.5"; color = '#f97316'; }
        else if (sev === 'medium') { riskClass = 'risk-medium'; score = "5.5"; color = '#eab308'; }
        else if (sev === 'info' || sev === 'safe') { riskClass = 'risk-safe'; score = "0.0"; color = '#10b981'; }

        const title = v.type || v.name || "Unknown Vulnerability";
        const evidence = v.evidence || v.url || v.location || "N/A";
        const desc = v.description || "No description provided.";
        const solution = v.solution || "No remediation provided.";

        const cardHtml = `
            <div class="finding-card ${riskClass}" style="--accent-gradient: ${color};">
              <div class="finding-header" onclick="this.parentElement.classList.toggle('expanded')">
                <div class="risk-indicator ${riskClass}" style="color: ${color};">
                  <div class="risk-dot" style="background: ${color};"></div>
                  <span>${sev.toUpperCase()}</span>
                </div>
                <div class="finding-title" title="${title}">${title}</div>
                <div class="score-container">
                  <span class="score-label">Risk</span>
                  <span class="score-val">${score}</span>
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
                    <div class="detail-text">${solution}</div>
                  </div>
                </div>
              </div>
            </div>`;
        els.vulnTableBody.insertAdjacentHTML("beforeend", cardHtml);
      });
    }

    // 3. Network Table
    els.networkTableBody.innerHTML = "";
    if (data.network && data.network.nmap_scan && data.network.nmap_scan.ports && data.network.nmap_scan.ports.length > 0) {
      data.network.nmap_scan.ports.forEach((p) => {
        const riskClass = "risk-safe";
        const scoreWidth = "20%"; // Default mock representation for ports

        const cardHtml = `
            <div class="discovery-card animate-card ${riskClass}">
                <div class="card-header">
                    <div class="port-badge">
                        <span class="port-num">${p.port}</span>
                        <span class="protocol-label">${p.protocol}</span>
                    </div>
                </div>
                <div class="service-main">
                    <div class="service-title" title="${p.service}">${p.service}</div>
                    <div class="service-ver">${p.version || p.product || "Unknown Version"}</div>
                </div>
                <div class="risk-section">
                    <div class="risk-header">
                        <span>Risk Profile</span>
                        <span>LOW</span>
                    </div>
                    <div class="risk-score-bar">
                        <div class="risk-score-fill" style="width: ${scoreWidth}"></div>
                    </div>
                </div>
                <div class="analysis-footer">
                    Active listener detected.
                </div>
            </div>`;
        els.networkTableBody.insertAdjacentHTML("beforeend", cardHtml);
      });
    } else {
      els.networkTableBody.innerHTML = '<div style="grid-column: 1 / -1; text-align:center; padding: 4rem; color: var(--neo-text-muted); font-family: var(--font-mono);">No open ports found.</div>';
    }

    // 4. Recon Table
    els.reconTableBody.innerHTML = "";
    const reconDataItems = [];
    if (data.recon && data.recon.subdomains && data.recon.subdomains.length > 0) {
      data.recon.subdomains.forEach(sub => reconDataItems.push({type: "SUBDOMAIN", item: sub, details: "Discovered via OSINT"}));
    }
    if (data.recon && data.recon.resolved_hosts && data.recon.resolved_hosts.length > 0) {
        data.recon.resolved_hosts.forEach(host => reconDataItems.push({type: "HOST IP", item: host.domain, details: host.ip}));
    }
    // Add crawled URLs and API endpoints from web_audit if available
    if (data.web_audit && data.web_audit.crawled_urls && data.web_audit.crawled_urls.length > 0) {
        data.web_audit.crawled_urls.slice(0, 10).forEach(url => reconDataItems.push({type: "CRAWLED URL", item: url, details: "Entry Point"}));
    }
    if (data.web_audit && data.web_audit.api_endpoints && data.web_audit.api_endpoints.length > 0) {
        data.web_audit.api_endpoints.slice(0, 5).forEach(endpoint => reconDataItems.push({type: "API ENDPOINT", item: endpoint, details: "JS Discovered"}));
    }


    if (reconDataItems.length > 0) {
      reconDataItems.forEach((item) => {
        const titleText = item.item.length > 40 ? item.item.substring(0, 37) + '...' : item.item;
        const iconMap = {
           "SUBDOMAIN": "dns",
           "HOST IP": "router",
           "CRAWLED URL": "link",
           "API ENDPOINT": "api"
        };
        const icon = iconMap[item.type] || "radar";
        
        const cardHtml = `
            <div class="discovery-card animate-card risk-safe">
                <div class="card-header">
                    <div style="font-size: 0.7rem; color: var(--neo-blue); font-weight: 800; display: flex; align-items: center; gap: 8px;">
                      <span class="material-symbols-outlined" style="font-size: 1.2rem;">${icon}</span>
                      ${item.type}
                    </div>
                </div>
                <div class="service-main" style="margin-top:0.5rem;">
                    <div class="service-title" style="text-transform:none;word-break:break-all;" title="${item.item}">${titleText}</div>
                    <div class="service-ver">${item.details || "Discovered asset"}</div>
                </div>
                <div class="analysis-footer" style="margin-top:auto;">
                    Passive Reconnaissance Data
                </div>
            </div>`;
        els.reconTableBody.insertAdjacentHTML("beforeend", cardHtml);
      });
    } else {
      els.reconTableBody.innerHTML = '<div style="grid-column: 1 / -1; text-align:center; padding: 4rem; color: var(--neo-text-muted); font-family: var(--font-mono);">No recon data found.</div>';
    }


    // 5. Tech Stack (Updated to render tech as structured objects)
    els.techStackContainer.innerHTML = "";
    if (data.tech && data.tech.technologies) {
        let techHtml = '<div style="margin-bottom: 1rem;">';
        for (const category in data.tech.technologies) {
            techHtml += `<h4 style="color: var(--neo-text-main); font-size: 0.9rem; margin-bottom: 0.5rem;">${category.toUpperCase()}</h4>`;
            data.tech.technologies[category].forEach(tech => {
                techHtml += `<span class="tech-tag">${tech}</span>`;
            });
        }
        techHtml += '</div>';

        if (data.tech.versions) {
            techHtml += '<div style="margin-top: 1rem;">';
            techHtml += '<h4 style="color: var(--neo-text-main); font-size: 0.9rem; margin-bottom: 0.5rem;">VERSIONS</h4>';
            for (const software in data.tech.versions) {
                techHtml += `<span class="tech-tag">${software} v${data.tech.versions[software]}</span>`;
            }
            techHtml += '</div>';
        }
        els.techStackContainer.innerHTML = techHtml;

        // Add some basic styling for tech-tag, match Neo-Tech colors
        const styleTag = document.createElement('style');
        styleTag.innerHTML = `
            .tech-tag {
                display: inline-flex;
                align-items: center;
                padding: 4px 10px;
                margin-right: 6px;
                margin-bottom: 6px;
                border-radius: 4px;
                background: var(--neo-input);
                border: 1px solid var(--neo-border);
                color: var(--neo-text-muted);
                font-size: 0.65rem;
                font-weight: 700;
                letter-spacing: 0.05em;
                text-transform: uppercase;
            }
        `;
        document.head.appendChild(styleTag);

    } else {
      els.techStackContainer.innerHTML = '<span style="color: #a1a1aa;">No technologies detected.</span>';
    }


    // 6. JSON Raw Data
    if (data) {
      els.jsonOutput.textContent = JSON.stringify(data, null, 2);
    }
  }

  // --- BUTTON LISTENERS ---
  if (els.startBtn) els.startBtn.addEventListener("click", startScan);

  if (els.refreshReportBtn) {
    els.refreshReportBtn.addEventListener("click", () => {
      // If there's a target in the input or an active scan, use normal fetchReportData.
      // Otherwise fall back to fetchLatestReport so the button always does something useful.
      if (els.targetInput.value.trim() || currentScanId || isScanning) {
        fetchReportData();
      } else {
        fetchLatestReport();
      }
    });
  }
  
  if (els.clearLogBtn) {
    els.clearLogBtn.addEventListener('click', () => {
        els.logOutput.innerHTML = '';
    });
  }

  if (els.copyJsonBtn) {
    els.copyJsonBtn.addEventListener("click", () => {
      const text = els.jsonOutput.textContent;
      if (!text || text.startsWith("//")) return;

      navigator.clipboard.writeText(text).then(() => {
          const icon = els.copyJsonBtn.querySelector("span");
          const originalIcon = icon.textContent;
          icon.textContent = "check";
          icon.style.color = "#10b981";
          setTimeout(() => {
            icon.textContent = originalIcon;
            icon.style.color = "";
          }, 2000);
        });
    });
  }

  if (els.downloadPdfBtn) {
    els.downloadPdfBtn.addEventListener("click", () => {
      const target = els.targetInput.value.trim();
      // Use currentScanId if target input is empty, assuming we resumed a scan
      const downloadIdentifier = target || currentScanId;

      if (!downloadIdentifier) {
        appendLog("[frontend] Error: Cannot download PDF. No target or scan ID available.");
        return;
      }
      const url = `${API_BASE}/download_pdf?target=${encodeURIComponent(downloadIdentifier)}`;
      window.location.href = url;
    });
  }

  // Toggle AI Dropdown
  if (els.aiAnalysisDropdown) {
    els.aiAnalysisDropdown.addEventListener("click", (e) => {
      if (els.aiAnalysisDropdown.disabled) return;
      e.stopPropagation();
      els.aiAnalysisOptions.classList.toggle("hidden");
    });
  }

  // Global Click listener for dropdowns
  document.addEventListener("click", (docEvent) => {
    if (els.aiAnalysisOptions && !els.aiAnalysisOptions.classList.contains("hidden")) {
      if (!els.aiAnalysisOptions.contains(docEvent.target) && docEvent.target !== els.aiAnalysisDropdown) {
        els.aiAnalysisOptions.classList.add("hidden");
      }
    }
  });

  // AI Option Selection
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

  // --- TAB LOGIC ---
  window.switchTab = (tabName) => {
    const tabs = ["vulns", "recon", "network", "tech"];
    tabs.forEach((t) => {
      const contentEl = document.getElementById(`content${t.charAt(0).toUpperCase() + t.slice(1)}`);
      if (contentEl) contentEl.classList.add("hidden");
      const pillEl = document.getElementById(`tab${t.charAt(0).toUpperCase() + t.slice(1)}`);
      if (pillEl) pillEl.classList.remove("active");
    });
    const targetContent = document.getElementById(`content${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`);
    if (targetContent) targetContent.classList.remove("hidden");
    const targetPill = document.getElementById(`tab${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`);
    if (targetPill) targetPill.classList.add("active");
  };

  // --- AI ANALYSIS HANDLER ---
  async function analyzeReport(llmMode) {
    const target = els.targetInput.value.trim();
    if (!target && !currentScanId) return;

    els.aiOverlay.classList.remove("hidden");
    els.aiText.textContent = llmMode.startsWith("gemini") ? "CONTACTING GEMINI..." : "LOADING LOCAL LLM...";

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
        els.aiText.textContent = "SYNTHESIZING REPORT...";
        const chatRes = await fetch(
          `${CHATBOT_REDIRECT_URL}/scanner_analysis`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "X-CSRFToken": csrfToken,
            },
            body: JSON.stringify({
              llm_mode: llmMode,
              scanner_type: "killchain",
              target: data.target,
              force_new_session: true // [NEW] Force a fresh chat
            }),
          }
        );
        const chatData = await chatRes.json();

        if (chatRes.ok && chatData.status === "success") {
          els.aiText.textContent = "REDIRECTING...";
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
      els.aiOverlay.classList.add("hidden");
    }
  }

  // --- HISTORY LOGIC ---

  async function fetchHistory() {
    if (!els.historyTableBody) return;
    els.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-text-muted);">LOADING HISTORY...</td></tr>';
    
    try {
      const res = await fetch(`${API_BASE}/report_history`);
      const data = await res.json();
      
      if (data.status === 'success' && data.history) {
        if (data.history.length === 0) {
          els.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-text-muted);">NO PRIOR SCANS FOUND</td></tr>';
          return;
        }
        
        els.historyTableBody.innerHTML = '';
        data.history.forEach(item => {
          const row = document.createElement('tr');
          // Extract target from filename (scanner_target.pdf)
          let target = item.filename.split('_').slice(1).join('_').replace('.pdf', '');
          if (!target) target = 'Previous Scan';
          
          row.innerHTML = `
            <td>${item.created_at}</td>
            <td class="font-mono text-blue-400">${target}</td>
            <td style="text-align: right;">
              <a href="${API_BASE}/download_pdf?filename=${item.filename}" class="btn-dash btn-secondary" style="display: inline-flex; height: 32px; padding: 0 10px;">
                <span class="material-symbols-outlined" style="font-size: 1.1rem;">download</span>
              </a>
            </td>
          `;
          els.historyTableBody.appendChild(row);
        });
      } else {
        els.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-red);">FAILED TO LOAD HISTORY</td></tr>';
      }
    } catch (e) {
      console.error('History fetch failed:', e);
      els.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-red);">ERROR LOADING HISTORY</td></tr>';
    }
  }

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
  checkActiveScan(); // Call checkActiveScan on page load
});
