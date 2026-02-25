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
    
    // Custom dropdowns for Profiles
    customProfileSelectTrigger: document.querySelector('#customProfileSelect .custom-select-trigger .selected-text'),
    customAggressionSelectTrigger: document.querySelector('#customAggressionSelect .custom-select-trigger .selected-text'),
  };

  // --- LOGGING LOGIC ---
  function appendLog(msg) {
    if (!msg) return;

    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });

    let cleanedMessage = msg.replace(/^\[?\d{1,2}:\d{2}:\d{2}\]?\s*/, '').trim();
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
    if (scanActive) {
      els.startBtn.querySelector(".spinner").classList.remove("hidden");
    } else {
      els.startBtn.querySelector(".spinner").classList.add("hidden");
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

  function setSelectedOption(wrapperId, hiddenSelectId, valueToSelect) {
    const wrapper = document.getElementById(wrapperId);
    const hiddenSelect = document.getElementById(hiddenSelectId);
    if (!wrapper || !hiddenSelect) return;

    const options = wrapper.querySelectorAll('.custom-option');
    const selectedTextSpan = wrapper.querySelector('.selected-text');

    let found = false;
    options.forEach(option => {
      if (option.getAttribute('data-value') === valueToSelect) {
        option.classList.add('selected');
        selectedTextSpan.textContent = option.textContent;
        hiddenSelect.value = valueToSelect;
        found = true;
      } else {
        option.classList.remove('selected');
      }
    });

    if (!found && options.length > 0) {
      options[0].classList.add('selected');
      selectedTextSpan.textContent = options[0].textContent;
      hiddenSelect.value = options[0].getAttribute('data-value');
    }
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

    // Only establish EventSource if queueId is valid
    if (!queueId) {
        appendLog("[frontend] Error: Invalid queue ID for log stream.");
        return;
    }
    
    eventSource = new EventSource(`${API_BASE}/log_stream?queue_id=${queueId}`);

    eventSource.onmessage = (e) => {
      const msg = e.data;
      if (msg.startsWith(":")) return; 
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
      appendLog("[SYSTEM] Scan Finished. Fetching report...");
      eventSource.close();
      isScanning = false;
      toggleButtons(false); // Enable report buttons, disable start button
      updateStatus("Complete", "success");
      updateProgress(100, "Done");
      fetchReportData();
    });

    eventSource.addEventListener("scan_failed", (e) => {
      const data = JSON.parse(e.data);
      appendLog(`[ERROR] Scan Aborted: ${data.message}`);
      eventSource.close();
      isScanning = false;
      toggleButtons(false); // Enable start button, disable report buttons
      updateStatus("Error", "error");
    });
    
    eventSource.onerror = (err) => {
        console.error("EventSource failed:", err);
        // Attempt to reconnect after a delay, but not if scan is complete/failed
        if (isScanning && eventSource.readyState === EventSource.CONNECTING) { // Only try to reconnect if connecting
            appendLog("[SYSTEM] Log stream disconnected. Attempting to reconnect...");
            setTimeout(() => initLogStream(queueId), 3000); // Try reconnecting after 3 seconds
        } else if (eventSource.readyState === EventSource.CLOSED) {
            appendLog("[SYSTEM] Log stream closed.");
        } else {
            appendLog("[SYSTEM] Log stream error or connection closed.");
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
            // Set selected options for custom dropdowns
            setSelectedOption('customProfileSelect', 'profileSelect', data.profile);
            setSelectedOption('customAggressionSelect', 'aggressionSelect', data.aggression);

            toggleButtons(true); // Disable start button, enable spinner
            updateStatus("Resuming Scan", "busy");
            // No progress here, as we don't know it from backend yet
            // updateProgress(data.progress_percent, data.current_phase); 

            appendLog(`[SYSTEM] Resuming active scan for ${data.target} (ID: ${data.scan_id}, Profile: ${data.profile}, Aggression: ${data.aggression})...`);
            initLogStream(data.queue_id);
            fetchReportData(); // Fetch existing report data to update tables if partial report exists
        } else {
            // No active scan, load previous report history
            toggleButtons(false); // Ensure start button is enabled, report buttons disabled
            loadHistory();
        }
    } catch (e) {
        console.error("Error checking active scan:", e);
        appendLog(`[frontend] Error checking for active scan: ${e.message}`);
        toggleButtons(false); // Ensure buttons are functional even on error
        loadHistory(); // Attempt to load history anyway
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
          // Reports not ready yet, keep reports/AI buttons disabled but scan can still be running
          toggleButtons(true); // Keep start button disabled if scan is still active
      }
    } catch (e) {
      appendLog(`[ERROR] Failed to load report: ${e.message}`);
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
      els.vulnTableBody.innerHTML = '<tr><td colspan="3" style="text-align:center; padding: 3rem; color: #555;">No vulnerabilities found.</td></tr>';
    } else {
      allFindings.forEach((v) => {
        const sev = (v.severity || v.risk || "info").toLowerCase(); // Normalize severity
        let color = '#3b82f6'; // Default Blue
        if (sev === 'critical') color = '#ef4444'; // Red
        if (sev === 'high') color = '#f97316'; // Orange
        if (sev === 'medium') color = '#eab308'; // Yellow

        const row = `
            <tr>
                <td style="color: ${color}; font-weight: 700;">${(v.severity || v.risk || "INFO").toUpperCase()}</td>
                <td style="font-weight: 600;">${v.type || v.name || "Unknown"}</td>
                <td style="font-family: monospace; font-size: 0.8rem; color: #a1a1aa; word-break: break-all;">${v.evidence || v.url || v.location || "-"}</td>
            </tr>`;
        els.vulnTableBody.insertAdjacentHTML("beforeend", row);
      });
    }

    // 3. Network Table
    els.networkTableBody.innerHTML = "";
    if (data.network && data.network.nmap_scan && data.network.nmap_scan.ports && data.network.nmap_scan.ports.length > 0) {
      data.network.nmap_scan.ports.forEach((p) => {
        const row = `
            <tr>
                <td style="color: #3b82f6; font-family: monospace; font-weight: 700;">${p.port}/${p.protocol}</td>
                <td style="font-weight: 600;">${p.service}</td>
                <td style="color: #a1a1aa; font-family: monospace;">${p.version || ""} ${p.product || ""}</td>
            </tr>`;
        els.networkTableBody.insertAdjacentHTML("beforeend", row);
      });
    } else {
      els.networkTableBody.innerHTML = '<tr><td colspan="3" style="text-align:center; padding: 3rem; color: #555;">No open ports found.</td></tr>';
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
        const row = `
            <tr>
                <td style="color: #a1a1aa; font-size: 0.75rem; text-transform: uppercase; font-weight: 700;">${item.type}</td>
                <td style="color: #10b981; font-family: monospace;">${item.item}</td>
                <td style="color: #a1a1aa;">${item.details || "-"}</td>
            </tr>`;
        els.reconTableBody.insertAdjacentHTML("beforeend", row);
      });
    } else {
      els.reconTableBody.innerHTML = '<tr><td colspan="3" style="text-align:center; padding: 3rem; color: #555;">No recon data found.</td></tr>';
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
      if (!currentScanId && !isScanning) { // Allow refresh only if scan_id exists or scan is running
        appendLog("No active scan or previous scan to refresh report from.");
        return;
      }
      fetchReportData();
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
    els.aiText.textContent = llmMode === "gemini" ? "CONTACTING GEMINI..." : "LOADING LOCAL LLM...";

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

  // --- INIT ---
  updateStatus("Ready");
  checkActiveScan(); // Call checkActiveScan on page load
});
