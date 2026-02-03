document.addEventListener("DOMContentLoaded", () => {
  // --- STATE ---
  const API_BASE = "/killchain";
  const CHATBOT_REDIRECT_URL = "/chatbot";
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content");

  let currentScanId = null;
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
  };

  // --- UI HELPERS ---

  function updateStatus(text, type = "idle") {
    let color = document.body.classList.contains("light-mode") ? "#64748b" : "#52525b"; // Default Slate/Gray
    if (type === "busy") color = "#eab308";
    if (type === "success") color = "#10b981";
    if (type === "error") color = "#ef4444";

    if (els.statusText)
      els.statusText.innerHTML = `<span style="color: ${color}; font-weight: bold;">${text.toUpperCase()}</span>`;
  }

  function updateProgress(percent, phase) {
    if (els.progressBar) els.progressBar.style.width = `${percent}%`;
    if (els.progressPercent) els.progressPercent.textContent = `${percent}%`;

    if (phase && els.phaseText) {
      els.phaseText.textContent = `PHASE: ${phase.toUpperCase()}`;
    }
  }

  function toggleButtons(enabled) {
    const opacity = enabled ? "1" : "0.7";
    const cursor = enabled ? "pointer" : "not-allowed";

    [els.aiAnalysisDropdown, els.downloadPdfBtn, els.copyJsonBtn].forEach(
      (btn) => {
        if (btn) {
          btn.disabled = !enabled;
          btn.style.opacity = opacity;
          btn.style.cursor = cursor;
        }
      }
    );
  }

  // --- LOGGING LOGIC ---
  function appendLog(msg) {
    if (!msg) return;

    // [FIX] Strip timestamps from the incoming message
    // Matches "[15:19:56] " or "15:19:56 " at the start of the line
    msg = msg.replace(/^\[?\d{1,2}:\d{2}:\d{2}\]?\s*/, '').trim();

    // [FIX] If the line was *only* a timestamp, it's now empty, so we skip it
    if (!msg) return;

    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });

    const isLight = document.body.classList.contains("light-mode");
    let style = isLight ? "color: #334155;" : "color: #d4d4d8;"; // Slate-700 / Zinc-300
    
    if (msg.includes("[x]") || msg.includes("CRITICAL") || msg.includes("ERROR") || msg.includes("Failed")) {
      style = "color: #ef4444;";
    } else if (msg.includes("[+]") || msg.includes("SUCCESS") || msg.includes("Complete")) {
      style = "color: #10b981;";
    } else if (msg.includes("[!]") || msg.includes("WARNING") || msg.includes("[WARN]")) {
      style = "color: #f97316;";
    } else if (msg.includes("[*]") || msg.includes("PHASE")) {
      style = "color: #3b82f6;";
    } else if (msg.includes("[>]")) {
      style = isLight ? "color: #64748b;" : "color: #a1a1aa;";
    }

    const timeColor = isLight ? "#64748b" : "#555";

    const line = document.createElement("div");
    line.className = "log-line";
    line.innerHTML = `
        <div style="color: ${timeColor}; width: 70px; flex-shrink: 0;">${timeStr}</div>
        <div class="log-content" style="${style} flex: 1; white-space: pre-wrap;">${msg}</div>
    `;
    els.logOutput.appendChild(line);
    els.logOutput.scrollTop = els.logOutput.scrollHeight;
  }

  // --- HISTORY LOADING ---
  async function loadHistory() {
    if (isScanning) return;

    try {
      const res = await fetch(`${API_BASE}/history`);
      const data = await res.json();

      if (data.status === "success" && data.scans && data.scans.length > 0) {
        const lastScan = data.scans[0];
        currentScanId = lastScan.scan_id;

        appendLog(`[SYSTEM] Restoring last scan on ${lastScan.target} (${lastScan.date})`);
        if (els.targetInput) els.targetInput.value = lastScan.target;
        
        fetchReportData();
        updateStatus("History Loaded", "success");
        updateProgress(100, "Scan Complete");
      }
    } catch (e) {
      console.error("Failed to load history", e);
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
    els.startBtn.disabled = true;
    els.startBtn.querySelector(".spinner").classList.remove("hidden");
    toggleButtons(false);

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
        initLogStream(data.queue_id);
      } else {
        throw new Error(data.message);
      }
    } catch (e) {
      appendLog(`[frontend] ERROR: Failed to start scan: ${e.message}`);
      isScanning = false;
      els.startBtn.disabled = false;
      els.startBtn.querySelector(".spinner").classList.add("hidden");
      updateStatus("Failed", "error");
    }
  }

  function initLogStream(queueId) {
    if (eventSource) eventSource.close();
    eventSource = new EventSource(`${API_BASE}/log_stream?queue_id=${queueId}`);

    eventSource.onmessage = (e) => {
      const msg = e.data;
      if (msg.startsWith(":")) return; 
      appendLog(msg);
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
      els.startBtn.disabled = false;
      els.startBtn.querySelector(".spinner").classList.add("hidden");
      updateStatus("Complete", "success");
      updateProgress(100, "Done");
      fetchReportData();
    });

    eventSource.addEventListener("scan_failed", (e) => {
      const data = JSON.parse(e.data);
      appendLog(`[ERROR] Scan Aborted: ${data.message}`);
      eventSource.close();
      isScanning = false;
      els.startBtn.disabled = false;
      els.startBtn.querySelector(".spinner").classList.add("hidden");
      updateStatus("Error", "error");
    });
  }

  async function fetchReportData() {
    if (!currentScanId) return;

    try {
      const checkRes = await fetch(
        `${API_BASE}/report_files?scan_id=${currentScanId}`
      );
      const checkData = await checkRes.json();

      if (checkData.status === "success") {
        toggleButtons(true);

        const jsonRes = await fetch(
          `${API_BASE}/get_json_report?scan_id=${currentScanId}`
        );
        const report = await jsonRes.json();
        renderReport(report);
      }
    } catch (e) {
      appendLog(`[ERROR] Failed to load report: ${e.message}`);
    }
  }

  // --- REPORT RENDERING (MATCHING ZAP SCANNER STYLE) ---
  function renderReport(data) {
    // 1. Metrics
    const vulns = data.vulns || [];
    const crit = vulns.filter((v) => v.severity && v.severity.toLowerCase() === "critical").length;
    const high = vulns.filter((v) => v.severity && v.severity.toLowerCase() === "high").length;
    const subs = data.recon && data.recon.subdomains ? data.recon.subdomains.length : 0;
    const ports = data.network && data.network.ports ? data.network.ports.length : 0;

    els.metricCritical.textContent = crit;
    els.metricHigh.textContent = high;
    els.metricSubdomains.textContent = subs;
    els.metricPorts.textContent = ports;

    // 2. Vulnerabilities Table (Replaces Badge with Colored Text)
    els.vulnTableBody.innerHTML = "";
    if (vulns.length === 0) {
      els.vulnTableBody.innerHTML = '<tr><td colspan="3" style="text-align:center; padding: 3rem; color: #555;">No vulnerabilities found.</td></tr>';
    } else {
      vulns.forEach((v) => {
        const sev = v.severity ? v.severity.toLowerCase() : "info";
        let color = '#3b82f6'; // Default Blue
        if (sev === 'critical') color = '#ef4444'; // Red
        if (sev === 'high') color = '#f97316'; // Orange
        if (sev === 'medium') color = '#eab308'; // Yellow

        const row = `
            <tr>
                <td style="color: ${color}; font-weight: 700;">${v.severity ? v.severity.toUpperCase() : "INFO"}</td>
                <td style="font-weight: 600;">${v.type}</td>
                <td style="font-family: monospace; font-size: 0.8rem; color: #a1a1aa; word-break: break-all;">${v.evidence || v.url || "-"}</td>
            </tr>`;
        els.vulnTableBody.insertAdjacentHTML("beforeend", row);
      });
    }

    // 3. Network Table
    els.networkTableBody.innerHTML = "";
    if (data.network && data.network.ports && data.network.ports.length > 0) {
      data.network.ports.forEach((p) => {
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
    if (data.recon && data.recon.subdomains && data.recon.subdomains.length > 0) {
      data.recon.subdomains.forEach((sub) => {
        const row = `
            <tr>
                <td style="color: #a1a1aa; font-size: 0.75rem; text-transform: uppercase; font-weight: 700;">SUBDOMAIN</td>
                <td style="color: #10b981; font-family: monospace;">${sub}</td>
                <td style="color: #a1a1aa;">-</td>
            </tr>`;
        els.reconTableBody.insertAdjacentHTML("beforeend", row);
      });
    } else {
      els.reconTableBody.innerHTML = '<tr><td colspan="3" style="text-align:center; padding: 3rem; color: #555;">No recon data found.</td></tr>';
    }

    // 5. Tech Stack (Keeps simple pills, but consistent colors)
    els.techStackContainer.innerHTML = "";
    if (data.tech && data.tech.technologies && data.tech.technologies.length > 0) {
      data.tech.technologies.forEach((t) => {
        const tag = document.createElement("span");
        // Styling manually to match Neo-Tech
        tag.style.display = "inline-flex";
        tag.style.alignItems = "center";
        tag.style.padding = "4px 10px";
        tag.style.marginRight = "6px";
        tag.style.marginBottom = "6px";
        tag.style.borderRadius = "4px";
        tag.style.background = "rgba(16, 185, 129, 0.1)";
        tag.style.border = "1px solid rgba(16, 185, 129, 0.3)";
        tag.style.color = "#10b981";
        tag.style.fontSize = "0.65rem";
        tag.style.fontWeight = "700";
        tag.style.letterSpacing = "0.05em";
        tag.style.textTransform = "uppercase";
        tag.textContent = t;
        els.techStackContainer.appendChild(tag);
      });
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
      if (!currentScanId) {
        appendLog("No active scan to refresh.");
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
      if (!currentScanId) return;
      window.location.href = `${API_BASE}/download_pdf?scan_id=${currentScanId}`;
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
    if (!currentScanId) return;

    els.aiOverlay.classList.remove("hidden");
    els.aiText.textContent = llmMode === "gemini" ? "CONTACTING GEMINI..." : "LOADING LOCAL LLM...";

    try {
      const res = await fetch(`${API_BASE}/trigger_ai_analysis`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
        },
        body: JSON.stringify({ scan_id: currentScanId }),
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
              scan_id: currentScanId,
            }),
          }
        );
        const chatData = await chatRes.json();

        if (chatRes.ok && chatData.status === "success") {
          els.aiText.textContent = "REDIRECTING...";
          setTimeout(() => {
            window.location.href = `${CHATBOT_REDIRECT_URL}?mode=${chatData.llm_mode}&summary=${encodeURIComponent(chatData.summary)}`;
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
  loadHistory();
});