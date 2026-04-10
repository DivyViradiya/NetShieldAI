document.addEventListener("DOMContentLoaded", function () {
  let snifferNetwork = null;
  
  // Helper function to safely open URLs
  const openTargetSafe = (rawUrl) => {
    if (!rawUrl) return;
    let finalUrl = rawUrl;
    if (!finalUrl.startsWith("http")) {
        finalUrl = "https://" + finalUrl;
    }
    const link = document.createElement("a");
    link.href = finalUrl;
    link.target = "_blank";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // --- 0. GLOBAL HEALTH DIAL ---
  function updateGlobalHealth() {
    if (typeof apiEndpoints !== 'undefined' && apiEndpoints.globalHealth) {
      fetch(apiEndpoints.globalHealth)
        .then(r => r.json())
        .then(data => {
            const valEl = document.getElementById("global-health-val");
            const dialEl = document.getElementById("global-health-dial");
            const statusEl = document.getElementById("health-status-text");

            if (valEl) valEl.textContent = Math.round(data.health_score || 0);
            if (statusEl) {
                statusEl.textContent = data.status || "UNKNOWN";
                statusEl.style.color = data.status === "CRITICAL" ? "var(--neo-red)" : (data.status === "WARNING" ? "var(--neo-amber)" : "var(--neo-green)");
            }
            if (dialEl) {
                dialEl.style.setProperty('--score', data.health_score || 0);
                dialEl.style.background = `conic-gradient(${data.status === "CRITICAL" ? "var(--neo-red)" : "var(--neo-green)"} calc(${data.health_score || 0} * 1%), var(--neo-border) 0)`;
            }
        })
        .catch(err => console.error("Health Dial Error:", err));
    }
  }

  // Initial call
  updateGlobalHealth();

  // --- 1. NETWORK (NMAP) ---
  function updateNmapStats() {
    if (typeof apiEndpoints !== 'undefined' && apiEndpoints.network) {
      fetch(apiEndpoints.network)
        .then((r) => r.json())
        .then((data) => {
          const isActive = ["Scanned", "Analyzed", "Completed", "Scanning"].includes(data.status);
          if (isActive) {
            const extIpEl = document.getElementById("tile-net-external-ip");
            if (extIpEl) extIpEl.textContent = data.external_ip || data.target || "SECURE_TUNNEL";
            
            const dnsEl = document.getElementById("tile-net-dns");
            if (dnsEl) dnsEl.textContent = data.dns_resolver || "AUTO";
            
            const hostEl = document.getElementById("tile-net-target-hostname");
            if (hostEl) hostEl.textContent = data.target_hostname || data.target || "--";
            
            const osEl = document.getElementById("tile-net-os");
            if (osEl) osEl.textContent = data.status === "Scanning" ? "ANALYZING OS..." : `OS Context: ${data.os_detected || "Unknown"}`;
            
            const argsEl = document.getElementById("tile-net-scan-args");
            if (argsEl) argsEl.textContent = data.scan_args || "nmap -sV -O -T4";

            const portListEl = document.getElementById("tile-net-port-list");
            if (portListEl) {
              portListEl.innerHTML = "";
              if (data.status === "Scanning") {
                  portListEl.innerHTML = '<tr><td colspan="3" style="padding: 2rem; text-align: center; color: var(--neo-blue); font-family:var(--font-mono); font-size:0.6rem;" class="status-alert">> NETWORK RECONNAISSANCE IN PROGRESS...</td></tr>';
              } else if (data.top_services && data.top_services.length > 0) {
                data.top_services.slice(0, 10).forEach((svc) => {
                  const port = svc.port || "??";
                  const desc = svc.service || svc.label || "Unknown";
                  const riskColor = svc.priority && svc.priority.includes('High') ? 'var(--neo-red)' : (svc.priority && svc.priority.includes('Medium') ? 'var(--neo-amber)' : 'var(--neo-blue)');
                  const priority = svc.priority ? svc.priority.split(' ')[0] : 'P3';
                  
                  portListEl.innerHTML += `
                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.02);">
                        <td style="padding: 6px 0; color: ${riskColor}; font-weight: 700;">${port}</td>
                        <td style="padding: 6px 0; color: #eee; opacity: 0.9;">${desc}</td>
                        <td style="padding: 6px 0; text-align: right; color: ${riskColor}; opacity: 0.8; font-size: 0.6rem;">[${priority}]</td>
                    </tr>
                  `;
                });
              } else {
                portListEl.innerHTML = '<tr><td colspan="3" style="padding: 1rem; text-align: center; opacity: 0.5;">No active ports detected.</td></tr>';
              }
            }
          } else {
            const extIpEl = document.getElementById("tile-net-external-ip");
            if (extIpEl) extIpEl.textContent = "IDLE";
            const portListEl = document.getElementById("tile-net-port-list");
            if (portListEl) portListEl.innerHTML = '<tr><td colspan="3" style="padding: 2rem; text-align: center; opacity: 0.3; font-size: 0.65rem;">NO NETWORK SCAN DATA</td></tr>';
          }
        })
        .catch(console.error);
    }
  }

  // --- 2. ZAP WEB SCAN ---
  function updateZapStats() {
    if (typeof apiEndpoints !== 'undefined' && apiEndpoints.zap) {
      fetch(apiEndpoints.zap)
        .then((r) => r.json())
        .then((data) => {
          const isActive = ["Scanned", "Analyzed", "Completed", "Scanning"].includes(data.status);
          if (isActive) {
            const urlCountEl = document.getElementById("tile-zap-url-count");
            if (urlCountEl) urlCountEl.textContent = data.crawled_urls_count || 0;
            
            const confEl = document.getElementById("tile-zap-confidence");
            if (confEl) confEl.textContent = data.status === "Scanning" ? "CRAWLING" : (data.confidence_score || "HIGH");
            
            const targetEl = document.getElementById("tile-zap-target");
            if (targetEl) targetEl.textContent = `TARGET: ${data.target || "Unknown"}`;

            const summary = data.alerts_summary || {};
            const highCount = summary.High || summary.high || 0;
            const medCount = summary.Medium || summary.medium || 0;
            const lowCount = summary.Low || summary.low || 0;
            const total = highCount + medCount + lowCount || 1;
            
            const barHigh = document.getElementById("zap-bar-high");
            if (barHigh) barHigh.style.width = `${(highCount / total) * 100}%`;
            const barMed = document.getElementById("zap-bar-med");
            if (barMed) barMed.style.width = `${(medCount / total) * 100}%`;
            const barLow = document.getElementById("zap-bar-low");
            if (barLow) barLow.style.width = `${(lowCount / total) * 100}%`;

            const listEl = document.getElementById("tile-zap-findings-list");
            if (listEl) {
              listEl.innerHTML = "";
              if (data.status === "Scanning") {
                  listEl.innerHTML = '<div style="opacity: 0.6; font-size: 0.65rem; padding: 1.5rem; text-align: center;" class="status-alert">> AUDITING WEB PERIMETER...</div>';
              } else if (data.top_risks && data.top_risks.length > 0) {
                data.top_risks.slice(0, 4).forEach(risk => {
                  const color = risk.risk === "High" ? "var(--neo-red)" : (risk.risk === "Medium" ? "var(--neo-amber)" : "var(--neo-blue)");
                  listEl.innerHTML += `
                    <div style="padding: 0.4rem; background: rgba(255,255,255,0.03); border-radius: 4px; border-left: 2px solid ${color}; margin-bottom: 4px;">
                       <div style="font-weight: 700; font-size: 0.65rem; color: #fff;">${risk.name}</div>
                       <div style="font-size: 0.55rem; color: #aaa; margin-top: 1px;">PRIORITY: ${risk.tctr_priority ? risk.tctr_priority.toFixed(2) : "1.00"}</div>
                    </div>
                  `;
                });
              } else {
                listEl.innerHTML = '<div style="opacity: 0.4; font-size: 0.65rem; padding: 1rem; text-align: center;">No critical web risks.</div>';
              }
            }
          } else {
            const listEl = document.getElementById("tile-zap-findings-list");
            if (listEl) listEl.innerHTML = '<div style="opacity: 0.3; font-size: 0.65rem; padding: 2rem; text-align: center;">NO WEB SCAN DATA</div>';
          }
        })
        .catch(console.error);
    }
  }

  // --- 3. TRAFFIC SNIFFER ---
  function updateSnifferStats() {
    if (typeof apiEndpoints !== 'undefined' && apiEndpoints.sniffer) {
      fetch(apiEndpoints.sniffer)
        .then((r) => r.json())
        .then((data) => {
          const isActive = ["Scanned", "Analyzed", "Completed", "Scanning"].includes(data.status); 
          if (isActive) {
            const rateEl = document.getElementById("tile-sniffer-rate");
            const rawRate = parseFloat(data.avg_rate_bps) || 0;
            if (rateEl) rateEl.innerHTML = `${rawRate.toFixed(2)} <span style="font-size: 0.7rem; font-weight: 400; color: var(--neo-text-muted); letter-spacing: 0;">KB/s</span>`;
            
            const totalEl = document.getElementById("tile-sniffer-total");
            const totalMB = data.total_bytes ? (data.total_bytes / 1024 / 1024).toFixed(2) : "0.00";
            if (totalEl) totalEl.textContent = `${totalMB} MB`;
            
            const durEl = document.getElementById("tile-sniffer-duration");
            if (durEl) durEl.textContent = data.duration || "--";
            
            const anonEl = document.getElementById("tile-sniffer-anomalies");
            if (anonEl) {
                const anomalies = data.security_anomalies || "None";
                anonEl.textContent = anomalies;
                const isAlert = (anomalies !== "None" && anomalies !== "No anomalies.");
                const isScanning = data.status === "Scanning";
                anonEl.className = (isAlert || isScanning) ? "status-alert" : "";
                if (isScanning && anomalies === "No anomalies.") anonEl.textContent = "ANALYZING LIVE TRAFFIC...";
            }

            const horizonList = document.getElementById("protocolHorizonList");
            if (horizonList && data.protocol_breakdown) {
                horizonList.innerHTML = "";
                const protos = data.protocol_breakdown;
                const totalPackets = Object.values(protos).reduce((a, b) => a + b, 0) || 1;
                
                Object.entries(protos)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 3)
                  .forEach(([name, count], idx) => {
                      const pct = Math.max(5, (count / totalPackets) * 100);
                      const opacity = 1 - (idx * 0.25);
                      horizonList.innerHTML += `
                          <div class="protocol-bar-row">
                              <span class="protocol-label">${name}</span>
                              <div class="protocol-track">
                                  <div class="protocol-fill" style="width: ${pct}%; opacity: ${opacity};"></div>
                              </div>
                          </div>
                      `;
                  });
            }
            if (data.graph_data) {
                renderSnifferGraph(data.graph_data);
            }
          } else {
            const rateEl = document.getElementById("tile-sniffer-rate");
            if (rateEl) rateEl.innerHTML = `0.00 <span style="font-size: 0.8rem; color: var(--neo-text-muted);">KB/s</span>`;
          }
        })
        .catch(console.error);
    }
  }

  function renderSnifferGraph(graphData) {
      const container = document.getElementById('tile-sniffer-graph');
      const emptyLabel = document.getElementById('tile-sniffer-graph-empty');
      if (!container) return;

      if (!graphData.nodes || graphData.nodes.length === 0) {
          if (emptyLabel) emptyLabel.classList.remove('hidden');
          return;
      }
      if (emptyLabel) emptyLabel.classList.add('hidden');

      const options = {
          nodes: {
              shape: 'dot',
              font: { face: 'Inter', size: 9, color: '#ffffff' },
              scaling: { min: 8, max: 20 },
              borderWidth: 0,
              shadow: { enabled: true, color: 'rgba(0,0,0,0.5)', size: 5 }
          },
          groups: {
              local: { color: { background: 'var(--neo-blue)', highlight: '#60a5fa' } },
              external: { color: { background: 'var(--neo-red)', highlight: '#f87171' } }
          },
          edges: {
              color: { color: 'rgba(255,255,255,0.1)', highlight: 'var(--neo-blue)' },
              smooth: { type: 'continuous', roundness: 0.5 },
              width: 1
          },
          physics: {
              enabled: true,
              stabilization: { enabled: true, iterations: 100 },
              barnesHut: { gravitationalConstant: -2000, centralGravity: 0.3, springLength: 95 }
          },
          interaction: { zoomView: false, dragView: true, hover: true }
      };

      const data = {
          nodes: new vis.DataSet(graphData.nodes),
          edges: new vis.DataSet(graphData.edges)
      };

      if (!snifferNetwork) {
          snifferNetwork = new vis.Network(container, data, options);
      } else {
          snifferNetwork.setData(data);
      }
  }

  // --- 4. KILLCHAIN AUDIT ---
  function updateKCStats() {
    if (typeof apiEndpoints !== 'undefined' && apiEndpoints.killchain) {
      fetch(apiEndpoints.killchain)
        .then((r) => r.json())
        .then((data) => {
          const isActive = ["Scanned", "Analyzed", "Completed", "Scanning"].includes(data.status);
          if (isActive) {
            const statusEl = document.getElementById("tile-kc-status");
            if (statusEl) {
                statusEl.textContent = data.status === "Scanning" ? "AUDITING..." : "AUDITED";
                statusEl.className = data.status === "Scanning" ? "badge status-alert" : "badge badge-secure";
            }
            const findingsEl = document.getElementById("tile-kc-findings");
            if (findingsEl) {
              findingsEl.innerHTML = "";
              const kcFindings = data.top_vulnerabilities || [];
              if (kcFindings.length > 0) {
                kcFindings.slice(0, 5).forEach(f => {
                  findingsEl.innerHTML += `<div style="font-family: var(--font-mono); font-size: 0.65rem; color: var(--neo-blue); padding: 2px 0;">> ${f.name}</div>`;
                });
              } else {
                findingsEl.innerHTML = '<div style="opacity: 0.4; font-size: 0.65rem;">No relevant findings.</div>';
              }
            }
          } else {
            const findingsEl = document.getElementById("tile-kc-findings");
            if (findingsEl) findingsEl.innerHTML = '<div style="opacity: 0.3; font-size: 0.65rem; padding: 1rem; text-align: center;">NO AUDIT DATA</div>';
          }
        })
        .catch(console.error);
    }
  }

  // --- 5. API SECURITY ---
  function updateApiStats() {
    if (typeof apiEndpoints !== 'undefined' && apiEndpoints.api) {
      fetch(apiEndpoints.api)
        .then((r) => r.json())
        .then((data) => {
          const isActive = ["Scanned", "Analyzed", "Completed", "Scanning"].includes(data.status);
          if (isActive) {
            const statusEl = document.getElementById("api-scan-status");
            if (statusEl) {
                statusEl.textContent = data.status === "Scanning" ? "SCANNING" : ((data.alerts_summary && data.alerts_summary.High > 0) ? "CRITICAL" : "STABLE");
                statusEl.className = (data.status === "Scanning" || (data.alerts_summary && data.alerts_summary.High > 0)) ? "badge badge-danger" : "badge badge-secure";
            }
            const countEl = document.getElementById("api-vuln-count");
            if (countEl && data.alerts_summary) {
                countEl.textContent = (data.alerts_summary.High || 0) + (data.alerts_summary.Medium || 0);
            }
            const listEl = document.getElementById("tile-api-findings");
            if (listEl) {
              listEl.innerHTML = "";
              const apiRisks = data.top_risks || [];
              if (apiRisks.length > 0) {
                apiRisks.slice(0, 3).forEach(risk => {
                   listEl.innerHTML += `
                     <div style="font-family: var(--font-mono); font-size: 0.6rem; display: flex; justify-content: space-between; margin-bottom: 4px;">
                        <span style="color: var(--neo-amber);">${risk.name}</span>
                        <span style="opacity: 0.6;">${risk.risk}</span>
                     </div>
                   `;
                });
              } else {
                listEl.innerHTML = '<div style="opacity: 0.4; font-size: 0.65rem;">No API risks detected.</div>';
              }
            }
          } else {
            const statusEl = document.getElementById("api-scan-status");
            if (statusEl) { statusEl.textContent = "IDLE"; statusEl.className = "badge"; }
            const listEl = document.getElementById("tile-api-findings");
            if (listEl) listEl.innerHTML = '<div style="opacity: 0.3; font-size: 0.65rem; padding: 1rem; text-align: center;">NO API DATA</div>';
          }
        })
        .catch(console.error);
    }
  }

  // --- 6. CODE SECURITY (SAST) ---
  function updateSemgrepStats() {
    if (typeof apiEndpoints !== 'undefined' && apiEndpoints.semgrep) {
      fetch(apiEndpoints.semgrep)
        .then((r) => r.json())
        .then((data) => {
          const isActive = ["Scanned", "Analyzed", "Completed", "Scanning"].includes(data.status);
          if (isActive) {
            const durEl = document.getElementById("tile-semgrep-duration");
            if (durEl) durEl.textContent = `SCAN TIME: ${data.scan_duration || "--"}`;
            
            const countEl = document.getElementById("semgrep-vuln-count");
            if (countEl) countEl.textContent = `TOTAL FINDINGS: ${data.total_findings || 0}`;
            
            const listEl = document.getElementById("tile-semgrep-findings-list");
            if (listEl) {
              listEl.innerHTML = "";
              if (data.status === "Scanning") {
                  listEl.innerHTML = '<div style="color: var(--neo-blue); font-family: var(--font-mono); font-size: 0.65rem; text-align: center; padding: 1.5rem;" class="status-alert">// SYSTEM ANALYZING CODEBASE...</div>';
              } else if (data.top_findings && data.top_findings.length > 0) {
                data.top_findings.forEach(f => {
                  const severityColor = f.severity === "ERROR" ? "var(--neo-red)" : (f.severity === "WARNING" ? "var(--neo-amber)" : "var(--neo-blue)");
                  listEl.innerHTML += `
                    <div style="padding: 0.6rem; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.05); border-radius: 6px; margin-bottom: 6px; display: flex; flex-direction: column; gap: 4px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="color: ${severityColor}; font-weight: 800; font-size: 0.6rem;">[${f.severity}] LINE ${f.line}</span>
                            <span style="color: var(--neo-text-muted); font-size: 0.55rem;">${f.file.split('/').pop()}</span>
                        </div>
                        <div style="color: #eee; font-size: 0.65rem; line-height: 1.3; font-weight: 500;">${f.message}</div>
                        <div style="font-size: 0.55rem; color: var(--neo-text-muted); opacity: 0.7;">PATTERN_DETECTED_IN_SOURCE</div>
                    </div>
                  `;
                });
              } else {
                listEl.innerHTML = '<div style="color: var(--neo-green); font-size: 0.6rem; opacity: 0.7; padding: 1rem; text-align: center;">// NO CODE VULNERABILITIES DETECTED</div>';
              }
            }
          } else {
            const listEl = document.getElementById("tile-semgrep-findings-list");
            if (listEl) listEl.innerHTML = '<div style="color: var(--neo-text-muted); opacity: 0.3; font-size: 0.65rem; padding: 1.5rem; text-align: center;">NO CODE SCAN DATA AVAILABLE</div>';
          }
        })
        .catch(console.error);
    }
  }
  updateSemgrepStats();

  // --- 7. SQL SECURITY ---
  function updateSqlStats() {
    if (typeof apiEndpoints !== 'undefined' && apiEndpoints.sql) {
      fetch(apiEndpoints.sql)
        .then((r) => r.json())
        .then((data) => {
          const isActive = ["Scanned", "Analyzed", "Completed", "Scanning"].includes(data.status);
          if (isActive) {
            const statusEl = document.getElementById("tile-sql-status");
            if (statusEl) {
                statusEl.textContent = data.status === "Scanning" ? "AUDITING..." : ((data.vuln_count > 0) ? "CRITICAL" : "STABLE");
                statusEl.className = (data.status === "Scanning" || data.vuln_count > 0) ? "badge badge-danger" : "badge badge-secure";
            }
            const userEl = document.getElementById("sql-user");
            if (userEl) userEl.textContent = data.db_user || "root";
            const dbEl = document.getElementById("sql-db");
            if (dbEl) dbEl.textContent = data.current_db || "Unknown";
            const listEl = document.getElementById("tile-sql-findings");
            if (listEl) {
              listEl.innerHTML = "";
              if (data.status === "Scanning") {
                  listEl.innerHTML = '<div style="opacity: 0.5; font-size: 0.6rem; padding: 1rem; text-align: center;" class="status-alert">> DATABASE SECURITY AUDIT IN PROGRESS...</div>';
              } else if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                 data.vulnerabilities.slice(0, 3).forEach(v => {
                   listEl.innerHTML += `<div style="font-family: var(--font-mono); font-size: 0.6rem; color: var(--neo-red);">> ${v.type} (${v.parameter})</div>`;
                 });
              } else {
                 listEl.innerHTML = '<div style="opacity: 0.4; font-size: 0.6rem;">No injections detected.</div>';
              }
            }
          } else {
            const listEl = document.getElementById("tile-sql-findings");
            if (listEl) listEl.innerHTML = '<div style="opacity: 0.3; font-size: 0.6rem; padding: 1rem; text-align: center;">NO DATABASE SCAN DATA</div>';
          }
        })
        .catch(console.error);
    }
  }

  // --- 8. SSL SECURITY ---
  function updateSslStats() {
    if (typeof apiEndpoints !== 'undefined' && apiEndpoints.ssl) {
      fetch(apiEndpoints.ssl)
        .then((r) => r.json())
        .then((data) => {
          const isActive = ["Scanned", "Analyzed", "Completed", "Scanning"].includes(data.status);
          if (isActive) {
            const encEl = document.getElementById("tile-ssl-encryption");
            if (encEl) {
                encEl.textContent = data.status === "Scanning" ? "VALIDATING" : (data.is_secure ? "ENCRYPTED" : "WEAK");
                encEl.style.color = data.status === "Scanning" ? "var(--neo-blue)" : (data.is_secure ? "var(--neo-green)" : "var(--neo-red)");
            }
            const compEl = document.getElementById("tile-ssl-compression");
            if (compEl) compEl.textContent = data.compression_supported ? "ENABLED (RISKY)" : "DISABLED";
            const issuerEl = document.getElementById("tile-ssl-issuer");
            if (issuerEl) issuerEl.textContent = data.issuer || "Unknown";
            const protoEl = document.getElementById("tile-ssl-protocols");
            if (protoEl) protoEl.textContent = data.available_protocols ? data.available_protocols.join(", ") : "None";
          } else {
             const encEl = document.getElementById("tile-ssl-encryption");
             if (encEl) encEl.textContent = "IDLE";
          }
        })
        .catch(console.error);
    }
  }

  // Global Telemetry Refresher
  const updateInterval = 10000;
  function refreshDashboardTelemetry() {
      updateGlobalHealth();
      updateNmapStats();
      updateZapStats();
      updateSnifferStats();
      updateKCStats();
      updateApiStats();
      updateSemgrepStats();
      updateSqlStats();
      updateSslStats();
  }

  // Initial Run
  refreshDashboardTelemetry();
  // Auto-Refresh Loop
  setInterval(refreshDashboardTelemetry, updateInterval);

  // --- 9. RECENT AI SESSIONS ---
  if (typeof apiEndpoints !== 'undefined' && apiEndpoints.chatbotSessions) {
    fetch(apiEndpoints.chatbotSessions)
      .then((r) => r.json())
      .then((sessions) => {
          const container = document.getElementById("recent-chats-container");
          if (container) {
            container.innerHTML = "";
            const sessionsArr = Array.isArray(sessions) ? sessions : (sessions.sessions || []);
            if (sessionsArr.length > 0) {
              sessionsArr.slice(0, 4).forEach(session => {
                container.innerHTML += `
                  <a href="/chatbot/?session_id=${session.id}" class="bento-tile" style="padding: 1rem; text-decoration: none; border: 1px solid var(--neo-border); background: rgba(255,255,255,0.02); transition: all 0.2s ease;">
                     <div style="display: flex; align-items: center; gap: 0.75rem;">
                         <i class="material-symbols-outlined" style="color: var(--neo-purple);">chat_bubble</i>
                         <div style="flex: 1;">
                            <div style="font-size: 0.75rem; font-weight: 700; color: var(--neo-text-main);">${session.name || "Unnamed Session"}</div>
                            <div style="font-size: 0.6rem; color: var(--neo-text-muted); margin-top: 2px;">${session.created_at || "Recent"}</div>
                         </div>
                         <i class="material-symbols-outlined" style="font-size: 1rem; color: var(--neo-blue);">arrow_forward</i>
                     </div>
                  </a>
                `;
              });
            } else {
              container.innerHTML = '<div style="grid-column: span 12; text-align: center; opacity: 0.5; font-size: 0.7rem; padding: 1rem;">No consultation history found.</div>';
            }
          }
      })
      .catch(console.error);
  }

  // --- 10. REPORT VAULT LOADER & FILTERING ---
  // --- 10. REPORT VAULT LOADER & FILTERING ---
  let allReports = [];
  let activeScannerTarget = "Global"; 

  if (typeof apiEndpoints !== 'undefined' && apiEndpoints.reports) {
    const reportGrid = document.getElementById("reports-grid-container");
    const targetFilter = document.getElementById("reportFilterTarget");
    const scannerFilter = document.getElementById("reportFilterScanner");
    const dateFilter = document.getElementById("reportFilterDate");
    const searchFilter = document.getElementById("reportFilterSearch");

    const scannerMeta = {
        'zap_scanner': { theme: 'theme-zap', icon: 'language' },
        'network_scanner': { theme: 'theme-network', icon: 'hub' },
        'ssl_scanner': { theme: 'theme-ssl', icon: 'encrypted' },
        'packet_sniffer': { theme: 'theme-sniffer', icon: 'troubleshoot' },
        'killchain': { theme: 'theme-killchain', icon: 'view_in_ar' },
        'sql_scanner': { theme: 'theme-sql', icon: 'database' },
        'api_scanner': { theme: 'theme-api', icon: 'api' },
        'semgrep_scanner': { theme: 'theme-semgrep', icon: 'code' },
        'default': { theme: 'theme-sniffer', icon: 'description' }
    };

    function getTimeGroup(timestamp) {
        const now = new Date();
        const rptDate = new Date(timestamp * 1000);
        const diffMs = now - rptDate;
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

        if (diffDays === 0) return "Today";
        if (diffDays === 1) return "Yesterday";
        if (diffDays < 7) return "Past 7 Days";
        if (diffDays < 30) return "Earlier this Month";
        return "Secure Archive";
    }

    function renderReports(reports) {
      if (!reportGrid) return;
      reportGrid.innerHTML = "";
      
      if (reports.length === 0) {
        reportGrid.innerHTML = '<div style="text-align: center; padding: 4rem; opacity: 0.3;"><div class="material-symbols-outlined" style="font-size: 3rem; margin-bottom: 1rem;">search_off</div><div>NO MATCHING RECORDS FOUND</div></div>';
        return;
      }

      // Grouping logic
      const groups = {};
      reports.forEach(rpt => {
          const groupName = getTimeGroup(rpt.timestamp);
          if (!groups[groupName]) groups[groupName] = [];
          groups[groupName].push(rpt);
      });

      // Maintain chronological group order
      const groupOrder = ["Today", "Yesterday", "Past 7 Days", "Earlier this Month", "Secure Archive"];
      
      groupOrder.forEach(gn => {
          if (!groups[gn] || groups[gn].length === 0) return;
          
          const groupWrapper = document.createElement("div");
          groupWrapper.className = "archive-group";
          
          groupWrapper.innerHTML = `
            <div class="archive-group-header">
                <span class="archive-group-label">${gn}</span>
                <div class="archive-group-line"></div>
            </div>
            <div class="reports-grid"></div>
          `;
          
          const grid = groupWrapper.querySelector(".reports-grid");
          
          groups[gn].forEach(rpt => {
            const meta = scannerMeta[rpt.folder] || scannerMeta['default'];
            const card = document.createElement("div");
            card.className = `report-hud-card ${meta.theme}`;
            card.innerHTML = `
              <div class="report-hud-icon-box">
                  <span class="material-symbols-outlined">${meta.icon}</span>
              </div>
              <div class="report-hud-content">
                  <div class="report-hud-title" title="${rpt.filename}">${rpt.filename}</div>
                  <div class="report-hud-target">${rpt.target || "GLOBAL"}</div>
                  <div class="report-hud-meta">
                      <div class="report-hud-stats">
                          <div class="report-hud-stat-item"><i class="material-symbols-outlined">schedule</i>${rpt.date}</div>
                          <div class="report-hud-stat-item"><i class="material-symbols-outlined">data_usage</i>${rpt.size}</div>
                      </div>
                      <a href="/dashboard/download/report?path=${rpt.rel_path}" class="report-download-btn">
                          <i class="material-symbols-outlined">download</i>
                          GET PDF
                      </a>
                  </div>
              </div>
            `;
            grid.appendChild(card);
          });
          
          reportGrid.appendChild(groupWrapper);
      });
    }

    function applyFilters() {
      const targetVal = targetFilter ? targetFilter.value : 'all';
      const scannerVal = scannerFilter ? scannerFilter.value : 'all';
      const dateVal = dateFilter ? dateFilter.value : '';
      const searchVal = searchFilter ? searchFilter.value.toLowerCase() : '';

      const filtered = allReports.filter(rpt => {
        const matchesTarget = targetVal === 'all' || (rpt.target || "GLOBAL") === targetVal;
        const matchesScanner = scannerVal === 'all' || rpt.folder === scannerVal;
        const matchesDate = !dateVal || rpt.date.includes(dateVal);
        const matchesSearch = !searchVal || 
                              rpt.filename.toLowerCase().includes(searchVal) || 
                              (rpt.target || "").toLowerCase().includes(searchVal) ||
                              rpt.type.toLowerCase().includes(searchVal);
                              
        return matchesTarget && matchesScanner && matchesDate && matchesSearch;
      });
      renderReports(filtered);
    }

    fetch(apiEndpoints.reports)
      .then(r => r.json())
      .then(data => {
        allReports = Array.isArray(data) ? data : (data.reports || []);
        if (targetFilter) {
            const uniqueTargets = [...new Set(allReports.map(r => r.target || "GLOBAL"))].sort();
            targetFilter.innerHTML = '<option value="all">All Targets</option>';
            uniqueTargets.forEach(t => {
                const opt = document.createElement("option");
                opt.value = t; opt.textContent = t;
                targetFilter.appendChild(opt);
            });
            initCustomSelect(targetFilter);
        }
        if (scannerFilter) initCustomSelect(scannerFilter);
        renderReports(allReports);
      })
      .catch(console.error);

    if (targetFilter) targetFilter.addEventListener("change", applyFilters);
    if (scannerFilter) scannerFilter.addEventListener("change", applyFilters);
    if (dateFilter) dateFilter.addEventListener("change", applyFilters);
    if (searchFilter) searchFilter.addEventListener("input", applyFilters);
  }

  // --- 11. TAB SWITCHING ---
  const tabBtns = document.querySelectorAll(".tab-btn[data-tab]");
  const tabPanes = document.querySelectorAll(".tab-pane");
  let cachedComplianceData = null; 

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      tabPanes.forEach(p => p.classList.add("hidden"));

      btn.classList.add("active");
      const targetId = `tab-${btn.getAttribute("data-tab")}`;
      const targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.remove("hidden");
      
      if (btn.getAttribute("data-tab") === "compliance-frameworks") {
          loadComplianceData();
      }
    });
  });

  // Initialize Flatpickr for Reports
  const dateInput = document.getElementById("reportFilterDate");
  if (dateInput) {
      flatpickr(dateInput, {
          dateFormat: "Y-m-d",
          static: true,
          onChange: function(selectedDates, dateStr) {
             dateInput.value = dateStr;
             dateInput.dispatchEvent(new Event('change'));
          }
      });
  }

  function showRemedyModal(stdName, req) {
      const modal = document.getElementById("remedyModal");
      const stdEl = document.getElementById("remedy-std");
      const titleEl = document.getElementById("remedy-title");
      const adviceEl = document.getElementById("remedy-advice-text");
      const evidenceList = document.getElementById("remedy-evidence-list");

      stdEl.textContent = `${stdName} ${req.id}`;
      titleEl.textContent = req.requirement;
      adviceEl.textContent = req.remediation || "No remediation advice provided.";
      
      evidenceList.innerHTML = "";
      if (req.evidence && req.evidence.length > 0) {
          req.evidence.forEach(ev => {
              const evItem = document.createElement("div");
              evItem.style.marginBottom = "10px";
              evItem.innerHTML = `
                  <div style="color:var(--neo-blue); font-weight:700;">[${ev.source}] ${ev.issue}</div>
                  <div style="font-size: 0.65rem;">${ev.description}</div>
              `;
              evidenceList.appendChild(evItem);
          });
      } else {
          evidenceList.innerHTML = '<div style="opacity:0.5;">No negative technical evidence found for this requirement.</div>';
      }

      modal.style.display = "flex";
  }

  function renderComplianceCards(targetName) {
    const container = document.getElementById("compliance-grid-container");
    if (!container || !cachedComplianceData) return;
    
    container.innerHTML = "";
    let targetData = cachedComplianceData.targets ? (cachedComplianceData.targets[targetName] || cachedComplianceData.targets["Global"]) : null;
    
    if (!targetData && cachedComplianceData.targets) {
         const norm = targetName.replace("http://", "").replace("https://", "").split('/')[0].split(':')[0];
         targetData = cachedComplianceData.targets[norm] || cachedComplianceData.targets["Global"];
    }

    const standards = targetData ? targetData.standards : (cachedComplianceData.standards || {});
    if (Object.keys(standards).length > 0) {
        Object.entries(standards).forEach(([key, std]) => {
            const card = document.createElement("div");
            card.className = "framework-card";
            const score = std.score_percentage || 0;
            const dashArray = (score / 100) * 157; 
            
            let reqChips = (std.details || []).map(req => {
                const cls = req.status === "PASS" ? "pass" : "fail";
                return `<div class="req-chip ${cls}" data-req='${JSON.stringify(req).replace(/'/g, "&apos;")}' title="Click for fix info">${req.id}</div>`;
            }).join("");

            card.innerHTML = `
                <div class="framework-header">
                    <div class="framework-v-info">
                        <div class="framework-title">${key}</div>
                        <div style="font-size: 0.65rem; color: var(--neo-text-muted); margin-top: 4px; max-width: 180px;">${std.name}</div>
                    </div>
                    <div class="framework-gauge">
                        <svg viewBox="0 0 60 60" style="width: 100%; height: 100%; transform: rotate(-90deg);">
                            <circle cx="30" cy="30" r="25" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="4"></circle>
                            <circle cx="30" cy="30" r="25" fill="none" stroke="var(--neo-blue)" stroke-width="4" 
                                stroke-dasharray="${dashArray} 157" stroke-linecap="round" style="transition: stroke-dasharray 1.5s ease; filter: drop-shadow(0 0 3px var(--neo-blue));"></circle>
                        </svg>
                        <div style="position: absolute; top:0; left:0; width:100%; height:100%; display: flex; align-items: center; justify-content: center; font-family: var(--font-mono); font-size: 0.75rem; font-weight: 800; color: #fff;">
                            ${Math.round(score)}%
                        </div>
                    </div>
                </div>
                <div style="margin-top: auto;">
                    <div style="display: flex; justify-content: space-between; font-size: 0.65rem; color: var(--neo-text-muted); margin-bottom: 8px;">
                        <span>${std.passed_requirements} PASSED</span>
                        <span>${std.failed_requirements} FAILED</span>
                    </div>
                    <div class="requirement-list">
                        ${reqChips}
                    </div>
                </div>
            `;
            card.querySelectorAll(".req-chip").forEach(chip => {
                chip.addEventListener("click", (e) => {
                    e.stopPropagation();
                    const reqData = JSON.parse(chip.getAttribute("data-req"));
                    showRemedyModal(key, reqData);
                });
            });
            container.appendChild(card);
        });
    }
  }

  function loadComplianceData() {
    if (typeof apiEndpoints !== 'undefined' && apiEndpoints.compliance) {
        const selector = document.getElementById("complianceTargetSelector");

        fetch(apiEndpoints.compliance)
            .then(r => r.json())
            .then(data => {
                cachedComplianceData = data;
                if (selector) {
                    const currentVal = selector.value;
                    selector.innerHTML = "";
                    const targets = data.targets ? Object.keys(data.targets) : ["Global"];
                    if (targets.length === 0) targets.push("Global");

                    targets.forEach(t => {
                        const opt = document.createElement("option");
                        opt.value = t; opt.textContent = t;
                        selector.appendChild(opt);
                    });

                    if (targets.includes(currentVal)) {
                        selector.value = currentVal;
                    } else if (targets.includes(activeScannerTarget)) {
                        selector.value = activeScannerTarget;
                    } else {
                        selector.value = targets[0];
                    }

                    if (!selector.dataset.listener) {
                        selector.addEventListener("change", () => renderComplianceCards(selector.value));
                        selector.dataset.listener = "true";
                    }
                    initCustomSelect(selector);
                }
                renderComplianceCards(selector.value || activeScannerTarget || "Global");
            })
            .catch(err => console.error("Compliance Load Error:", err));
    }
  }

  // Hook into Nmap results to update the active target
  const originalFetch = window.fetch;
  window.fetch = function() {
    return originalFetch.apply(this, arguments).then(response => {
        if (arguments[0] === apiEndpoints.network && response.ok) {
            const clone = response.clone();
            clone.json().then(data => {
                if (data.target || data.target_hostname) {
                    activeScannerTarget = data.target_hostname || data.target;
                }
            });
        }
        return response;
    });
  };
});