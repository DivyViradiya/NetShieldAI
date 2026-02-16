document.addEventListener("DOMContentLoaded", function () {
  
  // Helper function to safely open URLs
  const openTargetSafe = (rawUrl) => {
    if (!rawUrl) return;
    let finalUrl = rawUrl;
    // Auto-add https if missing to prevent localhost redirect errors
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

  // --- 1. NETWORK (NMAP) ---
  fetch(apiEndpoints.network)
    .then((r) => r.json())
    .then((data) => {
      const available = data.status === "Scanned";

      if (available) {
        const countEl = document.getElementById("nmap-count");
        if (countEl) countEl.textContent = data.open_ports_count;

        const targetEl = document.getElementById("nmap-target");
        if (targetEl) targetEl.textContent = data.target;

        const osEl = document.getElementById("nmap-os");
        if (osEl) osEl.textContent = data.os_detected || "Unknown";

        const listEl = document.getElementById("nmap-service-list");
        if (listEl) {
          listEl.innerHTML = "";
          if (data.top_services && data.top_services.length > 0) {
            data.top_services.forEach((svcString) => {
              const firstColonIndex = svcString.indexOf(":");
              let port = "??";
              let desc = svcString;
              if (firstColonIndex !== -1) {
                port = svcString.substring(0, firstColonIndex);
                desc = svcString.substring(firstColonIndex + 1);
              }
              listEl.innerHTML += `
                                <li class="service-item">
                                    <span style="color:var(--neo-blue); font-weight:bold;">${port}</span>
                                    <span style="color:#aaa;">${desc}</span>
                                </li>
                            `;
            });
          } else {
            listEl.innerHTML =
              '<li style="text-align:center; color:#666; padding:1rem;">No open ports found.</li>';
          }
        }
        const btn = document.getElementById("btn-nmap-pdf");
        if (btn) {
          btn.classList.remove("disabled");
          btn.href = reportUrls.network;
        }
      } else {
        const countEl = document.getElementById("nmap-count");
        if (countEl && countEl.textContent === "--") countEl.textContent = "--";
      }
    })
    .catch(console.error);

  // --- 2. ZAP (VULNERABILITIES) ---
  fetch(apiEndpoints.zap)
    .then((r) => r.json())
    .then((data) => {
      const available = data.status === "Scanned";

      if (available) {
        const totalRisks =
          (data.alerts_summary?.high || 0) + (data.alerts_summary?.medium || 0);
        const countEl = document.getElementById("zap-count-total");
        if (countEl) countEl.textContent = totalRisks;

        const zapTargetEl = document.getElementById("zap-target");
        if (zapTargetEl) {
          zapTargetEl.textContent = data.target || "Unknown";
          
          if (data.target) {
            zapTargetEl.style.cursor = "pointer";
            zapTargetEl.onclick = () => openTargetSafe(data.target);
          }
        }

        const listEl = document.getElementById("zap-vuln-list");
        if (listEl) {
          if (data.top_risks && data.top_risks.length > 0) {
            listEl.innerHTML = "";
            data.top_risks.forEach((vuln, index) => {
              const riskClass =
                vuln.risk === "High"
                  ? "risk-high"
                  : vuln.risk === "Medium"
                  ? "risk-med"
                  : "risk-low";
              const uid = `zap-vuln-${index}`;

              listEl.innerHTML += `
                                <div class="vuln-item">
                                    <div class="vuln-header" onclick="document.getElementById('${uid}').classList.toggle('active')">
                                        <span class="vuln-title">${vuln.name}</span>
                                        <span class="risk-badge ${riskClass}">${vuln.risk}</span>
                                    </div>
                                    <div id="${uid}" class="vuln-body">
                                        <strong style="color:var(--neo-green); display:block; margin-bottom:0.5rem;">Suggested Fix:</strong>
                                        ${vuln.solution}
                                    </div>
                                </div>
                            `;
            });
          } else {
            listEl.innerHTML =
              '<div style="text-align:center; padding:2rem; color:#444;">System Secure. No risks found.</div>';
          }
        }
        const btn = document.getElementById("btn-zap-pdf");
        if (btn) {
          btn.classList.remove("disabled");
          btn.href = reportUrls.zap;
        }
      }
    })
    .catch(console.error);

  // --- 3. SSL (ENCRYPTION) ---
  fetch(apiEndpoints.ssl)
    .then((r) => r.json())
    .then((data) => {
      const available = data.status === "Scanned";
      if (available) {
        const daysEl = document.getElementById("ssl-days");
        if (daysEl) daysEl.textContent = data.days_left;

        const keyEl = document.getElementById("ssl-key-info");
        if (keyEl) keyEl.textContent = data.key_info || "Unknown";

        const protoEl = document.getElementById("ssl-protocols");
        if (protoEl) {
          if (data.weak_protocols && data.weak_protocols.length > 0) {
            protoEl.textContent = data.weak_protocols.join(", ");
            protoEl.style.color = "#f43f5e";
          } else {
            protoEl.textContent = "Modern (TLS 1.2+)";
            protoEl.style.color = "#10b981";
          }
        }
        const btn = document.getElementById("btn-ssl-pdf");
        if (btn) {
          btn.classList.remove("disabled");
          btn.href = reportUrls.ssl;
        }
      }
    })
    .catch(console.error);

  // --- 4. SNIFFER (TRAFFIC) ---
  fetch(apiEndpoints.sniffer)
    .then((r) => r.json())
    .then((data) => {
      const available = data.status === "Analyzed";
      const countEl = document.getElementById("sniffer-packet-count");
      if (available && countEl) countEl.textContent = data.total_packets;

      if (available) {
        const durEl = document.getElementById("sniffer-duration");
        if (durEl) durEl.textContent = `Duration: ${data.duration}`;

        const tbody = document.getElementById("sniffer-table-body");
        if (tbody && data.top_talkers && data.top_talkers.length > 0) {
          tbody.innerHTML = "";
          data.top_talkers.forEach((t) => {
            tbody.innerHTML += `
                            <tr>
                                <td>${t.display}</td>
                                <td style="text-align:right; color:var(--neo-blue); font-family:var(--font-mono);">${t.bytes} B</td>
                            </tr>
                        `;
          });
        }
        const btn = document.getElementById("btn-sniffer-pdf");
        if (btn) {
          btn.classList.remove("disabled");
          btn.href = reportUrls.sniffer;
        }
      }
    })
    .catch(console.error);

  // --- 5. KILL CHAIN (FULL AUDIT) ---
  fetch(apiEndpoints.killchain)
    .then((r) => r.json())
    .then((data) => {
      const available = data.status === "Completed";

      if (available) {
        const btn = document.getElementById("btn-killchain-pdf");
        if (btn) {
          btn.classList.remove("disabled");
          btn.href = reportUrls.killchain;
        }
        
        const gridBtn = document.getElementById("btn-killchain-pdf-grid");
        if (gridBtn) {
          gridBtn.classList.remove("disabled");
          gridBtn.href = reportUrls.killchain;
        }

        const targetEl = document.getElementById("zap-target");
        if (targetEl && data.target) {
            targetEl.textContent = data.target; 
            targetEl.style.cursor = "pointer";
            targetEl.onclick = () => openTargetSafe(data.target);
        }

        const techContainer = document.getElementById("tech-stack-container");
        if (techContainer && data.tech_stack) {
          techContainer.innerHTML = "";
          let hasTech = false;
          for (const [category, techs] of Object.entries(data.tech_stack)) {
            if (Array.isArray(techs) && techs.length > 0) {
              techs.forEach((t) => {
                hasTech = true;
                techContainer.innerHTML += `<span class="tech-badge">${t}</span>`;
              });
            }
          }
          if (!hasTech)
            techContainer.innerHTML =
              '<span style="font-size:0.75rem; color:#666;">No specific tech detected</span>';
        }

        const subEl = document.getElementById("kc-subdomains");
        const urlEl = document.getElementById("kc-urls");

        const subCount =
          data.network_summary && data.network_summary.subdomains
            ? data.network_summary.subdomains
            : 0;
        if (subEl) subEl.textContent = subCount;

        if (urlEl && data.network_summary) {
          urlEl.textContent = data.network_summary.urls_crawled || "0";
        }

        const summary = data.vuln_summary || {};
        const c = summary.Critical || 0;
        const h = summary.High || 0;
        const m = summary.Medium || 0;
        const l = summary.Low || 0;

        if (document.getElementById("kc-count-crit"))
          document.getElementById("kc-count-crit").textContent = c;
        if (document.getElementById("kc-count-high"))
          document.getElementById("kc-count-high").textContent = h;
        if (document.getElementById("kc-count-med"))
          document.getElementById("kc-count-med").textContent = m;
        if (document.getElementById("kc-count-low"))
          document.getElementById("kc-count-low").textContent = l;

        const countEl = document.getElementById("zap-count-total");
        if (countEl) countEl.textContent = c + h + m;

        const listEl = document.getElementById("zap-vuln-list");
        if (listEl && data.top_risks && data.top_risks.length > 0) {
          listEl.innerHTML = "";
          data.top_risks.forEach((vuln, index) => {
            let riskClass = "risk-low";
            if (vuln.severity === "Critical") riskClass = "risk-critical";
            else if (vuln.severity === "High") riskClass = "risk-high";
            else if (vuln.severity === "Medium") riskClass = "risk-med";

            const uid = `kc-vuln-${index}`;
            listEl.innerHTML += `
                            <div class="vuln-item">
                                <div class="vuln-header" onclick="document.getElementById('${uid}').classList.toggle('active')">
                                    <span class="vuln-title">${vuln.type}</span>
                                    <span class="risk-badge ${riskClass}">${
              vuln.severity
            }</span>
                                </div>
                                <div id="${uid}" class="vuln-body">
                                    <div style="margin-bottom:0.5rem; color:#e4e4e7;">
                                        <strong>Evidence:</strong> <span style="font-family:monospace; color:#aaa;">${
                                          vuln.evidence || "N/A"
                                        }</span>
                                    </div>
                                    <div style="font-size:0.75rem; color:#666;">
                                        Parameter: <span style="color:var(--neo-blue);">${
                                          vuln.param || "Global"
                                        }</span>
                                    </div>
                                </div>
                            </div>
                        `;
          });
        }

        const netCountEl = document.getElementById("nmap-count");
        if (
          netCountEl &&
          (netCountEl.textContent === "--" || netCountEl.textContent === "0")
        ) {
          if (
            data.network_summary &&
            data.network_summary.open_ports !== undefined
          ) {
            netCountEl.textContent = data.network_summary.open_ports;
          }
        }
      }
    })
    .catch(console.error);

  // --- 6. COMPLIANCE (REGULATORY) ---
  fetch(apiEndpoints.compliance)
    .then((r) => r.json())
    .then((data) => {
      const container = document.getElementById('compliance-container');
      const tabsContainer = document.getElementById('compliance-tabs-container');
      if (!container || !tabsContainer) return;

      // Handle case where no data or no targets
      if (!data || !data.targets || Object.keys(data.targets).length === 0) {
        container.innerHTML = `<div style="text-align:center; padding:1rem; color:#666;">No compliance data generated yet.</div>`;
        tabsContainer.style.display = 'none';
        return;
      }

      tabsContainer.innerHTML = '';
      container.innerHTML = '';
      
      const targets = Object.keys(data.targets);
      
      targets.forEach((targetName, index) => {
        // Create Tab Button
        const btn = document.createElement('button');
        btn.className = `comp-tab-btn ${index === 0 ? 'active' : ''}`;
        btn.textContent = targetName;
        
        btn.onclick = () => {
            // Update buttons
            document.querySelectorAll('.comp-tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            // Show pane
            document.querySelectorAll('.comp-target-pane').forEach(p => p.style.display = 'none');
            document.getElementById(`comp-pane-${index}`).style.display = 'grid';
        };
        tabsContainer.appendChild(btn);

        // Create Content Pane
        const pane = document.createElement('div');
        pane.id = `comp-pane-${index}`;
        pane.className = 'comp-target-pane compliance-grid';
        pane.style.display = index === 0 ? 'grid' : 'none';

        const targetData = data.targets[targetName];
        let paneHtml = '';

        for (const [stdKey, stdData] of Object.entries(targetData.standards)) {
          const score = stdData.score_percentage || 0;
          const failedCount = stdData.failed_requirements || 0;
          
          let status = 'Pass';
          let statusClass = 'status-pass';
          if (failedCount > 0) {
              status = 'Fail';
              statusClass = 'status-fail';
          }
          
          const barColor = status === 'Pass' ? 'var(--neo-green)' : 'var(--neo-red)';

          paneHtml += `
          <div class="comp-item">
              <div class="comp-header">
                  <span class="comp-name">${stdKey}</span> <span class="comp-status ${statusClass}">${status}</span>
              </div>
              <div class="comp-desc">
                  ${stdData.name} </div>
              <div style="display:flex; justify-content:space-between; font-size:0.65rem; color:#555; margin-bottom:4px;">
                  <span>ADHERENCE</span>
                  <span>${score}%</span>
              </div>
              <div class="comp-progress-bg">
                  <div class="comp-progress-fill" style="width: ${score}%; background-color: ${barColor};"></div>
              </div>
          </div>`;
        }
        pane.innerHTML = paneHtml;
        container.appendChild(pane);
      });
    })
    .catch((err) => {
      console.error("Compliance Render Error:", err);
      const container = document.getElementById('compliance-container');
      if(container) {
          container.innerHTML = `<div style="color:var(--neo-red); text-align:center; padding:1rem;">Error rendering compliance data.</div>`;
      }
    });

  // --- 7. OPERATOR ACTIVITY / USAGE STATS ---
  let usageChartInstance = null;

  const getThemeColor = (varName) => {
    return getComputedStyle(document.body).getPropertyValue(varName).trim();
  };

  const updateChartTheme = () => {
    if (!usageChartInstance) return;
    
    const textColor = getThemeColor('--neo-text-muted');
    const tooltipBg = getThemeColor('--neo-card');
    const tooltipText = getThemeColor('--neo-text-main');
    const borderColor = getThemeColor('--neo-bg'); // Gap color matches background

    usageChartInstance.options.plugins.legend.labels.color = textColor;
    usageChartInstance.options.plugins.tooltip.backgroundColor = tooltipBg;
    usageChartInstance.options.plugins.tooltip.titleColor = tooltipText;
    usageChartInstance.options.plugins.tooltip.bodyColor = textColor;
    usageChartInstance.options.plugins.tooltip.borderColor = getThemeColor('--neo-border');
    usageChartInstance.data.datasets[0].borderColor = borderColor;
    
    usageChartInstance.update();
  };

  // Listen for custom event from base.html
  window.addEventListener('themeChanged', updateChartTheme);

  fetch(apiEndpoints.usage)
    .then((r) => r.json())
    .then((data) => {
      const typeEl = document.getElementById("usage-account-type");
      if (typeEl)
        typeEl.textContent = `${data.organization} (${data.account_type})`;

      const loginEl = document.getElementById("usage-last-login");
      if (loginEl) loginEl.textContent = data.last_login;

      const totalEl = document.getElementById("usage-total-scans");
      if (totalEl) totalEl.textContent = data.total_system_usage;

      const ctx = document.getElementById("usageChart");
      if (ctx && data.scans) {
        
        usageChartInstance = new Chart(ctx, {
          type: "doughnut",
          data: {
            labels: ["Network", "Web", "SSL", "Sniffer", "Kill Chain", "SQL", "API", "SAST"],
            datasets: [
              {
                data: [
                  data.scans.nmap,
                  data.scans.zap,
                  data.scans.ssl,
                  data.scans.sniffer,
                  data.scans.killchain,
                  data.scans.sql,
                  data.scans.api,
                  data.scans.semgrep
                ],
                backgroundColor: [
                  "#3b82f6", // Blue (Network)
                  "#f43f5e", // Red (Web)
                  "#10b981", // Green (SSL)
                  "#f59e0b", // Amber (Sniffer)
                  "#8b5cf6", // Purple (Killchain)
                  "#0ea5e9", // Sky (SQL)
                  "#ec4899", // Pink (API)
                  "#6366f1"  // Indigo (SAST)
                ],
                borderColor: getThemeColor('--neo-bg'), 
                borderWidth: 2,
                hoverOffset: 4,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                position: "right",
                labels: {
                  color: getThemeColor('--neo-text-muted'),
                  font: { family: "'JetBrains Mono', monospace", size: 10 },
                  boxWidth: 8,
                  padding: 10,
                },
              },
              tooltip: {
                backgroundColor: getThemeColor('--neo-card'),
                titleColor: getThemeColor('--neo-text-main'),
                bodyColor: getThemeColor('--neo-text-muted'),
                borderColor: getThemeColor('--neo-border'),
                borderWidth: 1,
                padding: 10,
              },
            },
            layout: {
              padding: 0,
            },
            cutout: "70%",
          },
        });
      }
    })
    .catch(console.error);

  // --- 8. DATABASE / SQL STATUS ---
  fetch(apiEndpoints.databaseStatus)
    .then(res => {
        if (!res.ok) throw new Error('No report');
        return res.json();
    })
    .then(data => {
        // Check if status is success and pdf path is returned
        if(data.status === 'success' && data.pdf_report) {
            const btn = document.getElementById('btn-sql-pdf');
            if(btn) {
                btn.classList.remove('disabled');
                btn.href = reportUrls.database;
            }
        }
    })
    .catch(err => {
        // Silent catch: database scan likely not run yet
    });

  // --- 8.5 NEW: SQL, API, SEMGREP STATS ---
  fetch(apiEndpoints.sql)
    .then(r => r.json())
    .then(data => {
      if (data.status === "Scanned") {
        const sqlCountEl = document.getElementById("sql-vuln-count");
        if (sqlCountEl) sqlCountEl.textContent = data.vuln_count;
        
        const btn = document.getElementById("btn-sql-pdf");
        if (btn) {
          btn.classList.remove("disabled");
          btn.href = reportUrls.database;
        }
      }
    }).catch(console.error);

  fetch(apiEndpoints.api)
    .then(r => r.json())
    .then(data => {
      if (data.status === "Scanned") {
        const apiCountEl = document.getElementById("api-vuln-count");
        if (apiCountEl) apiCountEl.textContent = data.alerts_summary.High + data.alerts_summary.Medium;
        
        const btn = document.getElementById("btn-api-pdf");
        if (btn) {
          btn.classList.remove("disabled");
          btn.href = reportUrls.api;
        }
      }
    }).catch(console.error);

  fetch(apiEndpoints.semgrep)
    .then(r => r.json())
    .then(data => {
      if (data.status === "Scanned") {
        const semgrepCountEl = document.getElementById("semgrep-vuln-count");
        if (semgrepCountEl) semgrepCountEl.textContent = data.total_findings;
        
        const btn = document.getElementById("btn-semgrep-pdf");
        if (btn) {
          btn.classList.remove("disabled");
          btn.href = reportUrls.semgrep;
        }
      }
    }).catch(console.error);

  // --- 8.6 NEW: RECENT CHATS ---
  const continueChat = (sessionId) => {
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
    fetch("/chatbot/switch_session", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken
        },
        body: JSON.stringify({ session_id: sessionId })
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            window.location.href = "/chatbot/";
        }
    })
    .catch(console.error);
  };

  fetch(apiEndpoints.chatbotSessions || "/chatbot/get_sessions")
    .then(r => r.json())
    .then(data => {
      const container = document.getElementById("recent-chats-container");
      if (!container) return;

      if (data.sessions && data.sessions.length > 0) {
        container.innerHTML = "";
        // Show only the 3 most recent sessions
        data.sessions.slice(0, 3).forEach(sess => {
          const card = document.createElement("div");
          card.style.cssText = `
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--neo-border);
            border-radius: 8px;
            padding: 0.75rem 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.2s;
            cursor: pointer;
          `;
          card.onmouseover = () => { card.style.borderColor = 'var(--neo-purple)'; card.style.background = 'rgba(139, 92, 246, 0.05)'; };
          card.onmouseout = () => { card.style.borderColor = 'var(--neo-border)'; card.style.background = 'rgba(255, 255, 255, 0.02)'; };
          card.onclick = () => continueChat(sess.session_id);

          card.innerHTML = `
            <div style="flex: 1; min-width: 0;">
                <div style="font-size: 0.8rem; font-weight: 600; color: var(--neo-text-main); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${sess.title}</div>
                <div style="font-size: 0.65rem; color: var(--neo-text-label); margin-top: 2px;">${sess.subtitle}</div>
            </div>
            <span class="material-symbols-outlined" style="font-size: 1.2rem; color: var(--neo-purple); margin-left: 1rem;">arrow_forward</span>
          `;
          container.appendChild(card);
        });
      } else {
        container.innerHTML = '<div style="text-align:center; padding:1rem; color:#444; font-size:0.75rem;">No recent consultations found.</div>';
      }
    })
    .catch(err => {
      console.error("Chat sessions fetch error:", err);
      const container = document.getElementById("recent-chats-container");
      if (container) container.innerHTML = '<div style="text-align:center; padding:1rem; color:var(--neo-red); font-size:0.75rem;">Failed to load chat history.</div>';
    });

  // --- 9. AGGREGATE SYSTEM EVENTS ---
  setTimeout(() => {
    const events = [];
    const logEl = document.getElementById("system-event-log");

    const addEvent = (source, statusId, icon, color) => {
      const el = document.getElementById(statusId);
      if (
        el &&
        el.textContent !== "--" &&
        el.textContent !== "0" &&
        el.textContent !== "Unknown" &&
        el.textContent !== ""
      ) {
        events.push({
          time: "Recent",
          msg: `${source} Analysis Completed`,
          icon: icon,
          color: color,
        });
      }
    };

    addEvent("Network", "nmap-count", "dns", "#3b82f6");
    addEvent("Vulnerability", "zap-count-total", "bug_report", "#f43f5e");
    addEvent("SSL/TLS", "ssl-days", "verified_user", "#10b981");
    addEvent("Traffic", "sniffer-packet-count", "swap_horiz", "#f59e0b");
    addEvent("SQL Injection", "sql-vuln-count", "database", "#3b82f6");
    addEvent("API Scan", "api-vuln-count", "api", "#8b5cf6");
    addEvent("SAST", "semgrep-vuln-count", "code", "#f43f5e");

    if (logEl && events.length > 0) {
      logEl.innerHTML = "";
      events.forEach((e) => {
        logEl.innerHTML += `
                    <div style="display: flex; align-items: center; gap: 1rem; padding-bottom: 0.5rem; border-bottom: 1px dashed #222;">
                        <span class="material-symbols-outlined" style="font-size: 1rem; color: ${e.color};">${e.icon}</span>
                        <div>
                            <div style="color: #eee;">${e.msg}</div>
                            <div style="font-size: 0.7rem; color: #555;">Status: Success • Data Synced</div>
                        </div>
                    </div>
                `;
      });
      logEl.innerHTML += `
                <div style="margin-top:0.5rem; display:flex; gap:0.5rem; color:#444; align-items:center;">
                    <div style="width:6px; height:6px; background:#10b981; border-radius:50%; box-shadow:0 0 5px #10b981;"></div>
                    System Monitor Active
                </div>
            `;
    }
  }, 1500);
});