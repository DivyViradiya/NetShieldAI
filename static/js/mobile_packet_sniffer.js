document.addEventListener('DOMContentLoaded', () => {
    const elements = {
        // Inputs
        targetIpInput: document.getElementById('snifferTargetIp'),
        durationInput: document.getElementById('captureDuration'),
        maxPacketsInput: document.getElementById('maxPackets'),
        bpfFilterInput: document.getElementById('bpfFilter'),

        // Buttons
        startCaptureBtn: document.getElementById('startCaptureBtn'),
        stopCaptureBtn: document.getElementById('stopCaptureBtn'),
        snifferDownloadReportBtn: document.getElementById('snifferDownloadReportBtn'),
        
        // Dropdowns & Analysis
        snifferAnalyzeReportDropdown: document.getElementById('snifferAnalyzeReportDropdown'),
        snifferLlmAnalysisOptions: document.getElementById('snifferLlmAnalysisOptions'),
        
        // AI Animation Elements
        aiProcessingOverlay: document.getElementById('aiProcessingOverlay'),
        aiProcessingText: document.getElementById('aiProcessingText'),
        
        // Status & Logs
        snifferStatus: document.getElementById('snifferStatus'),
        scanStatus: document.getElementById('scanStatus'),
        snifferLogOutput: document.getElementById('snifferLogOutput'),
        clearSnifferLogBtn: document.getElementById('clearSnifferLogBtn'),

        // History Modal
        snifferHistoryBtn: document.getElementById('snifferHistoryBtn'),
        historyModal: document.getElementById('historyModal'),
        closeHistoryModal: document.getElementById('closeHistoryModal'),
        historyTableBody: document.getElementById('historyTableBody'),

        // Header Metrics
        summaryTotalPackets: document.getElementById('summaryTotalPackets'),
        summaryTotalBytes: document.getElementById('summaryTotalBytes'),
        summaryPrimaryProto: document.getElementById('summaryPrimaryProto'),
        avgRateDisplay: document.getElementById('avgRateDisplay'),
        targetDisplay: document.getElementById('targetDisplay'), // Optional check

        // Tab Buttons
        tabsContainer: document.querySelector('.tabs-nav'),
        summaryTabBtn: document.getElementById('summaryTabBtn'),
        packetsTabBtn: document.getElementById('packetsTabBtn'),
        graphTabBtn: document.getElementById('graphTabBtn'),
        anomaliesTabBtn: document.getElementById('anomaliesTabBtn'),
        flowsTabBtn: document.getElementById('flowsTabBtn'),

        // Tab Content
        summaryContent: document.getElementById('summaryContent'),
        packetsContent: document.getElementById('packetsContent'),
        graphContent: document.getElementById('graphContent'),
        anomaliesContent: document.getElementById('anomaliesContent'),
        flowsContent: document.getElementById('flowsContent'),

        // Graph
        networkGraphCanvas: document.getElementById('networkGraphCanvas'),
        graphFitBtn: document.getElementById('graphFitBtn'),

        // Summary Data
        captureMetaBody: document.getElementById('captureMetaBody'),
        conversationStatsBody: document.getElementById('conversationStatsBody'),
        protocolStatsBody: document.getElementById('protocolStatsBody'),

        // Tables
        flowsTableBody: document.getElementById('flowsTableBody'),
        anomalySummaryText: document.getElementById('anomalySummaryText'),
        portScansBody: document.getElementById('portScansBody'),
        cleartextBody: document.getElementById('cleartextBody'),
        packetsTableBody: document.getElementById('packetsTableBody'),
        resultsContent: document.getElementById('resultsContent'),
        copyResultsBtn: document.getElementById('copyResultsBtn'),
    };

    const API_BASE_URL = '/packet_sniffer';
    const CHATBOT_REDIRECT_URL = '/chatbot';

    let isActionInProgress = false;
    let reportDownloadUrl = null;
    let eventSource = null;
    let networkInstance = null; 

    // --- 🔒 CSRF TOKEN ---
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

    // --- Mobile Helper Functions (Internal) ---

    window.toggleMobileDropdown = function(id) {
        const el = document.getElementById(id);
        if (!el) return;
        const menu = el.querySelector('.dropdown-menu');
        if (!menu) return;
        
        const isShow = menu.classList.contains('show');
        
        document.querySelectorAll('.dropdown-menu').forEach(m => {
            m.classList.remove('show');
            m.classList.add('hidden');
        });
        
        if (!isShow) {
            menu.classList.add('show');
            menu.classList.remove('hidden');
        } else {
            menu.classList.remove('show');
            menu.classList.add('hidden');
        }
        
        const closeDropdown = (e) => {
            if (!el.contains(e.target)) {
                menu.classList.remove('show');
                menu.classList.add('hidden');
                document.removeEventListener('click', closeDropdown);
            }
        };
        setTimeout(() => document.addEventListener('click', closeDropdown), 10);
    };

    window.toggleTerminal = function() {
        const sheet = document.getElementById('terminalSheet');
        if (sheet) sheet.classList.toggle('open');
    };

    window.loadRawScanResults = async function() {
        if (!elements.resultsContent) return;
        elements.resultsContent.textContent = '// Fetching engine report...';
        try {
            const response = await fetch(`${API_BASE_URL}/get_json_report`);
            const data = await response.json();
            if (response.ok) {
                elements.resultsContent.textContent = JSON.stringify(data.report || data, null, 2);
            } else {
                elements.resultsContent.textContent = '// Failed to load engine report.';
            }
        } catch (error) {
            elements.resultsContent.textContent = '// Error communicating with engine.';
        }
    };

    window.copyRawLogs = function() {
        if (elements.resultsContent) {
            navigator.clipboard.writeText(elements.resultsContent.innerText).then(() => {
                const btn = elements.copyResultsBtn || document.getElementById('copyResultsBtn');
                if (!btn) return;
                const originalIcon = btn.innerHTML;
                btn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 1.1rem;">check</span>';
                setTimeout(() => { btn.innerHTML = originalIcon; }, 2000);
            });
        }
    };

    // --- State & UI Helpers ---

    function switchTab(name) {
        const map = {
            summary: elements.summaryContent,
            packets: elements.packetsContent,
            graph: elements.graphContent,
            anomalies: elements.anomaliesContent,
            flows: elements.flowsContent,
        };
        const btnMap = {
            summary: elements.summaryTabBtn,
            packets: elements.packetsTabBtn,
            graph: elements.graphTabBtn,
            anomalies: elements.anomaliesTabBtn,
            flows: elements.flowsTabBtn,
        };

        Object.entries(map).forEach(([key, el]) => {
            if (el) el.classList.toggle('active', key === name);
        });

        Object.entries(btnMap).forEach(([key, btn]) => {
            if (btn) btn.classList.toggle('active', key === name);
        });
        
        if (name === 'graph' && networkInstance) {
             setTimeout(() => { networkInstance.fit(); }, 100);
        }
    }

    function toggleSpinner(button, isLoading) {
        if (!button) return;
        const spinnerSpan = button.querySelector('.spinner');
        const icon = button.querySelector('.material-symbols-outlined');

        button.disabled = isLoading;
        if (isLoading) {
            button.classList.add('cursor-not-allowed', 'opacity-70');
            if (icon) icon.classList.add('hidden');
            if (spinnerSpan) spinnerSpan.classList.remove('hidden');
        } else {
            button.classList.remove('opacity-70', 'cursor-not-allowed');
            if (icon) icon.classList.remove('hidden');
            if (spinnerSpan) spinnerSpan.classList.add('hidden');
        }
    }

    function appendLog(message) {
        if (!elements.snifferLogOutput) return;

        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });

        let cleanedMessage = message.replace(/\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s*/g, "").trim();

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
        
        line.innerHTML = `
            <div class="log-time">${timeStr}</div>
            <div class="log-content" style="${contentStyle}">${cleanedMessage}</div>
        `;
        
        elements.snifferLogOutput.appendChild(line);
        elements.snifferLogOutput.scrollTop = elements.snifferLogOutput.scrollHeight;
    }

    function setStatus(text, type = 'ready') {
        if (elements.snifferStatus) elements.snifferStatus.textContent = text.toUpperCase();
        if (!elements.scanStatus) return;
        
        elements.scanStatus.textContent = text.toUpperCase();
        elements.scanStatus.style.color = '#a1a1aa';

        if (type === 'busy') elements.scanStatus.style.color = '#eab308';
        else if (type === 'success') elements.scanStatus.style.color = '#10b981';
        else if (type === 'error') elements.scanStatus.style.color = '#ef4444';
    }

    // --- API HANDLER ---

    async function apiPost(endpoint, body = {}, button = null) {
        if (isActionInProgress) return null;
        isActionInProgress = true;
        if (button) toggleSpinner(button, true);

        if (!csrfToken) {
            appendLog('[x] Error: CSRF Token missing. Refresh page.');
            isActionInProgress = false;
            if (button) toggleSpinner(button, false);
            return null;
        }

        try {
            const res = await fetch(`${API_BASE_URL}${endpoint}`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken 
                },
                body: JSON.stringify(body),
            });
            const data = await res.json();
            
            if (!res.ok || data.status !== 'success') {
                throw new Error(data.message || `Request failed with ${res.status}`);
            }
            
            appendLog(`[✓] ${data.message}`);
            return data;
        } catch (err) {
            appendLog(`[x] Error: ${err.message}`);
            setStatus('Error occurred', 'error');
            return null;
        } finally {
            if (button) toggleSpinner(button, false);
            isActionInProgress = false;
        }
    }

    // --- SSE LOG STREAM ---

    function initializeLogStream() {
        if (eventSource) eventSource.close();
        eventSource = new EventSource(`${API_BASE_URL}/log_stream`);

        eventSource.onmessage = (evt) => {
            const msg = evt.data;
            if (!msg || msg.startsWith(':')) return;
            if (msg.includes("SYSTEM_EVENT: READY_FOR_ANALYSIS")) {
                checkReportAvailability();
            }

            const lower = msg.toLowerCase();
            if (lower.includes('capture complete') || lower.includes('analysis complete') || lower.includes('finished')) {
                setStatus('Processing report...', 'busy');
                if (elements.stopCaptureBtn) {
                     toggleSpinner(elements.stopCaptureBtn, false);
                     elements.stopCaptureBtn.disabled = true;
                }
                setTimeout(() => loadAndRenderReport(), 1000); 
            }

            if (msg.includes("EVENT:") || msg.startsWith("EVENT:")) return;
            appendLog(msg);
        };

        eventSource.onerror = () => {
            if (eventSource.readyState !== EventSource.CLOSED) {
                eventSource.close();
            }
        };
    }

    async function fetchHistory() {
        if (!elements.historyTableBody) return;
        elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-text-muted);">LOADING HISTORY...</td></tr>';
        
        try {
            const res = await fetch(`${API_BASE_URL}/report_history`);
            const data = await res.json();
            
            if (data.status === 'success' && data.history) {
                if (data.history.length === 0) {
                    elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-text-muted);">NO PRIOR SCANS FOUND</td></tr>';
                    return;
                }
                
                elements.historyTableBody.innerHTML = '';
                data.history.forEach(item => {
                    const row = document.createElement('tr');
                    let target = item.filename.split('_').slice(2).join('_').replace('.pdf', '');
                    if (!target || target === 'report') target = 'Previous Scan';
                    
                    row.innerHTML = `
                        <td style="padding: 1rem; font-size: 0.7rem; color: var(--neo-text-main); font-family: var(--font-mono);">${item.created_at}</td>
                        <td style="padding: 1rem; font-size: 0.7rem; color: var(--neo-blue); font-family: var(--font-mono);">${target}</td>
                        <td style="padding: 1rem; text-align: right;">
                            <a href="${API_BASE_URL}/download_pdf?filename=${item.filename}" class="btn-dash btn-secondary" style="display: inline-flex; height: 36px; padding: 0 12px; border-radius: 8px;">
                                <span class="material-symbols-outlined" style="font-size: 1.1rem;">download</span>
                            </a>
                        </td>
                    `;
                    elements.historyTableBody.appendChild(row);
                });
            } else {
                elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-red);">FAILED TO LOAD HISTORY</td></tr>';
            }
        } catch (e) {
            console.error('History fetch failed:', e);
            elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 3rem; color: var(--neo-red);">ERROR LOADING HISTORY</td></tr>';
        }
    }

    // --- RENDERING LOGIC ---

    async function loadAndRenderReport() {
        try {
            const res = await fetch(`${API_BASE_URL}/get_json_report`);
            const data = await res.json();
            
            if (!res.ok || data.status === 'error') return;
            
            const report = data.report || data;
            renderSummary(report);
            renderFlows(report);
            renderAnomalies(report);
            renderPackets(report);
            renderGraph(report);
            setStatus('Analysis Complete', 'success');
        } catch (e) {
            console.error(e);
            appendLog('[x] Failed to fetch sniffer report.');
        }
    }

    function renderSummary(report) {
        const ts = report.traffic_summary || {};
        const protoStats = ts.protocol_hierarchy_stats || ts.protocol_distribution || [];
        const tcpStats = ts.tcp_conversation_stats || ts.tcp_conversations || [];

        const totalPackets = ts.summary_io?.total_packets ?? ts.total_packets ?? (Array.isArray(report.dissected_packets) ? report.dissected_packets.length : 0);
        const totalBytes = ts.summary_io?.total_bytes ?? ts.total_bytes ?? 0;
        const dur = ts.effective_capture_duration_seconds ?? report.analysis_time_seconds ?? 0;
        const avgRate = ts.average_rate_bps ?? 0;

        if(elements.summaryTotalPackets) elements.summaryTotalPackets.textContent = totalPackets;
        if(elements.summaryTotalBytes) elements.summaryTotalBytes.textContent = totalBytes > 0 ? `${(totalBytes / 1024).toFixed(2)} KB` : '0 B';
        if(elements.avgRateDisplay) elements.avgRateDisplay.textContent = `${(avgRate / 1024).toFixed(1)} Kbps`;
        
        let primaryProto = 'N/A';
        if (Array.isArray(protoStats) && protoStats.length > 0) {
            const realProtoLines = protoStats.filter(l => l.trim() && !l.trim().startsWith('=') && !l.includes('Protocol Hierarchy'));
            const line = realProtoLines.find((l) => l.toLowerCase().includes('http') || l.toLowerCase().includes('tcp')) || realProtoLines[realProtoLines.length - 1];
            if (line) {
                const parts = line.trim().split(/\s+/);
                primaryProto = parts[0] || 'N/A';
            }
        }
        if(elements.summaryPrimaryProto) elements.summaryPrimaryProto.textContent = primaryProto.toUpperCase();

        if (elements.captureMetaBody) {
            elements.captureMetaBody.innerHTML = '';
            const metaRows = [
                ['Timestamp', report.timestamp || 'N/A'],
                ['Duration', `${(report.analysis_time_seconds || 0).toFixed(2)}s`],
                ['IP Range', report.target_ip || 'All Interfaces'],
            ];
            metaRows.forEach(([k, v]) => {
                elements.captureMetaBody.insertAdjacentHTML('beforeend',
                    `<tr><td>${k}</td><td style="text-align:right">${v}</td></tr>`
                );
            });
        }

        renderProtocolTable(protoStats);
        renderConversationTable(tcpStats);
    }

    function renderProtocolTable(lines) {
        if (!elements.protocolStatsBody) return;
        elements.protocolStatsBody.innerHTML = '';
        if (!Array.isArray(lines) || lines.length === 0) {
            elements.protocolStatsBody.innerHTML = `<tr><td colspan="3" style="text-align:center; padding: 2rem; color: var(--neo-text-muted)">Scanning for traffic...</td></tr>`;
            return;
        }
        const regex = /([a-zA-Z0-9\-\._]+)\s+frames:(\d+)\s+bytes:(\d+)/;
        lines.forEach(line => {
            const match = line.match(regex);
            if (match) {
                const name = match[1];
                const frames = match[2];
                const bytes = parseInt(match[3], 10);
                elements.protocolStatsBody.insertAdjacentHTML('beforeend', 
                    `<tr>
                        <td style="color:var(--neo-blue)">${name}</td>
                        <td style="text-align:right">${frames}</td>
                        <td style="text-align:right">${(bytes/1024).toFixed(1)} KB</td>
                    </tr>`
                );
            }
        });
    }

    function renderConversationTable(lines) {
        if (!elements.conversationStatsBody) return;
        elements.conversationStatsBody.innerHTML = '';
        const validLines = (lines || []).filter(l => l.includes('<->'));
        if (validLines.length === 0) {
            elements.conversationStatsBody.innerHTML = `<tr><td style="color: var(--neo-text-muted)">WAITING...</td></tr>`;
            return;
        }
        validLines.forEach(line => {
            const splitArrow = line.split('<->');
            if (splitArrow.length !== 2) return;
            const left = splitArrow[0].trim();
            const right = splitArrow[1].trim().split(/\s+/)[0]; 
            let bytes = '-';
            const bytesMatch = line.match(/\s(\d+)\s+bytes/); 
            if(bytesMatch) bytes = bytesMatch[1];
            elements.conversationStatsBody.insertAdjacentHTML('beforeend',
                `<tr><td colspan="3" style="font-size: 0.65rem;">${left} <span style="color:var(--neo-blue)">↔</span> ${right} (${bytes} B)</td></tr>`
            );
        });
    }

    function renderFlows(report) {
        if (!elements.flowsTableBody) return;
        const flows = (report.application_flow_analysis || {}).flows || [];
        elements.flowsTableBody.innerHTML = '';
        if (!flows.length) {
            elements.flowsTableBody.innerHTML = `<tr><td colspan="3" style="text-align:center; padding: 2rem; color: var(--neo-text-muted);">---</td></tr>`;
            return;
        }
        flows.forEach((flow) => {
            elements.flowsTableBody.insertAdjacentHTML('beforeend',
                `<tr>
                    <td class="truncate" style="max-width:80px">${flow.src_ip}</td>
                    <td class="truncate" style="max-width:80px">${flow.dst_ip}</td>
                    <td style="color:var(--neo-green)">${flow.method || '-'}</td>
                </tr>`
            );
        });
    }

    function renderAnomalies(report) {
        const ar = report.security_anomaly_report || {};
        if (elements.anomalySummaryText) elements.anomalySummaryText.textContent = ar.summary || 'No active threats detected.';
        if (elements.cleartextBody) elements.cleartextBody.textContent = (ar.cleartext_credentials && ar.cleartext_credentials.length) ? JSON.stringify(ar.cleartext_credentials, null, 2) : 'SAFE';
        if (elements.portScansBody) elements.portScansBody.textContent = (ar.port_scans && ar.port_scans.length) ? JSON.stringify(ar.port_scans, null, 2) : 'NONE';
    }

    function renderPackets(report) {
        if (!elements.packetsTableBody) return;
        const packets = report.dissected_packets || [];
        elements.packetsTableBody.innerHTML = '';
        if (!packets.length) {
            elements.packetsTableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 4rem; color: var(--neo-text-muted);">IDLE</td></tr>`;
            return;
        }
        packets.slice(0, 100).forEach((pkt) => {
            const layers = (pkt && pkt._source && pkt._source.layers) || {};
            const frame = layers.frame || {};
            const ip = layers.ip || layers.ipv6 || {};
            const frameNum = frame['frame.number'] || '?';
            const src = ip['ip.src'] || ip['ipv6.src'] || 'N/A';
            const dst = ip['ip.dst'] || ip['ipv6.dst'] || 'N/A';
            let proto = 'TCP';
            if (frame['frame.protocols']) {
                const pts = frame['frame.protocols'].split(':');
                proto = pts[pts.length - 1].toUpperCase();
            }
            elements.packetsTableBody.insertAdjacentHTML('beforeend',
                `<tr>
                    <td>${frameNum}</td>
                    <td class="truncate">${src}</td>
                    <td class="truncate">${dst}</td>
                    <td style="color:var(--neo-blue)">${proto}</td>
                    <td>${frame['frame.len']}</td>
                </tr>`
            );
        });
    }

    function renderGraph(report) {
        if (!elements.networkGraphCanvas) return;
        const ts = report.traffic_summary || {};
        const lines = ts.tcp_conversation_stats || ts.tcp_conversations || [];
        const nodesMap = new Map(); 
        const edges = [];

        lines.forEach(line => {
            if (!line.includes('<->')) return;
            const parts = line.split('<->');
            const leftFull = parts[0].trim();
            const rightFull = parts[1].trim().split(/\s+/)[0]; 
            const srcIp = leftFull.split(':')[0];
            const dstIp = rightFull.split(':')[0];
            if(!srcIp || !dstIp) return;
            let bytes = 0;
            const bytesMatch = line.match(/\s(\d+)\s+bytes/); 
            if(bytesMatch) bytes = parseInt(bytesMatch[1], 10);
            
            [srcIp, dstIp].forEach(ip => {
                if (!nodesMap.has(ip)) nodesMap.set(ip, { id: ip, label: ip, value: 0 });
                nodesMap.get(ip).value += bytes;
            });
            edges.push({ from: srcIp, to: dstIp, value: bytes });
        });

        const data = { 
            nodes: Array.from(nodesMap.values()).map(n => ({ ...n, value: Math.log(n.value + 1) })), 
            edges: edges 
        };
        const options = {
            nodes: { shape: 'dot', font: { color: '#fff', size: 10 } },
            edges: { color: { color: '#444' } },
            physics: { stabilization: true },
            interaction: { zoomView: false, dragView: true }
        };
        if (networkInstance) {
            networkInstance.setData(data);
        } else {
            networkInstance = new vis.Network(elements.networkGraphCanvas, data, options);
        }
    }

    // --- DOWNLOAD & AI LOGIC ---

    async function checkReportAvailability() {
        const target = elements.targetIpInput ? elements.targetIpInput.value.trim().toLowerCase() : "";
        try {
            const url = target ? `${API_BASE_URL}/report_files?target=${encodeURIComponent(target)}` : `${API_BASE_URL}/report_files`;
            const res = await fetch(url);
            const data = await res.json();
                if (res.ok && data.status === 'success' && data.pdf_report) {
                    reportDownloadUrl = data.pdf_report;
                    if (elements.snifferDownloadReportBtn) {
                        elements.snifferDownloadReportBtn.disabled = false;
                        elements.snifferDownloadReportBtn.style.opacity = '1';
                        elements.snifferDownloadReportBtn.classList.remove('cursor-not-allowed');
                    }
                    if (elements.snifferAnalyzeReportDropdown) {
                        elements.snifferAnalyzeReportDropdown.disabled = false;
                        elements.snifferAnalyzeReportDropdown.style.opacity = '1';
                        elements.snifferAnalyzeReportDropdown.classList.remove('cursor-not-allowed');
                    }
                    return;
                }
            } catch (e) {}

            reportDownloadUrl = null;
            if (elements.snifferDownloadReportBtn) {
                elements.snifferDownloadReportBtn.disabled = true;
                elements.snifferDownloadReportBtn.style.opacity = '0.5';
                elements.snifferDownloadReportBtn.classList.add('cursor-not-allowed');
            }
            if (elements.snifferAnalyzeReportDropdown) {
                elements.snifferAnalyzeReportDropdown.disabled = false;
            }
        }

        async function analyzeReport(llmMode) {
            const button = elements.snifferAnalyzeReportDropdown;
            const overlay = elements.aiProcessingOverlay;
            const processingText = elements.aiProcessingText;
            const target = elements.targetIpInput.value.trim().toLowerCase();

            if (!button || button.disabled) return;
            if (overlay) overlay.classList.remove('hidden');
            if (processingText) processingText.textContent = 'INITIATING AI...';

            setStatus(`AI analysis (${llmMode})...`, 'busy');

            try {
                let res = await fetch(`${API_BASE_URL}/trigger_ai_analysis`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                    body: JSON.stringify({ llm_mode: llmMode, target: target }),
                });
                let data = await res.json();
                if (data.status !== 'success') throw new Error(data.message);

                if (processingText) processingText.textContent = 'SYNTHESIZING...';

                res = await fetch(`${CHATBOT_REDIRECT_URL}/scanner_analysis`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                    body: JSON.stringify({ llm_mode: llmMode, scanner_type: 'packet_sniffer', target: data.target, force_new_session: true })
                });
                const aiData = await res.json();

                if (res.ok && aiData.status === 'success') {
                    if (processingText) processingText.textContent = 'REDIRECTING...';
                    setTimeout(() => {
                        window.location.href = `${CHATBOT_REDIRECT_URL}?mode=${aiData.llm_mode}&summary=${encodeURIComponent(aiData.summary)}&session_id=${aiData.session_id}`;
                    }, 800);
                } else { throw new Error(aiData.message || 'Analysis redirection failed'); }
            } catch (error) {
                appendLog(`[x] AI Error: ${error.message}`);
                if (overlay) overlay.classList.add('hidden');
            } 
        }

        // --- Event Listeners ---
        function setupEventListeners() {
            if(elements.startCaptureBtn) {
                elements.startCaptureBtn.addEventListener('click', () => {
                    const target = elements.targetIpInput.value.trim().toLowerCase();
                    const dur = elements.durationInput.value;
                    const max = elements.maxPacketsInput.value;
                    const bpf = elements.bpfFilterInput.value;
                    apiPost('/start_capture', { target_ip: target, duration: parseInt(dur), max_packets: parseInt(max), bpf_filter: bpf }, elements.startCaptureBtn);
                });
            }
            
            if(elements.stopCaptureBtn) {
                elements.stopCaptureBtn.addEventListener('click', () => {
                    apiPost('/stop_capture', {}, elements.stopCaptureBtn);
                });
            }

            if(elements.graphFitBtn) {
                elements.graphFitBtn.addEventListener('click', () => {
                    if(networkInstance) networkInstance.fit();
                });
            }

            // Tab Switching
            const tabs = ['summary', 'packets', 'graph', 'anomalies', 'flows'];
            tabs.forEach(t => {
                const btn = elements[`${t}TabBtn`];
                if(btn) btn.addEventListener('click', () => switchTab(t));
            });

            // AI Dropdown
            if (elements.snifferLlmAnalysisOptions) {
                elements.snifferLlmAnalysisOptions.addEventListener('click', (e) => {
                    e.preventDefault();
                    const opt = e.target.closest('[data-llm-mode]');
                    if(opt) analyzeReport(opt.dataset.llmMode);
                });
            }

            if(elements.snifferDownloadReportBtn) {
                elements.snifferDownloadReportBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    if (!elements.snifferDownloadReportBtn.disabled && reportDownloadUrl) {
                        window.location.href = reportDownloadUrl;
                        appendLog('[✓] Downloading PDF report...');
                    } else {
                        appendLog('[!] No report available yet.');
                    }
                });
            }

            if(elements.clearSnifferLogBtn) {
                elements.clearSnifferLogBtn.addEventListener('click', () => {
                    elements.snifferLogOutput.innerHTML = '';
                });
            }
            
            // Advanced Toggle
            const advToggle = document.getElementById('advancedScanToggle');
            if(advToggle) {
                advToggle.addEventListener('click', () => {
                    document.getElementById('advancedScanOptions').classList.toggle('hidden');
                });
            }

            if (elements.snifferHistoryBtn) {
                elements.snifferHistoryBtn.addEventListener('click', () => {
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
        }

        // --- Init ---
        setupEventListeners();
        initializeLogStream();
        checkReportAvailability();
        loadAndRenderReport();
        appendLog('Packet Sniffer Mobile Ready.');
    });
