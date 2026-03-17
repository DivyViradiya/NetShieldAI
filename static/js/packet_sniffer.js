document.addEventListener('DOMContentLoaded', () => {
    const elements = {
        // Inputs
        targetIpInput: document.getElementById('snifferTargetIp'),
        durationInput: document.getElementById('captureDuration'),
        maxPacketsInput: document.getElementById('maxPackets'),
        bpfFilterInput: document.getElementById('bpfFilter'),
        interfaceSelect: document.getElementById('interfaceSelect'),
        advancedScanToggle: document.getElementById('advancedScanToggle'),
        advancedScanOptions: document.getElementById('advancedScanOptions'),

        // Buttons
        startCaptureBtn: document.getElementById('startCaptureBtn'),
        stopCaptureBtn: document.getElementById('stopCaptureBtn'),
        refreshSnifferResultsBtn: document.getElementById('refreshSnifferResultsBtn'),
        snifferDownloadReportBtn: document.getElementById('snifferDownloadReportBtn'),
        snifferHistoryBtn: document.getElementById('snifferHistoryBtn'),
        historyModal: document.getElementById('historyModal'),
        closeHistoryModal: document.getElementById('closeHistoryModal'),
        historyTableBody: document.getElementById('historyTableBody'),
        
        // Dropdowns & Analysis
        snifferAnalyzeReportDropdown: document.getElementById('snifferAnalyzeReportDropdown'),
        snifferLlmAnalysisOptions: document.getElementById('snifferLlmAnalysisOptions'),
        
        // AI Animation Elements
        aiProcessingOverlay: document.getElementById('aiProcessingOverlay'),
        aiProcessingText: document.getElementById('aiProcessingText'),
        
        // Status & Logs
        snifferStatus: document.getElementById('snifferStatus'),
        snifferLogOutput: document.getElementById('snifferLogOutput'),
        clearSnifferLogBtn: document.getElementById('clearSnifferLogBtn'),

        // Header Metrics
        packetCountDisplay: document.getElementById('packetCountDisplay'),
        targetDisplay: document.getElementById('targetDisplay'),
        durationDisplay: document.getElementById('durationDisplay'),
        avgRateDisplay: document.getElementById('avgRateDisplay'),

        // Tab Buttons
        summaryTabBtn: document.getElementById('summaryTabBtn'),
        flowsTabBtn: document.getElementById('flowsTabBtn'),
        anomaliesTabBtn: document.getElementById('anomaliesTabBtn'),
        packetsTabBtn: document.getElementById('packetsTabBtn'),
        graphTabBtn: document.getElementById('graphTabBtn'),

        // Tab Content
        summaryContent: document.getElementById('summaryContent'),
        flowsContent: document.getElementById('flowsContent'),
        anomaliesContent: document.getElementById('anomaliesContent'),
        packetsContent: document.getElementById('packetsContent'),
        graphContent: document.getElementById('graphContent'),

        // Graph
        networkGraphCanvas: document.getElementById('networkGraphCanvas'),
        graphZoomInBtn: document.getElementById('graphZoomInBtn'),
        graphZoomOutBtn: document.getElementById('graphZoomOutBtn'),
        graphFitBtn: document.getElementById('graphFitBtn'),

        // Summary Data
        summaryStatus: document.getElementById('summaryStatus'),
        summaryTotalPackets: document.getElementById('summaryTotalPackets'),
        summaryTotalBytes: document.getElementById('summaryTotalBytes'),
        summaryPrimaryProto: document.getElementById('summaryPrimaryProto'),
        captureMetaBody: document.getElementById('captureMetaBody'),
        protocolStatsBody: document.getElementById('protocolStatsBody'),
        conversationStatsBody: document.getElementById('conversationStatsBody'),

        // Tables
        flowsTableBody: document.getElementById('flowsTableBody'),
        anomalySummaryText: document.getElementById('anomalySummaryText'),
        portScansBody: document.getElementById('portScansBody'),
        cleartextBody: document.getElementById('cleartextBody'),
        packetsTableBody: document.getElementById('packetsTableBody'),
    };

    const API_BASE_URL = '/packet_sniffer';
    const CHATBOT_REDIRECT_URL = '/chatbot';

    let isActionInProgress = false;
    let reportDownloadUrl = null;
    let eventSource = null;
    let networkInstance = null; 

    // --- 🔒 CSRF TOKEN ---
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

    // --- UI HELPERS ---

    function toggleSpinner(button, isLoading) {
        if (!button) return;
        var spinner = button.querySelector('.spinner');
        var icon = button.querySelector('.material-symbols-outlined'); 
        
        if (button.id !== 'snifferAnalyzeReportDropdown') {
            button.disabled = isLoading;
        }
        if (isLoading) {
            button.classList.add('cursor-not-allowed', 'opacity-70');
            if (spinner) spinner.classList.remove('hidden');
            if (icon && !icon.textContent.includes('expand_more')) icon.classList.add('hidden'); 
        } else {
            button.classList.remove('opacity-70', 'cursor-not-allowed');
            if (spinner) spinner.classList.add('hidden');
            if (icon) icon.classList.remove('hidden');
        }
    }

    // --- LOG APPEND FUNCTION ---
    function appendLog(message) {
        if (!elements.snifferLogOutput) return;

        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });

        let cleanedMessage = message.replace(/\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s*/g, "");
        cleanedMessage = cleanedMessage.replace(/^\[?\d{1,2}:\d{2}:\d{2}\]?\s*/, '');
        cleanedMessage = cleanedMessage.replace(/(\[[A-Z]+\])\s*\1/g, '$1');
        cleanedMessage = cleanedMessage.trim();

        if (!cleanedMessage || cleanedMessage === '|' || cleanedMessage.includes('deprecated method')) return;

        let contentStyle = '';
        if (cleanedMessage.includes('[!]') || cleanedMessage.includes('Error')) {
            contentStyle = 'color: var(--neo-red);';
        } else if (cleanedMessage.includes('[+]') || cleanedMessage.includes('Success')) {
            contentStyle = 'color: var(--neo-green);';
        } else if (cleanedMessage.includes('[*]')) {
            contentStyle = 'color: var(--neo-blue);';
        }
    
        const line = document.createElement('div');
        line.className = 'log-line';
        
        line.innerHTML = `
            <div class="log-time" style="color: var(--neo-text-muted); font-family: var(--font-mono); font-size: 0.75rem;">${timeStr}</div>
            <div class="log-content" style="${contentStyle} font-family: var(--font-mono); font-size: 0.8rem;">${cleanedMessage}</div>
        `;
        
        elements.snifferLogOutput.appendChild(line);
        elements.snifferLogOutput.scrollTop = elements.snifferLogOutput.scrollHeight;
    }

    function setStatus(text, type = 'ready') {
        if (!elements.snifferStatus) return;
        
        elements.snifferStatus.textContent = text.toUpperCase();
        
        elements.snifferStatus.style.color = 'var(--neo-text-muted)';
        
        if (type === 'busy') elements.snifferStatus.style.color = 'var(--neo-amber)';
        else if (type === 'success') elements.snifferStatus.style.color = 'var(--neo-green)';
        else if (type === 'error') elements.snifferStatus.style.color = 'var(--neo-red)';
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

    // --- TABS LOGIC ---

    function switchTab(name) {
        const map = {
            summary: elements.summaryContent,
            flows: elements.flowsContent,
            anomalies: elements.anomaliesContent,
            packets: elements.packetsContent,
            graph: elements.graphContent,
        };
        const btnMap = {
            summary: elements.summaryTabBtn,
            flows: elements.flowsTabBtn,
            anomalies: elements.anomaliesTabBtn,
            packets: elements.packetsTabBtn,
            graph: elements.graphTabBtn,
        };

        Object.entries(map).forEach(([key, el]) => {
            if (!el) return;
            if (key === name) {
                el.classList.remove('hidden');
                el.classList.add('active');
            } else {
                el.classList.add('hidden');
                el.classList.remove('active');
            }
        });

        Object.entries(btnMap).forEach(([key, btn]) => {
            if (!btn) return;
            btn.classList.toggle('active', key === name);
        });
        
        if (name === 'graph') {
             setTimeout(() => {
                 mountGraphIfNeeded(); // Deferred graph creation — canvas now has real dimensions
                 if (networkInstance) {
                     networkInstance.redraw();
                     networkInstance.fit();
                 }
             }, 100);
        }
    }

    // --- SSE LOG STREAM (UPDATED) ---

    function initializeLogStream() {
        if (eventSource) eventSource.close();
        eventSource = new EventSource(`${API_BASE_URL}/log_stream`);

        eventSource.onmessage = (evt) => {
            const msg = evt.data;
            if (!msg || msg.startsWith(':')) return;
            if (msg.includes("SYSTEM_EVENT: READY_FOR_ANALYSIS")) {
                isActionInProgress = false;
                if (elements.startCaptureBtn) toggleSpinner(elements.startCaptureBtn, false);
                setStatus('System Ready', 'success');
                checkReportAvailability();
            }

            const lower = msg.toLowerCase();
            // FIX: Ensure we switch to packets tab when capture is done
            if (lower.includes('capture complete') || lower.includes('analysis complete') || lower.includes('finished')) {
                setStatus('Processing report...', 'busy');
                if (elements.stopCaptureBtn) {
                     toggleSpinner(elements.stopCaptureBtn, false);
                     elements.stopCaptureBtn.disabled = true;
                }
                setTimeout(() => loadAndRenderReport(), 1000); 
            }

            // Only trigger UI failure on definitive scan-failure events, not incidental log lines.
            if (msg.includes("[!] Packet capture failed") || msg.includes("Scan failed to produce") || msg.includes("capture_failed") || msg.includes("analysis_failed")) {
                setStatus('Scan Failed', 'error');
                isActionInProgress = false;
                if (elements.startCaptureBtn) toggleSpinner(elements.startCaptureBtn, false);
            }

            if (msg.includes("EVENT:") || msg.startsWith("EVENT:")) return;
            appendLog(msg);
        };
        // Let the browser handle SSE auto-reconnects natively if disconnected
    }

    // --- RENDERING LOGIC ---

    async function loadAndRenderReport() {
        try {
            const target = elements.targetIpInput ? elements.targetIpInput.value.trim() : "";
            const url = target 
                ? `${API_BASE_URL}/get_json_report?target=${encodeURIComponent(target)}`
                : `${API_BASE_URL}/get_json_report`;

            const res = await fetch(url);
            const data = await res.json();
            
            if (!res.ok || data.status === 'error') {
                return;
            }
            
            const report = data.report || data;
            renderSummary(report);
            renderFlows(report);
            renderAnomalies(report);
            renderPackets(report);
            renderGraph(report);
        } catch (e) {
            console.error(e);
            appendLog('[x] Failed to fetch sniffer report.');
        }
    }

    function renderSummary(report) {
        const ts = report.traffic_summary || {};
        const protoStats = ts.protocol_distribution || ts.protocol_hierarchy_stats || [];
        const tcpStats = ts.tcp_conversations || ts.tcp_conversation_stats || [];
        
        let extractedPackets = 0;
        let extractedBytes = 0;
        
        // Scan protocol stats for total packets/bytes at the 'frame' level
        for (const line of protoStats) {
            if (line.includes('frame') && line.includes('frames:')) {
                const parts = line.split('frames:');
                if (parts.length > 1) {
                    extractedPackets = parseInt(parts[1].split(' ')[0], 10) || 0;
                }
                const bytesParts = line.split('bytes:');
                if (bytesParts.length > 1) {
                    extractedBytes = parseInt(bytesParts[1], 10) || 0;
                }
                break;
            }
        }

        const totalPackets = ts.summary_io?.total_packets ?? ts.total_packets ?? extractedPackets ?? (Array.isArray(report.dissected_packets) ? report.dissected_packets.length : 0);
        const totalBytes = ts.summary_io?.total_bytes ?? ts.total_bytes ?? extractedBytes ?? 0;
        const dur = ts.effective_capture_duration_seconds ?? report.analysis_time_seconds ?? report.capture_duration ?? 0;
        const avgRate = dur > 0 ? (totalBytes * 8) / dur : 0;

        if(elements.packetCountDisplay) elements.packetCountDisplay.textContent = totalPackets;
        if(elements.durationDisplay) elements.durationDisplay.textContent = `${dur.toFixed(1)}s`;
        if(elements.avgRateDisplay) elements.avgRateDisplay.textContent = `${(avgRate / 1024).toFixed(1)} Kbps`;
        
        const targetDisplay = report.target_ip || 'Any';
        if(elements.targetDisplay) elements.targetDisplay.textContent = targetDisplay;

        if(elements.summaryTotalPackets) elements.summaryTotalPackets.textContent = totalPackets;
        if(elements.summaryTotalBytes) elements.summaryTotalBytes.textContent = totalBytes > 0 ? `${(totalBytes / 1024).toFixed(2)} KB` : '0 B';
        if(elements.summaryStatus) elements.summaryStatus.textContent = (report.status || 'Done').toUpperCase();

        let primaryProto = 'N/A';
        if (Array.isArray(protoStats) && protoStats.length > 0) {
            const realProtoLines = protoStats.filter(l => l.trim() && !l.trim().startsWith('=') && !l.includes('Protocol Hierarchy') && !l.includes('frame') && !l.includes('eth') && !l.includes('ip') && !l.includes('tcp') && !l.includes('udp'));
            
            if (realProtoLines.length > 0) {
                const line = realProtoLines.find((l) => l.toLowerCase().includes('http') || l.toLowerCase().includes('tls') || l.toLowerCase().includes('quic')) || realProtoLines[realProtoLines.length - 1];
                if (line) {
                    primaryProto = line.trim().split(/\s+/)[0] || 'N/A';
                }
            }
        }
        if(elements.summaryPrimaryProto) elements.summaryPrimaryProto.textContent = primaryProto.toUpperCase();

        const tsDate = new Date(report.timestamp || Date.now());
        const timeStr = tsDate.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });

        const metaRows = [
            ['Time', timeStr],
            ['Target', targetDisplay],
            ['File', report.pcap_file ? report.pcap_file.split(/[\\/]/).pop() : 'N/A'], 
            ['Packets Analysed', totalPackets],
        ];
        
        if (elements.captureMetaBody) {
            elements.captureMetaBody.innerHTML = '';
            metaRows.forEach(([k, v]) => {
                elements.captureMetaBody.insertAdjacentHTML('beforeend',
                    `<tr>
                        <td class="px-4 py-2 text-xs font-medium" style="color: var(--neo-text-muted);">${k}</td>
                        <td class="px-4 py-2 text-xs font-mono text-right" style="color: var(--neo-text-main);">${v}</td>
                    </tr>`
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
            elements.protocolStatsBody.innerHTML = `<tr><td colspan="3" class="px-4 py-4 text-center" style="color: var(--neo-text-muted);">No data available.</td></tr>`;
            return;
        }
    
        const regex = /([a-zA-Z0-9\-\._]+)\s+frames:(\d+)\s+bytes:(\d+)/;
        
        // Ensure we filter out decorative elements
        const validLines = lines.filter(l => l.includes('frames:') && l.includes('bytes:'));
        
        if (validLines.length === 0) {
            elements.protocolStatsBody.innerHTML = `<tr><td colspan="3" class="px-4 py-4 text-center" style="color: var(--neo-text-muted);">No protocol hierarchy mapped.</td></tr>`;
            return;
        }
    
        validLines.forEach(line => {
            const match = line.match(regex);
            if (match) {
                const name = match[1];
                const frames = match[2];
                const bytes = parseInt(match[3], 10);
                
                const leadingSpaces = line.search(/\S|$/);
                const indent = Math.max(0, (leadingSpaces / 2) * 10); 
    
                elements.protocolStatsBody.insertAdjacentHTML('beforeend', 
                    `<tr style="transition: background-color 0.2s;" onmouseover="this.style.backgroundColor='var(--neo-card-hover)'" onmouseout="this.style.backgroundColor='transparent'">
                        <td class="px-4 py-2 text-xs font-mono" style="padding-left: ${indent + 16}px; color: var(--neo-blue);">${name}</td>
                        <td class="px-4 py-2 text-xs font-mono text-right" style="color: var(--neo-text-main);">${frames}</td>
                        <td class="px-4 py-2 text-xs font-mono text-right" style="color: var(--neo-text-muted);">${(bytes/1024).toFixed(1)} KB</td>
                    </tr>`
                );
            }
        });
    }

    function renderConversationTable(lines) {
        if (!elements.conversationStatsBody) return;
        elements.conversationStatsBody.innerHTML = '';
        const textSecondary = 'var(--neo-text-muted)';
    
        const validLines = (lines || []).filter(l => l.includes('<->'));
    
        if (validLines.length === 0) {
            elements.conversationStatsBody.innerHTML = `<tr><td colspan="4" class="px-4 py-4 text-center" style="color: var(--neo-text-muted);">No conversations recorded.</td></tr>`;
            return;
        }
    
        validLines.forEach(line => {
            if (!line.includes('\u2192') && !line.includes('<->')) return; // skip headers
            
            let leftSide, rightSide, bytes, proto;
            
            // Format 1: 1   0.000000 34.54.84.110 -> 192.168.29.48 TLSv1.2 140 Application Data
            if (line.includes('\u2192')) {
                const parts = line.split(/\s+/).filter(Boolean);
                // The arrow is usually parts[3]
                const arrowIdx = parts.indexOf('\u2192');
                if (arrowIdx > 0) {
                    leftSide = parts[arrowIdx - 1];
                    rightSide = parts[arrowIdx + 1];
                    proto = parts[arrowIdx + 2];
                    bytes = parts[arrowIdx + 3] || '-';
                    // Make it look conversational
                    leftSide = `${leftSide} (${proto})`;
                }
            } else if (line.includes('<->')) {
                // Format 2: raw tshark tstat format
                const splitArrow = line.split('<->');
                leftSide = splitArrow[0].trim();
                const rightSideRaw = splitArrow[1].trim();
                const rightParts = rightSideRaw.split(/\s+/);
                rightSide = rightParts[0]; 
        
                bytes = '-';
                const bytesMatch = line.match(/\s(\d+)\s+bytes/); 
                if(bytesMatch) {
                    bytes = bytesMatch[1];
                } else if (rightParts.length >= 4) {
                     bytes = rightParts[rightParts.length - 2] || '?';
                }
            }
            
            if (!leftSide || !rightSide) return;
    
            elements.conversationStatsBody.insertAdjacentHTML('beforeend',
                `<tr style="transition: background-color 0.2s;" onmouseover="this.style.backgroundColor='var(--neo-card-hover)'" onmouseout="this.style.backgroundColor='transparent'">
                    <td class="px-4 py-2 text-xs font-mono truncate max-w-[150px]" style="color: var(--neo-green);" title="${leftSide}">${leftSide}</td>
                    <td class="px-4 py-2 text-center"><i class="fas fa-exchange-alt text-[10px]" style="color: ${textSecondary};"></i></td>
                    <td class="px-4 py-2 text-xs font-mono truncate max-w-[150px]" style="color: var(--neo-blue);" title="${rightSide}">${rightSide}</td>
                    <td class="px-4 py-2 text-xs font-mono text-right" style="color: var(--neo-text-main);">${bytes}</td>
                </tr>`
            );
        });
    }

    function renderFlows(report) {
        if (!elements.flowsTableBody) return;
    
        const flowsObj = report.application_flow_analysis || {};
        // Match both 'flows' and 'application_flows' depending on API
        const flows = flowsObj.flows || flowsObj.application_flows || report.application_flows || [];
        
        elements.flowsTableBody.innerHTML = '';
        const isLight = document.body.classList.contains("light-mode");
        const textPrimary = isLight ? 'text-slate-700' : 'text-slate-300';
        const textSecondary = isLight ? 'text-slate-500' : 'text-slate-400';
        const hoverBg = isLight ? 'hover:bg-slate-100' : 'hover:bg-slate-800/50';
    
        if (!flows.length) {
            elements.flowsTableBody.innerHTML = `<tr><td colspan="6" class="p-12 text-center text-sm ${textSecondary}">No HTTP/Application flows recorded.</td></tr>`;
            return;
        }
    
        flows.forEach((flow) => {
            const resp = (flow.response_code || flow.response_phrase || flow.status) ? `${flow.response_code || flow.status || ''} ${flow.response_phrase || ''}`.trim() : '-';
    
            elements.flowsTableBody.insertAdjacentHTML('beforeend',
                `<tr class="${hoverBg} transition-colors">
                    <td class="px-6 py-3 text-xs font-mono ${textSecondary}">${flow.timestamp || ''}</td>
                    <td class="px-6 py-3 text-xs font-mono text-blue-400">${flow.src_ip || '-'}</td>
                    <td class="px-6 py-3 text-xs font-mono text-emerald-400">${flow.dst_ip || '-'}</td>
                    <td class="px-6 py-3 text-xs font-bold ${textPrimary}">${flow.method || '-'}</td>
                    <td class="px-6 py-3 text-xs truncate max-w-[200px] ${textPrimary}" title="${flow.uri}">${flow.uri || '-'}</td>
                    <td class="px-6 py-3 text-xs ${textPrimary}">${resp}</td>
                </tr>`
            );
        });
    }

    function renderAnomalies(report) {
        let ar = report.security_anomaly_report || {};
        
        // Handle alternative backend payload structures
        if (!ar.summary && report.security_anomalies_detected) {
             ar = report.security_anomalies_detected;
        }
        
        if (elements.anomalySummaryText) elements.anomalySummaryText.textContent = ar.summary || 'No anomalies detected.';
        
        const isLight = document.body.classList.contains("light-mode");
        const textSecondary = isLight ? 'text-slate-500' : 'text-slate-500';
        const textCode = isLight ? 'text-slate-800' : 'text-slate-300';
        const bgCode = isLight ? 'bg-slate-100' : 'bg-slate-950/50';
        const borderCode = isLight ? 'border-slate-200' : 'border-slate-800';
    
        function renderList(bodyEl, arr) {
            if (!bodyEl) return;
            bodyEl.innerHTML = '';
            
            // if object array with details instead of objects 
            if (arr && !Array.isArray(arr) && Object.keys(arr).length > 0) {
                 arr = Object.entries(arr).map(([k, v]) => ({ event: k, details: v }));
            }
            
            if (!arr || !arr.length) {
                bodyEl.innerHTML = `<tr><td class="px-4 py-4 text-center ${textSecondary}">None detected.</td></tr>`;
                return;
            }
            
            arr.forEach((item, idx) => {
                const jsonStr = typeof item === 'string' ? item : JSON.stringify(item, null, 2);
                bodyEl.insertAdjacentHTML('beforeend',
                    `<tr>
                        <td class="px-4 py-3 align-top" style="border-bottom: 1px solid var(--neo-border);">
                            <div class="text-[10px] mb-1 font-mono ${textSecondary}">EVENT #${idx + 1}</div>
                            <pre class="text-[11px] font-mono whitespace-pre-wrap p-2 ${bgCode} ${textCode} rounded border ${borderCode}">${jsonStr}</pre>
                        </td>
                    </tr>`
                );
            });
        }
    
        renderList(elements.portScansBody, ar.port_scans || ar.suspicious_connections || []);
        renderList(elements.cleartextBody, ar.cleartext_credentials || ar.cleartext_protocols || []);
    }

    function renderPackets(report) {
        if (!elements.packetsTableBody) return;
    
        const packets = report.dissected_packets || [];
        elements.packetsTableBody.innerHTML = '';
        
        const isLight = document.body.classList.contains("light-mode");
        const textPrimary = isLight ? 'text-slate-700' : 'text-slate-300';
        const textSecondary = isLight ? 'text-slate-500' : 'text-slate-500';
        const textMuted = isLight ? 'text-slate-400' : 'text-slate-400';
        const hoverBg = isLight ? 'hover:bg-slate-100' : 'hover:bg-slate-800/50';
    
        if (!packets.length) {
            elements.packetsTableBody.innerHTML = `
                <tr>
                    <td colspan="7" style="padding: 6rem 2rem;">
                        <div class="w-full flex flex-col items-center justify-center animate-card" style="gap: 1rem;">
                            <div class="ai-pulse-container" style="opacity: 0.3;">
                                <div class="ai-pulse-ring"></div>
                                <span class="material-symbols-outlined" style="font-size: 3rem; color: var(--neo-text-muted);">wifi</span>
                            </div>
                            <div style="font-family: var(--font-mono); font-size: 0.85rem; color: var(--neo-text-muted); text-transform: uppercase; letter-spacing: 0.2em; text-align: center;">
                                INITIATE A SCAN TO VIEW RESULTS...
                            </div>
                        </div>
                    </td>
                </tr>`;
            return;
        }
    
        const displayPackets = packets.slice(0, 500); 
    
        displayPackets.forEach((pkt) => {
            const layers = (pkt && pkt._source && pkt._source.layers) || pkt.layers || pkt || {};
            const frame = layers.frame || layers || {};
            const ip = layers.ip || layers.ipv6 || layers || {};
    
            const frameNum = frame['frame.number'] || frame.number || '?';
            const timeRel = frame['frame.time_relative'] || frame.time_relative || '0.0';
            const len = frame['frame.len'] || frame.length || '?';
    
            const src = ip['ip.src'] || ip['ipv6.src'] || ip['ip.src_host'] || ip.src || 'N/A';
            const dst = ip['ip.dst'] || ip['ipv6.dst'] || ip['ip.dst_host'] || ip.dst || 'N/A';
    
            let proto = pkt.protocol || 'TCP/UDP';
            const protoStr = frame['frame.protocols'] || frame.protocols;
            if (protoStr) {
                const parts = protoStr.split(':');
                proto = (parts[parts.length - 1] || 'DATA').toUpperCase();
            }
    
            // [NEW] Risk Score Rendering
            const rawScore = pkt.predicted_risk_score !== undefined ? pkt.predicted_risk_score : 0;
            const scoreLabel = (rawScore * 10).toFixed(1);
            const scoreColor = rawScore > 0.7 ? '#ef4444' : (rawScore > 0.4 ? '#f97316' : '#3b82f6');
    
            elements.packetsTableBody.insertAdjacentHTML('beforeend',
                `<tr class="${hoverBg} transition-colors">
                    <td class="px-6 py-2 text-xs font-mono ${textSecondary}">${frameNum}</td>
                    <td class="px-6 py-2 text-xs font-mono ${textMuted}">${parseFloat(timeRel).toFixed(4)}</td>
                    <td class="px-6 py-2 text-xs font-mono text-blue-400">${src}</td>
                    <td class="px-6 py-2 text-xs font-mono text-emerald-400">${dst}</td>
                    <td class="px-6 py-2 text-xs font-bold ${textPrimary}">${proto}</td>
                    <td class="px-6 py-2 text-xs font-mono" style="color: ${scoreColor}; font-weight: 800;">${scoreLabel}</td>
                    <td class="px-6 py-2 text-xs font-mono ${textMuted}">${len}</td>
                </tr>`
            );
        });
        
        if (packets.length > 500) {
            elements.packetsTableBody.insertAdjacentHTML('beforeend', 
                `<tr><td colspan="7" class="p-2 text-center text-xs ${textSecondary} italic">... ${packets.length - 500} more packets not shown ...</td></tr>`
            );
        }
    }

    // Stores the last processed graph data so renderGraph can be called lazily
    let pendingGraphData = null;

    function processGraphData(report) {
        const ts = report.traffic_summary || {};
        const lines = ts.tcp_conversation_stats || ts.tcp_conversations || [];
        const nodesMap = new Map(); 
        const edges = [];

        lines.forEach(line => {
            if (!line.includes('<->')) return;
            
            const parts = line.split('<->');
            const leftFull = parts[0].trim();
            const rightFull = parts[1].trim().split(/\s+/)[0]; 

            const leftParts = leftFull.split(':');
            const rightParts = rightFull.split(':');

            const srcIp = leftParts[0].trim();
            const srcPort = leftParts[1] || '?';
            const dstIp = rightParts[0].trim();
            const dstPort = rightParts[1] || '?';
            
            if(!srcIp || !dstIp) return;

            // Parse bytes — tshark uses formats like "6061 bytes", "77 kB", "1.2 MB"
            let bytes = 0;
            const bytesRaw = parts[1];
            const mbMatch = bytesRaw.match(/([\d.]+)\s*MB/);
            const kbMatch = bytesRaw.match(/([\d.]+)\s*kB/);
            const bMatch  = bytesRaw.match(/(\d+)\s+bytes/);
            if (mbMatch)      bytes = parseFloat(mbMatch[1]) * 1024 * 1024;
            else if (kbMatch) bytes = parseFloat(kbMatch[1]) * 1024;
            else if (bMatch)  bytes = parseInt(bMatch[1], 10);

            const isLocal = (ip) => /^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.)/.test(ip);

            if (!nodesMap.has(srcIp)) {
                nodesMap.set(srcIp, { 
                    id: srcIp, 
                    label: srcIp, 
                    group: isLocal(srcIp) ? 'local' : 'external',
                    value: bytes 
                });
            } else {
                nodesMap.get(srcIp).value += bytes;
            }

            if (!nodesMap.has(dstIp)) {
                nodesMap.set(dstIp, { 
                    id: dstIp, 
                    label: dstIp, 
                    group: isLocal(dstIp) ? 'local' : 'external',
                    value: bytes
                });
            } else {
                nodesMap.get(dstIp).value += bytes;
            }

            const displayPort = (parseInt(srcPort) < parseInt(dstPort) && parseInt(srcPort) < 10000) ? srcPort : dstPort;
            
            edges.push({ 
                from: srcIp, 
                to: dstIp, 
                label: displayPort !== '?' ? displayPort : '', 
                font: { align: 'top', size: 10, strokeWidth: 2, strokeColor: '#050505', color: '#94a3b8' },
                width: bytes > 50000 ? 4 : bytes > 10000 ? 2 : 1, 
                title: `${(bytes/1024).toFixed(1)} KB Transferred` 
            });
        });

        const nodes = Array.from(nodesMap.values()).map(n => ({
            id: n.id,
            label: n.id,
            group: n.group,
            value: Math.log(n.value + 1000), 
            title: `IP:  ${n.id}\nLoc: ${n.group.toUpperCase()}\nVol: ${(n.value/1024).toFixed(2)} KB`
        }));

        return { nodes, edges };
    }

    function renderGraph(report) {
        // Process and cache graph data but do NOT create vis.Network yet.
        // The canvas is hidden (display:none) when other tabs are active,
        // which causes vis.js to render into a 0x0 element → blank graph.
        // We defer actual rendering until the Graph tab is clicked.
        const data = processGraphData(report);
        if (data.nodes.length > 0) {
            pendingGraphData = data;
        }
    }

    function mountGraphIfNeeded() {
        if (!elements.networkGraphCanvas || !pendingGraphData) return;

        const options = {
            nodes: {
                shape: 'dot',
                font: { face: 'IBM Plex Sans', size: 12, color: '#ffffff', strokeWidth: 0 },
                scaling: { min: 10, max: 30 }, 
                shadow: false
            },
            groups: {
                local: {
                    color: { background: '#3b82f6', border: '#2563eb', highlight: { background: '#60a5fa', border: '#3b82f6' } }, 
                },
                external: {
                    color: { background: '#ef4444', border: '#dc2626', highlight: { background: '#f87171', border: '#ef4444' } }, 
                }
            },
            edges: {
                color: { color: 'rgba(255,255,255,0.15)', highlight: '#3b82f6' },
                smooth: { type: 'continuous' },
                selectionWidth: 2
            },
            physics: {
                stabilization: { enabled: true, iterations: 500 },
                barnesHut: {
                    gravitationalConstant: -12000, 
                    centralGravity: 0.3,           
                    springLength: 150,             
                    springConstant: 0.04,
                    damping: 0.09,
                    avoidOverlap: 0.2
                },
                solver: 'barnesHut',
                minVelocity: 0.75
            },
            interaction: {
                hover: true,
                tooltipDelay: 100,
                zoomView: false, 
                dragView: true
            }
        };

        if (networkInstance) {
            networkInstance.setData(pendingGraphData);
            networkInstance.redraw();
        } else {
            networkInstance = new vis.Network(elements.networkGraphCanvas, pendingGraphData, options);
        }

        setTimeout(() => {
            if (networkInstance) {
                networkInstance.redraw();
                networkInstance.fit();
            }
        }, 150);

        pendingGraphData = null; // consumed
    }

    // --- DOWNLOAD & AI LOGIC ---

    async function checkReportAvailability() {
        const target = elements.targetIpInput ? elements.targetIpInput.value.trim() : "";
        console.log('Checking report availability for:', target || 'generic');
        
        try {
            const url = target ? `${API_BASE_URL}/report_files?target=${encodeURIComponent(target)}` : `${API_BASE_URL}/report_files`;
            const res = await fetch(url);
            const data = await res.json();

            if (res.ok && data.status === 'success' && data.pdf_report) {
                console.log('Report found:', data.pdf_report);
                reportDownloadUrl = data.pdf_report;
                
                if (elements.snifferDownloadReportBtn) {
                    elements.snifferDownloadReportBtn.disabled = false;
                    elements.snifferDownloadReportBtn.classList.remove('opacity-70', 'cursor-not-allowed');
                }
                if (elements.snifferAnalyzeReportDropdown) {
                    elements.snifferAnalyzeReportDropdown.disabled = false;
                    elements.snifferAnalyzeReportDropdown.classList.remove('opacity-70', 'cursor-not-allowed');
                }
                return;
            } else if (target) {
                console.log('Specific report not found, checking generic fallback...');
                const fallbackRes = await fetch(`${API_BASE_URL}/report_files`);
                const fallbackData = await fallbackRes.json();
                if (fallbackRes.ok && fallbackData.status === 'success' && fallbackData.pdf_report) {
                    console.log('Fallback report found:', fallbackData.pdf_report);
                    reportDownloadUrl = fallbackData.pdf_report;
                    if (elements.snifferDownloadReportBtn) {
                        elements.snifferDownloadReportBtn.disabled = false;
                        elements.snifferDownloadReportBtn.classList.remove('opacity-70', 'cursor-not-allowed');
                    }
                    if (elements.snifferAnalyzeReportDropdown) {
                        elements.snifferAnalyzeReportDropdown.disabled = false;
                        elements.snifferAnalyzeReportDropdown.classList.remove('opacity-70', 'cursor-not-allowed');
                    }
                    return;
                }
            }
        } catch (e) {
            console.error('Report availability check failed:', e);
        }

        console.log('No report found, updating button states.');
        reportDownloadUrl = null;
        if (elements.snifferDownloadReportBtn) {
            elements.snifferDownloadReportBtn.disabled = true;
            elements.snifferDownloadReportBtn.classList.add('opacity-70', 'cursor-not-allowed');
        }
        // AI Analysis button remains enabled so user can see options, matching network_scanner.js
        if (elements.snifferAnalyzeReportDropdown) {
            elements.snifferAnalyzeReportDropdown.disabled = false;
            elements.snifferAnalyzeReportDropdown.classList.remove('opacity-70', 'cursor-not-allowed');
        }
    }

    // --- HISTORY LOGIC ---

    async function fetchHistory() {
        if (!elements.historyTableBody) return;
        elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-text-muted);">LOADING HISTORY...</td></tr>';
        
        try {
            const res = await fetch(`${API_BASE_URL}/report_history`);
            const data = await res.json();
            
            if (data.status === 'success' && data.history) {
                if (data.history.length === 0) {
                    elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-text-muted);">NO PRIOR SCANS FOUND</td></tr>';
                    return;
                }
                
                elements.historyTableBody.innerHTML = '';
                data.history.forEach(item => {
                    const row = document.createElement('tr');
                    // Extract target from filename (scanner_target.pdf)
                    let target = item.filename.split('_').slice(3).join('_').replace('.pdf', '');                    target = target.replace(/_\d{8}_\d{6}$/, '');
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
                    elements.historyTableBody.appendChild(row);
                });
            } else {
                elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-red);">FAILED TO LOAD HISTORY</td></tr>';
            }
        } catch (e) {
            console.error('History fetch failed:', e);
            elements.historyTableBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 2rem; color: var(--neo-red);">ERROR LOADING HISTORY</td></tr>';
        }
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

    async function analyzeReport(llmMode) {
        const button = elements.snifferAnalyzeReportDropdown;
        const overlay = elements.aiProcessingOverlay;
        const processingText = elements.aiProcessingText;
        const llmOptions = elements.snifferLlmAnalysisOptions;
        const target = elements.targetIpInput.value.trim();

        if (!button || button.disabled) return;
        if (!csrfToken) {
            appendLog('[x] Error: CSRF Token missing. Refresh page.');
            return;
        }

        // 1. UI Setup
        if (llmOptions) llmOptions.classList.remove('show');
        if (overlay) overlay.classList.remove('hidden');
        
        if (processingText) {
            processingText.textContent = llmMode.includes('gemini') 
                ? 'CONTACTING GEMINI...' 
                : 'LOADING LOCAL MODEL...';
        }

        setStatus(`Preparing AI analysis (${llmMode})...`, 'busy');
        toggleSpinner(button, true);

        try {
            // 2. Trigger
            let res = await fetch(`${API_BASE_URL}/trigger_ai_analysis`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken 
                },
                body: JSON.stringify({ llm_mode: llmMode, target: target }),
            });
            let data = await res.json();
            
            if (data.status !== 'success') {
                throw new Error(data.message || 'Analysis trigger failed.');
            }

            // 3. Second Phase
            if (processingText) processingText.textContent = 'SYNTHESIZING REPORT...';

            res = await fetch(`${CHATBOT_REDIRECT_URL}/scanner_analysis`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ 
                    llm_mode: llmMode, 
                    scanner_type: data.scanner_type,
                    target: data.target,
                    force_new_session: true // [NEW] Force a fresh chat
                }),
            });
            data = await res.json();

            if (res.ok && data.status === 'success') {
                if (processingText) processingText.textContent = 'REDIRECTING...';
                appendLog('[✓] AI analysis initiated. Redirecting...');
                
                setTimeout(() => {
                     window.location.href = `${CHATBOT_REDIRECT_URL}?mode=${data.llm_mode}&summary=${encodeURIComponent(data.summary)}&session_id=${data.session_id}`;
                }, 800);
            } else {
                throw new Error(data.message || `Analysis failed.`);
            }
        } catch (err) {
            appendLog(`[x] AI Analysis Error: ${err.message}`);
            setStatus('Analysis failed', 'error');
             // Hide overlay on error so user can try again
            if (overlay) overlay.classList.add('hidden');
        } finally {
            toggleSpinner(button, false);
            checkReportAvailability();
        }
    }

    // --- ACTION HANDLERS ---

    async function startCapture() {
        const targetIp = elements.targetIpInput.value.trim() || null;
        const duration = parseInt(elements.durationInput.value, 10) || 10;
        const maxPackets = parseInt(elements.maxPacketsInput.value, 10) || 200;
        const bpfFilter = elements.bpfFilterInput.value.trim() || null;

        // NOTE: Do NOT set isActionInProgress here — apiPost() manages it.
        // Setting it before calling apiPost() caused apiPost to immediately
        // return null (its own guard), which triggered "Failed to start".

        setStatus('Starting capture...', 'busy');
        switchTab('summary');
        appendLog('--- New Capture Initiated ---');

        // Pass the button so apiPost shows/hides spinner during the HTTP call
        const data = await apiPost('/start_capture', {
            target_ip: targetIp,
            duration,
            max_packets: maxPackets,
            interface_id: elements.interfaceSelect ? elements.interfaceSelect.value || null : null,
            custom_bpf_filter: bpfFilter,
        }, elements.startCaptureBtn);

        if (!data || data.status !== 'success') {
            // apiPost already reset isActionInProgress in its finally block
            setStatus('Failed to start', 'error');
            return;
        }

        // Capture initiated successfully — keep button in spinner/busy state
        // until the SSE log stream signals SYSTEM_EVENT: READY_FOR_ANALYSIS
        if (elements.startCaptureBtn) toggleSpinner(elements.startCaptureBtn, true);
        if (elements.stopCaptureBtn) elements.stopCaptureBtn.disabled = false;
        setStatus('Capture running...', 'busy');
        // isActionInProgress stays true until SSE signals completion
        isActionInProgress = true;
    }

    async function stopCapture() {
        // Use fetch directly — apiPost() is blocked by isActionInProgress during a scan.
        setStatus('Stopping...', 'busy');
        try {
            const res = await fetch(`${API_BASE_URL}/stop_capture`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
                body: JSON.stringify({}),
            });
            const data = await res.json();
            appendLog(data.status === 'success' ? '[✓] Stop signal sent.' : `[!] Stop: ${data.message}`);
        } catch (e) {
            appendLog(`[x] Stop error: ${e.message}`);
        } finally {
            isActionInProgress = false;
            if (elements.startCaptureBtn) toggleSpinner(elements.startCaptureBtn, false);
            if (elements.stopCaptureBtn) elements.stopCaptureBtn.disabled = true;
        }
    }

    // --- INIT ---

    function setupEventListeners() {
        if(elements.startCaptureBtn) elements.startCaptureBtn.addEventListener('click', startCapture);
        if(elements.stopCaptureBtn) elements.stopCaptureBtn.addEventListener('click', stopCapture);

        if(elements.advancedScanToggle) {
            elements.advancedScanToggle.addEventListener('click', (e) => {
                e.preventDefault();
                if (elements.advancedScanOptions) {
                    elements.advancedScanOptions.classList.toggle('hidden');
                }
            });
        }
        // Close dropdown when interacting outside
        document.addEventListener('click', (e) => {
            if (elements.advancedScanOptions && !elements.advancedScanOptions.classList.contains('hidden') && 
                e.target !== elements.advancedScanToggle && !elements.advancedScanToggle.contains(e.target) &&
                !elements.advancedScanOptions.contains(e.target)) {
                elements.advancedScanOptions.classList.add('hidden');
            }
        });

        if(elements.summaryTabBtn) elements.summaryTabBtn.addEventListener('click', () => switchTab('summary'));
        if(elements.flowsTabBtn) elements.flowsTabBtn.addEventListener('click', () => switchTab('flows'));
        if(elements.anomaliesTabBtn) elements.anomaliesTabBtn.addEventListener('click', () => switchTab('anomalies'));
        if(elements.packetsTabBtn) elements.packetsTabBtn.addEventListener('click', () => switchTab('packets'));
        if(elements.graphTabBtn) elements.graphTabBtn.addEventListener('click', () => switchTab('graph'));

        // NEW: Graph Zoom Controls
        if (elements.graphZoomInBtn) {
            elements.graphZoomInBtn.addEventListener('click', () => {
                if (networkInstance) {
                    const scale = networkInstance.getScale() + 0.3;
                    networkInstance.moveTo({ scale: scale, animation: true });
                }
            });
        }

        if (elements.graphZoomOutBtn) {
            elements.graphZoomOutBtn.addEventListener('click', () => {
                if (networkInstance) {
                    const scale = networkInstance.getScale() - 0.3;
                    networkInstance.moveTo({ scale: scale, animation: true });
                }
            });
        }

        if (elements.graphFitBtn) {
            elements.graphFitBtn.addEventListener('click', () => {
                if (networkInstance) {
                    networkInstance.fit({ animation: true });
                }
            });
        }

        if(elements.refreshSnifferResultsBtn) {
            elements.refreshSnifferResultsBtn.addEventListener('click', () => {
                setStatus('Refreshing data...', 'busy');
                Promise.all([loadAndRenderReport(), checkReportAvailability()]).then(() =>
                    setStatus('Ready', 'ready')
                );
            });
        }

        if(elements.snifferAnalyzeReportDropdown) {
            elements.snifferAnalyzeReportDropdown.addEventListener('click', (e) => {
                e.preventDefault();
                if (elements.snifferLlmAnalysisOptions) {
                    elements.snifferLlmAnalysisOptions.classList.toggle('hidden');
                    elements.snifferLlmAnalysisOptions.classList.toggle('show');
                }
            });
        }

        if(elements.clearSnifferLogBtn) {
            elements.clearSnifferLogBtn.addEventListener('click', async () => {
                if(elements.snifferLogOutput) elements.snifferLogOutput.textContent = '';
                await apiPost('/clear_log', {});
            });
        }

        if(elements.snifferDownloadReportBtn) {
            elements.snifferDownloadReportBtn.addEventListener('click', () => {
                if (reportDownloadUrl) {
                    window.location.href = reportDownloadUrl;
                    appendLog('[✓] Downloading PDF report...');
                } else {
                    appendLog('[!] No report available.');
                }
            });
        }

        if(elements.snifferLlmAnalysisOptions) {
            elements.snifferLlmAnalysisOptions.addEventListener('click', (e) => {
                e.preventDefault();
                const link = e.target.closest('a[data-llm-mode]');
                if (!link) return;
                
                const mode = link.dataset.llmMode;
                elements.snifferLlmAnalysisOptions.classList.remove('show'); 
                elements.snifferLlmAnalysisOptions.classList.add('hidden');
                analyzeReport(mode);
            });
        }
    }

    async function analyzeReport(llmMode) {
        if (elements.snifferAnalyzeReportDropdown.disabled) return;
        const target = elements.targetIpInput.value.trim();

        if (!csrfToken) {
            appendLog('[!] Error: CSRF Token missing. Refresh page.');
            return;
        }

        // 1. LOCK UI & SHOW OVERLAY
        if (elements.snifferLlmAnalysisOptions) elements.snifferLlmAnalysisOptions.classList.add('hidden');
        if (elements.aiProcessingOverlay) {
            elements.aiProcessingOverlay.classList.remove('hidden');
            if (elements.aiProcessingText) {
                elements.aiProcessingText.textContent = llmMode.includes('gemini') 
                    ? 'CONTACTING GEMINI...' 
                    : 'LOADING LOCAL MODEL...';
            }
        }

        setStatus(`AI Analysis (${llmMode})...`, 'busy');
        
        // Disable dropdown interactions
        elements.snifferAnalyzeReportDropdown.disabled = true;
        
        try {
            let response = await fetch(`${API_BASE_URL}/trigger_ai_analysis`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken 
                },
                body: JSON.stringify({ llm_mode: llmMode, target: target })
            });
            let data = await response.json();
            
            if (data.status !== 'success') throw new Error(data.message);
            
            if (elements.aiProcessingText) elements.aiProcessingText.textContent = 'SYNTHESIZING REPORT...';

            response = await fetch(`${CHATBOT_REDIRECT_URL}/scanner_analysis`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken 
                },
                body: JSON.stringify({ 
                    llm_mode: llmMode, 
                    scanner_type: data.scanner_type,
                    target: data.target, // Pass sanitized target
                    force_new_session: true 
                })
            });

            data = await response.json();

            if (response.ok && data.status === 'success') {
                if (elements.aiProcessingText) elements.aiProcessingText.textContent = 'REDIRECTING...';
                appendLog(`[✓] Analysis complete. Redirecting...`);
                
                setTimeout(() => {
                    const params = new URLSearchParams({
                        mode: data.llm_mode,
                        summary: data.summary,
                        session_id: data.session_id
                    });
                    window.location.href = `${CHATBOT_REDIRECT_URL}?${params.toString()}`;
                }, 800);
            } else {
                throw new Error(data.message);
            }
        } catch (error) {
            appendLog(`[!] AI Analysis Error: ${error.message}`);
            setStatus('Analysis failed', 'error');
            
            // Hide overlay to allow retry
            if (elements.aiProcessingOverlay) elements.aiProcessingOverlay.classList.add('hidden');
            elements.snifferAnalyzeReportDropdown.disabled = false;
        } finally {
            checkReportAvailability(); 
        }
    }

    async function loadInterfaces() {
        if (!elements.interfaceSelect) return;
        try {
            const res = await fetch(`${API_BASE_URL}/get_interfaces`);
            const data = await res.json();
            if (data.status === 'success' && data.interfaces) {
                data.interfaces.forEach(intf => {
                    const opt = document.createElement('option');
                    opt.value = intf.id;
                    opt.textContent = intf.description || intf.name;
                    elements.interfaceSelect.appendChild(opt);
                });
            }
        } catch (e) {
            console.error('Failed to load interfaces:', e);
        }
    }

    function init() {
        // Initial log message with delay to ensure DOM is ready
        setTimeout(() => appendLog('System Ready. Initializing Packet Sniffer interface...'), 100);
        
        loadInterfaces();
        setupEventListeners();
        initializeLogStream();
        switchTab('summary'); // Default tab

        loadAndRenderReport();
        checkReportAvailability();
        setStatus('Ready to capture', 'ready');
    }

    init();
});