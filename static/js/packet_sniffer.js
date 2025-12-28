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
        refreshSnifferResultsBtn: document.getElementById('refreshSnifferResultsBtn'),
        snifferDownloadReportBtn: document.getElementById('snifferDownloadReportBtn'),
        
        // Dropdowns & Analysis
        snifferAnalyzeReportDropdown: document.getElementById('snifferAnalyzeReportDropdown'),
        snifferLlmAnalysisOptions: document.getElementById('snifferLlmAnalysisOptions'),
        
        // Status & Logs
        snifferStatus: document.getElementById('snifferStatus'),
        snifferLogOutput: document.getElementById('snifferLogOutput'),
        clearSnifferLogBtn: document.getElementById('clearSnifferLogBtn'),

        // Header Metrics (Top Right)
        packetCountDisplay: document.getElementById('packetCountDisplay'),
        targetDisplay: document.getElementById('targetDisplay'),
        durationDisplay: document.getElementById('durationDisplay'),
        avgRateDisplay: document.getElementById('avgRateDisplay'),

        // Tab Buttons
        summaryTabBtn: document.getElementById('summaryTabBtn'),
        flowsTabBtn: document.getElementById('flowsTabBtn'),
        anomaliesTabBtn: document.getElementById('anomaliesTabBtn'),
        packetsTabBtn: document.getElementById('packetsTabBtn'),

        // Tab Content Containers
        summaryContent: document.getElementById('summaryContent'),
        flowsContent: document.getElementById('flowsContent'),
        anomaliesContent: document.getElementById('anomaliesContent'),
        packetsContent: document.getElementById('packetsContent'),

        // Summary Tab Specifics
        summaryStatus: document.getElementById('summaryStatus'),
        summaryTotalPackets: document.getElementById('summaryTotalPackets'),
        summaryTotalBytes: document.getElementById('summaryTotalBytes'),
        summaryPrimaryProto: document.getElementById('summaryPrimaryProto'),
        captureMetaBody: document.getElementById('captureMetaBody'),
        
        // UPDATED: Now points to table bodies instead of raw text boxes
        protocolStatsBody: document.getElementById('protocolStatsBody'),
        conversationStatsBody: document.getElementById('conversationStatsBody'),

        // Flows Tab
        flowsTableBody: document.getElementById('flowsTableBody'),

        // Anomalies Tab
        anomalySummaryText: document.getElementById('anomalySummaryText'),
        portScansBody: document.getElementById('portScansBody'),
        cleartextBody: document.getElementById('cleartextBody'),

        // Packets Tab
        packetsTableBody: document.getElementById('packetsTableBody'),
    };

    const API_BASE_URL = '/packet_sniffer';
    const CHATBOT_REDIRECT_URL = '/chatbot';

    let isActionInProgress = false;
    let reportDownloadUrl = null;
    let eventSource = null;

    // --- UI HELPERS ---

    function toggleSpinner(button, isLoading) {
        if (!button) return;
        
        const textSpan = button.querySelector('.button-text');
        const spinnerSpan = button.querySelector('.spinner');
        const caretIcon = button.querySelector('.fa-caret-down');

        button.disabled = isLoading;

        // Toggle opacity/cursor classes for the button itself
        if (isLoading) {
            button.classList.add('cursor-not-allowed', 'opacity-70');
        } else {
            button.classList.remove('cursor-not-allowed', 'opacity-70');
        }

        // Toggle visibility of inner elements
        if (textSpan) textSpan.classList.toggle('hidden', isLoading); 
        if (spinnerSpan) spinnerSpan.classList.toggle('hidden', !isLoading);
        if (caretIcon) caretIcon.classList.toggle('hidden', isLoading); 
    }

    function appendLog(msg) {
        if (!elements.snifferLogOutput) return;
        elements.snifferLogOutput.textContent += msg + '\n';
        elements.snifferLogOutput.scrollTop = elements.snifferLogOutput.scrollHeight;
    }

    function setStatus(text, type = 'ready') {
        if (!elements.snifferStatus) return;

        // Reset base classes
        elements.snifferStatus.className = 'text-center text-xs py-2 rounded border border-slate-800 bg-slate-900/50 text-slate-400';
        
        // Remove old icon
        const oldIcon = elements.snifferStatus.querySelector('i');
        if (oldIcon) oldIcon.remove();

        const icon = document.createElement('i');
        let iconClass = '';
        let colorClass = '';

        switch (type) {
            case 'busy':
                colorClass = 'text-yellow-400 bg-yellow-900/20 border-yellow-900/50';
                iconClass = 'fas fa-cog fa-spin';
                break;
            case 'error':
                colorClass = 'text-red-400 bg-red-900/20 border-red-900/50';
                iconClass = 'fas fa-exclamation-circle';
                break;
            case 'success':
                colorClass = 'text-green-400 bg-green-900/20 border-green-900/50';
                iconClass = 'fas fa-check-circle';
                break;
            default: // ready
                colorClass = 'text-slate-400 bg-slate-900/50 border-slate-800';
                iconClass = 'fas fa-circle text-green-500'; 
                break;
        }

        if (type !== 'ready') {
            elements.snifferStatus.className = `text-center text-xs py-2 rounded border ${colorClass}`;
        }

        icon.className = `${iconClass} text-[10px] mr-2`;
        elements.snifferStatus.textContent = text;
        elements.snifferStatus.prepend(icon);
    }

    // --- API HANDLER ---

    async function apiPost(endpoint, body = {}, button = null) {
        if (isActionInProgress) return null;
        isActionInProgress = true;
        if (button) toggleSpinner(button, true);

        try {
            const res = await fetch(`${API_BASE_URL}${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
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
        };
        const btnMap = {
            summary: elements.summaryTabBtn,
            flows: elements.flowsTabBtn,
            anomalies: elements.anomaliesTabBtn,
            packets: elements.packetsTabBtn,
        };

        Object.entries(map).forEach(([key, el]) => {
            if (!el) return;
            el.classList.toggle('hidden', key !== name);
        });

        Object.entries(btnMap).forEach(([key, btn]) => {
            if (!btn) return;
            btn.classList.toggle('active', key === name);
        });
    }

    // --- SSE LOG STREAM ---

    function initializeLogStream() {
        if (eventSource) eventSource.close();
        eventSource = new EventSource(`${API_BASE_URL}/log_stream`);

        eventSource.onmessage = (evt) => {
            const msg = evt.data;
            if (!msg || msg.startsWith(':')) return;

            appendLog(msg);

            const lower = msg.toLowerCase();
            if (lower.includes('capture complete') || lower.includes('analysis complete') || lower.includes('finished')) {
                setStatus('Capture complete', 'success');
                loadAndRenderReport();
                checkReportAvailability();
            }
        };

        eventSource.onerror = () => {
            if (eventSource.readyState !== EventSource.CLOSED) {
                appendLog('[!] Log stream disconnected.');
                eventSource.close();
            }
        };
    }

    // --- RENDERING LOGIC ---

    async function loadAndRenderReport() {
        try {
            const res = await fetch(`${API_BASE_URL}/get_json_report`);
            const data = await res.json();
            
            if (!res.ok || data.status === 'error') {
                return;
            }
            
            const report = data.report || data;
            renderSummary(report);
            renderFlows(report);
            renderAnomalies(report);
            renderPackets(report);
        } catch (e) {
            console.error(e);
            appendLog('[x] Failed to fetch sniffer report.');
        }
    }

    function renderSummary(report) {
        const ts = report.traffic_summary || {};
        const protoStats = ts.protocol_hierarchy_stats || [];
        const tcpStats = ts.tcp_conversation_stats || [];

        const totalPackets = ts.total_packets ?? (Array.isArray(report.dissected_packets) ? report.dissected_packets.length : 0);
        const totalBytes = ts.total_bytes ?? 0;
        const dur = ts.effective_capture_duration_seconds ?? report.analysis_time_seconds ?? 0;
        const avgRate = ts.average_rate_bps ?? 0;

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
            const line = protoStats.find((l) => l.toLowerCase().includes('http') || l.toLowerCase().includes('tcp')) || protoStats[protoStats.length - 1];
            if (line) {
                const parts = line.trim().split(/\s+/);
                primaryProto = parts[0] || 'N/A';
            }
        }
        if(elements.summaryPrimaryProto) elements.summaryPrimaryProto.textContent = primaryProto.toUpperCase();

        const metaRows = [
            ['Timestamp', report.timestamp || 'N/A'],
            ['Target', targetDisplay],
            ['File', report.pcap_file ? report.pcap_file.split(/[\\/]/).pop() : 'N/A'], 
            ['Duration', `${(report.analysis_time_seconds || 0).toFixed(2)}s`],
        ];
        
        if (elements.captureMetaBody) {
            elements.captureMetaBody.innerHTML = '';
            metaRows.forEach(([k, v]) => {
                elements.captureMetaBody.insertAdjacentHTML('beforeend',
                    `<tr>
                        <td class="px-4 py-2 text-xs text-slate-400 font-medium">${k}</td>
                        <td class="px-4 py-2 text-xs font-mono text-slate-200 text-right">${v}</td>
                    </tr>`
                );
            });
        }

        // --- NEW: Render the parsed tables ---
        renderProtocolTable(protoStats);
        renderConversationTable(tcpStats);
    }

    // --- NEW TABLE PARSERS ---

    function renderProtocolTable(lines) {
        if (!elements.protocolStatsBody) return;
        elements.protocolStatsBody.innerHTML = '';

        if (!Array.isArray(lines) || lines.length === 0) {
            elements.protocolStatsBody.innerHTML = `<tr><td colspan="3" class="px-4 py-4 text-center text-slate-500">No data available.</td></tr>`;
            return;
        }

        // TShark line example: "  eth      frames:6 bytes:360"
        const regex = /([a-zA-Z0-9\-\._]+)\s+frames:(\d+)\s+bytes:(\d+)/;

        lines.forEach(line => {
            const match = line.match(regex);
            if (match) {
                const name = match[1];
                const frames = match[2];
                const bytes = parseInt(match[3], 10);
                
                // Calculate indentation based on leading spaces
                const leadingSpaces = line.search(/\S|$/);
                const indent = Math.max(0, (leadingSpaces / 2) * 10); 

                elements.protocolStatsBody.insertAdjacentHTML('beforeend', 
                    `<tr class="hover:bg-slate-800/50 transition-colors">
                        <td class="px-4 py-2 text-xs font-mono text-blue-400" style="padding-left: ${indent + 16}px">${name}</td>
                        <td class="px-4 py-2 text-xs font-mono text-slate-300 text-right">${frames}</td>
                        <td class="px-4 py-2 text-xs font-mono text-slate-400 text-right">${(bytes/1024).toFixed(1)} KB</td>
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
            elements.conversationStatsBody.innerHTML = `<tr><td colspan="4" class="px-4 py-4 text-center text-slate-500">No conversations recorded.</td></tr>`;
            return;
        }

        validLines.forEach(line => {
            // Raw: "192.168.1.5:5432 <-> 10.0.0.1:80      10 500 ..."
            const splitArrow = line.split('<->');
            if (splitArrow.length !== 2) return;

            const leftSide = splitArrow[0].trim();
            const rightSideRaw = splitArrow[1].trim();

            const rightParts = rightSideRaw.split(/\s+/);
            const rightSide = rightParts[0]; // IP:Port

            // Attempt to grab bytes. Heuristic: Usually the 2nd to last "bytes" looking number, or just the last large integer.
            // Using regex to find "X bytes" if TShark labels it, or just grab from columns if unlabeled.
            let displayBytes = '-';
            
            const bytesMatch = line.match(/\s(\d+)\s+bytes/); 
            if(bytesMatch) {
                displayBytes = bytesMatch[1];
            } else if (rightParts.length >= 4) {
                 // Fallback for unlabeled columns: endpoints <-> endpoint B  framesA bytesA framesB bytesB totalFrames totalBytes duration
                 // totalBytes is often 2nd from last
                 displayBytes = rightParts[rightParts.length - 2] || '?';
            }

            elements.conversationStatsBody.insertAdjacentHTML('beforeend',
                `<tr class="hover:bg-slate-800/50 transition-colors">
                    <td class="px-4 py-2 text-xs font-mono text-emerald-400 truncate max-w-[150px]" title="${leftSide}">${leftSide}</td>
                    <td class="px-4 py-2 text-center"><i class="fas fa-exchange-alt text-[10px] text-slate-600"></i></td>
                    <td class="px-4 py-2 text-xs font-mono text-blue-400 truncate max-w-[150px]" title="${rightSide}">${rightSide}</td>
                    <td class="px-4 py-2 text-xs font-mono text-slate-300 text-right">${displayBytes}</td>
                </tr>`
            );
        });
    }

    function renderFlows(report) {
        if (!elements.flowsTableBody) return;

        const flowsObj = report.application_flow_analysis || {};
        const flows = flowsObj.flows || [];
        
        elements.flowsTableBody.innerHTML = '';

        if (!flows.length) {
            elements.flowsTableBody.innerHTML = `<tr><td colspan="6" class="p-12 text-center text-slate-500 text-sm">No HTTP/Application flows recorded.</td></tr>`;
            return;
        }

        flows.forEach((flow) => {
            const resp = (flow.response_code || flow.response_phrase) ? `${flow.response_code || ''} ${flow.response_phrase || ''}`.trim() : '-';

            elements.flowsTableBody.insertAdjacentHTML('beforeend',
                `<tr class="hover:bg-slate-800/50 transition-colors">
                    <td class="px-6 py-3 text-xs font-mono text-slate-400">${flow.timestamp || ''}</td>
                    <td class="px-6 py-3 text-xs font-mono text-blue-400">${flow.src_ip || '-'}</td>
                    <td class="px-6 py-3 text-xs font-mono text-emerald-400">${flow.dst_ip || '-'}</td>
                    <td class="px-6 py-3 text-xs text-slate-300 font-bold">${flow.method || '-'}</td>
                    <td class="px-6 py-3 text-xs text-slate-300 truncate max-w-[200px]" title="${flow.uri}">${flow.uri || '-'}</td>
                    <td class="px-6 py-3 text-xs text-slate-300">${resp}</td>
                </tr>`
            );
        });
    }

    function renderAnomalies(report) {
        const ar = report.security_anomaly_report || {};
        if (elements.anomalySummaryText) elements.anomalySummaryText.textContent = ar.summary || 'No anomalies detected.';

        function renderList(bodyEl, arr) {
            if (!bodyEl) return;
            bodyEl.innerHTML = '';
            
            if (!arr || !arr.length) {
                bodyEl.innerHTML = `<tr><td class="px-4 py-4 text-center text-slate-500">None detected.</td></tr>`;
                return;
            }
            
            arr.forEach((item, idx) => {
                const jsonStr = typeof item === 'string' ? item : JSON.stringify(item, null, 2);
                bodyEl.insertAdjacentHTML('beforeend',
                    `<tr>
                        <td class="px-4 py-3 align-top">
                            <div class="text-[10px] text-slate-500 mb-1 font-mono">EVENT #${idx + 1}</div>
                            <pre class="text-[11px] font-mono whitespace-pre-wrap text-slate-300 bg-slate-950/50 p-2 rounded border border-slate-800">${jsonStr}</pre>
                        </td>
                    </tr>`
                );
            });
        }

        renderList(elements.portScansBody, ar.port_scans);
        renderList(elements.cleartextBody, ar.cleartext_credentials);
    }

    function renderPackets(report) {
        if (!elements.packetsTableBody) return;

        const packets = report.dissected_packets || [];
        elements.packetsTableBody.innerHTML = '';

        if (!packets.length) {
            elements.packetsTableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="p-12 text-center">
                        <div class="text-slate-600 mb-2"><i class="fas fa-network-wired text-4xl opacity-20"></i></div>
                        <p class="text-slate-500">Start a capture to view dissected packets.</p>
                    </td>
                </tr>`;
            return;
        }

        const displayPackets = packets.slice(0, 500); 

        displayPackets.forEach((pkt) => {
            const layers = (pkt && pkt._source && pkt._source.layers) || {};
            const frame = layers.frame || {};
            const ip = layers.ip || layers.ipv6 || {};

            const frameNum = frame['frame.number'] || '?';
            const timeRel = frame['frame.time_relative'] || '0.0';
            const len = frame['frame.len'] || '?';

            const src = ip['ip.src'] || ip['ipv6.src'] || ip['ip.src_host'] || 'N/A';
            const dst = ip['ip.dst'] || ip['ipv6.dst'] || ip['ip.dst_host'] || 'N/A';

            let proto = 'TCP/UDP';
            const protoStr = frame['frame.protocols'];
            if (protoStr) {
                const parts = protoStr.split(':');
                proto = (parts[parts.length - 1] || 'DATA').toUpperCase();
            }

            elements.packetsTableBody.insertAdjacentHTML('beforeend',
                `<tr class="hover:bg-slate-800/50 transition-colors">
                    <td class="px-6 py-2 text-xs font-mono text-slate-500">${frameNum}</td>
                    <td class="px-6 py-2 text-xs font-mono text-slate-400">${parseFloat(timeRel).toFixed(4)}</td>
                    <td class="px-6 py-2 text-xs font-mono text-blue-400">${src}</td>
                    <td class="px-6 py-2 text-xs font-mono text-emerald-400">${dst}</td>
                    <td class="px-6 py-2 text-xs font-bold text-slate-300">${proto}</td>
                    <td class="px-6 py-2 text-xs font-mono text-slate-400">${len}</td>
                </tr>`
            );
        });
        
        if (packets.length > 500) {
            elements.packetsTableBody.insertAdjacentHTML('beforeend', 
                `<tr><td colspan="6" class="p-2 text-center text-xs text-slate-500 italic">... ${packets.length - 500} more packets not shown ...</td></tr>`
            );
        }
    }

    // --- DOWNLOAD & AI LOGIC ---

    async function checkReportAvailability() {
        try {
            const res = await fetch(`${API_BASE_URL}/report_files`);
            if (!res.ok) throw new Error('HTTP error');
            const data = await res.json();

            if (data.status === 'success' && data.pdf_report) {
                reportDownloadUrl = data.pdf_report;
                
                if (elements.snifferDownloadReportBtn) {
                    elements.snifferDownloadReportBtn.disabled = false;
                    elements.snifferDownloadReportBtn.classList.remove('opacity-50', 'cursor-not-allowed');
                }

                if (elements.snifferAnalyzeReportDropdown) {
                    elements.snifferAnalyzeReportDropdown.disabled = false;
                    elements.snifferAnalyzeReportDropdown.classList.remove('opacity-50', 'cursor-not-allowed');
                }
                return;
            }
        } catch (e) {
            // silent fail
        }

        reportDownloadUrl = null;
        if (elements.snifferDownloadReportBtn) {
            elements.snifferDownloadReportBtn.disabled = true;
            elements.snifferDownloadReportBtn.classList.add('opacity-50', 'cursor-not-allowed');
        }
        if (elements.snifferAnalyzeReportDropdown) {
            elements.snifferAnalyzeReportDropdown.disabled = true;
            elements.snifferAnalyzeReportDropdown.classList.add('opacity-50', 'cursor-not-allowed');
        }
    }

    async function analyzeReport(llmMode) {
        const button = elements.snifferAnalyzeReportDropdown;
        if (!button || button.disabled) return;

        setStatus(`Preparing AI analysis (${llmMode})...`, 'busy');
        toggleSpinner(button, true);

        try {
            let res = await fetch(`${API_BASE_URL}/trigger_ai_analysis`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ llm_mode: llmMode }),
            });
            let data = await res.json();
            
            if (data.status !== 'success') {
                throw new Error(data.message || 'Analysis trigger failed.');
            }

            res = await fetch(`${CHATBOT_REDIRECT_URL}/scanner_analysis`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ llm_mode: llmMode, scanner_type: data.scanner_type }),
            });
            data = await res.json();

            if (res.ok && data.status === 'success') {
                appendLog('[✓] AI analysis initiated. Redirecting...');
                setStatus('Redirecting to AI...', 'success');
                window.location.href = `${CHATBOT_REDIRECT_URL}?mode=${data.llm_mode}&summary=${encodeURIComponent(data.summary)}`;
            } else {
                throw new Error(data.message || `Analysis failed.`);
            }
        } catch (err) {
            appendLog(`[x] AI Analysis Error: ${err.message}`);
            setStatus('Analysis failed', 'error');
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

        setStatus('Starting capture...', 'busy');
        switchTab('summary'); 

        appendLog('--- New Capture Initiated ---');

        await apiPost('/start_capture', {
            target_ip: targetIp,
            duration,
            max_packets: maxPackets,
            interface_id: null, 
            custom_bpf_filter: bpfFilter,
        }, elements.startCaptureBtn);
    }

    async function stopCapture() {
        setStatus('Stopping...', 'busy');
        await apiPost('/stop_capture', {}, elements.stopCaptureBtn);
    }

    // --- INIT ---

    function setupEventListeners() {
        if(elements.startCaptureBtn) elements.startCaptureBtn.addEventListener('click', startCapture);
        if(elements.stopCaptureBtn) elements.stopCaptureBtn.addEventListener('click', stopCapture);

        if(elements.summaryTabBtn) elements.summaryTabBtn.addEventListener('click', () => switchTab('summary'));
        if(elements.flowsTabBtn) elements.flowsTabBtn.addEventListener('click', () => switchTab('flows'));
        if(elements.anomaliesTabBtn) elements.anomaliesTabBtn.addEventListener('click', () => switchTab('anomalies'));
        if(elements.packetsTabBtn) elements.packetsTabBtn.addEventListener('click', () => switchTab('packets'));

        if(elements.refreshSnifferResultsBtn) {
            elements.refreshSnifferResultsBtn.addEventListener('click', () => {
                setStatus('Refreshing data...', 'busy');
                Promise.all([loadAndRenderReport(), checkReportAvailability()]).then(() =>
                    setStatus('Ready', 'ready')
                );
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

        if(elements.snifferAnalyzeReportDropdown) {
            elements.snifferAnalyzeReportDropdown.addEventListener('click', (e) => {
                if (!elements.snifferAnalyzeReportDropdown.disabled) {
                    e.stopPropagation();
                    elements.snifferLlmAnalysisOptions.classList.toggle('hidden');
                }
            });
        }

        if(elements.snifferLlmAnalysisOptions) {
            elements.snifferLlmAnalysisOptions.addEventListener('click', (e) => {
                e.preventDefault();
                const link = e.target.closest('a[data-llm-mode]');
                if (!link) return;
                
                const mode = link.dataset.llmMode;
                elements.snifferLlmAnalysisOptions.classList.add('hidden'); 
                analyzeReport(mode);
            });
        }

        document.addEventListener('click', (e) => {
            if (elements.snifferAnalyzeReportDropdown && elements.snifferLlmAnalysisOptions) {
                if (!elements.snifferAnalyzeReportDropdown.contains(e.target)) {
                    elements.snifferLlmAnalysisOptions.classList.add('hidden');
                }
            }
        });
    }

    function init() {
        appendLog('Initializing Packet Sniffer...');
        setupEventListeners();
        initializeLogStream();
        switchTab('summary');

        loadAndRenderReport();
        checkReportAvailability();
        setStatus('Ready to capture', 'ready');
    }

    init();
});