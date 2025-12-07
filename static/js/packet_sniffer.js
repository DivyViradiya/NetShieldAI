document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Element Selectors ---
    const elements = {
        // Inputs & Controls
        detectIpBtn: document.getElementById('detectIpBtn'),
        startCaptureBtn: document.getElementById('startCaptureBtn'),
        stopCaptureBtn: document.getElementById('stopCaptureBtn'),
        refreshResultsBtn: document.getElementById('refreshResultsBtn'),
        clearLogBtn: document.getElementById('clearLogBtn'),
        
        // Data Inputs
        targetIpInput: document.getElementById('targetIp'),
        interfaceSelect: document.getElementById('interfaceId'),
        durationInput: document.getElementById('duration'),
        maxPacketsInput: document.getElementById('maxPackets'),
        bpfFilterInput: document.getElementById('customBpfFilter'),
        
        // Output Displays
        logOutput: document.getElementById('logOutput'),
        scanStatus: document.getElementById('scanStatus'),
        totalPacketsDisplay: document.getElementById('totalPacketsDisplay'),
        captureDurationDisplay: document.getElementById('captureDurationDisplay'),
        filterDisplay: document.getElementById('filterDisplay'),

        // Report Buttons
        downloadReportBtn: document.getElementById('downloadReportBtn'),
        downloadJsonBtn: document.getElementById('downloadJsonBtn'),
        analyzeReportDropdown: document.getElementById('analyzeReportDropdown'),
        llmAnalysisOptions: document.getElementById('llmAnalysisOptions'),
        
        // Tab Buttons
        packetsTabBtn: document.getElementById('packetsTabBtn'),
        flowsTabBtn: document.getElementById('flowsTabBtn'),
        statsTabBtn: document.getElementById('statsTabBtn'),
        
        // Content Containers
        packetsContent: document.getElementById('packetsContent'),
        flowsContent: document.getElementById('flowsContent'),
        statsContent: document.getElementById('statsContent'),
        
        // Table/Text Areas
        dissectedPacketsTableBody: document.getElementById('dissectedPacketsTableBody'),
        applicationFlowsTableBody: document.getElementById('applicationFlowsTableBody'),
        
        // Reworked Stats elements
        generalSummaryTableBody: document.getElementById('generalSummaryTableBody'),
        anomalyReportTableBody: document.getElementById('anomalyReportTableBody'),
        anomalyCountDisplay: document.getElementById('anomalyCountDisplay'),
        rawStatsOutput: document.getElementById('rawStatsOutput'),
    };

    // --- State Variables ---
    const API_BASE_URL = '/packet_sniffer';
    const CHATBOT_REDIRECT_URL = '/chatbot'; 
    let isActionInProgress = false;
    let reportDownloadUrl = null;
    let jsonDownloadUrl = null;
    let activeTab = 'packets';


    // --- Helper Functions ---
    
    /**
     * Toggles the loading spinner on a button.
     */
    function toggleSpinner(button, isLoading) {
        if (!button) return;
        let buttonText = button.querySelector('.button-text');
        let spinner = button.querySelector('.spinner');
        
        if (!buttonText) buttonText = button;
        if (!spinner) spinner = button.querySelector('.spinner');

        button.disabled = isLoading;
        if (buttonText && spinner) {
            buttonText.classList.toggle('hidden', isLoading);
            spinner.classList.toggle('hidden', !isLoading);
        } else if (isLoading) {
             button.classList.add('opacity-50', 'cursor-not-allowed');
        } else {
             button.classList.remove('opacity-50', 'cursor-not-allowed');
        }
        
        const caret = button.querySelector('.fa-caret-down');
        if (caret) caret.classList.toggle('hidden', isLoading);
    }
    
    /**
     * Appends a message to the log display.
     */
    function appendLog(message) {
        if (!elements.logOutput) return;
        elements.logOutput.textContent += message + '\n'; 
        elements.logOutput.scrollTop = elements.logOutput.scrollHeight;
    }

    /**
     * Sets the main status message text and color.
     */
    function setStatus(text, type = 'ready') {
        if (!elements.scanStatus) return;
        
        elements.scanStatus.className = 'text-center text-xs py-2 rounded border border-slate-800 bg-slate-900/50 text-slate-400';
        const currentIcon = elements.scanStatus.querySelector('i');
        if (currentIcon) currentIcon.remove();

        let iconClass = '';

        switch (type) {
            case 'busy':
                elements.scanStatus.classList.add('bg-yellow-900/50', 'text-yellow-400');
                iconClass = 'fas fa-cog fa-spin';
                break;
            case 'error':
                elements.scanStatus.classList.add('bg-red-900/50', 'text-red-400');
                iconClass = 'fas fa-times-circle';
                break;
            case 'success':
                elements.scanStatus.classList.add('bg-green-900/50', 'text-green-400');
                iconClass = 'fas fa-check-circle';
                break;
            default: // ready
                elements.scanStatus.classList.add('bg-slate-900/50', 'text-green-400');
                iconClass = 'fas fa-circle';
        }
        
        const iconElement = document.createElement('i');
        iconElement.className = `${iconClass} text-[8px] mr-2`;
        elements.scanStatus.prepend(iconElement);

        elements.scanStatus.textContent = text;
    }
    
    /**
     * Default state setter for when analysis fails or report is missing.
     * Resets all tables to the 'no data' state.
     */
    function resetAnalysisDisplays(targetIp) {
        elements.totalPacketsDisplay.textContent = '0';
        elements.captureDurationDisplay.textContent = '0.00s';
        elements.filterDisplay.textContent = targetIp ? `host ${targetIp}` : 'N/A';
        elements.rawStatsOutput.textContent = '// No raw statistics output.';
        
        elements.dissectedPacketsTableBody.innerHTML = `<tr><td colspan="7" class="p-12 text-center">
            <p class="text-slate-500">No packets were captured or analyzed.</p>
            </td></tr>`;
        
        elements.applicationFlowsTableBody.innerHTML = `<tr><td colspan="6" class="p-12 text-center">
            <p class="text-slate-500">No application layer flows (e.g., HTTP) found.</p>
            </td></tr>`;

        elements.generalSummaryTableBody.innerHTML = `<tr><td colspan="2" class="px-4 py-8 text-center text-slate-500">Run capture to view summary.</td></tr>`;
        
        elements.anomalyReportTableBody.innerHTML = `<tr><td colspan="2" class="px-4 py-4 text-center text-slate-500">No anomalies checked.</td></tr>`;
        elements.anomalyCountDisplay.textContent = '0';
        
        checkReportAvailability(); // Ensure buttons are disabled
    }


    // --- API & Data Functions ---

    /**
     * A generic function to handle API POST requests.
     */
    async function apiPost(endpoint, body = {}, button = null) {
        if (isActionInProgress) return;
        isActionInProgress = true;
        if (button) toggleSpinner(button, true);

        try {
            const response = await fetch(`${API_BASE_URL}${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.message || `Request failed with status ${response.status}`);
            }
            appendLog(`[✓] ${data.message}`);
            return data;
        } catch (error) {
            appendLog(`[x] Error: ${error.message}`);
            setStatus('Error occurred', 'error');
            return null;
        } finally {
            if (button) toggleSpinner(button, false);
            isActionInProgress = false;
        }
    }
    
    /**
     * Fetches and populates the network interface dropdown.
     */
    async function fetchInterfaces() {
        elements.interfaceSelect.innerHTML = '<option value="">Loading...</option>';
        try {
            const response = await fetch(`${API_BASE_URL}/get_interfaces`);
            const data = await response.json();

            if (data.status === 'success') {
                elements.interfaceSelect.innerHTML = ''; // Clear loading
                data.interfaces.forEach(iface => {
                    const option = document.createElement('option');
                    option.value = iface.id;
                    option.textContent = `${iface.id}. ${iface.description}`;
                    elements.interfaceSelect.appendChild(option);
                });
                // Attempt to auto-select the first non-loopback interface if possible
                if (data.interfaces.length > 0) {
                    elements.interfaceSelect.value = data.interfaces[0].id;
                }
            } else {
                throw new Error(data.message);
            }
        } catch (error) {
            appendLog(`[x] Failed to list interfaces: ${error.message}. TShark might be missing or permission denied.`);
            elements.interfaceSelect.innerHTML = '<option value="">Error Loading Interfaces</option>';
        }
    }

    /**
     * Fetches the local IP and updates the target field if empty.
     */
    async function fetchAndSetLocalIp() {
        try {
            // Re-using the network_scanner endpoint for local IP detection logic
            const response = await fetch('/network_scanner/local_ip'); 
            const data = await response.json();
            const localIp = data.local_ip || '127.0.0.1';
            if (elements.targetIpInput.value === '') {
                elements.targetIpInput.value = localIp;
            }
            elements.filterDisplay.textContent = elements.bpfFilterInput.value || `host ${elements.targetIpInput.value.trim()}`;
        } catch (error) {
            appendLog('[x] Error fetching local IP.');
        }
    }
    
    /**
     * Updates the Dissected Packets table.
     */
    function updateDissectedPacketsTable(packets, anomalies) {
        elements.dissectedPacketsTableBody.innerHTML = '';
        const anomalyMap = {};
        
        // Map frame number to anomaly type for quick lookup
        anomalies.protocol_violations.forEach(a => {
            anomalyMap[a.frame_number] = a.type;
        });

        if (!packets || packets.length === 0) {
            elements.dissectedPacketsTableBody.innerHTML = `<tr><td colspan="7" class="p-12 text-center">
                <p class="text-slate-500">No packets were captured or analyzed.</p>
                </td></tr>`;
            return;
        }
        
        packets.forEach((p, index) => {
            const layers = p._source.layers;
            const frameNum = layers.frame['frame.number'];
            const timeRel = layers.frame['frame.time_relative'];
            const srcIp = layers.ip ? layers.ip['ip.src'] : 'N/A';
            const dstIp = layers.ip ? layers.ip['ip.dst'] : 'N/A';
            const protocol = layers.frame['frame.protocols'].split(':').pop().toUpperCase();
            
            // TShark puts a summary string in the last protocol layer (e.g., tcp.summary, http.request.line)
            const infoSummary = layers.http ? layers.http['http.request.line'] || layers.http['http.response.phrase'] : layers.tcp ? layers.tcp['tcp.summary'] : layers.udp ? layers.udp['udp.summary'] : '...';
            
            const anomaly = anomalyMap[frameNum];
            let anomalyColor = 'text-slate-500';

            if (anomaly) {
                anomalyColor = 'text-red-400 font-semibold';
            }

            const row = `
                <tr>
                    <td class="px-4 py-2 text-sm text-slate-400">${frameNum}</td>
                    <td class="px-4 py-2 text-sm font-mono">${parseFloat(timeRel).toFixed(4)}</td>
                    <td class="px-4 py-2 text-sm font-mono text-indigo-400">${srcIp}</td>
                    <td class="px-4 py-2 text-sm font-mono text-green-400">${dstIp}</td>
                    <td class="px-4 py-2 text-sm font-semibold">${protocol}</td>
                    <td class="px-4 py-2 text-sm">${infoSummary || 'N/A'}</td>
                    <td class="px-4 py-2 text-sm ${anomalyColor}">${anomaly || 'None'}</td>
                </tr>`;
            elements.dissectedPacketsTableBody.insertAdjacentHTML('beforeend', row);
        });
    }

    /**
     * Updates the Application Flows table.
     */
    function updateApplicationFlowsTable(flows) {
        elements.applicationFlowsTableBody.innerHTML = ''; 

        if (!flows || flows.length === 0) {
            elements.applicationFlowsTableBody.innerHTML = `<tr><td colspan="6" class="p-12 text-center">
                <p class="text-slate-500">No application layer flows (e.g., HTTP) found.</p>
                </td></tr>`;
            return;
        }

        flows.forEach(flow => {
            const row = `
                <tr>
                    <td class="px-4 py-2 text-sm font-mono">${flow.timestamp ? parseFloat(flow.timestamp).toFixed(4) : 'N/A'}</td>
                    <td class="px-4 py-2 text-sm font-mono">${flow.src_ip || 'N/A'}</td>
                    <td class="px-4 py-2 text-sm font-mono">${flow.dst_ip || 'N/A'}</td>
                    <td class="px-4 py-2 text-sm font-semibold text-yellow-400">${flow.method || 'N/A'}</td>
                    <td class="px-4 py-2 text-sm text-slate-300 break-all">${flow.uri || 'N/A'}</td>
                    <td class="px-4 py-2 text-sm font-semibold text-green-400">${flow.response_code || 'N/A'}</td>
                </tr>`;
            elements.applicationFlowsTableBody.insertAdjacentHTML('beforeend', row);
        });
    }

    /**
     * Formats and displays the Traffic Statistics and Anomaly Report in tables.
     */
    function updateTrafficStats(stats) {
        const summary = stats.traffic_summary;
        const anomalies = stats.security_anomaly_report;
        let summaryHtml = '';

        // --- 1. General Summary Table ---
        if (summary) {
            summaryHtml += `
                <tr><td class="px-4 py-2 font-semibold w-1/4">Target IP</td><td class="px-4 py-2 font-mono text-indigo-400">${stats.target_ip}</td></tr>
                <tr><td class="px-4 py-2 font-semibold">Total Packets</td><td class="px-4 py-2">${summary.total_packets.toLocaleString()}</td></tr>
                <tr><td class="px-4 py-2 font-semibold">Total Bytes</td><td class="px-4 py-2">${summary.total_bytes.toLocaleString()}</td></tr>
                <tr><td class="px-4 py-2 font-semibold">Duration Analyzed</td><td class="px-4 py-2">${summary.effective_capture_duration_seconds} seconds</td></tr>
                <tr><td class="px-4 py-2 font-semibold">Average Rate (Bps)</td><td class="px-4 py-2">${summary.average_rate_bps.toLocaleString()}</td></tr>
                <tr><td class="px-4 py-2 font-semibold">Analysis Time</td><td class="px-4 py-2">${stats.analysis_time_seconds} seconds</td></tr>
            `;
            elements.generalSummaryTableBody.innerHTML = summaryHtml;
            elements.totalPacketsDisplay.textContent = summary.total_packets.toLocaleString();
            elements.captureDurationDisplay.textContent = `${summary.effective_capture_duration_seconds}s`;
        } else {
             elements.generalSummaryTableBody.innerHTML = `<tr><td colspan="2" class="px-4 py-8 text-center text-slate-500">No summary data available.</td></tr>`;
             elements.totalPacketsDisplay.textContent = '0';
             elements.captureDurationDisplay.textContent = '0.00s';
        }

        // --- 2. Security Anomaly Table ---
        let anomalyHtml = '';
        let totalAlerts = 0;
        
        const allAnomalies = [
            ...(anomalies.port_scans || []).map(a => ({ type: 'Port Scan', details: a.details })),
            ...(anomalies.fragmentation_alerts || []).map(a => ({ type: 'Fragmentation Alert', details: a.details })),
            ...(anomalies.protocol_violations || []).map(a => ({ type: 'Protocol Violation', details: a.details })),
            ...(anomalies.cleartext_credentials || []).map(a => ({ type: 'Cleartext Credential Leak', details: a.details })),
        ];
        
        if (allAnomalies.length > 0) {
            totalAlerts = allAnomalies.length;
            allAnomalies.forEach(a => {
                const color = a.type.includes('Leak') || a.type.includes('Violation') ? 'text-red-400' : 'text-yellow-400';
                anomalyHtml += `
                    <tr>
                        <td class="px-4 py-2 font-semibold ${color}">${a.type}</td>
                        <td class="px-4 py-2 text-slate-300">${a.details}</td>
                    </tr>
                `;
            });
            elements.anomalyReportTableBody.innerHTML = anomalyHtml;
        } else {
            // Ensure the anomaly table reflects the overall summary if no specific issues are listed
            anomalyHtml = `<tr><td colspan="2" class="px-4 py-4 text-center text-green-500/70">Summary: ${anomalies.summary}. No specific issues found.</td></tr>`;
            elements.anomalyReportTableBody.innerHTML = anomalyHtml;
        }
        elements.anomalyCountDisplay.textContent = totalAlerts;


        // --- 3. Raw Stats Output (Protocol Hierarchy / Conversation Stats) ---
        let rawOutput = '';
        if (summary) {
            rawOutput += "========================================\nPROTOCOL HIERARCHY STATISTICS\n========================================\n";
            // Filter out empty lines and trim whitespace before joining
            rawOutput += summary.protocol_hierarchy_stats.filter(line => line.trim()).join('\n');
            rawOutput += "\n\n========================================\nTCP CONVERSATION STATISTICS (Top Talkers)\n========================================\n";
            rawOutput += summary.tcp_conversation_stats.filter(line => line.trim()).join('\n');
        }
        elements.rawStatsOutput.textContent = rawOutput.trim() || '// No raw statistics output.';
    }

    /**
     * Fetches the latest analysis report JSON and updates all result displays.
     */
    async function fetchAndDisplayAnalysis() {
        const targetIp = elements.targetIpInput.value.trim();
        try {
            const response = await fetch(`${API_BASE_URL}/get_json_report`);
            const data = await response.json();
            
            if (response.ok && data.status === 'success') {
                const packets = data.dissected_packets;
                const flows = data.application_flow_analysis.flows;
                const anomalies = data.security_anomaly_report;

                // Update all displays
                updateDissectedPacketsTable(packets, anomalies);
                updateApplicationFlowsTable(flows);
                updateTrafficStats(data);
                
                // Update header filter display
                elements.filterDisplay.textContent = elements.bpfFilterInput.value || `host ${targetIp}`;

            } else {
                // If API returns success=false or bad JSON format (or 404/500)
                resetAnalysisDisplays(targetIp);
                throw new Error(data.message || 'JSON analysis data not found.');
            }
        } catch (error) {
            // Reset displays and log error if fetch fails completely (e.g., 404)
            resetAnalysisDisplays(targetIp);
            appendLog(`[x] Error fetching analysis report: ${error.message}`);
        }
    }


    // --- Core Capture Logic (Unchanged) ---

    /**
     * Initiates a packet capture.
     */
    async function startCapture() {
        const targetIp = elements.targetIpInput.value.trim();
        const interfaceId = elements.interfaceSelect.value;
        const duration = elements.durationInput.value;
        const maxPackets = elements.maxPacketsInput.value;
        const customBpfFilter = elements.bpfFilterInput.value.trim();

        if (!targetIp || !interfaceId) {
            appendLog('[!] Target IP and Interface are required.');
            setStatus('Input required', 'error');
            return;
        }

        setStatus(`Starting capture for ${targetIp} on interface ${interfaceId}...`, 'busy');
        
        // Disable start/enable stop
        elements.startCaptureBtn.disabled = true;
        elements.stopCaptureBtn.disabled = false;
        
        // Update filter display
        elements.filterDisplay.textContent = customBpfFilter || `host ${targetIp}`;
        
        // Switch to Packets tab automatically
        switchTab('packets');

        const result = await apiPost('/start_capture', {
            target_ip: targetIp,
            duration: duration,
            max_packets: maxPackets,
            interface_id: interfaceId,
            custom_bpf_filter: customBpfFilter
        }, null); // Don't use button spinner here, relies on global status

        if (!result) {
            elements.startCaptureBtn.disabled = false;
            elements.stopCaptureBtn.disabled = true;
        }
    }
    
    /**
     * Stops an active packet capture.
     */
    async function stopCapture() {
        setStatus('Stopping capture...', 'busy');
        const result = await apiPost('/stop_capture', {}, elements.stopCaptureBtn);
        
        if (result) {
            elements.startCaptureBtn.disabled = false;
        }
    }


    /**
     * Server-Sent Events (SSE) for Live Log.
     */
    function initializeLogStream() {
        const eventSource = new EventSource(`${API_BASE_URL}/log_stream`);

        eventSource.onmessage = (event) => {
            const message = event.data;
            if (message.startsWith(':')) return;

            appendLog(message);

            // Custom event sent from packet_sniffer_bp.py when analysis thread finishes
            if (event.lastEventId === 'analysis_complete') {
                setStatus('Analysis complete! Check results.', 'success');
                // Auto-refresh data on completion
                fetchAndDisplayAnalysis();
                checkReportAvailability();
                // Ensure buttons are reset if process finished without manual stop
                elements.startCaptureBtn.disabled = false;
                elements.stopCaptureBtn.disabled = true;
            } else if (message.includes("Packet capture failed") || message.includes("Requires Admin Privileges")) {
                // Handle immediate error during capture start
                 elements.startCaptureBtn.disabled = false;
                 elements.stopCaptureBtn.disabled = true;
                 setStatus('Capture failed. Check logs.', 'error');
            }
        };

        eventSource.onerror = () => {
            appendLog('[!] Log stream connection failed. Please refresh.');
            setStatus('Log stream disconnected', 'error');
            eventSource.close();
        };
    }
    
    /**
     * Tab Switching Logic.
     */
    function switchTab(tabName) {
        activeTab = tabName;
        // Update tab buttons
        elements.packetsTabBtn.classList.toggle('active', tabName === 'packets');
        elements.flowsTabBtn.classList.toggle('active', tabName === 'flows');
        elements.statsTabBtn.classList.toggle('active', tabName === 'stats');

        // Update content containers
        elements.packetsContent.classList.toggle('hidden', tabName !== 'packets');
        elements.flowsContent.classList.toggle('hidden', tabName !== 'flows');
        elements.statsContent.classList.toggle('hidden', tabName !== 'stats');
    }


    /**
     * Checks if reports are available and updates the download/analysis buttons.
     */
    async function checkReportAvailability() {
        // ... (checkReportAvailability logic is the same as before)
        try {
            const response = await fetch(`${API_BASE_URL}/report_files`);
            if (response.ok) {
                const data = await response.json();
                if (data.status === 'success') {
                    reportDownloadUrl = data.pdf_report;
                    jsonDownloadUrl = data.json_report;
                    
                    // Enable Download Buttons
                    [elements.downloadReportBtn, elements.downloadJsonBtn].forEach(btn => {
                        btn.disabled = false;
                        btn.classList.remove('opacity-50', 'cursor-not-allowed');
                    });
                    
                    // Enable Analysis Button
                    if (elements.analyzeReportDropdown) {
                        elements.analyzeReportDropdown.disabled = false;
                        elements.analyzeReportDropdown.classList.remove('opacity-50', 'cursor-not-allowed');
                        elements.analyzeReportDropdown.classList.add('hover:bg-indigo-500');
                    }
                    return;
                }
            }
        } catch (error) {
            console.error('Error checking report availability:', error);
        }

        // Disable all report actions if no reports are found
        reportDownloadUrl = null;
        jsonDownloadUrl = null;
        [elements.downloadReportBtn, elements.downloadJsonBtn, elements.analyzeReportDropdown].forEach(btn => {
            if (btn) {
                btn.disabled = true;
                btn.classList.add('opacity-50', 'cursor-not-allowed');
                btn.classList.remove('hover:bg-red-500', 'hover:bg-indigo-500'); 
            }
        });
    }

    /**
     * Triggers the server-side proxy to upload the PDF for AI analysis.
     */
    async function analyzeReport(llmMode) {
        const button = elements.analyzeReportDropdown;
        if (!button || button.disabled) return;
        
        setStatus(`Preparing report for AI analysis (${llmMode})...`, 'busy');
        toggleSpinner(button, true); 
        
        // Disable other buttons during proxy transfer
        elements.downloadReportBtn.disabled = true;
        elements.downloadJsonBtn.disabled = true;

        try {
            // 1. Check local PDF availability via the local blueprint.
            let response = await fetch(`${API_BASE_URL}/trigger_ai_analysis`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
            });
            let data = await response.json();
            
            if (data.status !== 'success') {
                throw new Error(data.message || 'PDF availability check failed.');
            }
            
            // 2. Call the central proxy route on the chatbot blueprint.
            response = await fetch(`${CHATBOT_REDIRECT_URL}/scanner_analysis`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ llm_mode: llmMode, scanner_type: data.scanner_type }) // Pass scanner_type
            });

            data = await response.json(); // Data now contains summary and llm_mode

            if (response.ok && data.status === 'success') {
                appendLog(`[✓] AI analysis initiated. Redirecting...`);
                setStatus('Analysis complete. Redirecting...', 'success');
                
                // 3. Redirect, passing summary and mode 
                window.location.href = `${CHATBOT_REDIRECT_URL}?mode=${data.llm_mode}&summary=${encodeURIComponent(data.summary)}`;
            } else {
                throw new Error(data.message || `Analysis failed with status ${response.status}`);
            }
        } catch (error) {
            appendLog(`[x] AI Analysis Error: ${error.message}`);
            setStatus('Analysis failed', 'error');
        } finally {
            // Only run cleanup if no redirect happened (i.e., if it failed)
            toggleSpinner(button, false);
            checkReportAvailability(); 
        }
    }


    // --- Event Listeners ---
    
    function setupEventListeners() {
        elements.detectIpBtn.addEventListener('click', fetchAndSetLocalIp);
        elements.startCaptureBtn.addEventListener('click', startCapture);
        elements.stopCaptureBtn.addEventListener('click', stopCapture);

        // Tab Event Listeners
        elements.packetsTabBtn.addEventListener('click', () => switchTab('packets'));
        elements.flowsTabBtn.addEventListener('click', () => switchTab('flows'));
        elements.statsTabBtn.addEventListener('click', () => switchTab('stats'));
        
        elements.clearLogBtn.addEventListener('click', async () => {
            const originalContent = elements.clearLogBtn.innerHTML;
            elements.clearLogBtn.disabled = true;
            elements.clearLogBtn.innerHTML = '<i class="fas fa-spinner fa-spin text-slate-400"></i>';
            
            try {
                // The /clear_log route is a placeholder in the backend, but we clear the frontend log regardless
                const result = await apiPost('/clear_log', {}, null);
                if (result) {
                    elements.logOutput.textContent = '';
                }
            } finally {
                elements.clearLogBtn.disabled = false;
                elements.clearLogBtn.innerHTML = originalContent; // Reset to "CLEAR"
            }
        });

        elements.refreshResultsBtn.addEventListener('click', () => {
            setStatus('Refreshing data...', 'busy');
            Promise.all([
                fetchInterfaces(),
                fetchAndSetLocalIp(),
                fetchAndDisplayAnalysis(),
                checkReportAvailability()
            ]).then(() => setStatus('System Ready', 'ready'));
        });

        // Report Downloads
        if (elements.downloadReportBtn) {
            elements.downloadReportBtn.addEventListener('click', () => {
                if (reportDownloadUrl) {
                    window.location.href = reportDownloadUrl;
                    appendLog('[✓] Downloading PDF report...');
                } else {
                    appendLog('[!] No PDF report available to download.');
                }
            });
        }
        
        if (elements.downloadJsonBtn) {
            elements.downloadJsonBtn.addEventListener('click', () => {
                if (jsonDownloadUrl) {
                    window.location.href = jsonDownloadUrl;
                    appendLog('[✓] Downloading JSON report...');
                } else {
                    appendLog('[!] No JSON report available to download.');
                }
            });
        }
        
        // Analysis Dropdown Toggle
        elements.analyzeReportDropdown.addEventListener('click', (e) => {
            if (!elements.analyzeReportDropdown.disabled) {
                elements.llmAnalysisOptions.classList.toggle('hidden');
                e.stopPropagation(); 
            }
        });
        
        // Analysis Option Selection
        elements.llmAnalysisOptions.addEventListener('click', (e) => {
            e.preventDefault();
            const option = e.target.closest('a[data-llm-mode]');
            if (option) {
                const llmMode = option.dataset.llmMode;
                elements.llmAnalysisOptions.classList.add('hidden'); 
                analyzeReport(llmMode); 
            }
        });

        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (elements.llmAnalysisOptions && elements.analyzeReportDropdown && !elements.analyzeReportDropdown.contains(e.target)) {
                elements.llmAnalysisOptions.classList.add('hidden');
            }
        });
    }

    // --- Initialization ---
    function init() {
        appendLog('Initializing UI...');
        setupEventListeners();
        initializeLogStream();
        
        // Set default tab
        switchTab('packets'); 

        // Initial data fetch
        setStatus('Initializing...', 'busy');
        Promise.all([
            fetchInterfaces(),
            fetchAndSetLocalIp(),
            fetchAndDisplayAnalysis(),
            checkReportAvailability()
        ]).then(() => {
            setStatus('System Ready', 'ready');
            appendLog('Initialization complete. Ready for capture.');
        });
    }

    init();
});