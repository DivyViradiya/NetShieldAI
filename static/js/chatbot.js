document.addEventListener('DOMContentLoaded', () => {
    
    // --- 0. SECURITY & ALERTS ---
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

    window.neoAlert = function(msg, title = 'System Notification', icon = 'notification_important') {
        return new Promise(resolve => {
            const modal = document.getElementById('system-modal');
            if(!modal) { alert(msg); resolve(true); return; }
            document.getElementById('system-modal-msg').innerHTML = msg;
            document.getElementById('system-modal-title-text').innerText = title;
            document.getElementById('system-modal-icon').innerText = icon;
            const cancelBtn = document.getElementById('system-modal-cancel');
            const confirmBtn = document.getElementById('system-modal-confirm');
            cancelBtn.style.display = 'none';
            confirmBtn.innerText = 'OK';
            modal.classList.add('show');
            confirmBtn.onclick = () => { modal.classList.remove('show'); resolve(true); };
        });
    };

    window.neoConfirm = function(msg, title = 'Confirm Action', icon = 'warning') {
        return new Promise(resolve => {
            const modal = document.getElementById('system-modal');
            if(!modal) { resolve(confirm(msg)); return; }
            document.getElementById('system-modal-msg').innerHTML = msg;
            document.getElementById('system-modal-title-text').innerText = title;
            document.getElementById('system-modal-icon').innerText = icon;
            const cancelBtn = document.getElementById('system-modal-cancel');
            const confirmBtn = document.getElementById('system-modal-confirm');
            cancelBtn.style.display = 'block';
            confirmBtn.innerText = 'Confirm';
            modal.classList.add('show');
            confirmBtn.onclick = () => { modal.classList.remove('show'); resolve(true); };
            cancelBtn.onclick = () => { modal.classList.remove('show'); resolve(false); };
        });
    };

    const MAX_FILE_SIZE = 16 * 1024 * 1024; // 16MB

    // Helper for file size validation
    function validateFileSize(file) {
        if (file.size > MAX_FILE_SIZE) {
            neoAlert(`File "${file.name}" is too large (${(file.size / (1024 * 1024)).toFixed(2)}MB). Maximum allowed is 16MB.`, 'Upload Error', 'error');
            return false;
        }
        return true;
    }

    // Helper to send authorized requests
    async function fetchWithAuth(url, options = {}) {
        const headers = {
            'X-CSRFToken': csrfToken,
            ...options.headers
        };
        
        // Add session ID if present
        if (currentSessionId) {
            headers['X-Session-ID'] = currentSessionId;
        }
        
        if (options.body && !(options.body instanceof FormData)) {
            headers['Content-Type'] = 'application/json';
        }
        
        try {
            const response = await fetch(url, { ...options, headers });
            
            // Handle Session Desync (401 Unauthorized or 404 Not Found for session)
            if ((response.status === 401 || response.status === 404) && currentSessionId) {
                console.warn(`[!] Session desync detected (${response.status}). Resetting UI context.`);
                neoAlert("Your session has expired or was cleared in the background. Resetting view.", "Session Desync", "sync_problem");
                clearView();
                return response; // Return anyway so caller can handle if needed
            }
            
            return response;
        } catch (err) {
            console.error("[FETCH_ERROR]", err);
            throw err;
        }
    }

    // Helper to get error message from RFC 7807 detail or generic error fields
    async function getErrorDetail(response) {
        try {
            const result = await response.json();
            return result.detail || result.error || result.message || `System Error (${response.status})`;
        } catch (e) {
            return `System Communication Error (${response.status})`;
        }
    }

    // --- 1. Initialize Markdown ---
    marked.setOptions({
        highlight: function(code, lang) {
            // [PERF] Skip syntax highlighting for large code blocks to prevent main-thread freeze
            if (code.length > 5000) return code;
            try {
                const language = hljs.getLanguage(lang) ? lang : 'plaintext';
                return hljs.highlight(code, { language }).value;
            } catch (err) {
                return code;
            }
        },
        langPrefix: 'hljs language-',
        breaks: true,
        gfm: true
    });

    // --- 2. UI Elements Map ---
    const ui = {
        // Layout
        layout: document.querySelector('.app-layout'),
        sidebarToggle: document.getElementById('sidebar-toggle'),
        commandCenter: document.getElementById('command-center'),
        ccToggle: document.getElementById('cc-toggle'),
        ccClose: document.getElementById('cc-close'),
        
        // Settings Inputs
        settingVerbosity: document.getElementById('setting-verbosity'),
        settingSpeed: document.getElementById('setting-speed'),
        settingIncognito: document.getElementById('setting-incognito'),
        
        // CC Actions
        btnClearContext: document.getElementById('cc-clear-context'),
        btnDeleteSession: document.getElementById('cc-delete-session'),
        btnWipeAll: document.getElementById('cc-wipe-all'),
        btnClearMemory: document.getElementById('cc-clear-memory'),
        btnDownloadTranscript: document.getElementById('cc-download-transcript'),

        // Status & Workflow
        statusText: document.getElementById('status-text'),
        statusDot: document.getElementById('status-dot'),
        workflowPanel: document.getElementById('workflow-panel'),
        
        // Upload View
        fileInput: document.getElementById('file-upload-input'),
        uploadZone: document.getElementById('upload-zone'),
        
        // Config View
        selectedFilename: document.getElementById('selected-filename'),
        removeFileBtn: document.getElementById('remove-file-btn'),
        customSelect: document.querySelector('.custom-select'),
        customTrigger: document.getElementById('custom-trigger'),
        hiddenModelInput: document.getElementById('selected-model-value'),
        customOptions: document.querySelectorAll('.custom-option'),
        startBtn: document.getElementById('start-analysis-btn'),
        uploadStatus: document.getElementById('upload-status'),
        
        // Compact Model Select
        compactTrigger: document.getElementById('model-trigger-compact'),
        compactDropdown: document.getElementById('model-dropdown-compact'),
        compactOptions: document.querySelectorAll('.model-opt'),
        
        // Chat Interface
        chatHistory: document.getElementById('chat-history'),
        messagesContainer: document.getElementById('messages-container'),
        welcomeState: document.getElementById('welcome-state'),
        typingIndicator: document.getElementById('typing-indicator'),
        userInput: document.getElementById('user-input'),
        sendBtn: document.getElementById('send-btn'),
        suggestionGrid: document.getElementById('suggestion-grid'),
        sessionList: document.getElementById('session-list'),
        sessionSearch: document.getElementById('session-search'),
        newChatBtn: document.getElementById('new-chat-btn'),

        // Modal Elements
        renameModal: document.getElementById('rename-modal'),
        renameInput: document.getElementById('rename-input'),
        cancelRenameBtn: document.getElementById('cancel-rename'),
        confirmRenameBtn: document.getElementById('confirm-rename'),

        // Topology Graph Elements
        btnViewTopology: document.getElementById('cc-view-topology'),
        topologyModal: document.getElementById('topology-modal'),
        btnCloseTopology: document.getElementById('close-topology-btn'),
        topologyContainer: document.getElementById('vis-network-container'),

        // Multimodal Elements
        attachmentPlusBtn: document.getElementById('attachment-plus-btn'),
        attachmentMenu: document.getElementById('attachment-menu'),
        attachmentPreview: document.getElementById('attachment-preview-area'),
        multimodalInput: document.getElementById('multimodal-file-input'),
        attachImage: document.getElementById('attach-image'),
        attachDoc: document.getElementById('attach-doc'),
        attachPcap: document.getElementById('attach-pcap')
    };

    // --- 3. State Variables ---
    let selectedFile = null;
    let isProcessing = false;
    let currentSessionId = null; 
    let attachedFiles = []; // Array of {file: File, id: string, type: 'image'|'doc'|'pcap', previewUrl: string}
    let sessionToRename = null;
    let isPinning = false;
    let allSessions = []; 
    let lastUserMessage = ""; 
    let inputHistory    = JSON.parse(sessionStorage.getItem('chatInputHistory') || '[]');
    let historyIndex    = -1;
    let tempDraft       = ""; 

    // --- 4. Command Center & Settings Logic ---

    ui.ccToggle.onclick = () => ui.commandCenter.classList.add('open');
    ui.ccClose.onclick = () => ui.commandCenter.classList.remove('open');

    // Clear Context (Keep session, wipe UI and backend history)
    ui.btnClearContext.onclick = async () => {
        if (await neoConfirm("Clear current analysis history? The AI context will be reset.", "Clear Context")) {
            try {
                await fetchWithAuth('/chatbot/clear_history', { method: 'POST' });
                ui.chatHistory.innerHTML = '';
                ui.welcomeState.style.display = 'block';
                ui.commandCenter.classList.remove('open');
            } catch (e) { console.error(e); }
        }
    };

    // Delete Active Session
    ui.btnDeleteSession.onclick = async () => {
        if (currentSessionId && await neoConfirm("Permanently delete this session?", "Delete Session", "delete_forever")) {
            await deleteSession(currentSessionId);
            ui.commandCenter.classList.remove('open');
        }
    };

    // Nuclear Wipe
    ui.btnWipeAll.onclick = async () => {
        if (await neoConfirm("DANGER: This will delete ALL past analysis sessions. This cannot be undone. Proceed?", "Wipe Database", "warning")) {
            try {
                await fetchWithAuth('/chatbot/delete_all_sessions', { method: 'POST' });
                clearView();
                loadSessionList();
                ui.commandCenter.classList.remove('open');
            } catch (e) { console.error(e); }
        }
    };

    // Clear AI Memory
    if (ui.btnClearMemory) {
        ui.btnClearMemory.onclick = async () => {
            if (await neoConfirm("Are you sure you want to wipe AI semantic memory? The Agent will forget your specific preferences and rules.", "Clear Memory", "memory")) {
                try {
                    const response = await fetchWithAuth('/chatbot/clear_memory', { method: 'POST' });
                    const res = await response.json();
                    if (res.success || res.status === 'success') {
                        addMessage('system', "SYSTEM_NOTIFICATION: Memory Banks Purged. All persistent rules and semantic facts have been wiped.", false);
                        ui.commandCenter.classList.remove('open');
                    } else {
                        throw new Error(res.error || res.message || "Memory wipe failed.");
                    }
                } catch (e) { 
                    console.error(e); 
                    neoAlert("Failed to clear memory: " + e.message, "Error", "error"); 
                }
            }
        };
    }

    // Export Transcript
    ui.btnDownloadTranscript.onclick = () => {
        const rows = document.querySelectorAll('.msg-row');
        let transcript = `NetShield AI Analysis Transcript\nDate: ${new Date().toLocaleString()}\n\n`;
        
        rows.forEach(row => {
            const role = row.classList.contains('user') ? 'HUMAN' : 'AI';
            if (row.classList.contains('system')) role = 'SYSTEM';
            if (row.classList.contains('system-action')) role = 'ACTION';
            
            const actionText = row.querySelector('.action-header')?.innerText || '';
            const bubble = row.querySelector('.msg-bubble');
            let text = bubble ? bubble.innerText.replace(/content_copyrefreshthumb_upthumb_down/g, '') : ''; 
            
            if (role === 'ACTION') text = `[Automated Task Triggered] ${actionText}`;
            if (text) transcript += `[${role}]: ${text}\n\n`;
        });

        const blob = new Blob([transcript], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `NetShield_Transcript_${new Date().getTime()}.txt`;
        a.click();
        URL.revokeObjectURL(url);
    };

    // --- Topology Graph Logic ---
    let networkInstance = null;

    if (ui.btnViewTopology) {
        ui.btnViewTopology.onclick = async () => {
            if (!currentSessionId) {
                alert("Please start an analysis session first.");
                return;
            }

            ui.commandCenter.classList.remove('open');
            ui.topologyModal.classList.add('show');
            
            ui.topologyContainer.innerHTML = '<div style="color: white; padding: 20px; text-align: center;">Fetching topology data...</div>';

            try {
                const response = await fetchWithAuth(`/chatbot/session/${currentSessionId}/graph`);
                
                if (!response.ok) {
                    const detail = await getErrorDetail(response);
                    throw new Error(detail);
                }

                const data = await response.json();

                if (data.success && data.graph_data && data.graph_data.nodes && data.graph_data.nodes.length > 0) {
                    renderTopology(data.graph_data);
                } else {
                    ui.topologyContainer.innerHTML = `<div style="color: #ef4444; padding: 20px; text-align: center;">No physical or logical topology data available for this session yet.</div>`;
                }
            } catch (error) {
                console.error("Graph Fetch Error:", error);
                ui.topologyContainer.innerHTML = `<div style="color: #ef4444; padding: 20px; text-align: center;">Failed to retrieve topology data.<br><br><span style="font-size:0.7rem; opacity:0.8;">${error.message}</span></div>`;
            }
        };
    }

    if (ui.btnCloseTopology) {
        ui.btnCloseTopology.onclick = () => {
            ui.topologyModal.classList.remove('show');
            // Clean up old instance to prevent memory leaks
            if (networkInstance) {
                networkInstance.destroy();
                networkInstance = null;
            }
        };
    }

    function renderTopology(graphData) {
        // Map NetworkX data to Vis.js format
        const visNodes = new vis.DataSet(graphData.nodes.map(node => {
            // Determine styling based on node type
            let color = '#3b82f6'; // Default blue
            let shape = 'dot';
            let icon = '';

            let displayLabel = node.id.split(':').pop();

            switch(node.type) {
                case 'Host': color = '#10b981'; shape = 'hexagon'; break;
                case 'Port': color = '#f59e0b'; shape = 'diamond'; break;
                case 'VulnerabilityType': color = '#ef4444'; shape = 'triangleDown'; displayLabel = node.name || node.title || displayLabel; break;
                case 'CodeFile': color = '#6366f1'; shape = 'box'; break;
                case 'ScanEvent': color = '#64748b'; shape = 'database'; break;
                case 'WebApplication': color = '#8b5cf6'; shape = 'box'; break;
                case 'Endpoint': color = '#0ea5e9'; break;
            }

            // Truncate long labels
            if (displayLabel.length > 25) displayLabel = displayLabel.substring(0, 22) + "...";

            // Build tooltip text (title) from arbitrary properties
            let propsHtml = '';
            for (const [key, value] of Object.entries(node)) {
                if (key !== 'id' && key !== 'type' && value) {
                   propsHtml += `<b>${key}:</b> ${value}<br>`;
                }
            }

            return {
                id: node.id,
                label: `[${node.type}]\n${displayLabel}`,
                title: `<div style="padding:5px; font-size:12px;"><b>ID:</b> ${node.id}<br>${propsHtml}</div>`,
                color: { background: color, border: '#1e1e24' },
                shape: shape,
                font: { color: '#f8fafc', face: 'monospace', size: 12 },
                borderWidth: 2,
                shadow: true
            };
        }));

        const visEdges = new vis.DataSet(graphData.links.map(link => {
            return {
                from: link.source,
                to: link.target,
                label: link.label || '',
                font: { color: '#94a3b8', size: 10, align: 'horizontal' },
                color: { color: '#475569', opacity: 0.8 },
                arrows: 'to',
                smooth: { type: 'continuous' }
            };
        }));

        const container = ui.topologyContainer;
        const data = { nodes: visNodes, edges: visEdges };
        
        const options = {
            nodes: {
                scaling: { min: 10, max: 30 }
            },
            interaction: {
                hover: true,
                tooltipDelay: 200,
                navigationButtons: true,
                keyboard: true
            },
            physics: {
                forceAtlas2Based: {
                    gravitationalConstant: -50,
                    centralGravity: 0.01,
                    springLength: 100,
                    springConstant: 0.08
                },
                maxVelocity: 50,
                solver: 'forceAtlas2Based',
                timestep: 0.35,
                stabilization: { iterations: 150 }
            }
        };

        // Initialize Network
        ui.topologyContainer.innerHTML = ''; // clear loading text
        networkInstance = new vis.Network(container, data, options);
    }

    // Helper Functions ... (keep existing)

    // Collapsible Section Logic
    const ingestionHeader = document.getElementById('data-ingestion-header');
    const ingestionSection = document.getElementById('sidebar-main-content');
    if (ingestionHeader && ingestionSection) {
        ingestionHeader.addEventListener('click', () => {
            ingestionSection.classList.toggle('collapsed');
        });
    }

    // Toggle Sidebar
    ui.sidebarToggle.addEventListener('click', () => {
        ui.layout.classList.toggle('sidebar-collapsed');
        ui.sidebarToggle.querySelector('span').textContent = 
            ui.layout.classList.contains('sidebar-collapsed') ? 'chevron_right' : 'chevron_left';
    });

    // File Upload Functionality
    if (ui.uploadZone && ui.fileInput) {
        ui.uploadZone.addEventListener('click', () => ui.fileInput.click());
        
        ui.uploadZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            ui.uploadZone.style.borderColor = 'var(--neo-blue)';
            ui.uploadZone.style.background = 'rgba(59, 130, 246, 0.05)';
        });

        ui.uploadZone.addEventListener('dragleave', () => {
            ui.uploadZone.style.borderColor = '';
            ui.uploadZone.style.background = '';
        });

        ui.uploadZone.addEventListener('drop', (e) => {
            e.preventDefault();
            ui.uploadZone.style.borderColor = '';
            ui.uploadZone.style.background = '';
            if (e.dataTransfer.files.length > 0) {
                ui.fileInput.files = e.dataTransfer.files;
                handleFileSelect(e.dataTransfer.files[0]);
            }
        });

        ui.fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                handleFileSelect(e.target.files[0]);
            }
        });
    }

    function handleFileSelect(file) {
        if (!validateFileSize(file)) {
            if (ui.fileInput) ui.fileInput.value = '';
            return;
        }
        selectedFile = file;
        ui.selectedFilename.textContent = file.name;
        switchView('config');
        ui.removeFileBtn.style.display = 'flex'; 
        if (ui.hiddenModelInput.value) {
            ui.startBtn.disabled = false;
        }
    }

    if (ui.removeFileBtn) {
        ui.removeFileBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            selectedFile = null;
            if (ui.fileInput) ui.fileInput.value = '';
            switchView('upload');
            updateContextStatus(false);
        });
    }

    // [FIXED] Analysis Start Logic
    ui.startBtn.onclick = async () => {
        if (!selectedFile || isProcessing) return;

        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('llm_mode', ui.hiddenModelInput.value);

        isProcessing = true;
        ui.startBtn.disabled = true;
        ui.startBtn.querySelector('.spinner').style.display = 'block';
        ui.startBtn.querySelector('.btn-text').textContent = "UPLOADING...";
        ui.uploadStatus.textContent = "Transmitting to Security Core...";

        try {
            const response = await fetch('/chatbot/upload_report', {
                method: 'POST',
                headers: { 'X-CSRFToken': csrfToken },
                body: formData
            });

            if (!response.ok) {
                const detail = await getErrorDetail(response);
                throw new Error(detail);
            }

            const result = await response.json();
            if (result.message || result.summary) {
                // Sync session ID if returned
                if (result.session_id) currentSessionId = result.session_id;

                ui.uploadStatus.textContent = "Success. Analysis loaded.";
                
                // Add AI summary message as a System component
                const summaryContent = result.summary || result.message;
                addMessage('system', `SYSTEM_NOTIFICATION: Upload Complete. Report successfully synchronized. Summary: ${summaryContent}`, false);
                
                // Reset view
                selectedFile = null;
                if (ui.fileInput) ui.fileInput.value = '';
                switchView('upload');
                updateContextStatus(true, "Report Loaded");
                loadSessionList();
            } else {
                throw new Error("Upload failed but no error message returned.");
            }
        } catch (e) {
            console.error(e);
            ui.uploadStatus.textContent = "Error: " + e.message;
            ui.uploadStatus.style.color = "#ef4444";
        } finally {
            isProcessing = false;
            ui.startBtn.querySelector('.spinner').style.display = 'none';
            ui.startBtn.querySelector('.btn-text').textContent = "INITIALIZE SCAN";
            ui.startBtn.disabled = false;
        }
    };

    // Mini Rail Listeners
    document.getElementById('mini-new-chat').onclick = () => ui.newChatBtn.click();
    document.getElementById('mini-history').onclick = () => {
        ui.layout.classList.remove('sidebar-collapsed');
        ui.sidebarToggle.querySelector('span').textContent = 'chevron_left';
        setTimeout(() => ui.sessionList.scrollIntoView({ behavior: 'smooth' }), 400);
    };
    document.getElementById('mini-settings').onclick = () => {
        ui.layout.classList.remove('sidebar-collapsed');
        ui.sidebarToggle.querySelector('span').textContent = 'chevron_left';
    };

    /**
     * Triggers a file download without opening new tabs or causing page flashes.
     * Useful for PDF reports.
     */
    function triggerDownload(url) {
        if (!url) return;
        const link = document.createElement('a');
        link.href = url;
        // Don't set link.download here to let the server's Content-Disposition header decide the filename
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }

    function scrollToBottom() {
        requestAnimationFrame(() => {
            ui.messagesContainer.scrollTop = ui.messagesContainer.scrollHeight;
        });
    }

    function highlightThreats(text) {
        // Split-regex approach: the alternation matches either an HTML tag (returned unchanged)
        // or a risk word in TEXT context (highlighted). This prevents corruption of CSS class names.
        return text.replace(/(<[^>]*>)|(\b(critical|high|medium|low|info)\b)/gi, (match, tag, word) => {
            if (tag) return tag; // HTML tag — return untouched
            const cls = `threat-${word.toLowerCase()}`;
            return `<span class="${cls}">${word}</span>`;
        });
    }

    // Custom Markdown parsing with threat highlighting and report sectioning
    function parseContent(text) {
        if (!text) return "";
        try {
            // [PHASE 5] COLLECTION: Extract follow-up suggestions and actions before markdown parsing
            const suggestions = [];
            const actions = [];
            
            let processedText = text.replace(/(?:__|\*\*)*SUGGESTION(?:__|\*\*)*:\s*(.*?)(?=\n|$)/gi, (match, sText) => {
                const cleanStr = sText.replace(/<\/?[^>]+(>|$)/g, "").trim();
                if (cleanStr) suggestions.push(cleanStr);
                return '';
            });

            processedText = processedText.replace(/(?:__|\*\*)*ACTION(?:__|\*\*)*:\s*(.*?)\s*\|\s*(.*?)(?=\n|$)/gi, (match, label, prompt) => {
                const cleanLabel = label.replace(/<\/?[^>]+(>|$)/g, "").trim();
                const cleanPrompt = prompt.replace(/<\/?[^>]+(>|$)/g, "").trim();
                if (cleanLabel && cleanPrompt) actions.push({ label: cleanLabel, prompt: cleanPrompt });
                return '';
            });


            // ================================================================
            // PRE-PROCESSOR: Decision Guide (PATH N — STATUS [...] blocks)
            // Runs BEFORE marked.parse(). Marked.js leaves block-level <div>
            // HTML untouched, so we inject card HTML here and it survives.
            // ================================================================
            if (/PATH\s*\d+\s*[—–\-]/m.test(processedText)) {
                const _pathSevClass = (s) => {
                    const l = (s || '').toLowerCase();
                    if (l.includes('critical'))                  return 'path-critical';
                    if (l.includes('at risk') || l.includes('risk')) return 'path-risk';
                    if (l.includes('moderate'))                  return 'path-moderate';
                    if (l.includes('secure') || l.includes('safe')) return 'path-secure';
                    return '';
                };

                const firstIdx = processedText.search(/PATH\s*\d+\s*[—–\-]/m);
                if (firstIdx !== -1) {
                    // Everything before the first PATH block (strip trailing ━ lines)
                    const before = processedText.substring(0, firstIdx).replace(/[━─]+[\s\n]*$/, '').trimEnd();
                    const pathsBlock = processedText.substring(firstIdx);

                    // Split into individual PATH sections on each PATH N header
                    const sections = pathsBlock.split(/(?=\bPATH\s*\d+\s*[—–\-])/m).filter(s => s.trim());
                    let hubHtml = '<div class="decision-grid">';

                    sections.forEach(section => {
                        const nlIdx = section.indexOf('\n');
                        if (nlIdx === -1) return;
                        // Strip stray ━ chars from header line
                        const headerLine = section.substring(0, nlIdx).replace(/[━─]/g, '').trim();
                        const bodyText   = section.substring(nlIdx + 1);

                        const hm = headerLine.match(/PATH\s*(\d+)\s*[—–\-]\s*(.+?)(?:\s*\[([^\]]*)\])?\s*$/i);
                        if (!hm) return;

                        const [, num, rawStatus, metadata] = hm;
                        const cleanStatus = rawStatus.trim();
                        const isActive    = (metadata || '').toUpperCase().includes('YOU ARE HERE');
                        const sevClass    = _pathSevClass(cleanStatus);

                        // Parse body lines into description / steps / timeline
                        const descParts = [], steps = [];
                        let timeline = '';

                        bodyText.split('\n').forEach(line => {
                            const l = line.trim();
                            if (!l || /^[━─]+/.test(l)) return;
                            if (/^Recommended Timeline/i.test(l)) {
                                timeline = l.replace(/^Recommended Timeline\s*:\s*/i, '').trim();
                            } else if (l.includes('→') || l.includes('\u2192')) {
                                l.split(/→|\u2192/).forEach(p => { const t = p.trim(); if (t) steps.push(t); });
                            } else {
                                descParts.push(l);
                            }
                        });

                        const stepsHtml = steps.map((s, i) =>
                            `<div class="path-step"><span class="path-step-num">${i + 1}</span><span class="path-step-text">${s}</span></div>`
                        ).join('');

                        const footerHtml = timeline
                            ? `<div class="path-card-footer"><div class="path-timeline"><span class="material-symbols-outlined path-timeline-icon">schedule</span>${timeline}</div></div>`
                            : '';

                        const rightBadges = isActive
                            ? `<span class="path-status-badge">${cleanStatus}</span><span class="path-here-badge">YOU ARE HERE</span>`
                            : `<span class="path-status-badge">${cleanStatus}</span>`;

                        hubHtml +=
                            `<div class="path-card ${sevClass}${isActive ? ' active' : ''}">` +
                                `<div class="path-card-header">` +
                                    `<span class="path-num-pill">PATH ${num}</span>` +
                                    `<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">${rightBadges}</div>` +
                                `</div>` +
                                `<div class="path-card-body">` +
                                    (descParts.length ? `<div class="path-description">${descParts.join(' ')}</div>` : '') +
                                    `<div class="path-steps">${stepsHtml}</div>` +
                                `</div>` +
                                footerHtml +
                            `</div>`;
                    });

                    hubHtml += '</div>';
                    processedText = before + '\n\n' + hubHtml + '\n\n';
                }
            }

            let html = marked.parse(processedText);
            const tempDiv = document.createElement('div');
            tempDiv.innerHTML = html;

            // ===================================================================
            // IMMERSIVE REPORT RENDERER — 7 Sequential Enrichment Passes
            // ===================================================================

            // --- PASS 1: Section Dividers (numbered H2 headers) ---
            tempDiv.querySelectorAll('h2').forEach(h2 => {
                const text = h2.innerText.trim();
                const match = text.match(/^(\d+)\.\s+(.+)$/);
                if (!match) return;
                const div = document.createElement('div');
                div.className = 'llm-section-divider';
                div.innerHTML = `
                    <div class="llm-divider-line"></div>
                    <span class="llm-section-pill">§${match[1]}</span>
                    <span class="llm-section-title">${match[2]}</span>
                    <div class="llm-divider-line llm-divider-line-rev"></div>
                `;
                h2.replaceWith(div);
            });

            // --- PASS 2: Finding Cards (H3/H4 or bold-para matching Finding pattern) ---
            // Detects: "Finding #1 — CSP Header Not Set | MEDIUM" in any heading level
            // or as **strong** inside a paragraph. Wraps block into a severity-coloured card.
            const _buildFindingCard = (num, name, sev, siblings) => {
                const sevLower = sev.toLowerCase();
                const card = document.createElement('div');
                card.className = `llm-finding-card sev-${sevLower}`;
                card.innerHTML = `
                    <div class="llm-finding-header">
                        <div class="llm-finding-meta">
                            <span class="llm-finding-number">FINDING #${num}</span>
                            <span class="llm-finding-name">${name.trim()}</span>
                        </div>
                        <span class="llm-severity-badge">${sev}</span>
                    </div>
                    <div class="llm-finding-body"></div>
                `;
                const body = card.querySelector('.llm-finding-body');
                siblings.forEach(s => body.appendChild(s));
                return card;
            };

            const _collectSiblings = (startEl) => {
                const siblings = [];
                let next = startEl.nextElementSibling;
                while (next &&
                    !['H2','H3','H4'].includes(next.tagName) &&
                    !next.classList.contains('llm-section-divider') &&
                    !next.classList.contains('llm-finding-card')) {
                    const toAdd = next;
                    next = next.nextElementSibling;
                    siblings.push(toAdd);
                }
                return siblings;
            };

            // Heading-based findings (H3 / H4)
            tempDiv.querySelectorAll('h3, h4').forEach(hx => {
                const rawText = hx.innerText.trim();
                const m = rawText.match(/Finding\s+#?(\d+)\s*[\u2014\u2013-]\s*(.+?)\s*\|\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)/i);
                if (!m) return;
                const card = _buildFindingCard(m[1], m[2], m[3], _collectSiblings(hx));
                hx.replaceWith(card);
            });

            // Bold-paragraph-based findings (rendered as **bold** in markdown)
            tempDiv.querySelectorAll('p').forEach(p => {
                const strong = p.querySelector('strong');
                if (!strong) return;
                const rawText = strong.innerText.trim();
                const m = rawText.match(/Finding\s+#?(\d+)\s*[\u2014\u2013-]\s*(.+?)\s*\|\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)/i);
                if (!m) return;
                const card = _buildFindingCard(m[1], m[2], m[3], _collectSiblings(p));
                p.replaceWith(card);
            });

            // --- PASS 2.5: Lettered Context Items (a., b., c.) ---
            tempDiv.querySelectorAll('p').forEach(p => {
                const text = p.innerText.trim();
                // Match "a. text", "b) text", or "**a.** text"
                if (/^[a-z][\.\)]\s+/i.test(text) || /^<strong>[a-z][\.\)]\s*<\/strong>/i.test(p.innerHTML)) {
                    p.classList.add('llm-context-item');
                }
            });

            // --- PASS 2.6: Remediation Action Cards (Issue, Action, Benefit, Owner) ---
            tempDiv.querySelectorAll('p').forEach(p => {
                const text = p.innerText.trim();
                // Start a card when "Issue:" is found at the beginning of a paragraph
                if (text.startsWith('Issue:')) {
                    const card = document.createElement('div');
                    card.className = 'llm-remediation-card';
                    
                    const siblings = [p];
                    let next = p.nextElementSibling;
                    const stopKeywords = ['Issue:', 'Finding #', '1. ', '2. '];
                    const fields = ['Action:', 'Benefit:', 'Owner:'];
                    
                    while (next && next.tagName === 'P') {
                        const nextText = next.innerText.trim();
                        // If it starts with one of our fields, collect it
                        if (fields.some(f => nextText.startsWith(f))) {
                            siblings.push(next);
                            next = next.nextElementSibling;
                        } else if (stopKeywords.some(k => nextText.startsWith(k))) {
                            // Don't include sibling if it's a new card or different section
                            break; 
                        } else {
                            // Only include if it's very short or looks like list content? 
                            // Strategy: strict collection of marked fields for card integrity.
                            break;
                        }
                    }
                    
                    // Only wrap if we found at least one related field (prevent false positives)
                    if (siblings.length > 1) {
                        p.parentNode.insertBefore(card, p);
                        siblings.forEach(s => {
                            // Transform "Label:" into a styled component
                            s.innerHTML = s.innerHTML.replace(/^(Issue|Action|Benefit|Owner):/i, '<span class="remediation-label">$1:</span>');
                            card.appendChild(s);
                        });
                    }
                }
            });

            // --- PASS 3: Table Panel Wrapping ---
            // Each table gets a glassmorphic container with a context label.
            // Variant classes cycle to ensure adjacent tables look different.
            const _panelVariants = ['variant-meta', 'variant-stat', 'variant-compare', 'variant-action'];
            let _tableIdx = 0;
            tempDiv.querySelectorAll('table').forEach(table => {
                if (table.closest('.llm-table-panel')) return; // Already wrapped
                const variant = _panelVariants[_tableIdx % _panelVariants.length];
                _tableIdx++;

                // Derive a label from the nearest preceding text element
                let prev = table.previousElementSibling;
                let label = 'REPORT DATA';
                while (prev) {
                    const txt = (prev.innerText || prev.textContent || '').trim();
                    if (txt && txt.length > 0 && txt.length < 120) {
                        label = txt.replace(/^[#§\s]+/, '').replace(/^\d+\.\s*/, '')
                                   .toUpperCase().substring(0, 55);
                        break;
                    }
                    prev = prev.previousElementSibling;
                }

                const wrapper = document.createElement('div');
                wrapper.className = `llm-table-panel ${variant}`;
                wrapper.innerHTML = `<div class="llm-table-panel-header">${label}</div>`;
                table.parentNode.insertBefore(wrapper, table);
                wrapper.appendChild(table);
            });

            // --- PASS 4: Risk Label Badges (whole-cell keyword match only) ---
            // Replaces plain text risk words in table cells with styled badge spans.
            const _riskClassMap = {
                'critical': 'critical', 'high': 'high', 'at risk': 'high',
                'moderate': 'moderate', 'medium': 'moderate',
                'low': 'low', 'safe': 'safe', 'info': 'safe'
            };
            tempDiv.querySelectorAll('td').forEach(td => {
                if (td.querySelector('.llm-risk-label')) return; // Already processed
                const txt = td.innerText.trim().toLowerCase();
                for (const [key, cls] of Object.entries(_riskClassMap)) {
                    if (txt === key) {
                        const badge = document.createElement('span');
                        badge.className = `llm-risk-label ${cls}`;
                        badge.textContent = td.innerText.trim().toUpperCase();
                        td.innerHTML = '';
                        td.appendChild(badge);
                        break;
                    }
                }
            });

            // --- PASS 5: Remediation Priority Row Accents ---
            // Priority 1 → rose accent, 2 → stone, 3 → steel blue
            tempDiv.querySelectorAll('tr').forEach(tr => {
                const firstTd = tr.querySelector('td:first-child');
                if (!firstTd || firstTd.querySelector('.llm-priority-badge')) return;
                const txt = firstTd.innerText.trim();
                if (['1','2','3'].includes(txt)) {
                    tr.classList.add(`llm-priority-${txt}`);
                    firstTd.innerHTML = `<span class="llm-priority-badge p${txt}">${txt}</span>`;
                }
            });

            // --- PASS 6: Risk Score Animated Fill Bars ---
            // Detects numeric 0-10 scores in table cells and adds an animated
            // colour-coded background fill bar.
            tempDiv.querySelectorAll('td').forEach(td => {
                if (td.querySelector('.llm-risk-label,.llm-score-bar')) return;
                const txt = td.innerText.trim();
                const score = parseFloat(txt);
                // Only match pure numeric values between 0–10
                if (isNaN(score) || score < 0 || score > 10) return;
                if (txt !== String(score) && txt !== score.toFixed(1)) return;

                td.classList.add('llm-score-cell');
                const barColor = score >= 7.5 ? 'rgba(251,113,133,0.18)' :
                                  score >= 4.5 ? 'rgba(251,191,36,0.14)' :
                                                 'rgba(96,165,250,0.14)';
                const bar = document.createElement('div');
                bar.className = 'llm-score-bar';
                bar.style.cssText = `--bar-color: ${barColor}; width: 0%;`;
                td.prepend(bar);
                // Animate on next frame to trigger CSS transition
                requestAnimationFrame(() => {
                    setTimeout(() => { bar.style.width = (score * 10) + '%'; }, 80);
                });
            });

            // --- PASS 7: Code Container Standardization (preserved) ---
            tempDiv.querySelectorAll('pre').forEach(pre => {
                if (pre.closest('.code-container')) return;
                const container = document.createElement('div');
                container.className = 'code-container';
                const copyBtn = document.createElement('button');
                copyBtn.className = 'copy-code-btn';
                copyBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size:14px">content_copy</span> Copy';
                pre.parentNode.insertBefore(container, pre);
                container.appendChild(pre);
                container.appendChild(copyBtn);
            });

            // --- PASS 8: Scheduling Options Grid ---
            // Detects [MISSION_PRESETS] marker and transforms the associated list into a grid.
            tempDiv.querySelectorAll('p, div, h4').forEach(el => {
              const text = el.innerText.trim();
              if (text.includes('[MISSION_PRESETS]')) {
                // Find the nearest UL after this element
                let ul = el.nextElementSibling;
                while (ul && ul.tagName !== 'UL' && ul.tagName !== 'OL') {
                    // Stop if we hit another header or divider
                    if (['H2', 'H3', 'DIV'].includes(ul.tagName) && ul.className.includes('divider')) break;
                    ul = ul.nextElementSibling;
                }

                if (ul && (ul.tagName === 'UL' || ul.tagName === 'OL')) {
                  const grid = document.createElement('div');
                  grid.className = 'scheduling-grid';
                  
                  ul.querySelectorAll('li').forEach(li => {
                    const liText = li.innerText.trim();
                    const [label, ...descParts] = liText.split(':');
                    const desc = descParts.join(':').trim();
                    
                    const tile = document.createElement('div');
                    tile.className = 'freq-option';
                    
                    let icon = 'schedule';
                    const l = label.toLowerCase();
                    if (l.includes('daily')) icon = 'event_repeat';
                    if (l.includes('weekly')) icon = 'calendar_view_week';
                    if (l.includes('monthly')) icon = 'calendar_month';
                    if (l.includes('once') || l.includes('shot')) icon = 'timer_10_alt_1';
                    if (l.includes('periodic')) icon = 'update';

                    tile.innerHTML = `
                      <span class="material-symbols-outlined">${icon}</span>
                      <span class="freq-label">${label.trim()}</span>
                      <span class="freq-desc">${desc}</span>
                    `;
                    grid.appendChild(tile);
                  });
                  
                  // Hide the marker element and replace the list with the grid
                  el.style.display = 'none';
                  ul.replaceWith(grid);
                }
              }
            });

            // --- PASS 8.5: Security Tools Grid (Multi-Category) ---
            // Detects [SCAN_PRESETS] marker and transforms segregated lists into tool grids.
            tempDiv.querySelectorAll('p, div, h4').forEach(el => {
              const text = el.innerText.trim();
              if (text.includes('[SCAN_PRESETS]')) {
                let next = el.nextElementSibling;
                const groups = [];
                let currentCategory = null;

                while (next) {
                    // Stop if we hit a major section divider or another hidden/system element
                    if (['H2', 'DIV'].includes(next.tagName) && (next.className.includes('divider') || next.className.includes('msg-actions'))) break;
                    
                    const inner = next.innerText.trim();
                    if (!inner) {
                        next = next.nextElementSibling;
                        continue;
                    }

                    // Detection logic for Category Headers vs Lists
                    if ((next.tagName === 'P' && next.querySelector('strong') && inner.length < 60) || (next.tagName === 'H4' || next.tagName === 'H5')) {
                        currentCategory = inner.replace(/^\*+|\*+$/g, ''); // Clean markdown bold
                        next.style.display = 'none';
                    } else if (next.tagName === 'UL' || next.tagName === 'OL') {
                        groups.push({ category: currentCategory, ul: next });
                        currentCategory = null; 
                        next.style.display = 'none';
                    } else if (inner.includes('[SCAN_PRESETS]')) {
                        next.style.display = 'none';
                    } else if (next.tagName === 'P' && inner.length < 50 && !inner.includes(':')) {
                        // Likely a plain text category header
                        currentCategory = inner;
                        next.style.display = 'none';
                    } else {
                        // If we hit random text that isn't a header or list, we might have exited the preset area
                        break; 
                    }
                    
                    next = next.nextElementSibling;
                }

                if (groups.length > 0) {
                    const container = document.createElement('div');
                    container.className = 'security-tools-container';
                    container.style.marginBottom = '1.25rem';
                    
                    groups.forEach(group => {
                        const grid = document.createElement('div');
                        grid.className = 'scheduling-grid security-tools-grid';
                        
                        group.ul.querySelectorAll('li').forEach(li => {
                            const liText = li.innerText.trim();
                            const [label, ...descParts] = liText.split(':');
                            const desc = descParts.join(':').trim();
                            
                            const tile = document.createElement('div');
                            tile.className = 'freq-option'; 
                            
                            let icon = 'security';
                            const l = label.toLowerCase();
                            if (l.includes('nmap')) icon = 'radar';
                            if (l.includes('zap')) icon = 'bug_report';
                            if (l.includes('ssl') || l.includes('tls')) icon = 'lock_reset';
                            if (l.includes('sql')) icon = 'database';
                            if (l.includes('sniffer') || l.includes('packet')) icon = 'settings_input_antenna';
                            if (l.includes('api')) icon = 'api';
                            if (l.includes('killchain') || l.includes('kill chain')) icon = 'account_tree';
                            if (l.includes('semgrep') || l.includes('sast')) icon = 'terminal';

                            tile.innerHTML = `
                              <span class="material-symbols-outlined">${icon}</span>
                              <span class="freq-label">${label.trim()}</span>
                              <span class="freq-desc">${desc}</span>
                            `;
                            grid.appendChild(tile);
                        });
                        
                        container.appendChild(grid);
                    });
                    
                    el.style.display = 'none';
                    el.after(container);
                }
              }
            });

            // --- PASS 9: Smart Suggestions ---
            tempDiv.querySelectorAll('p, div, blockquote').forEach(el => {
                let inner = el.innerHTML;
                if(/SUGGESTION/i.test(inner)) {
                    // Match SUGGESTION regardless of surrounding bold tags/HTML that marked might have added
                    const regex = /(?:<[^>]+>|__|\*\*)*SUGGESTION(?:<[^>]+>|__|\*\*)*:\s*(.*?)(?=<br>|<\/p>|<\/div>|$)/ig;
                    if (regex.test(inner)) {
             // Pass 9 handled by string pre-processor in parseContent start (Instant rendering)
                    }
                }
            });

            // --- PASS 10: Special System Markers ---
            tempDiv.innerHTML = tempDiv.innerHTML
                .replace(/<p>\s*\[GRID_INTRO\]\s*<\/p>|\[GRID_INTRO\]/g, 
                    `<div class="grid-intro-banner">
                        <span class="material-symbols-outlined grid-icon">hub</span>
                        <div class="grid-text">
                            <div class="grid-title">Security Grid Orchestration</div>
                            <div class="grid-sub">Select a module below to initiate a strategic security assessment.</div>
                        </div>
                    </div>`)
                .replace(/<p>\s*\[MEMORY_UPDATED\]\s*<\/p>|\[MEMORY_UPDATED\]/g,
                    `<div class="memory-updated-chip" title="A persistent fact or rule has been saved to your personal context.">
                        <span class="material-symbols-outlined">memory</span>
                        <span>Memory Banks Updated</span>
                    </div>`)
                .replace(/\[SCAN_PRESETS\]/g, ''); // Ensure the marker is never visible

            // --- Cleanup: Remove empty paragraphs that cause ghost vertical spacing ---
            tempDiv.querySelectorAll('p').forEach(p => {
                if (!p.innerText.trim() && !p.querySelector('img, video, iframe, .ai-suggestion-chip, .memory-updated-chip')) {
                    p.remove();
                }
            });

            // --- Font Sanitization ---
            const FONT_UI   = "'Geist', sans-serif";
            const FONT_MONO = "'JetBrains Mono', monospace";
            const _uiEls = 'p, li, td, th, blockquote, strong, em, a, .llm-context-item, .llm-finding-body';
            tempDiv.querySelectorAll(_uiEls).forEach(el => {
                el.style.setProperty('font-family', FONT_UI, 'important');
            });
            tempDiv.querySelectorAll('h1, h2, h3, h4, h5, h6, code, pre, pre *, .remediation-label, .llm-finding-number, .llm-finding-name, .llm-table-panel-header').forEach(el => {
                el.style.setProperty('font-family', FONT_MONO, 'important');
            });

            // --- PASS 11: Render Follow-up Tray (Suggestions & Actions) ---
            if (suggestions.length > 0 || actions.length > 0) {
                let trayHtml = '<div class="ai-followup-tray" style="display: flex; flex-direction: column; gap: 1rem; margin-top: 1rem;">';

                // Add Suggestions (Grouped into a single minimal banner)
                if (suggestions.length > 0) {
                    trayHtml += `
                        <div class="ai-followup-suggestion" style="display: flex; gap: 12px; padding: 16px; background: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px; margin-bottom: 0.5rem; color: #f8fafc; font-size: 0.85rem; line-height: 1.6;">
                            <span class="material-symbols-outlined" style="color: rgba(255, 255, 255, 0.6); font-size: 1.2rem; flex-shrink: 0; margin-top: 2px;">lightbulb</span>
                            <div style="flex: 1;">
                                <div style="font-family: var(--font-code); font-size: 0.65rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.1em; opacity: 0.5; margin-bottom: 8px;">Recommendations</div>
                                <ul style="margin: 0; padding-left: 1.2rem; display: flex; flex-direction: column; gap: 6px;">`;
                    suggestions.forEach(s => {
                        trayHtml += `<li style="opacity: 0.9;">${s}</li>`;
                    });
                    trayHtml += `
                                </ul>
                            </div>
                        </div>`;
                }

                // Add Actions (Flex wrap layout side-by-side)
                if (actions.length > 0) {
                    trayHtml += '<div class="ai-actions-group" style="display: flex; flex-wrap: wrap; gap: 12px;">';
                    actions.forEach(a => {
                        trayHtml += `
                            <div class="ai-followup-card action" style="flex: 1 1 calc(50% - 12px); min-width: 280px; margin: 0;" data-prompt="${encodeURIComponent(a.prompt)}">
                                <span class="material-symbols-outlined card-icon">bolt</span>
                                <div class="card-content">
                                    <span class="card-label">${a.label}</span>
                                    <span class="card-text">${a.prompt}</span>
                                </div>
                            </div>`;
                    });
                    trayHtml += '</div>';
                }

                trayHtml += '</div>';
                tempDiv.innerHTML += trayHtml;
            }

            return highlightThreats(tempDiv.innerHTML);
        } catch (e) {
            console.error("Markdown parsing error:", e);
            return text;
        }
    }


    // [NEW] Global listener for copy code buttons
    document.addEventListener('click', (e) => {
        const btn = e.target.closest('.copy-code-btn');
        if (btn) {
            const pre = btn.parentElement.querySelector('pre');
            if (pre) {
                const code = pre.innerText;
                navigator.clipboard.writeText(code).then(() => {
                    const originalHTML = btn.innerHTML;
                    btn.classList.add('copied');
                    btn.innerHTML = '<span class="material-symbols-outlined" style="font-size:14px">check</span> Copied!';
                    setTimeout(() => {
                        btn.classList.remove('copied');
                        btn.innerHTML = originalHTML;
                    }, 2000);
                });
            }
        }
    });

    // [NEW] Global listener for Interactive Security Grid Cards and Suggestions
    document.addEventListener('click', (e) => {
        // [PHASE 5: Enhanced Follow-up Cards]
        const followupCard = e.target.closest('.ai-followup-card');
        if (followupCard && ui.userInput) {
            const isAction = followupCard.classList.contains('action');
            const dataAttr = isAction ? 'data-prompt' : 'data-suggestion';
            const messageText = decodeURIComponent(followupCard.getAttribute(dataAttr));
            
            ui.userInput.value = messageText;
            ui.userInput.focus();
            if (typeof autoResizeInput === 'function') autoResizeInput();
            else ui.userInput.dispatchEvent(new Event('input', { bubbles: true }));
            
            // Visual feedback
            followupCard.style.transform = 'scale(0.98) translateX(2px)';
            followupCard.style.borderColor = isAction ? 'var(--neo-blue)' : '#10b981';
            
            setTimeout(() => {
                if (ui.sendBtn && !ui.sendBtn.disabled) {
                    ui.sendBtn.click();
                } else {
                    sendMessage();
                }
            }, 100);
            return;
        }

        const tile = e.target.closest('.freq-option');
        if (!tile || !ui.userInput) return;

        const labelEl = tile.querySelector('.freq-label');
        if (!labelEl) return;

        const label = labelEl.innerText.trim();
        const l = label.toLowerCase();
        let template = "";

        // --- SCANNER TEMPLATES (Structured) ---
        if (l.includes('nmap')) {
            template = "Initiate Nmap Security Scan:\n- Target IP: [IP_OR_HOST]\n- Protocol: [TCP/UDP]\n- Scan Type: [default/os/aggressive/vuln/etc]\n- Timing: [4]";
        } else if (l.includes('zap')) {
            template = "Perform ZAP Application Audit:\n- Target URL: [URL_HERE]\n- Scan Mode: [Quick Scan/Full Scan/Deep Scan]\n- AJAX Spider: [false]";
        } else if (l.includes('ssl') || l.includes('tls')) {
            template = "Execute SSL/TLS Protocol Check:\n- Target Host: [DOMAIN_HERE]";
        } else if (l.includes('sql')) {
            template = "Launch SQL Injection Audit:\n- Target URL: [VULN_ENDPOINT]\n- Scan Mode: [quick/full/deep]\n- Risk Level: [3]\n- Scan Level: [3]\n- Check WAF: [true]";
        } else if (l.includes('sniffer') || l.includes('packet')) {
            template = "Deploy Packet Sniffer Module:\n- Target IP: [IP_HERE]\n- Duration: [60 seconds]\n- Max Packets: [1000]";
        } else if (l.includes('api')) {
            template = "Initiate API Security Audit:\n- Target URL: [BASE_URL]\n- Definition URL: [SWAGGER_JSON_URL]\n- Auth Token: [OPTIONAL_TOKEN]";
        } else if (l.includes('killchain') || l.includes('kill chain')) {
            template = "Launch Full Kill Chain Audit:\n- Target: [TARGET_IDENTIFIER]\n- Profile: [Recon Only/Network Audit/Web Audit/Full Scan]\n- Aggression: [Normal/Stealth/Attack]";
        } else if (l.includes('semgrep') || l.includes('sast')) {
            template = "Execute Semgrep SAST Scan:\n- Repository URL: [GIT_URL]";
        } 
        // --- SCHEDULING TEMPLATES ---
        else if (l.includes('one-shot') || l.includes('once')) {
            template = "Schedule a one-shot scan for [TOOL] on target [TARGET] at [TIME].";
        } else if (l.includes('daily')) {
            template = "Set up a daily recurring scan for [TOOL] on target [TARGET] at [TIME].";
        } else if (l.includes('weekly')) {
            template = "Orchestrate a weekly security audit for [TOOL] on target [TARGET] every [DAY_OF_WEEK] at [TIME].";
        } else if (l.includes('monthly')) {
            template = "Establish a monthly periodic scan for [TOOL] on target [TARGET] (Day: [1-31], Time: [TIME]).";
        } else if (l.includes('periodic') || l.includes('recurring')) {
            template = "Configure a periodic scan mission for [TOOL] on target [TARGET] every [N] [hours/days].";
        }

        if (template) {
            ui.userInput.value = template;
            ui.userInput.focus();
            
            // Trigger auto-resize if the function exists
            if (typeof autoResizeInput === 'function') {
                autoResizeInput();
            } else {
                // Manual trigger for the input event to activate any existing listeners
                ui.userInput.dispatchEvent(new Event('input', { bubbles: true }));
            }
            
            // Subtle visual feedback on the tile
            tile.style.borderColor = 'var(--neo-blue)';
            setTimeout(() => { tile.style.borderColor = ''; }, 400);
        }
    });

    function addMessage(role, text, animate = true, attachments = []) {
        ui.welcomeState.style.display = 'none';

        // Suppress the raw [ANALYSIS_TRIGGER] from being RENDERED
        if (text === "[ANALYSIS_TRIGGER]") {
            return; 
        }
        
        // Suppress system_hidden messages (internal context only)
        if (role === 'system_hidden') {
            return;
        }

        // --- RESTORATION LOGIC: Check for Action Metadata ---
        let cleanText = text;
        let metadataAction = null;
        if (text.includes("__METADATA_ACTION__:")) {
            const parts = text.split("__METADATA_ACTION__:");
            cleanText = parts[0].trim();
            try {
                metadataAction = JSON.parse(parts[1]);
            } catch(e) { console.error("Restore metadata parse error:", e); }
        }

        // If the AI message is empty and it's an action, we might skip the AI bubble 
        // and just show the action bubble, but only if it's not a restore or if we want to keep it clean.
        if (cleanText === "" && metadataAction && !animate) {
             return metadataAction;
        }

        const row = document.createElement('div');
        row.className = `msg-row ${role}`;
        
        const bubble = document.createElement('div');
        bubble.className = 'msg-bubble';
        
        if (role === 'system') {
            row.classList.add('unbounded');
        } else {
            if (role === 'ai') row.classList.add('unbounded');

            const identity = document.createElement('div');
            identity.className = 'msg-identity';
            
            if (role === 'ai' || role === 'assistant') {
                identity.classList.add('ai-identity');
                identity.innerHTML = `<span>NETSHIELD AI</span>`;
            } else {
                const icon = role === 'user' ? 'person' : 'terminal';
                const label = role === 'user' ? 'ANALYST' : 'SECURITY LOG';
                identity.innerHTML = `<span class="material-symbols-outlined">${icon}</span> ${label}`;
            }
            
            bubble.appendChild(identity);
        }
        
        // Create content container
        const contentDiv = document.createElement('div');
        contentDiv.className = 'markdown-content';

        // Use IBM Plex Sans for the main bubble container
        const BUBBLE_FONT = "'IBM Plex Sans', sans-serif";
        contentDiv.style.setProperty('font-family', BUBBLE_FONT, 'important');
        contentDiv.style.setProperty('font-size', '0.935rem', 'important');
        contentDiv.style.setProperty('line-height', '1.65', 'important');
        contentDiv.style.setProperty('letter-spacing', '0', 'important');


        
        let displayContext = cleanText;
        if (role === 'system' && displayContext.includes("SYSTEM_NOTIFICATION:")) {
            displayContext = displayContext.replace("SYSTEM_NOTIFICATION:", "**STATUS:**")
                                          .replace("successfully synchronized.", "Analysis Online.")
                                          .replace("Summary: ", "\n\n---\n\n");
        }

        contentDiv.innerHTML = parseContent(displayContext);
        
        // --- Render Attachments if present ---
        if (attachments && attachments.length > 0) {
            const attachContainer = document.createElement('div');
            attachContainer.className = 'msg-attachments';
            
            attachments.forEach(a => {
                const card = document.createElement('div');
                card.className = 'msg-attachment-card';
                
                const url = a.url || a.previewUrl; // Handle both history and live
                
                if (a.type === 'image') {
                    card.innerHTML = `<img src="${url}" alt="Attachment" />`;
                } else {
                    card.classList.add('doc-type');
                    const icon = a.type === 'pcap' ? 'settings_input_component' : 'description';
                    card.innerHTML = `
                        <span class="material-symbols-outlined" style="font-size: 1.5rem;">${icon}</span>
                        <div class="file-name">${a.name}</div>
                    `;
                }
                attachContainer.appendChild(card);
            });
            row.appendChild(attachContainer); // Append to ROW (above bubble)
        }

        bubble.appendChild(contentDiv);

        if (role === 'ai' || role === 'assistant' || role === 'system') {
            // Enable actions for all AI and System summary responses
            const actions = document.createElement('div');
                actions.className = 'msg-actions';
                actions.innerHTML = `
                    <button class="action-btn copy-btn" title="Copy response"><span class="material-symbols-outlined" style="font-size:14px">content_copy</span></button>
                    <button class="action-btn regen-btn" title="Regenerate"><span class="material-symbols-outlined" style="font-size:14px">refresh</span></button>
                    <button class="action-btn feedback-btn up" title="Helpful"><span class="material-symbols-outlined" style="font-size:14px">thumb_up</span></button>
                    <button class="action-btn feedback-btn down" title="Not helpful"><span class="material-symbols-outlined" style="font-size:14px">thumb_down</span></button>
                `;
                actions.querySelector('.copy-btn').onclick = () => {
                    navigator.clipboard.writeText(cleanText);
                    const icon = actions.querySelector('.copy-btn span');
                    icon.textContent = 'check';
                    setTimeout(() => icon.textContent = 'content_copy', 2000);
                };

                actions.querySelector('.regen-btn').onclick = () => {
                    ui.userInput.value = lastUserMessage;
                    sendMessage();
                };

                actions.querySelectorAll('.feedback-btn').forEach(btn => {
                    btn.onclick = () => {
                        const isUp = btn.classList.contains('up');
                        btn.style.color = isUp ? '#10b981' : '#ef4444';
                        btn.parentElement.style.opacity = '1';
                        submitFeedback(currentSessionId, isUp);
                    };
                });

                bubble.appendChild(actions);
        } else {
            lastUserMessage = cleanText;
        }
        
        row.appendChild(bubble); // Still append bubble to row
        ui.chatHistory.appendChild(row);
        
        // If it's a restore (not animated) we just return the metadata to the caller
        if (animate) scrollToBottom();
        
        return metadataAction;
    }

    // --- 5. Session List & Context Menu Logic ---

    function groupSessions(sessions) {
        const now = new Date();
        const groups = {
            'Pinned': [],
            'Today': [],
            'Yesterday': [],
            'Previous 7 Days': [],
            'Older': []
        };

        sessions.forEach(sess => {
            if (sess.is_pinned) {
                groups['Pinned'].push(sess);
                return;
            }

            // subtitle is usually "14 Feb 2026, 12:30 PM"
            // We need a proper date for grouping. If backend doesn't provide it, we guess from subtitle or just don't group.
            // Assuming subtitle format: "DD MMM YYYY, ..."
            const sessDate = new Date(sess.subtitle);
            const diffDays = Math.floor((now - sessDate) / (1000 * 60 * 60 * 24));

            if (diffDays === 0) groups['Today'].push(sess);
            else if (diffDays === 1) groups['Yesterday'].push(sess);
            else if (diffDays < 8) groups['Previous 7 Days'].push(sess);
            else groups['Older'].push(sess);
        });

        return groups;
    }

    function renderSessionList(sessions) {
        ui.sessionList.innerHTML = ''; 
        if (!sessions || sessions.length === 0) {
            ui.sessionList.innerHTML = '<p style="color:#444; font-size:0.7rem; padding:0.5rem; font-style:italic;">No results found.</p>';
            return;
        }

        const groups = groupSessions(sessions);

        Object.keys(groups).forEach(groupName => {
            if (groups[groupName].length === 0) return;

            const groupEl = document.createElement('div');
            groupEl.className = 'session-group';
            groupEl.innerHTML = `<div class="group-label">${groupName}</div>`;

            groups[groupName].forEach(sess => {
                const item = document.createElement('div');
                item.className = `session-item ${sess.is_pinned ? 'pinned' : ''} ${sess.session_id === currentSessionId ? 'active' : ''}`;
                item.dataset.id = sess.session_id;
                
                item.innerHTML = `
                    <div class="session-icon-box">
                        <span class="material-symbols-outlined" style="font-size: 1.1rem;">${sess.is_pinned ? 'push_pin' : 'chat_bubble'}</span>
                    </div>
                    <div class="session-info">
                        <span class="session-title">${sess.title}</span>
                        <span class="session-date">${sess.subtitle}</span>
                    </div>
                    <button class="session-menu-btn" title="Actions"><span class="material-symbols-outlined" style="font-size:16px">more_horiz</span></button>
                    
                    <div class="context-menu" id="menu-${sess.session_id}">
                        <div class="menu-item action-pin">
                            <span class="material-symbols-outlined" style="font-size:14px">${sess.is_pinned ? 'do_not_disturb_on' : 'push_pin'}</span>
                            ${sess.is_pinned ? 'Unpin' : 'Pin'}
                        </div>
                        <div class="menu-item action-rename">
                            <span class="material-symbols-outlined" style="font-size:14px">edit</span> Rename
                        </div>
                        <div class="menu-item action-delete delete">
                            <span class="material-symbols-outlined" style="font-size:14px">delete</span> Delete
                        </div>
                    </div>
                `;

                // Event listeners for session items... (Same as before)
                item.addEventListener('click', (e) => {
                    if (!e.target.closest('.session-menu-btn') && !e.target.closest('.context-menu')) {
                        switchSession(sess.session_id);
                    }
                });

                const menuBtn = item.querySelector('.session-menu-btn');
                const menu = item.querySelector('.context-menu');
                menuBtn.addEventListener('click', (e) => {
                    e.stopPropagation(); 
                    const alreadyOpen = menu.classList.contains('show');
                    
                    // Close all other menus
                    document.querySelectorAll('.context-menu').forEach(m => m.classList.remove('show'));
                    document.querySelectorAll('.session-item').forEach(si => si.classList.remove('menu-open'));
                    
                    if (!alreadyOpen) {
                        menu.classList.add('show');
                        item.classList.add('menu-open');
                    }
                });

                // Prevent click on menu from selecting the chat
                menu.addEventListener('click', (e) => e.stopPropagation());

                item.querySelector('.action-pin').addEventListener('click', (e) => {
                    e.stopPropagation();
                    menu.classList.remove('show');
                    item.classList.remove('menu-open');
                    togglePin(sess.session_id, !sess.is_pinned);
                });
                
                item.querySelector('.action-rename').addEventListener('click', (e) => {
                    e.stopPropagation();
                    menu.classList.remove('show');
                    item.classList.remove('menu-open');
                    openRenameModal(sess.session_id, sess.title);
                });
                
                item.querySelector('.action-delete').addEventListener('click', (e) => {
                    e.stopPropagation();
                    menu.classList.remove('show');
                    item.classList.remove('menu-open');
                    deleteSession(sess.session_id);
                });

                groupEl.appendChild(item);
            });
            ui.sessionList.appendChild(groupEl);
        });
    }

    // Search Logic
    ui.sessionSearch.addEventListener('input', (e) => {
        const term = e.target.value.toLowerCase();
        const filtered = allSessions.filter(s => 
            s.title.toLowerCase().includes(term) || 
            s.subtitle.toLowerCase().includes(term)
        );
        renderSessionList(filtered);
    });

    async function loadSessionList() {
        try {
            if (window.PRELOADED_SESSIONS) {
                allSessions = window.PRELOADED_SESSIONS;
                renderSessionList(allSessions);
                window.PRELOADED_SESSIONS = null;
                return;
            }

            const response = await fetchWithAuth('/chatbot/get_sessions');
            const data = await response.json();
            allSessions = data.sessions || [];
            renderSessionList(allSessions);

        } catch (e) { console.error("Error loading sessions:", e); }
    }

    // --- Keyboard Shortcuts ---
    window.addEventListener('keydown', (e) => {
        // Ctrl + K to focus search
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
            e.preventDefault();
            if (ui.layout.classList.contains('sidebar-collapsed')) {
                ui.sidebarToggle.click();
            }
            ui.sessionSearch.focus();
        }
        
        // Ctrl + B to toggle sidebar
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'b') {
            e.preventDefault();
            ui.sidebarToggle.click();
        }

        // Ctrl + M for new chat
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'm') {
            e.preventDefault();
            ui.newChatBtn.click();
        }

        // Cmd/Ctrl + Enter to send (Universal shortcut)
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'enter' && document.activeElement === ui.userInput) {
            e.preventDefault();
            sendMessage();
        }
    });

    // --- Smart Input Logic (Multiline / Auto-resize / History) ---
    function pushToHistory(text) {
        if (!text || (inputHistory.length > 0 && inputHistory[0] === text)) {
            historyIndex = -1;
            return;
        }
        inputHistory.unshift(text);
        if (inputHistory.length > 50) inputHistory.pop(); // Cap history at 50
        sessionStorage.setItem('chatInputHistory', JSON.stringify(inputHistory));
        historyIndex = -1;
    }

    function autoResizeInput() {
        const input = ui.userInput;
        input.style.height = 'auto'; // Reset height to shrink if needed
        const newHeight = Math.min(input.scrollHeight, 200); // Max 200px
        input.style.height = (newHeight) + 'px';
        
        // Toggle send button state
        ui.sendBtn.disabled = !input.value.trim();
        
        // Auto-scroll messages area if the input expands near the bottom
        if (newHeight > 60) scrollToBottom();
    }

    if (ui.userInput) {
        // 1. Text Expansion
        ui.userInput.addEventListener('input', autoResizeInput);

        // 2. Multiline & Send Handling & Terminal History
        ui.userInput.addEventListener('keydown', (e) => {
            // Enter sends, Shift+Enter adds new line
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }

            // History Up
            if (e.key === 'ArrowUp' && ui.userInput.selectionStart === 0) {
                if (inputHistory.length > 0) {
                    if (historyIndex === -1) tempDraft = ui.userInput.value;
                    
                    if (historyIndex < inputHistory.length - 1) {
                        e.preventDefault();
                        historyIndex++;
                        ui.userInput.value = inputHistory[historyIndex];
                        autoResizeInput();
                        // Place cursor at end for terminal feel
                        setTimeout(() => {
                           ui.userInput.selectionStart = ui.userInput.selectionEnd = ui.userInput.value.length;
                        }, 0);
                    }
                }
            }

            // History Down
            if (e.key === 'ArrowDown' && ui.userInput.selectionEnd === ui.userInput.value.length) {
                if (historyIndex > -1) {
                    e.preventDefault();
                    historyIndex--;
                    ui.userInput.value = (historyIndex === -1) ? tempDraft : inputHistory[historyIndex];
                    autoResizeInput();
                }
            }

            // Escape clears input
            if (e.key === 'Escape') {
                ui.userInput.value = '';
                autoResizeInput();
            }
        });
        
        // Ensure starting state is correct
        ui.sendBtn.disabled = true;
    }

    async function submitFeedback(sessId, isHelpful) {
        try {
            await fetchWithAuth('/chatbot/submit_feedback', {
                method: 'POST',
                body: JSON.stringify({ 
                    session_id: sessId, 
                    is_helpful: isHelpful 
                })
            });
        } catch (e) { console.error("Feedback error:", e); }
    }

    function updateContextStatus(hasFile, title = null) {
        const isLight = document.body.classList.contains('light-mode');
        if (hasFile) {
            ui.statusText.textContent = title ? `Active: ${title}` : `Active: KB + Report`;
            ui.statusText.style.color = "#10b981";
            ui.statusDot.style.background = "#10b981";
        } else {
            ui.statusText.textContent = "SYSTEM ONLINE";
            ui.statusText.style.color = isLight ? "#64748b" : "#9ca3af";
            ui.statusDot.style.background = "#10b981"; 
        }
    }

    function switchView(mode) {
        if (mode === 'config') {
            ui.workflowPanel.classList.add('mode-config');
        } else {
            ui.workflowPanel.classList.remove('mode-config');
            ui.hiddenModelInput.value = 'gemini';
            ui.customTrigger.querySelector('span').textContent = 'Google Gemini';
            ui.customOptions.forEach(opt => opt.classList.remove('selected'));
            document.querySelector('.custom-option[data-value="gemini"]')?.classList.add('selected');
            ui.startBtn.disabled = true;
            ui.uploadStatus.textContent = '';
        }
    }

    async function togglePin(sessionId, newStatus) {
        if (isPinning) return; 
        isPinning = true;
        try {
            await fetchWithAuth('/chatbot/toggle_pin', {
                method: 'POST',
                body: JSON.stringify({ session_id: sessionId, is_pinned: newStatus })
            });
            await loadSessionList();
        } catch (e) { console.error(e); } 
        finally { isPinning = false; }
    }

    async function deleteSession(sessionId) {
        if (sessionId === currentSessionId) clearView();
        try {
            await fetchWithAuth('/chatbot/delete_session', {
                method: 'POST',
                body: JSON.stringify({ session_id: sessionId })
            });
            await loadSessionList();
        } catch (e) { console.error("Delete failed:", e); }
    }

    function openRenameModal(sessionId, currentTitle) {
        sessionToRename = sessionId;
        ui.renameInput.value = currentTitle;
        ui.renameModal.classList.add('show');
        ui.renameInput.focus();
    }

    ui.cancelRenameBtn.addEventListener('click', () => ui.renameModal.classList.remove('show'));
    ui.confirmRenameBtn.addEventListener('click', async () => {
        const newTitle = ui.renameInput.value.trim();
        if (newTitle && sessionToRename) {
            try {
                await fetchWithAuth('/chatbot/rename_session', {
                    method: 'POST',
                    body: JSON.stringify({ session_id: sessionToRename, new_title: newTitle })
                });
                ui.renameModal.classList.remove('show');
                await loadSessionList();
            } catch (e) { console.error(e); }
        }
    });

    async function switchSession(sessionId) {
        if (sessionId === currentSessionId) return;
        ui.chatHistory.innerHTML = '';
        ui.welcomeState.style.display = 'block';
        try {
            await fetchWithAuth('/chatbot/switch_session', {
                method: 'POST',
                body: JSON.stringify({ session_id: sessionId })
            });
            currentSessionId = sessionId;
            await restoreSession();
            await loadSessionList(); 
        } catch (e) { console.error("Failed to switch:", e); }
    }

    async function restoreSession() {
        try {
            const response = await fetchWithAuth('/chatbot/get_history');
            const data = await response.json();
            if (data.chat_history && data.chat_history.length > 0) {
                ui.welcomeState.style.display = 'none';
                ui.chatHistory.innerHTML = ''; 
                
                // We do NOT use activeScans anymore; we rely on Action ID correlation
                for (let i = 0; i < data.chat_history.length; i++) {
                    const msg = data.chat_history[i];
                    try {
                        const role = msg.role === 'assistant' ? 'ai' : msg.role;
                        
                        let attachments = [];
                        if (msg.attachments && typeof msg.attachments === 'string' && msg.attachments.trim() !== "" && msg.attachments !== "null") {
                            try {
                                attachments = JSON.parse(msg.attachments);
                            } catch(e) { console.error("History attachment parse error:", e, msg.attachments); }
                        }

                        // Use addMessage for everything. addMessage will handle text/attachments and return metadata Action
                        let metadataAction = addMessage(role, msg.content, false, attachments);

                        // If the message had an action, restore its state
                        if (metadataAction && metadataAction.tool) {
                            const isLastMessage = (i === data.chat_history.length - 1);
                            await handleAction(metadataAction, true, null, false, isLastMessage);
                        }
                    } catch (loopErr) {
                        console.error("Error restoring history item:", loopErr, msg);
                    }
                }
                scrollToBottom();
                if (data.session_metadata && data.session_metadata.report_type) {
                    switchView('config');
                    ui.selectedFilename.textContent = data.session_metadata.title || "Active Session";
                    ui.removeFileBtn.style.display = 'flex'; 
                    ui.startBtn.disabled = true;
                    ui.startBtn.querySelector('.btn-text').textContent = "ANALYSIS LOADED";
                    updateContextStatus(true, data.session_metadata.title);
                } else {
                    switchView('upload');
                    updateContextStatus(false);
                }
            } else {
                ui.welcomeState.style.display = 'block';
                updateContextStatus(false);
            }
        } catch (err) { console.error("Failed to restore session:", err); }
    }

    function clearView() {
        currentSessionId = null;
        ui.chatHistory.innerHTML = '';
        ui.welcomeState.style.display = 'block';
        switchView('upload');
        selectedFile = null;
        ui.fileInput.value = '';
        ui.startBtn.disabled = true; 
        updateContextStatus(false);

        // Auto-expand the sidebar when returning to a clean/new state
        ui.layout.classList.remove('sidebar-collapsed');
        ui.sidebarToggle.querySelector('span').textContent = 'chevron_left';
    }

    // --- Select Model Logic ---
    
    // Compact Model Selector Logic
    if (ui.compactTrigger) {
        ui.compactTrigger.onclick = (e) => {
            e.stopPropagation();
            ui.compactDropdown.classList.toggle('show');
        };

        ui.compactOptions.forEach(opt => {
            opt.onclick = function(e) {
                e.stopPropagation();
                const val = this.getAttribute('data-value');
                const text = this.textContent;
                
                // Update Compact UI
                ui.compactOptions.forEach(o => o.classList.remove('selected'));
                this.classList.add('selected');
                
                // [NEW] Update the text inside the trigger
                const textSpan = ui.compactTrigger.querySelector('.current-model-text');
                if (textSpan) textSpan.textContent = text;
                
                ui.compactDropdown.classList.remove('show');
                
                // Sync with Hidden Input & Sidebar
                ui.hiddenModelInput.value = val;
                
                // Update Sidebar UI if it exists
                if (ui.customTrigger) {
                    ui.customTrigger.querySelector('span').textContent = text.includes('Local') ? 'NetShield Local' : text;
                    ui.customOptions.forEach(so => {
                        so.classList.toggle('selected', so.getAttribute('data-value') === val);
                    });
                }
            };
        });
    }

    if(ui.customSelect) {
        // Ensure default state is set correctly
        ui.hiddenModelInput.value = 'gemini-2.5-flash';
        ui.customTrigger.querySelector('span').textContent = 'Gemini 2.5 Flash';

        ui.customTrigger.addEventListener('click', (e) => {
            e.stopPropagation();
            ui.customSelect.classList.toggle('open');
        });

        ui.customOptions.forEach(option => {
            option.addEventListener('click', function(e) {
                e.stopPropagation();
                const val = this.getAttribute('data-value');
                const text = this.querySelector('.option-title').textContent;

                ui.customOptions.forEach(opt => opt.classList.remove('selected'));
                this.classList.add('selected');
                ui.customTrigger.querySelector('span').textContent = text;
                ui.hiddenModelInput.value = val;
                ui.customSelect.classList.remove('open');
                ui.startBtn.disabled = false;

                // Sync with Compact UI
                if (ui.compactTrigger) {
                    const textSpan = ui.compactTrigger.querySelector('.current-model-text');
                    if (textSpan) textSpan.textContent = text;
                    
                    ui.compactOptions.forEach(co => {
                        co.classList.toggle('selected', co.getAttribute('data-value') === val);
                    });
                }
            });
        });

        window.addEventListener('click', (e) => {
            if (ui.customSelect && !ui.customSelect.contains(e.target)) {
                ui.customSelect.classList.remove('open');
            }
            if (ui.compactDropdown && !ui.compactDropdown.contains(e.target)) {
                ui.compactDropdown.classList.remove('show');
            }
            document.querySelectorAll('.context-menu').forEach(m => m.classList.remove('show'));
            document.querySelectorAll('.session-item').forEach(si => si.classList.remove('menu-open'));
        });
    }

    // --- 9. ACTION EXECUTION LOGIC ---
    // Tool icon map for the action card header
    const _toolIconMap = {
        'nmap_scan': 'radar', 'zap_scan': 'bolt', 'ssl_scan': 'lock',
        'sql_injection_scan': 'database', 'packet_sniffer': 'wifi_tethering',
        'api_security_scan': 'api', 'killchain_audit': 'account_tree',
        'semgrep_sast_scan': 'code', 'schedule_scan': 'calendar_month'
    };

    async function handleAction(action, isRestore = false, reattachStreamUrl = null, isCompleted = false, isLastMessage = false) {
        if (!action || !action.tool) return;
        
        // [NEW] Resolve actual status via DB if restoring
        if (isRestore && action.action_id) {
            try {
                const statusRes = await fetchWithAuth(`/chatbot/get_action_status?action_id=${action.action_id}`);
                const statusData = await statusRes.json();
                if (statusData.status === 'success') {
                    if (statusData.scan_status === 'Running') {
                        isRestore = false; // Act as if we just triggered it
                        reattachStreamUrl = statusData.stream_url;
                    } else if (statusData.scan_status === 'Completed') {
                        isRestore = true;
                        isCompleted = true;
                    } else {
                        isRestore = false; // Render deployable state
                    }
                }
            } catch (e) { console.error("Status fetch failed", e); }
        }

        const displayTool = action.tool.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
        const toolIcon    = _toolIconMap[action.tool] || 'security';

        let stateClass, stateLabel, stateIcon, stateIconSpin;
        if (action.tool === 'schedule_scan') {
            stateClass = 'state-scheduled'; stateLabel = 'MISSION SCHEDULED'; stateIcon = 'event_available'; stateIconSpin = false;
        } else if (isCompleted || (isRestore && !reattachStreamUrl)) {
            stateClass = 'state-complete'; stateLabel = 'DATA ACQUIRED'; stateIcon = 'check_circle'; stateIconSpin = false;
        } else if (reattachStreamUrl) {
            stateClass = 'state-active';   stateLabel = 'SYNCHRONIZING'; stateIcon = 'sync';          stateIconSpin = true;
        } else {
            stateClass = 'state-deploy';   stateLabel = 'DEPLOYING';     stateIcon = 'sync';          stateIconSpin = true;
        }

        // Build parameter rows
        let paramRowsHtml = '';
        if (action.parameters) {
            for (const [key, value] of Object.entries(action.parameters)) {
                paramRowsHtml += `
                    <div class="ac-param-row">
                        <span class="ac-param-key">${key.replace(/_/g, ' ')}</span>
                        <span class="ac-param-val">${value}</span>
                    </div>`;
            }
        }

        const terminalHidden = (isCompleted || (isRestore && !reattachStreamUrl)) ? 'display:none' : (reattachStreamUrl ? '' : 'display:none');
        const footerHidden   = (isCompleted || (isRestore && !reattachStreamUrl)) ? '' : 'display:none';
        const dlHidden       = (isCompleted || (isRestore && !reattachStreamUrl)) ? '' : 'display:none';
        const footerLabel    = (isCompleted || (isRestore && !reattachStreamUrl)) ? 'DATASET LOADED FROM CACHE.' : 'SYNCHRONIZING ANALYTICS...';

        const row = document.createElement('div');
        row.className = 'msg-row system-action';
        row.innerHTML = `
            <div class="action-card ${stateClass}">
                <div class="ac-header">
                    <div class="ac-title-group">
                        <div class="ac-tool-icon">
                            <span class="material-symbols-outlined">${toolIcon}</span>
                        </div>
                        <div class="ac-tool-info">
                            <span class="ac-tool-name">${displayTool}</span>
                            <span class="ac-tool-sub">Security Module</span>
                        </div>
                    </div>
                    <div class="ac-state-badge">
                        <span class="material-symbols-outlined ac-state-icon${stateIconSpin ? ' spin' : ''}">${stateIcon}</span>
                        <span>${stateLabel}</span>
                    </div>
                </div>

                ${paramRowsHtml ? `<div class="ac-params">${paramRowsHtml}</div>` : ''}

                <div class="ac-actions">
                    <button class="ac-btn btn-redirect">
                        <span class="material-symbols-outlined" style="font-size:0.9rem">open_in_new</span>
                        VIEW MODULE
                    </button>
                    <button class="ac-btn btn-download" style="${dlHidden}">
                        <span class="material-symbols-outlined" style="font-size:0.9rem">download</span>
                        PDF REPORT
                    </button>
                </div>

                <div class="ac-terminal" style="${terminalHidden}">
                    <div class="ac-terminal-header">
                        <div class="ac-terminal-title">
                            <span class="material-symbols-outlined" style="font-size:0.85rem">terminal</span>
                            LIVE TELEMETRY
                        </div>
                        <div class="progress-container" style="display:none; flex:1; align-items:center; gap:0.75rem; max-width:240px;">
                            <div class="ac-progress-track">
                                <div class="progress-fill"></div>
                            </div>
                            <span class="progress-percent">0%</span>
                        </div>
                    </div>
                    <div class="terminal-body"></div>
                </div>

                <div class="ac-footer" style="${footerHidden}">
                    <span class="material-symbols-outlined" style="font-size:0.9rem">insights</span>
                    <span class="status-badge">${footerLabel}</span>
                </div>
            </div>
        `;
        ui.chatHistory.appendChild(row);
        if (!isRestore) scrollToBottom();

        // Common Tool URL Maps
        const toolUrlMap = {
            'nmap_scan': '/network_scanner/',
            'zap_scan': '/zap_scanner/',
            'ssl_scan': '/ssl_scanner/',
            'sql_injection_scan': '/sql_scanner/',
            'packet_sniffer': '/packet_sniffer/',
            'api_security_scan': '/api_scanner/',
            'killchain_audit': '/killchain/',
            'semgrep_sast_scan': '/semgrep_scanner/',
            'schedule_scan': '/scheduler/'
        };

        const toolDownloadMap = {
            'nmap_scan': '/network_scanner/download_pdf',
            'zap_scan': '/zap_scanner/download_pdf',
            'ssl_scan': '/ssl_scanner/download_pdf',
            'sql_injection_scan': '/sql_scanner/download_pdf',
            'packet_sniffer': '/packet_sniffer/download_pdf',
            'api_security_scan': '/api_scanner/download_pdf',
            'killchain_audit': '/killchain/download_pdf',
            'semgrep_sast_scan': '/semgrep_scanner/download_pdf'
        };

        const btnRedirect = row.querySelector('.btn-redirect');
        const btnDownload = row.querySelector('.btn-download');

        // Helper to attach listeners to specific buttons in this row
        const setupButtons = () => {
            btnRedirect.onclick = (e) => {
                const url = toolUrlMap[action.tool];
                if (url) window.location.href = url;
            };
            btnDownload.onclick = () => {
                const url = toolDownloadMap[action.tool];
                triggerDownload(url);
            };
        };

        setupButtons();

        if (isRestore && !isCompleted) return;

        // [NEW] If completed, we stop here (already rendered success card)
        // If this is the last message in the session, prompt for analysis
        if (isCompleted) {
            if (isLastMessage) promptForAnalysis(action.tool);
            return;
        }

        // If we are re-attaching to a running scan, we go straight to streaming
        if (reattachStreamUrl) {
            setupStreaming(reattachStreamUrl, row, displayTool, action.tool, btnDownload);
            return;
        }

        // Special handling for Scheduling
        if (action.tool === 'schedule_scan') {
            try {
                const response = await fetchWithAuth('/chatbot/execute_schedule', {
                    method: 'POST',
                    body: JSON.stringify(action.parameters)
                });
                if (!response.ok) throw new Error(await getErrorDetail(response));
                const result = await response.json();
                
                const card = row.querySelector('.action-card');
                const stateBadge = row.querySelector('.ac-state-badge span:last-child');
                const stateIconEl = row.querySelector('.ac-state-icon');
                
                if (card) { card.classList.remove('state-deploy'); card.classList.add('state-scheduled'); }
                if (stateBadge) stateBadge.textContent = 'PERSISTED';
                if (stateIconEl) stateIconEl.textContent = 'event_available';
                
                const successMsg = document.createElement('p');
                successMsg.className = 'ac-prompt-text';
                successMsg.style.cssText = 'color: #818cf8; margin-top: 10px; font-weight: 500; font-family: var(--font-code); font-size: 0.75rem;';
                successMsg.textContent = `SUCCESS: Mission orchestrated for ${result.next_run || 'future'}.`;
                row.querySelector('.ac-params')?.appendChild(successMsg) || row.querySelector('.action-card')?.appendChild(successMsg);
                
            } catch (e) {
                console.error("Scheduling failed:", e);
                const card = row.querySelector('.action-card');
                if (card) { card.classList.remove('state-deploy'); card.classList.add('state-error'); }
            }
            return;
        }

        try {
            const response = await fetchWithAuth('/chatbot/execute_action', {
                method: 'POST',
                body: JSON.stringify(action)
            });
            
            if (!response.ok) {
                const detail = await getErrorDetail(response);
                throw new Error(detail);
            }

            const result = await response.json();

            if (result.status === 'success') {
                setupStreaming(result.stream_url, row, displayTool, action.tool, btnDownload);
            } else {
                throw new Error(result.message || "Unknown scanner initialization error.");
            }
        } catch (e) {
            console.error("Action execution failed:", e);
            const card = row.querySelector('.action-card');
            const stateIcon = row.querySelector('.ac-state-icon');
            const stateBadge = row.querySelector('.ac-state-badge');
            if (card) { card.classList.remove('state-deploy'); card.classList.add('state-error'); }
            if (stateIcon) { stateIcon.textContent = 'error'; stateIcon.classList.remove('spin'); }
            if (stateBadge) stateBadge.querySelector('span:last-child').textContent = 'OFFLINE';
            
            const errorDiv = document.createElement('p');
            errorDiv.className = 'ac-prompt-text';
            errorDiv.style.cssText = 'color: #fb7185; margin-top: 10px; font-weight: 500; font-family: var(--font-code); font-size: 0.75rem;';
            errorDiv.textContent = `CRITICAL_ERROR: ${e.message}`;
            row.querySelector('.ac-params')?.appendChild(errorDiv) || row.querySelector('.action-card')?.appendChild(errorDiv);
        }
    }

    /**
     * Internal helper to manage the SSE stream for terminal output
     */
    function setupStreaming(streamUrl, row, displayTool, toolName, btnDownload) {
        const card        = row.querySelector('.action-card');
        const stateIcon   = row.querySelector('.ac-state-icon');
        const stateBadge  = row.querySelector('.ac-state-badge span:last-child');
        const terminalEl  = row.querySelector('.ac-terminal');
        const terminalBody = row.querySelector('.terminal-body');

        if (card)      { card.classList.remove('state-deploy'); card.classList.add('state-active'); }
        if (stateIcon) { stateIcon.textContent = 'check_circle'; stateIcon.classList.remove('spin'); }
        if (stateBadge) stateBadge.textContent = 'CORE ACTIVE';

        if (terminalEl) terminalEl.style.display = '';
        const eventSource = new EventSource(streamUrl);

        eventSource.onmessage = (e) => {
            if (e.data === ': keep-alive') return;

            let isProgress = false;
            // [NEW] Handle Progress Updates for ZAP and other scanners
            if (e.data.includes('[PROGRESS]')) {
                const match = e.data.match(/(\d+)%/);
                if (match) {
                    const percent = match[1];
                    const progressContainer = row.querySelector('.progress-container');
                    const progressFill = row.querySelector('.progress-fill');
                    const progressText = row.querySelector('.progress-percent');
                    
                    if (progressContainer) {
                        progressContainer.style.display = 'flex';
                        progressFill.style.width = `${percent}%`;
                        progressText.textContent = `${percent}%`;
                        
                        if (percent === "100") {
                            progressText.style.color = "#10b981";
                        }
                    }
                    isProgress = true;
                }
            }

            // [NEW] Check for text-based progress bars (e.g. "[===== ] 75%")
            const cleanedMessage = e.data.replace(/\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s*/g, "").trim();
            const isTextProgressBar = cleanedMessage.startsWith('[') && cleanedMessage.includes('%');

            if (isTextProgressBar) {
                const lastLine = terminalBody.lastElementChild;
                if (lastLine && lastLine.getAttribute('data-is-progress') === 'true') {
                    // Update existing progress line
                    lastLine.querySelector('.term-time').textContent = new Date().toLocaleTimeString([], { hour12: false });
                    lastLine.querySelector('.term-text').textContent = cleanedMessage;
                    return;
                }
            }

            const line = document.createElement('div');
            line.className = 'terminal-line';
            if (isProgress) {
                line.classList.add('progress-line');
                // Remove previous progress lines to keep terminal clean
                terminalBody.querySelectorAll('.progress-line').forEach(el => el.remove());
            }
            
            if (isTextProgressBar) {
                line.setAttribute('data-is-progress', 'true');
            }
            
            const timeSpan = document.createElement('span');
            timeSpan.className = 'term-time';
            timeSpan.style.color = '#52525b';
            timeSpan.textContent = new Date().toLocaleTimeString([], { hour12: false });
            
            const textSpan = document.createElement('span');
            textSpan.className = 'term-text';
            
            if (e.data.includes('[!]') || e.data.toLowerCase().includes('error')) textSpan.classList.add('error');
            else if (e.data.includes('[+') || e.data.toLowerCase().includes('success')) textSpan.classList.add('success');
            else if (e.data.includes('[*]')) textSpan.classList.add('info');
            
            // Clean up the progress prefix for terminal display
            textSpan.textContent = e.data.replace('[PROGRESS] ', '');
            
            line.appendChild(timeSpan);
            line.appendChild(textSpan);
            terminalBody.appendChild(line);
            terminalBody.scrollTop = terminalBody.scrollHeight;

            if (e.data.includes('SYSTEM_EVENT: READY_FOR_ANALYSIS')) {
                eventSource.close();
                
                // Fix: Define headerText by finding it in the card
                const titleNode = row.querySelector('.ac-tool-name');
                if (titleNode) titleNode.textContent = `[COMPLETE]: ${displayTool.toUpperCase()}`;
                
                const footerBadge = row.querySelector('.status-badge');
                if (footerBadge) {
                    footerBadge.innerHTML = `
                        <span class="material-symbols-outlined" style="font-size: 1rem;">analytics</span>
                        DATASET READY.
                    `;
                }
                
                const footer = row.querySelector('.action-footer');
                if (footer) footer.style.display = 'flex';
                
                btnDownload.style.display = 'block';
                promptForAnalysis(toolName);
            }
        };

        eventSource.onerror = () => {
            eventSource.close();
        };
    }

    function promptForAnalysis(tool) {
        scrollToBottom();

        const row = document.createElement('div');
        row.className = 'msg-row system-action';
        row.innerHTML = `
            <div class="action-card state-prompt">
                <div class="ac-header">
                    <div class="ac-title-group">
                        <div class="ac-tool-icon" style="--ac-icon-bg: rgba(59,130,246,0.1); --ac-icon-color: var(--neo-blue);">
                            <span class="material-symbols-outlined">smart_toy</span>
                        </div>
                        <div class="ac-tool-info">
                            <span class="ac-tool-name">AI Analysis Ready</span>
                            <span class="ac-tool-sub">Scan complete — dataset acquired</span>
                        </div>
                    </div>
                    <div class="ac-state-badge" style="--ac-badge-color: var(--neo-blue); --ac-badge-bg: rgba(59,130,246,0.08);">
                        <span class="material-symbols-outlined ac-state-icon">help_outline</span>
                        <span>ACTION REQUIRED</span>
                    </div>
                </div>
                <p class="ac-prompt-text">The scan completed successfully. Would you like the AI Analyst to parse the PDF report and generate a structured security assessment?</p>
                <div class="ac-actions prompt-actions">
                    <button class="ac-btn btn-yes">
                        <span class="material-symbols-outlined" style="font-size:0.9rem">analytics</span>
                        YES, ANALYZE
                    </button>
                    <button class="ac-btn btn-no">
                        <span class="material-symbols-outlined" style="font-size:0.9rem">close</span>
                        SKIP
                    </button>
                </div>
            </div>
        `;

        ui.chatHistory.appendChild(row);
        scrollToBottom();

        const btnYes = row.querySelector('.btn-yes');
        const btnNo = row.querySelector('.btn-no');

        btnYes.onclick = () => {
            row.remove();
            addMessage('user', "Yes, please analyze the recent scan report.", true);
            triggerAutoAnalysis(tool);
        };

        btnNo.onclick = () => {
            row.remove();
            addMessage('system', "SYSTEM_NOTIFICATION: Scan Analysis Skipped. The report is saved and can be viewed or downloaded from the module page.", false);
        };
    }

    async function triggerAutoAnalysis(tool) {
        // Show typing indicator immediately to signal AI reasoning is starting
        ui.typingIndicator.style.display = 'block';
        scrollToBottom();

        // Map AI tool names to scanner types for the analysis proxy
        const toolToScannerMap = {
            'nmap_scan': 'nmap',
            'zap_scan': 'zap',
            'ssl_scan': 'ssl',
            'sql_injection_scan': 'sql',
            'packet_sniffer': 'packet_sniffer',
            'api_security_scan': 'api',
            'killchain_audit': 'killchain',
            'semgrep_sast_scan': 'semgrep'
        };

        const scannerType = toolToScannerMap[tool];
        if (!scannerType) return;

        try {
            const response = await fetchWithAuth('/chatbot/scanner_analysis', {
                method: 'POST',
                body: JSON.stringify({ 
                    scanner_type: scannerType, 
                    llm_mode: ui.hiddenModelInput.value,
                    force_new_session: false // Stay in same chat if auto-triggered
                })
            });

            if (!response.ok) {
                const detail = await getErrorDetail(response);
                throw new Error(detail);
            }

            const result = await response.json();

            if (result.status === 'success') {
                // Sync session ID if returned
                if (result.session_id) currentSessionId = result.session_id;

                ui.typingIndicator.style.display = 'none';
                
                // Directly render the System Core's generated summary
                addMessage('system', "SYSTEM_NOTIFICATION: Scan Complete. Report successfully synchronized. Summary: " + result.summary, false);
            }
        } catch (e) {
            console.error("Auto-analysis failed:", e);
            ui.typingIndicator.style.display = 'none';
            addMessage('ai', `⚠️ **AI Intelligence Failure:** ${e.message}`, false);
        }
    }

    // --- 10. STREAMING MESSAGE LOGIC (WITH VISUAL SMOOTHING) ---
    async function sendMessage() {
        const text = ui.userInput.value.trim();
        if (!text || isProcessing) return;
        
        const verbosity = ui.settingVerbosity.value;
        const isIncognito = ui.settingIncognito.checked;
        const typeSpeed = parseInt(ui.settingSpeed.value);
        const llmMode = ui.hiddenModelInput.value || 'local';

        ui.userInput.value = '';
        ui.userInput.style.height = 'auto'; // Reset height
        ui.sendBtn.disabled = true; // Disable until new input
        pushToHistory(text); // [NEW] Add to terminal history

        // Capture a snapshot of current attachments before clearing
        const messageAttachments = [...attachedFiles];

        addMessage('user', text, true, messageAttachments); 
        clearAttachments(); // Instant clear as requested

        isProcessing = true;

        // Auto-collapse the sidebar to maximize chat area when conversation starts
        if (!ui.layout.classList.contains('sidebar-collapsed')) {
            ui.layout.classList.add('sidebar-collapsed');
            ui.sidebarToggle.querySelector('span').textContent = 'chevron_right';
        }
        
        ui.typingIndicator.style.display = 'block';
        scrollToBottom();

        let aiRow = null;
        let contentDiv = null;
        let fullMarkdownText = "";
        let displayedText = "";
        let isStreamActive = true;
        let metadataAction = null;

        try {
            let response;
            if (attachedFiles.length > 0) {
                const formData = new FormData();
                formData.append('message', text);
                formData.append('verbosity', verbosity);
                formData.append('is_incognito', isIncognito);
                formData.append('llm_mode', llmMode);
                
                attachedFiles.forEach(a => {
                    formData.append('files', a.file);
                });

                response = await fetchWithAuth('/chatbot/chat_stream', {
                    method: 'POST',
                    body: formData
                });
            } else {
                response = await fetchWithAuth('/chatbot/chat_stream', {
                    method: 'POST',
                    body: JSON.stringify({ 
                        message: text,
                        verbosity: verbosity,
                        is_incognito: isIncognito,
                        llm_mode: llmMode
                    })
                });
            }

            // Clear attachments after sending
            clearAttachments();

            if (!response.ok) {
                const detail = await getErrorDetail(response);
                throw new Error(detail);
            }

            if (!response.body) throw new Error('ReadableStream not supported.');

            // [NEW] Sync Session ID from Response Headers
            const newSessionId = response.headers.get('X-Session-ID');
            if (newSessionId && newSessionId !== currentSessionId) {
                console.log(`[*] Updating local session ID to: ${newSessionId}`);
                currentSessionId = newSessionId;
            }

            const reader = response.body.getReader();
            const decoder = new TextDecoder();

            const networkLoop = async () => {
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    const chunk = decoder.decode(value, { stream: true });
                    
                    if (chunk.includes("__METADATA_ACTION__:")) {
                        const parts = chunk.split("__METADATA_ACTION__:");
                        fullMarkdownText += parts[0];
                        try {
                            metadataAction = JSON.parse(parts[1]);
                        } catch(e) { console.error("Metadata parse error:", e); }
                    } else {
                        fullMarkdownText += chunk;
                    }
                    
                    if (!aiRow && fullMarkdownText.trim().length > 0) {
                        ui.typingIndicator.style.display = 'none';
                        aiRow = document.createElement('div');
                        aiRow.className = 'msg-row ai';
                        const aiBubble = document.createElement('div');
                        aiBubble.className = 'msg-bubble';
                        
                        // [NEW] Persist NETSHIELD AI identity with bottom border during stream
                        const identity = document.createElement('div');
                        identity.className = 'msg-identity ai-identity';
                        identity.innerHTML = `<span class="material-symbols-outlined" style="font-size:16px">bolt</span> <span>NETSHIELD AI</span>`;
                        aiBubble.appendChild(identity);

                        contentDiv = document.createElement('div');
                        contentDiv.className = 'markdown-content';
                        
                        // [FIX] Apply identical styling to streaming content as in addMessage
                        const BUBBLE_FONT = "'Geist', sans-serif";
                        contentDiv.style.setProperty('font-family', BUBBLE_FONT, 'important');
                        contentDiv.style.setProperty('font-size', '0.935rem', 'important');
                        contentDiv.style.setProperty('line-height', '1.65', 'important');
                        contentDiv.style.setProperty('letter-spacing', '0', 'important');

                        aiBubble.appendChild(contentDiv);
                        
                        const actions = document.createElement('div');
                        actions.className = 'msg-actions';
                        actions.innerHTML = `
                            <button class="action-btn copy-btn" title="Copy response"><span class="material-symbols-outlined" style="font-size:14px">content_copy</span></button>
                            <button class="action-btn regen-btn" title="Regenerate"><span class="material-symbols-outlined" style="font-size:14px">refresh</span></button>
                            <button class="action-btn feedback-btn up" title="Helpful"><span class="material-symbols-outlined" style="font-size:14px">thumb_up</span></button>
                            <button class="action-btn feedback-btn down" title="Not helpful"><span class="material-symbols-outlined" style="font-size:14px">thumb_down</span></button>
                        `;
                        aiBubble.appendChild(actions);

                        aiRow.appendChild(aiBubble);
                        ui.chatHistory.appendChild(aiRow);

                        actions.querySelector('.copy-btn').onclick = () => {
                            navigator.clipboard.writeText(fullMarkdownText);
                            const icon = actions.querySelector('.copy-btn span');
                            icon.textContent = 'check';
                            setTimeout(() => icon.textContent = 'content_copy', 2000);
                        };
                        actions.querySelector('.regen-btn').onclick = () => {
                            ui.userInput.value = text;
                            sendMessage();
                        };

                        actions.querySelectorAll('.feedback-btn').forEach(btn => {
                            btn.onclick = () => {
                                const isUp = btn.classList.contains('up');
                                btn.style.color = isUp ? '#10b981' : '#ef4444';
                                btn.parentElement.style.opacity = '1';
                                submitFeedback(currentSessionId, isUp);
                            };
                        });
                    }
                }
                isStreamActive = false;

                // Check if metadata was hidden in full text
                if (fullMarkdownText.includes("__METADATA_ACTION__:")) {
                    const parts = fullMarkdownText.split("__METADATA_ACTION__:");
                    fullMarkdownText = parts[0];
                    try { metadataAction = JSON.parse(parts[1]); } catch(e) {}
                }
            };

            networkLoop();

            const renderLoop = () => {
                if (displayedText.length < fullMarkdownText.length) {
                    const lag = fullMarkdownText.length - displayedText.length;
                    const step = lag > 50 ? 8 : (lag > 20 ? 4 : 2); 
                    displayedText = fullMarkdownText.substring(0, displayedText.length + step);
                    
                    if (contentDiv) {
                        contentDiv.innerHTML = parseContent(displayedText);
                        scrollToBottom();
                    }
                }

                if (isStreamActive || displayedText.length < fullMarkdownText.length) {
                    setTimeout(renderLoop, typeSpeed);
                } else {
                    // Stream finished
                    ui.typingIndicator.style.display = 'none';
                    isProcessing = false;
                    ui.userInput.focus();

                    if (contentDiv) {
                        contentDiv.innerHTML = parseContent(fullMarkdownText);
                        if (!isIncognito) loadSessionList(); 
                    }
                    
                    if (metadataAction) {
                        handleAction(metadataAction);
                    }
                }
            };

            renderLoop();

        } catch (err) {
            ui.typingIndicator.style.display = 'none';
            isProcessing = false;
            ui.userInput.focus();

            const errorStr = String(err).toLowerCase();
            if (errorStr.includes("429") || errorStr.includes("quota") || errorStr.includes("limit")) {
                addMessage('assistant', `⚠️ **API Rate Limit Reached.** Gemini is cooling down. Please wait 30-60 seconds before retrying your request. (Error: 429 Quota Exceeded)`, false);
            } else {
                if(!aiRow) addMessage('ai', `_Error: ${err.message}_`);
            }
        }
    }

    ui.newChatBtn.addEventListener('click', async () => {
        try {
             await fetchWithAuth('/chatbot/switch_session', { 
                 method: 'POST', 
                 body: JSON.stringify({ session_id: null }) 
             });
        } catch(e) { console.error(e); }
        clearView();
        currentSessionId = null;
        loadSessionList();
        renderSuggestions();
    });

    ui.sendBtn.addEventListener('click', sendMessage);
    // ui.userInput.addEventListener('keydown', ...) was moved to the Smart Input Logic section to support Shift+Enter
    
    const suggestionPool = [
        { title: "Vulnerability Analysis", desc: "Analyze the severity and impact of a Time-Based Blind SQL Injection." },
        { title: "Remediation", desc: "Provide a secure coding strategy to patch DOM-based XSS vulnerabilities." },
        { title: "Network Audit", desc: "What are the security implications of exposing RDP (Port 3389) to the public internet?" },
        { title: "Compliance", desc: "Map our current password hashing strategy (bcrypt) against NIST 800-63B guidelines." },
        { title: "Incident Response", desc: "Draft an initial response playbook for a suspected ransomware outbreak." },
        { title: "Architecture Review", desc: "Evaluate the security trade-offs between JWT and stateful session cookies." },
        { title: "Threat Hunting", desc: "Write a Splunk query to detect lateral movement using Pass-the-Hash." },
        { title: "Cloud Security", desc: "Identify common misconfigurations in AWS S3 bucket policies." },
        { title: "Malware Analysis", desc: "Explain the purpose of process hollowing in evasive malware." },
        { title: "Cryptography", desc: "Why is AES-GCM preferred over AES-CBC for securing web traffic?" },
        { title: "Web Application", desc: "Explain how Server-Side Request Forgery (SSRF) can be used to pivot into an internal network." },
        { title: "API Security", desc: "How do I implement rate limiting and thwart BOLA (Broken Object Level Authorization) attacks?" },
        { title: "Zero Trust", desc: "What are the core principles of a Zero Trust Architecture?" },
        { title: "DevSecOps", desc: "How can I integrate Semgrep smoothly into a GitHub Actions CI/CD pipeline?" },
        { title: "Active Directory", desc: "Describe the mechanics of a Kerberoasting attack and how to mitigate it." }
    ];

    function renderSuggestions() {
        if (!ui.suggestionGrid) return;
        ui.suggestionGrid.innerHTML = '';
        
        // Shuffle the pool and pick the first 4
        const shuffled = [...suggestionPool].sort(() => 0.5 - Math.random());
        const selected = shuffled.slice(0, 4);
        
        selected.forEach(s => {
            const card = document.createElement('div');
            card.className = 'suggestion-card';
            card.innerHTML = `<h5>${s.title}</h5><p>${s.desc}</p>`;
            card.onclick = () => { 
                ui.userInput.value = s.desc; 
                ui.userInput.focus(); 
                if (typeof autoResizeInput === 'function') autoResizeInput();
            };
            ui.suggestionGrid.appendChild(card);
        });
    }

    renderSuggestions();

    // --- [MULTIMODAL] ATTACHMENT HANDLERS ---
    
    // Toggle Attachment Menu
    if (ui.attachmentPlusBtn) {
        ui.attachmentPlusBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            ui.attachmentMenu.classList.toggle('show');
            ui.attachmentPlusBtn.classList.toggle('active');
        });
    }

    // Close menu when clicking outside
    document.addEventListener('click', (e) => {
        if (ui.attachmentMenu && !ui.attachmentMenu.contains(e.target) && e.target !== ui.attachmentPlusBtn) {
            ui.attachmentMenu.classList.remove('show');
            ui.attachmentPlusBtn.classList.remove('active');
        }
    });

    // Handle Attachment Menu Clicks
    if (ui.attachImage) ui.attachImage.onclick = () => { ui.multimodalInput.accept = "image/*"; ui.multimodalInput.click(); };
    if (ui.attachDoc) ui.attachDoc.onclick = () => { ui.multimodalInput.accept = ".log,.txt,.yaml,.json"; ui.multimodalInput.click(); };
    if (ui.attachPcap) ui.attachPcap.onclick = () => { ui.multimodalInput.accept = ".pcap,.pcapng"; ui.multimodalInput.click(); };

    if (ui.multimodalInput) {
        ui.multimodalInput.addEventListener('change', (e) => {
            handleAttachments(e.target.files);
            ui.attachmentMenu.classList.remove('show');
            ui.attachmentPlusBtn.classList.remove('active');
            ui.multimodalInput.value = ''; // Reset for same file re-upload
        });
    }

    // Paste Support
    ui.userInput.addEventListener('paste', (e) => {
        const items = (e.clipboardData || e.originalEvent.clipboardData).items;
        for (let item of items) {
            if (item.type.indexOf('image') !== -1) {
                const blob = item.getAsFile();
                handleAttachments([blob]);
            }
        }
    });

    function handleAttachments(files) {
        if (attachedFiles.length + files.length > 10) {
            alert("Maximum 10 attachments allowed");
            return;
        }

        Array.from(files).forEach(file => {
            if (!validateFileSize(file)) return;
            
            const id = Math.random().toString(36).substr(2, 9);
            const type = file.type.startsWith('image/') ? 'image' : 
                         (file.name.endsWith('.pcap') || file.name.endsWith('.pcapng') ? 'pcap' : 'doc');
            
            const attachment = {
                file: file,
                id: id,
                type: type,
                name: file.name || `Pasted Image ${attachedFiles.length + 1}`,
                previewUrl: type === 'image' ? URL.createObjectURL(file) : null
            };

            attachedFiles.push(attachment);
            renderAttachmentPreview(attachment);
        });
    }

    function renderAttachmentPreview(attachment) {
        if (!ui.attachmentPreview) return;
        const item = document.createElement('div');
        item.className = 'attachment-item';
        item.setAttribute('data-id', attachment.id);
        
        let content = '';
        if (attachment.type === 'image') {
            content = `<img src="${attachment.previewUrl}" alt="Preview" />`;
        } else {
            const icon = attachment.type === 'pcap' ? 'settings_input_component' : 'description';
            content = `
                <span class="material-symbols-outlined" style="font-size: 1.5rem;">${icon}</span>
                <span style="font-size: 0.6rem; margin-top: 4px; color: #71717a; text-align: center; width: 90%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                    ${attachment.file.name}
                </span>
            `;
        }
        
        item.innerHTML = `
            ${content}
            <div class="remove-btn" title="Remove attachment">&times;</div>
        `;
        
        item.querySelector('.remove-btn').onclick = (e) => {
            e.stopPropagation();
            removeAttachment(attachment.id);
        };
        
        ui.attachmentPreview.appendChild(item);
    }

    function removeAttachment(id) {
        const index = attachedFiles.findIndex(a => a.id === id);
        if (index !== -1) {
            if (attachedFiles[index].previewUrl) {
                URL.revokeObjectURL(attachedFiles[index].previewUrl);
            }
            attachedFiles.splice(index, 1);
            const el = document.getElementById(`attach-${id}`);
            if (el) el.remove();
        }
    }

    function clearAttachments() {
        if (!ui.attachmentPreview) return;
        attachedFiles.forEach(a => {
            if (a.previewUrl) URL.revokeObjectURL(a.previewUrl);
        });
        attachedFiles = [];
        ui.attachmentPreview.innerHTML = '';
    }

    async function init() {
        console.log("[*] Initializing Chatbot interface...");
        
        // 1. Load the sidebar session list
        await loadSessionList();

        // 2. Check if we arrived from a scanner AI Analysis redirect
        const urlParams = new URLSearchParams(window.location.search);
        const urlSessionId = urlParams.get('session_id');
        
        // 3. Restore history if an active session exists
        if (window.ACTIVE_SESSION_ID && window.ACTIVE_SESSION_ID !== "None" && window.ACTIVE_SESSION_ID !== "") {
            console.log(`[*] Active session detected: ${window.ACTIVE_SESSION_ID}. Restoring...`);
            currentSessionId = window.ACTIVE_SESSION_ID;

            // If we arrived via scanner redirect, poll until the LLM summary is ready
            if (urlSessionId && urlSessionId === currentSessionId) {
                await restoreSessionWithPolling();
            } else {
                await restoreSession();
            }

            // [NEW] Auto-collapse sidebar if history was successfully restored
            if (ui.chatHistory.children.length > 0) {
                ui.layout.classList.add('sidebar-collapsed');
                ui.sidebarToggle.querySelector('span').textContent = 'chevron_right';
            }
        } else {
            console.log("[*] No active session. Waiting for user input.");
            ui.welcomeState.style.display = 'block';
            switchView('upload');
        }
        
        // 4. Set a default model if not set
        if (!ui.hiddenModelInput.value) {
            ui.hiddenModelInput.value = 'gemini-2.5-flash';
        }
    }

    /**
     * Polls get_history up to MAX_POLL_ATTEMPTS times (every POLL_INTERVAL ms) 
     * waiting for the LLM background summary to be stored.
     * Shows a subtle "Generating AI Summary…" indicator while waiting.
     */
    async function restoreSessionWithPolling() {
        const MAX_WAIT_MS = 45000;   // 45 seconds max
        const POLL_INTERVAL_MS = 3000; // check every 3 seconds
        const deadline = Date.now() + MAX_WAIT_MS;

        // Show a placeholder so the user knows something is loading
        ui.welcomeState.style.display = 'none';
        ui.chatHistory.innerHTML = `
            <div id="summary-loading-row" class="msg-row ai" style="justify-content:center; padding:2rem;">
                <div class="msg-bubble" style="display:flex; align-items:center; gap:12px; background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); padding:1rem 1.5rem; border-radius:12px;">
                    <span class="material-symbols-outlined spin" style="font-size:1.3rem; color:var(--neo-blue);">autorenew</span>
                    <span style="font-size:0.8rem; color:var(--neo-text-muted); font-weight:600; letter-spacing:0.05em;">GENERATING AI SECURITY SUMMARY…</span>
                </div>
            </div>
        `;

        while (Date.now() < deadline) {
            try {
                const response = await fetchWithAuth('/chatbot/get_history');
                const data = await response.json();
                if (data.chat_history && data.chat_history.length > 0) {
                    // History is ready — hand off to normal restoreSession
                    ui.chatHistory.innerHTML = '';
                    await restoreSession();
                    return;
                }
            } catch (e) {
                console.warn("[*] Polling get_history failed:", e);
            }
            // Wait before next poll
            await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL_MS));
        }

        // Timed out — just do normal restore (may still be empty)
        ui.chatHistory.innerHTML = '';
        await restoreSession();
    }

    init();
});
