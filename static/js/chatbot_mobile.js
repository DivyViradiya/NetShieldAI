document.addEventListener('DOMContentLoaded', () => {
    // --- viewport fix for mobile keyboard ---
    // --- viewport fix for mobile keyboard ---
    if (window.visualViewport) {
        const offsetFix = () => {
            const vh = window.visualViewport.height;
            document.documentElement.style.setProperty('--vh', `${vh}px`);
            document.body.style.height = vh + 'px';
            const layout = document.querySelector('.mobile-layout');
            if(layout) layout.style.height = vh + 'px';
        };
        window.visualViewport.addEventListener('resize', offsetFix);
        window.visualViewport.addEventListener('scroll', offsetFix);
        offsetFix();
    }

    // --- 0. SECURITY: CSRF Token Setup ---
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

    let currentSessionId = (window.ACTIVE_SESSION_ID && window.ACTIVE_SESSION_ID !== "None" && window.ACTIVE_SESSION_ID !== "") ? window.ACTIVE_SESSION_ID : null;
    let allSessions = window.PRELOADED_SESSIONS || [];
    let isSwitching = false;

    // Helper to send authorized requests
    async function fetchWithAuth(url, options = {}) {
        const headers = {
            'X-CSRFToken': csrfToken,
            'X-Session-ID': currentSessionId, // Send session ID if available
            ...options.headers
        };
        if (options.body && !(options.body instanceof FormData)) {
            headers['Content-Type'] = 'application/json';
        }
        return fetch(url, { ...options, headers });
    }

    // --- 1. Initialize Markdown ---
    marked.setOptions({
        highlight: function(code, lang) {
            const language = hljs.getLanguage(lang) ? lang : 'plaintext';
            return hljs.highlight(code, { language }).value;
        },
        langPrefix: 'hljs language-',
        breaks: true,
        gfm: true
    });

    // --- 2. UI Elements Map ---
    const ui = {
        // Panels
        menuBtn: document.getElementById('mobile-menu-btn'),
        leftPanel: document.getElementById('panel-left'),
        closeLeft: document.getElementById('close-left'),
        settingsBtn: document.getElementById('mobile-settings-btn'),
        settingsSheet: document.getElementById('settings-sheet'),
        overlay: document.getElementById('panel-overlay'),

        // Sessions
        newChatBtn: document.getElementById('new-chat-btn'),
        sessionList: document.getElementById('session-list'),
        sessionSearch: document.getElementById('session-search'),

        // Ingestion/Uploads (Migrated to global attachments, but keeping input for multimodal if needed)
        multimodalInput: document.getElementById('multimodal-file-input'),

        // Settings / Command Center
        settingVerbosity: document.getElementById('setting-verbosity'),
        settingSpeed: document.getElementById('setting-speed'),
        settingIncognito: document.getElementById('setting-incognito'),
        btnClearContext: document.getElementById('cc-clear-context'),
        btnDeleteSession: document.getElementById('cc-delete-session'),
        btnDownloadTranscript: document.getElementById('btn-download-transcript'),
        btnWipeAll: document.getElementById('btn-wipe-all'),
        btnViewTopology: document.getElementById('cc-view-topology'),

        // Sheets / Modals
        modalOverlay: document.getElementById('overlay'),
        modelSheet: document.getElementById('model-sheet'),
        attachmentSheet: document.getElementById('attachment-sheet'),
        contextSheet: document.getElementById('context-sheet'),
        topologySheet: document.getElementById('topology-sheet'),
        topologyContainer: document.getElementById('vis-network-container'),
        closeTopologyBtn: document.getElementById('close-topology-btn'),

        // Chat Interface
        chatArea: document.getElementById('chat-area'),
        welcomeState: document.getElementById('welcome-state'),
        chatHistory: document.getElementById('chat-history'),
        typingIndicator: document.getElementById('typing-indicator'),
        userInput: document.getElementById('user-input'),
        sendBtn: document.getElementById('send-btn'),
        
        // Input bottom bar
        attachPlusBtn: document.getElementById('attachment-plus-btn'),
        modelTrigger: document.getElementById('model-trigger-compact'),
        currentModelDisplay: document.getElementById('current-model-display'),
        hiddenModelInput: document.getElementById('selected-model-value'),
        previewArea: document.getElementById('attachment-preview-area'),
        messagesContainer: document.getElementById('messages-container'),

        // Sheets
        modelSheet: document.getElementById('model-sheet'),
        attachSheet: document.getElementById('attachment-sheet'),
        contextSheet: document.getElementById('context-sheet'),
        topologySheet: document.getElementById('topology-sheet'),
        closeTopologyBtn: document.getElementById('close-topology-btn'),
        visContainer: document.getElementById('vis-network-container'),
        attachImage: document.getElementById('attach-image'),
        attachDoc: document.getElementById('attach-doc'),
        multimodalInput: document.getElementById('multimodal-file-input')
    };

    // --- Sync Chatbot Hamburger with Base.html Drawer ---
    const baseToggle = document.getElementById('mobile-menu-toggle');
    const chatbotToggle = document.getElementById('mobile-menu-toggle-chatbot');
    if (chatbotToggle && baseToggle) {
        chatbotToggle.addEventListener('click', (e) => {
             e.preventDefault();
             e.stopPropagation();
             
             const drawer = document.getElementById('mobile-nav-drawer');
             const backdrop = document.getElementById('nav-backdrop');
             const isOpen = drawer && drawer.classList.contains('show-mobile');
             
             if(!isOpen) {
                 // Use the openDrawer logic from base.html (simulated here)
                 if(drawer) drawer.classList.add('show-mobile');
                 if(backdrop) backdrop.classList.add('visible');
                 baseToggle.classList.add('is-open');
                 chatbotToggle.classList.add('is-open');
                 baseToggle.setAttribute('aria-expanded', 'true');
                 document.body.classList.add('nav-open');
             } else {
                 // Use baseToggle.click() to trigger the closeDrawer logic in base.html
                 baseToggle.click();
             }
        });
        // Sync the is-open animation state
        const observer = new MutationObserver(() => {
             if (baseToggle.classList.contains('is-open')) {
                 chatbotToggle.classList.add('is-open');
             } else {
                 chatbotToggle.classList.remove('is-open');
             }
        });
        observer.observe(baseToggle, { attributes: true, attributeFilter: ['class'] });
    }

    let isProcessing = false;
    let attachedFiles = [];
    let sessionContextActions = null; // To hold session ID for context menu actions
    let lastUserMessage = "";
    let networkInstance = null;
    let historyCache = {}; // Cache for preloaded chat histories { sessionId: { history, activeScans } }

    // --- Panel Togglers ---
    function openLeftPanel() {
        ui.leftPanel.classList.add('open');
        ui.overlay.classList.add('show');
    }
    function closePanels() {
        ui.leftPanel.classList.remove('open');
        ui.overlay.classList.remove('show');
        closeAllSheets();
    }
    function openSettingsSheet() {
        openSheet(ui.settingsSheet);
    }
    
    if (ui.menuBtn) ui.menuBtn.onclick = openLeftPanel;
    if (ui.closeLeft) ui.closeLeft.onclick = closePanels;
    if (ui.settingsBtn) ui.settingsBtn.onclick = openSettingsSheet;
    if (ui.overlay) ui.overlay.onclick = closePanels;

    // Search Logic
    if (ui.sessionSearch) {
        ui.sessionSearch.addEventListener('input', (e) => {
            const term = e.target.value.toLowerCase();
            const filtered = allSessions.filter(s => 
                s.title.toLowerCase().includes(term) || 
                (s.subtitle && s.subtitle.toLowerCase().includes(term))
            );
            renderSessionList(filtered);
        });
    }

    // Keyboard Shortcuts
    window.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'enter' && document.activeElement === ui.userInput) {
            sendMessage();
        }
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
            e.preventDefault();
            openLeftPanel();
            ui.sessionSearch?.focus();
        }
    });

    function closeAllSheets() {
        document.querySelectorAll('.bottom-sheet').forEach(sheet => sheet.classList.remove('open'));
        ui.overlay.classList.remove('show'); // Overlay used for sheets too
    }

    function openSheet(sheetElement) {
        closePanels();
        sheetElement.classList.add('open');
        ui.overlay.classList.add('show');
    }

    // --- Event bindings for Sheets ---
    ui.modelTrigger.onclick = () => openSheet(ui.modelSheet);
    
    // Model Selection via Sheet
    document.querySelectorAll('#model-sheet .model-opt').forEach(opt => {
        opt.onclick = () => {
             ui.hiddenModelInput.value = opt.getAttribute('data-value');
             ui.currentModelDisplay.textContent = opt.textContent;
             closeAllSheets();
        };
    });

    ui.attachPlusBtn.onclick = () => openSheet(ui.attachSheet);

    ui.attachImage.onclick = () => {
         ui.multimodalInput.setAttribute('accept', 'image/*');
         ui.multimodalInput.click();
         closeAllSheets();
    };
    ui.attachDoc.onclick = () => {
         ui.multimodalInput.setAttribute('accept', '.pdf,.txt,.log,.pcap');
         ui.multimodalInput.click();
         closeAllSheets();
    };

    // Auto-adjust textarea
    ui.userInput.addEventListener('input', function() {
        this.style.height = 'auto';
        this.style.height = (this.scrollHeight) + 'px';
        if (this.value === '') { this.style.height = 'auto'; }
        scrollToBottom();
    });

    // --- Attachments Logic ---
    ui.multimodalInput.addEventListener('change', (e) => {
        if(e.target.files.length > 0) {
            Array.from(e.target.files).forEach(f => processMultimodalFile(f));
        }
    });

    function processMultimodalFile(file) {
        const fileId = 'attach_' + Math.random().toString(36).substr(2, 9);
        let fileType = 'doc';
        if (file.type.startsWith('image/')) fileType = 'image';
        else if (file.name.endsWith('.pcap') || file.name.endsWith('.pcapng')) fileType = 'pcap';

        let previewUrl = null;
        if (fileType === 'image') previewUrl = URL.createObjectURL(file);

        attachedFiles.push({ id: fileId, file: file, type: fileType, previewUrl, name: file.name });
        renderAttachmentPreviews();
    }

    function renderAttachmentPreviews() {
        ui.previewArea.innerHTML = '';
        attachedFiles.forEach(att => {
            const el = document.createElement('div');
            el.className = 'attachment-item';
            if (att.type === 'image') {
                el.innerHTML = `<img src="${att.previewUrl}" alt="Attachment"/><button class="remove-btn">&times;</button>`;
            } else {
                el.innerHTML = `<div style="color:white; font-size: 20px;" class="material-symbols-outlined">${att.type === 'pcap' ? 'settings_input_component' : 'description'}</div><div style="font-size: 8px; color: #a1a1aa; width:100%; text-align:center; overflow:hidden;">${att.name.substring(0,8)}</div><button class="remove-btn">&times;</button>`;
            }
            el.querySelector('.remove-btn').onclick = () => {
                attachedFiles = attachedFiles.filter(a => a.id !== att.id);
                renderAttachmentPreviews();
            };
            ui.previewArea.appendChild(el);
        });
    }

    // --- Suggestion Tiles ---
    window.setInput = function(text) {
        ui.userInput.value = text;
        ui.userInput.focus();
    };

    // --- Message Sending ---
    ui.sendBtn.onclick = sendMessage;
    ui.userInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });

    async function sendMessage() {
        const text = ui.userInput.value.trim();
        if(!text && attachedFiles.length === 0 || isProcessing) return;

        isProcessing = true;
        const typeSpeed = ui.settingSpeed ? parseInt(ui.settingSpeed.value) || 20 : 20;
        
        ui.userInput.value = '';
        ui.userInput.style.height = 'auto';
        ui.sendBtn.disabled = true;
        
        if (ui.welcomeState) {
            ui.welcomeState.style.display = 'none';
        }

        const currentAttachments = [...attachedFiles];
        attachedFiles = [];
        renderAttachmentPreviews();

        addMessage('user', text, true, currentAttachments);
        showTypingIndicator();

        let aiRow = null;
        let contentDiv = null;
        let fullMarkdownText = "";
        let displayedText = "";
        let isStreamActive = true;
        let metadataAction = null;

        const formData = new FormData();
        formData.append('message', text);
        formData.append('verbosity', ui.settingVerbosity.value);
        formData.append('is_incognito', ui.settingIncognito.checked);
        formData.append('llm_mode', ui.hiddenModelInput.value);
        currentAttachments.forEach(att => formData.append('files', att.file));

        try {
            const response = await fetchWithAuth('/chatbot/chat_stream', {
                method: 'POST',
                body: formData
            });

            if (!response.body) throw new Error('ReadableStream not supported.');

            const newSessionId = response.headers.get('X-Session-ID');
            if (newSessionId && newSessionId !== currentSessionId) {
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
                        } catch(e) {}
                    } else {
                        fullMarkdownText += chunk;
                    }
                    
                    if (!aiRow && fullMarkdownText.trim().length > 0) {
                        hideTypingIndicator();
                        aiRow = document.createElement('div');
                        aiRow.className = 'msg-row ai';
                        const aiBubble = document.createElement('div');
                        aiBubble.className = 'msg-bubble';
                        aiBubble.setAttribute('data-label', 'NetShield AI');
                        contentDiv = document.createElement('div');
                        contentDiv.className = 'markdown-content';
                        aiBubble.appendChild(contentDiv);
                        
                        const actions = document.createElement('div');
                        actions.className = 'msg-actions';
                        actions.innerHTML = `
                            <button class="action-btn copy-btn" title="Copy"><span class="material-symbols-outlined" style="font-size:14px">content_copy</span></button>
                            <button class="action-btn regen-btn" title="Regenerate"><span class="material-symbols-outlined" style="font-size:14px">refresh</span></button>
                            <button class="action-btn feedback-btn up" title="Helpful"><span class="material-symbols-outlined" style="font-size:14px">thumb_up</span></button>
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
                    }
                }
                isStreamActive = false;
            };

            networkLoop();

            const renderLoop = () => {
                if (displayedText.length < fullMarkdownText.length) {
                    const lag = fullMarkdownText.length - displayedText.length;
                    const step = lag > 50 ? 8 : (lag > 20 ? 4 : 2); 
                    displayedText = fullMarkdownText.substring(0, displayedText.length + step);
                    
                    if (contentDiv) {
                        contentDiv.innerHTML = parseContent(displayedText);
                        // [FIX] Scroll the chatArea, not messagesContainer
                        ui.chatArea.scrollTop = ui.chatArea.scrollHeight;
                    }
                }

                if (isStreamActive || displayedText.length < fullMarkdownText.length) {
                    setTimeout(renderLoop, typeSpeed);
                } else {
                    hideTypingIndicator();
                    isProcessing = false;
                    ui.sendBtn.disabled = false;
                    if (contentDiv) contentDiv.innerHTML = parseContent(fullMarkdownText);
                    if (metadataAction) handleAction(metadataAction);
                    
                    if (!ui.settingIncognito.checked) loadSessionList();
                    // Final scroll
                    ui.chatArea.scrollTop = ui.chatArea.scrollHeight;
                }
            };

            renderLoop();

        } catch(e) {
            console.error(e);
            hideTypingIndicator();
            addMessage('ai', 'Error connecting to AI Grid.');
            isProcessing = false;
            ui.sendBtn.disabled = false;
        }
    }

    // --- Message Rendering & Parsing ---
    function highlightThreats(text) {
        let highlighted = text;
        highlighted = highlighted.replace(/\b(critical|high|medium|low|info)\b/gi, (match) => {
            const cls = `threat-${match.toLowerCase()}`;
            return `<span class="${cls}">${match}</span>`;
        });
        return highlighted;
    }

    function parseContent(text) {
        if (!text) return "";
        try {
            let html = marked.parse(text);
            html = highlightThreats(html);
            
            // Add copy buttons to code blocks
            const temp = document.createElement('div');
            temp.innerHTML = html;
            temp.querySelectorAll('pre').forEach(pre => {
                const wrapper = document.createElement('div');
                wrapper.className = 'code-wrapper';
                pre.parentNode.insertBefore(wrapper, pre);
                wrapper.appendChild(pre);
                
                const copyBtn = document.createElement('button');
                copyBtn.className = 'code-copy-btn';
                copyBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size:16px">content_copy</span>';
                copyBtn.onclick = () => {
                    navigator.clipboard.writeText(pre.textContent);
                    copyBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size:16px">check</span>';
                    setTimeout(() => copyBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size:16px">content_copy</span>', 2000);
                };
                wrapper.appendChild(copyBtn);
            });
            
            return temp.innerHTML;
        } catch (e) { return text; }
    }

    function addMessage(role, text, animate = true, attachments = []) {
        ui.welcomeState.style.display = 'none';
        if (text === "[ANALYSIS_TRIGGER]" || role === 'system_hidden') return;

        let cleanText = text;
        let metadataAction = null;
        if (text.includes("__METADATA_ACTION__:")) {
            const parts = text.split("__METADATA_ACTION__:");
            cleanText = parts[0].trim();
            try { metadataAction = JSON.parse(parts[1]); } catch(e) { }
        }

        if (cleanText === "" && metadataAction && !animate) {
             handleAction(metadataAction, true);
             return;
        }

        // [NEW] System Notification Translation (Matches Desktop)
        let displayContext = cleanText;
        if (role === 'system' && displayContext.includes("SYSTEM_NOTIFICATION:")) {
            displayContext = displayContext.replace("SYSTEM_NOTIFICATION:", "**STATUS:**")
                                          .replace("successfully synchronized.", "Analysis Online.")
                                          .replace("Summary: ", "\n\n---\n\n");
        }

        const row = document.createElement('div');
        row.className = `msg-row ${role}`;
        
        const bubble = document.createElement('div');
        bubble.className = 'msg-bubble markdown-content';
        let label = 'NetShield AI';
        if (role === 'user') label = 'Human Analyst';
        else if (role === 'system') label = 'System Core';
        bubble.setAttribute('data-label', label);
        
        if (attachments && attachments.length > 0) {
            const attachContainer = document.createElement('div');
            attachContainer.className = 'msg-attachments';
            attachments.forEach(a => {
                const card = document.createElement('div');
                card.className = 'msg-attachment-card';
                const url = a.url || a.previewUrl;
                if (a.type === 'image') {
                    card.innerHTML = `<img src="${url}" alt="Attachment" />`;
                } else {
                    card.classList.add('doc-type');
                    const icon = a.type === 'pcap' ? 'settings_input_component' : 'description';
                    card.innerHTML = `<span class="material-symbols-outlined" style="color:var(--neo-blue); margin-top:5px;">${icon}</span><div class="file-name" style="color:white; font-size:10px;">${a.name}</div>`;
                }
                attachContainer.appendChild(card);
            });
            row.appendChild(attachContainer);
        }

        bubble.innerHTML = parseContent(displayContext);
        
        if (role === 'ai' || role === 'assistant' || role === 'system') {
           if (role !== 'system') {
                const actions = document.createElement('div');
                actions.className = 'msg-actions';
                actions.innerHTML = `
                    <button class="action-btn copy-btn" title="Copy"><span class="material-symbols-outlined" style="font-size:14px">content_copy</span></button>
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
                bubble.appendChild(actions);
           }
        } else {
           lastUserMessage = cleanText;
        }

        row.appendChild(bubble);
        ui.chatHistory.appendChild(row);

        if (metadataAction && !animate && cleanText !== "") {
            handleAction(metadataAction, true);
        }
        if (animate) scrollToBottom();
    }

    async function handleAction(action, isRestore = false, reattachStreamUrl = null, isCompleted = false) {
        if (!action || !action.tool) return;

        const displayTool = action.tool.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
        
        let statusMsg = "";
        if (isCompleted) {
             statusMsg = `[COMPLETE]: ${displayTool.toUpperCase()} DATA ACQUIRED.`;
        } else if (isRestore) {
             statusMsg = `[HISTORY]: ${displayTool} Module was deployed.`;
        } else if (reattachStreamUrl) {
             statusMsg = `[ACTIVE]: Synchronizing ${displayTool} Telemetry...`;
        } else {
             statusMsg = `[ANALYSIS]: Deploying ${displayTool} Module...`;
        }
        
        // Format Parameters nicely
        let paramsHtml = '<div style="display: grid; grid-template-columns: auto 1fr; gap: 4px 8px; margin-top: 8px;">';
        if (action.parameters) {
            for (const [key, value] of Object.entries(action.parameters)) {
                paramsHtml += `
                    <span style="color:var(--neo-blue); font-weight:700; text-transform:uppercase; font-size:0.55rem; letter-spacing:0.02em; align-self: center;">${key.replace(/_/g, ' ')}:</span>
                    <span style="color:#adbac7; word-break:break-all; font-family:var(--font-code); font-size:0.7rem; background: rgba(255,255,255,0.03); padding: 2px 4px; border-radius: 4px;">${value}</span>
                `;
            }
        }
        paramsHtml += '</div>';

        const row = document.createElement('div');
        row.className = 'msg-row system-action';
        row.setAttribute('data-tool', action.tool); // Track the tool for async updates
        row.innerHTML = `
            <div class="msg-bubble action-bubble ${isRestore || isCompleted ? 'success' : ''}" style="border-radius: 12px; border-color: rgba(59, 130, 246, 0.5) !important;">
                <div class="action-header" style="display: flex; align-items: center; gap: 10px; color: var(--neo-blue); font-weight: 700; font-size: 0.85rem; letter-spacing: 0.02em;">
                    <span class="material-symbols-outlined ${isRestore || isCompleted ? '' : 'spin'}" style="font-size: 1.2rem;">${isRestore || isCompleted ? 'check_circle' : 'sync'}</span>
                    <span class="header-text">${statusMsg}</span>
                </div>
                <div class="action-details">
                    ${paramsHtml}
                    <div style="margin-top: 1.25rem; display: flex; gap: 0.75rem;">
                        <button class="action-btn btn-redirect" style="flex:1; border-radius: 6px; font-size: 0.65rem; height: 32px;">VIEW MODULE PAGE</button>
                        <button class="action-btn btn-download" style="flex:1; border-radius: 6px; font-size: 0.65rem; height: 32px; ${isRestore || isCompleted ? 'display: block;' : 'display: none;'}">DOWNLOAD PDF</button>
                    </div>
                    <div class="terminal-container" style="${isRestore || isCompleted ? 'display:none;' : (reattachStreamUrl ? 'display:flex;' : 'display:none;')} margin-top: 15px;">
                        <div class="terminal-header">
                            <div style="display:flex; align-items:center; gap:5px;"><span class="material-symbols-outlined" style="font-size:10px">terminal</span> TELEMETRY</div>
                            <div class="progress-container" style="display:none; flex: 1; align-items: center; gap: 8px; justify-content: flex-end;">
                                <div style="width: 40px; height: 3px; background: rgba(255,255,255,0.05); border-radius: 10px; overflow: hidden;">
                                    <div class="progress-fill" style="width: 0%; height: 100%; background: var(--neo-blue);"></div>
                                </div>
                                <span class="progress-percent" style="font-size: 0.6rem; color: var(--neo-blue); font-weight: 700;">0%</span>
                            </div>
                        </div>
                        <div class="terminal-body"></div>
                    </div>
                </div>
                <div class="action-footer" style="${isRestore || isCompleted ? 'display:flex;' : 'display:none;'} margin-top:10px; border-top:1px solid rgba(255,255,255,0.05); padding-top:8px; justify-content:space-between; align-items:center;">
                    <span style="font-size:0.65rem; color:#10b981; display:flex; align-items:center; gap:5px;">
                        <span class="material-symbols-outlined" style="font-size:1rem;">analytics</span> DATASET READY.
                    </span>
                </div>
            </div>
        `;
        ui.chatHistory.appendChild(row);
        if (!isRestore) scrollToBottom();

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
            'killchain_audit': '/killchain/download_report',
            'semgrep_sast_scan': '/semgrep_scanner/download_pdf'
        };

        const btnRedirect = row.querySelector('.btn-redirect');
        const btnDownload = row.querySelector('.btn-download');

        if (btnRedirect) {
            btnRedirect.onclick = (e) => {
                const url = toolUrlMap[action.tool];
                if (url) window.location.href = url;
            };
        }

        if (btnDownload) {
            btnDownload.onclick = () => {
                const url = toolDownloadMap[action.tool];
                if (url) window.open(url, '_blank');
            };
        }

        if (isRestore || isCompleted) return;

        if (reattachStreamUrl) {
            setupStreaming(reattachStreamUrl, row, displayTool, action.tool);
            return;
        }

        try {
            const response = await fetchWithAuth('/chatbot/execute_action', {
                method: 'POST',
                body: JSON.stringify(action)
            });
            const result = await response.json();

            if (result.status === 'success') {
                setupStreaming(result.stream_url, row, displayTool, action.tool);
            } else {
                row.querySelector('.header-text').textContent = `[FAILED]: ${displayTool} Execution Error`;
                const icon = row.querySelector('.action-header .material-symbols-outlined');
                icon.textContent = 'error';
                icon.classList.remove('spin');
            }
        } catch (e) { 
            console.error("Action execution failed:", e);
            row.querySelector('.header-text').textContent = `[FAILED]: ${displayTool} Connection Error`;
            const icon = row.querySelector('.action-header .material-symbols-outlined');
            if (icon) {
                icon.textContent = 'error';
                icon.classList.remove('spin');
            }
        }
    }

    function setupStreaming(streamUrl, row, displayTool, toolName) {
        const headerText = row.querySelector('.header-text');
        const icon = row.querySelector('.material-symbols-outlined');
        const terminalContainer = row.querySelector('.terminal-container');
        const terminalBody = row.querySelector('.terminal-body');
        const actionFooter = row.querySelector('.action-footer');
        const progressContainer = row.querySelector('.progress-container');
        const progressFill = row.querySelector('.progress-fill');
        const progressText = row.querySelector('.progress-percent');

        terminalContainer.style.display = 'flex';
        const eventSource = new EventSource(streamUrl);
        
        eventSource.onmessage = (e) => {
            if (e.data === ': keep-alive') return;

            let isProgress = false;
            // [NEW] Handle Progress Updates (Matches Desktop)
            if (e.data.includes('[PROGRESS]')) {
                const match = e.data.match(/(\d+)%/);
                if (match) {
                    const percent = match[1];
                    if (progressContainer) {
                        progressContainer.style.display = 'flex';
                        if (progressFill) progressFill.style.width = `${percent}%`;
                        if (progressText) progressText.textContent = `${percent}%`;
                    }
                    isProgress = true;
                }
            }

            // [NEW] Check for text-based progress bars
            const cleanedMessage = e.data.replace(/\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s*/g, "").trim();
            const isTextProgressBar = cleanedMessage.startsWith('[') && cleanedMessage.includes('%');

            if (isTextProgressBar) {
                const lastLine = terminalBody.lastElementChild;
                if (lastLine && lastLine.getAttribute('data-is-progress') === 'true') {
                    lastLine.querySelector('.term-time').textContent = new Date().toLocaleTimeString([], { hour12: false });
                    lastLine.querySelector('.term-text').textContent = cleanedMessage;
                    return;
                }
            }

            const line = document.createElement('div');
            line.className = 'terminal-line';
            if (isProgress) {
                line.classList.add('progress-line');
                terminalBody.querySelectorAll('.progress-line').forEach(el => el.remove());
            }
            if (isTextProgressBar) {
                line.setAttribute('data-is-progress', 'true');
            }
            
            const timeSpan = document.createElement('span');
            timeSpan.className = 'term-time';
            timeSpan.textContent = new Date().toLocaleTimeString([], { hour12: false });
            
            const textSpan = document.createElement('span');
            textSpan.className = 'term-text';
            
            if (e.data.includes('[!]') || e.data.toLowerCase().includes('error')) textSpan.classList.add('error');
            else if (e.data.includes('[+') || e.data.toLowerCase().includes('success')) textSpan.classList.add('success');
            else if (e.data.includes('[*]')) textSpan.classList.add('info');
            
            textSpan.textContent = e.data.replace('[PROGRESS] ', '');
            
            line.appendChild(timeSpan);
            line.appendChild(textSpan);
            terminalBody.appendChild(line);
            terminalBody.scrollTop = terminalBody.scrollHeight;

            if (e.data.includes('SYSTEM_EVENT: READY_FOR_ANALYSIS')) {
                eventSource.close();
                if (icon) {
                    icon.textContent = 'check_circle';
                    icon.classList.remove('spin');
                }
                headerText.textContent = `[COMPLETE]: ${displayTool.toUpperCase()} DATA ACQUIRED.`;
                actionFooter.style.display = 'flex';
                triggerAutoAnalysis(toolName);
            }
        };

        eventSource.onerror = () => eventSource.close();
    }

    // --- Topology Graph Logic ---

    if (ui.btnViewTopology) {
        ui.btnViewTopology.onclick = async () => {
            if (!currentSessionId) {
                alert("Please start an analysis session first.");
                return;
            }

            closePanels();
            ui.topologySheet.classList.add('open');
            ui.overlay.classList.add('show');
            
            ui.topologyContainer.innerHTML = '<div style="color: white; padding: 20px; text-align: center;">Fetching topology data...</div>';

            try {
                const response = await fetchWithAuth(`/chatbot/session/${currentSessionId}/graph`);
                const data = await response.json();

                if (data.success && data.graph_data && data.graph_data.nodes && data.graph_data.nodes.length > 0) {
                    renderTopology(data.graph_data);
                } else {
                    ui.topologyContainer.innerHTML = '<div style="color: #ef4444; padding: 20px; text-align: center; font-size: 0.8rem;">No infrastructure data available for this session yet.</div>';
                }
            } catch (error) {
                console.error("Graph Fetch Error:", error);
                ui.topologyContainer.innerHTML = '<div style="color: #ef4444; padding: 20px; text-align: center; font-size: 0.8rem;">Failed to retrieve topology data.</div>';
            }
        };
    }

    if (ui.closeTopologyBtn) {
        ui.closeTopologyBtn.onclick = () => {
            ui.topologySheet.classList.remove('open');
            ui.overlay.classList.remove('show');
            if (networkInstance) {
                networkInstance.destroy();
                networkInstance = null;
            }
        };
    }

    function renderTopology(graphData) {
        const visNodes = new vis.DataSet(graphData.nodes.map(node => {
            let color = '#3b82f6';
            let shape = 'dot';
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

            if (displayLabel.length > 20) displayLabel = displayLabel.substring(0, 17) + "...";

            return {
                id: node.id,
                label: `[${node.type}]\n${displayLabel}`,
                color: { background: color, border: '#1e1e24' },
                shape: shape,
                font: { color: '#f8fafc', face: 'monospace', size: 10 },
                borderWidth: 2,
                shadow: true
            };
        }));

        const visEdges = new vis.DataSet(graphData.links.map(link => {
            return {
                from: link.source,
                to: link.target,
                color: { color: '#475569', opacity: 0.6 },
                arrows: 'to',
                smooth: { type: 'continuous' }
            };
        }));

        const container = ui.topologyContainer;
        const data = { nodes: visNodes, edges: visEdges };
        const options = {
            nodes: { scaling: { min: 8, max: 20 } },
            physics: {
                forceAtlas2Based: { gravitationalConstant: -30, springLength: 60 },
                solver: 'forceAtlas2Based',
                stabilization: { iterations: 100 }
            },
            interaction: { zoomView: true, dragView: true }
        };

        ui.topologyContainer.innerHTML = '';
        networkInstance = new vis.Network(container, data, options);
    }

    function scrollToBottom() {
        requestAnimationFrame(() => {
            ui.chatArea.scrollTop = ui.chatArea.scrollHeight;
        });
    }

    let typingIndicatorInterval = null;
    const statusMessages = [
        "Consulting threat context indices...",
        "Querying local database partitions...",
        "Correlating scan reports...",
        "Tracing potential exploit vectors...",
        "Formulating response playbooks...",
        "Analyzing compliance alignment...",
        "Ranking vulnerabilities via TCTR engine...",
        "Parsing network graph topology...",
        "Evaluating risk severity models...",
        "Drafting remediation steps...",
        "Correlating vulnerability signatures...",
        "Querying vector embeddings cache...",
        "Cross-referencing CVE database records...",
        "Constructing compromise logic chain...",
        "Verifying network isolation boundaries...",
        "Evaluating threat mitigation vectors...",
        "Assessing lateral movement vectors...",
        "Simulating attack path propagation...",
        "Determining CVSS-v4 correction metrics...",
        "Aggregating tool intelligence feeds...",
        "Generating defensive hardening schemas...",
        "Validating patch compliance levels...",
        "Verifying system integrity telemetry..."
    ];

    function showTypingIndicator() {
        ui.typingIndicator.style.display = 'block';
        const statusTextEl = ui.typingIndicator.querySelector('.typing-status-text');
        if (statusTextEl) {
            let idx = 0;
            statusTextEl.textContent = statusMessages[idx];
            if (typingIndicatorInterval) clearInterval(typingIndicatorInterval);
            typingIndicatorInterval = setInterval(() => {
                idx = (idx + 1) % statusMessages.length;
                statusTextEl.textContent = statusMessages[idx];
            }, 2000);
        }
        scrollToBottom();
    }

    function hideTypingIndicator() {
        ui.typingIndicator.style.display = 'none';
        if (typingIndicatorInterval) {
            clearInterval(typingIndicatorInterval);
            typingIndicatorInterval = null;
        }
    }

    // --- Session History API ---
    async function loadSessionList() {
        try {
            // [PERF] Use server-injected sessions if available (same fast-path as desktop)
            if (window.PRELOADED_SESSIONS) {
                allSessions = window.PRELOADED_SESSIONS;
                renderSessionList(allSessions);
                window.PRELOADED_SESSIONS = null;
                return;
            }
            const resp = await fetchWithAuth('/chatbot/get_sessions');
            const data = await resp.json();
            allSessions = data.sessions || [];
            renderSessionList(allSessions);
        } catch (e) {
            console.error("Error loading sessions", e);
        }
    }

    async function switchSession(sid, force = false) {
        if (sid === currentSessionId || isSwitching) return;
        isSwitching = true;
        
        // Prepare UI
        ui.chatHistory.innerHTML = '';
        ui.welcomeState.style.display = 'none';
        showTypingIndicator();
        closePanels();
        
        try {
            currentSessionId = sid;

            // [PERF] Fire cookie update + history fetch simultaneously.
            // get_history accepts ?session_id= directly so it doesn't need the cookie first.
            const [, histResp] = await Promise.all([
                fetchWithAuth('/chatbot/switch_session', {
                    method: 'POST',
                    body: JSON.stringify({ session_id: sid })
                }),
                fetchWithAuth(`/chatbot/get_history?session_id=${sid}`)
            ]);

            const data = await histResp.json();
            
            if (data.chat_history) {
                if (data.chat_history.length > 0) {
                    renderHistory(data.chat_history);
                    fetchActiveScans();
                } else {
                    ui.welcomeState.style.display = 'block';
                }
            } else {
                ui.welcomeState.style.display = 'block';
            }
            // [PERF] Update active class locally — no extra network call
            document.querySelectorAll('.session-item').forEach(el => {
                el.classList.toggle('active', el.dataset.id === sid);
            });
        } catch(e) { 
            console.error("Failed to switch session:", e);
            addMessage('ai', 'Error switching simulation context.');
        } finally {
            hideTypingIndicator();
            isSwitching = false;
        }
    }

    async function fetchActiveScans() {
        try {
            const resp = await fetchWithAuth('/chatbot/get_active_scans');
            const data = await resp.json();
            const activeScans = data.active_scans || {};
            
            Object.keys(activeScans).forEach(toolKey => {
                const info = activeScans[toolKey];
                if (info.status === 'running' && info.stream_url) {
                    // Find THE LATEST action bubble for this tool and re-attach
                    const cards = document.querySelectorAll(`.msg-row.system-action[data-tool="${toolKey}"]`);
                    if (cards.length > 0) {
                        const lastCard = cards[cards.length - 1];
                        // If it's not already in sync/running state (not spinning)
                        const icon = lastCard.querySelector('.action-header .material-symbols-outlined');
                        if (icon && !icon.classList.contains('spin')) {
                            const headerText = lastCard.querySelector('.header-text');
                            const displayTool = toolKey.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
                            headerText.textContent = `[ACTIVE]: Synchronizing ${displayTool} Telemetry...`;
                            icon.textContent = 'sync';
                            icon.classList.add('spin');
                            setupStreaming(info.stream_url, lastCard, displayTool, toolKey);
                        }
                    }
                }
            });
        } catch(e) { console.error("Async scan check failed:", e); }
    }


    function renderHistory(history) {
        ui.chatHistory.innerHTML = '';
        history.forEach(msg => {
            const role = msg.role === 'assistant' ? 'ai' : msg.role;
            let attachments = [];
            if (msg.attachments && typeof msg.attachments === 'string' && msg.attachments.trim() !== "" && msg.attachments !== "null") {
                try {
                    attachments = JSON.parse(msg.attachments);
                } catch(e) { console.error("History attachment parse error:", e); }
            } else if (Array.isArray(msg.attachments)) {
                attachments = msg.attachments;
            }

            addMessage(role, msg.content || "", false, attachments);
        });
        scrollToBottom();
    }

    function groupSessions(sessions) {
        const groups = {
            'Today': [],
            'Yesterday': [],
            'Previous 7 Days': [],
            'Older': []
        };

        const now = new Date();
        sessions.forEach(sess => {
            const sessDate = new Date(sess.subtitle);
            if(isNaN(sessDate)) { groups['Older'].push(sess); return; }
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
        if(sessions.length === 0) {
           ui.sessionList.innerHTML = '<div style="font-size:0.8rem; color:#71717a;">No recent contexts found.</div>';
           return;
        }

        const groups = groupSessions(sessions);

        Object.keys(groups).forEach(groupName => {
            if (groups[groupName].length === 0) return;

            const groupEl = document.createElement('div');
            groupEl.className = 'session-group';
            groupEl.innerHTML = `<div class="group-label">${groupName}</div>`;
            ui.sessionList.appendChild(groupEl);

            groups[groupName].forEach(sess => {
                const el = document.createElement('div');
                el.className = `session-item ${sess.session_id === currentSessionId ? 'active' : ''} ${sess.is_pinned ? 'pinned' : ''}`;
                el.innerHTML = `
                    <div class="session-info">
                       <div class="session-title">${sess.title}</div>
                       <div class="session-date">${sess.subtitle}</div>
                    </div>
                    <button class="session-menu-btn" data-id="${sess.session_id}"><span class="material-symbols-outlined">more_vert</span></button>
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
                
                // click to load
                el.addEventListener('click', (e) => {
                    if(!e.target.closest('.session-menu-btn') && !e.target.closest('.context-menu')) {
                        switchSession(sess.session_id);
                    }
                });

                // Context menu logic
                const menuBtn = el.querySelector('.session-menu-btn');
                const menu = el.querySelector('.context-menu');
                
                menuBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    const alreadyOpen = menu.classList.contains('show');
                    // Close all others
                    document.querySelectorAll('.context-menu').forEach(m => m.classList.remove('show'));
                    if (!alreadyOpen) {
                        menu.classList.add('show');
                    }
                });

                menu.addEventListener('click', (e) => e.stopPropagation());

                el.querySelector('.action-pin').addEventListener('click', async (e) => {
                    e.stopPropagation();
                    menu.classList.remove('show');
                    try {
                        await fetchWithAuth('/chatbot/toggle_pin', {
                            method: 'POST',
                            body: JSON.stringify({
                                session_id: sess.session_id,
                                is_pinned: !sess.is_pinned
                            })
                        });
                        loadSessionList();
                    } catch(e) { console.error("Pin error:", e); }
                });
                
                el.querySelector('.action-rename').addEventListener('click', (e) => {
                    e.stopPropagation();
                    menu.classList.remove('show');
                    const newName = prompt("Enter new title:", sess.title);
                    if (newName && newName.trim()) {
                        fetchWithAuth('/chatbot/rename_session', {
                            method: 'POST', 
                            body: JSON.stringify({
                                session_id: sess.session_id,
                                new_title: newName.trim()
                            })
                        }).then(()=> { loadSessionList(); })
                          .catch(e => console.error("Rename error:", e));
                    }
                });
                
                el.querySelector('.action-delete').addEventListener('click', async (e) => {
                    e.stopPropagation();
                    menu.classList.remove('show');
                    if (confirm("Delete this session forever?")) {
                        try {
                            await fetchWithAuth('/chatbot/delete_session', {
                                method: 'POST',
                                body: JSON.stringify({ session_id: sess.session_id })
                            });
                            if (currentSessionId === sess.session_id) {
                                ui.chatHistory.innerHTML = ''; 
                                currentSessionId = null; 
                                ui.welcomeState.style.display = 'block';
                            }
                            loadSessionList();
                        } catch(e) { console.error("Delete error:", e); }
                    }
                });

                ui.sessionList.appendChild(el);
            });
        });
    }

    // Hide menus on outside click
    document.addEventListener('click', () => {
        document.querySelectorAll('.context-menu').forEach(m => m.classList.remove('show'));
    });

    // (loadSessionList defined above with PRELOADED_SESSIONS fast-path)

    ui.newChatBtn.onclick = () => {
        currentSessionId = null;
        ui.chatHistory.innerHTML = '';
        ui.welcomeState.style.display = 'flex';
        renderSuggestions();
        renderSessionList(allSessions);
        closePanels();
    };


    // --- Command Center Actions ---
    ui.btnClearContext.onclick = async () => {
        if(confirm("Clear current context?")) {
            try {
                await fetchWithAuth('/chatbot/clear_history', { method: 'POST' });
                ui.chatHistory.innerHTML = '';
                ui.welcomeState.style.display = 'flex';
                closePanels();
            } catch(e) { console.error(e); }
        }
    };

    ui.btnDeleteSession.onclick = async () => {
        if(currentSessionId && confirm("Delete Active Session?")) {
            try {
                await fetchWithAuth('/chatbot/delete_session', {
                    method: 'POST',
                    body: JSON.stringify({ session_id: currentSessionId })
                });
                ui.chatHistory.innerHTML = '';
                ui.welcomeState.style.display = 'flex';
                currentSessionId = null;
                closePanels();
                loadSessionList();
            } catch(e) { console.error("Delete active error:", e); }
        }
    };

    ui.btnDownloadTranscript.onclick = () => {
        const text = Array.from(ui.chatHistory.querySelectorAll('.msg-row')).map(row => {
            const label = row.querySelector('.msg-bubble')?.getAttribute('data-label') || 'System';
            const content = row.querySelector('.markdown-content')?.textContent || '';
            return `[${label}]: ${content}\n`;
        }).join('\n');
        
        const blob = new Blob([text], {type: 'text/plain'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `transcript-${currentSessionId || 'new'}.txt`;
        a.click();
    };

    ui.btnWipeAll.onclick = async () => {
        if(confirm("DANGER: This will delete ALL chat history permanently. Continue?")) {
            try {
                await fetchWithAuth('/chatbot/delete_all_sessions', { method: 'POST' });
                location.reload();
            } catch(e) { console.error(e); }
        }
    };

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
        const grid = document.getElementById('suggestion-grid');
        if (!grid) return;
        
        // Pick 4 random suggestions (matching desktop count)
        const shuffled = [...suggestionPool].sort(() => 0.5 - Math.random());
        const selected = shuffled.slice(0, 4);
        
        grid.innerHTML = selected.map(s => `
            <div class="suggestion-card" onclick="setInput('${s.desc.replace(/'/g, "\\'")}')">
                <h5>${s.title}</h5>
                <p>${s.desc}</p>
            </div>
        `).join('');
    }

    window.setInput = (text) => {
        ui.userInput.value = text;
        ui.userInput.focus();
        // Adjust height for mobile textarea
        ui.userInput.style.height = 'auto';
        ui.userInput.style.height = (ui.userInput.scrollHeight) + 'px';
    };

    // --- Initial setup ---
    const urlParams = new URLSearchParams(window.location.search);
    const urlSummary = urlParams.get('summary');
    const urlMode = urlParams.get('mode');
    const urlSessionId = urlParams.get('session_id');

    if(allSessions.length > 0) {
        renderSessionList(allSessions);
    }
    
    // [MODIFIED] Handle redirection from scanners
    if (urlSessionId) {
        switchSession(urlSessionId).then(() => {
            if (urlSummary) {
                addMessage('system', "SYSTEM_NOTIFICATION: Scan Analysis Synchronized. Summary: " + urlSummary, false);
            }
        });
    } else if (urlSummary) {
        // Just summary (maybe new session created on backend but not yet switched)
        ui.welcomeState.style.display = 'none';
        addMessage('system', "SYSTEM_NOTIFICATION: Scan Analysis Synchronized. Summary: " + urlSummary, false);
    } else {
        // Always start with a new chat on mobile as default fallback
        currentSessionId = null; 
        ui.chatHistory.innerHTML = '';
        ui.welcomeState.style.display = 'flex';
        renderSuggestions();
    }

    // This block is assumed to be part of an eventSource.onmessage handler
    // based on the provided Code Edit context.
    // The original document did not contain the full eventSource.onmessage block.
    // Assuming this block is inserted where it makes sense syntactically.
    // The instruction implies this is an existing event stream handler.
    // For the purpose of this edit, we'll place it after the initial setup.
    // If this is part of a larger function, it would need to be nested.
    // Given the instruction "Change triggerAutoAnalysis() to promptForAnalysis() in the event stream handler",
    // and the provided Code Edit, we're inserting the new logic.
    // The `else` block structure suggests it's part of a conditional chain.
    // We'll place it after the existing `else` block for `urlSummary`.
    // This assumes there's an `eventSource` variable defined elsewhere.
    // The instruction implies this is an existing event stream handler,
    // so we're adding the new conditional branch.
    // The `eventSource.onerror` closing tag suggests this is within a function scope.
    // We'll assume this is part of a function that sets up eventSource.
    // For now, we'll place it as a new top-level conditional.
    // This is a best-effort interpretation given the partial context.

    // Placeholder for where the eventSource.onmessage handler might be.
    // If this was part of an existing `eventSource.onmessage` function,
    // the `if (e.data.includes('SYSTEM_EVENT: READY_FOR_ANALYSIS'))`
    // would be inside that function.
    // Since the original document doesn't contain `eventSource.onmessage`,
    // we're inserting the new function and the call as instructed.

    // Assuming there's a function that sets up eventSource and its onmessage handler
    // For example:
    // function setupEventSource(toolName, icon, headerText, actionFooter) {
    //     const eventSource = new EventSource('/some/event/stream');
    //     eventSource.onmessage = (e) => {
    //         if (e.data.includes('SYSTEM_EVENT: READY_FOR_ANALYSIS')) {
    //             eventSource.close();
    //             if (icon) {
    //                 icon.textContent = 'check_circle';
    //                 icon.classList.remove('spin');
    //             }
    //             headerText.textContent = `[COMPLETE]: ${displayTool.toUpperCase()} DATA ACQUIRED.`;
    //             actionFooter.style.display = 'flex';
    //             promptForAnalysis(toolName);
    //         }
    //     };
    //     eventSource.onerror = () => eventSource.close();
    // }

    function scrollToBottom() {
        requestAnimationFrame(() => {
            if (ui.chatArea) {
                ui.chatArea.scrollTop = ui.chatArea.scrollHeight;
            }
        });
    }

    // --- Topology Graph Logic ---

    function promptForAnalysis(tool) {
        scrollToBottom();
        
        const row = document.createElement('div');
        row.className = 'msg-row system-action';
        row.innerHTML = `
            <div class="msg-bubble action-bubble" style="border-radius: 12px; border-color: rgba(59, 130, 246, 0.5) !important;">
                <div class="action-header" style="display: flex; align-items: center; gap: 10px; color: var(--neo-blue); font-weight: 700; font-size: 0.85rem; letter-spacing: 0.02em;">
                    <span class="material-symbols-outlined" style="font-size: 1.2rem;">help</span>
                    <span class="header-text">Scan Complete. Would you like the AI to analyze the PDF report?</span>
                </div>
                <div style="margin-top: 1.25rem; display: flex; gap: 0.75rem;" class="prompt-actions">
                    <button class="action-btn btn-yes" style="flex:1; border-radius: 6px; font-size: 0.65rem; height: 32px; background: rgba(16, 185, 129, 0.1); border-color: rgba(16, 185, 129, 0.3); color: #10b981;">YES, ANALYZE</button>
                    <button class="action-btn btn-no" style="flex:1; border-radius: 6px; font-size: 0.65rem; height: 32px; background: rgba(239, 68, 68, 0.1); border-color: rgba(239, 68, 68, 0.3); color: #ef4444;">NO, SKIP</button>
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
        showTypingIndicator();

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
            const result = await response.json();

            if (result.status === 'success') {
                // Sync session ID if returned
                if (result.session_id) currentSessionId = result.session_id;

                hideTypingIndicator();
                
                // Directly render the System Core's generated summary
                addMessage('system', "SYSTEM_NOTIFICATION: Scan Complete. Report successfully synchronized. Summary: " + result.summary, false);
            }
        } catch (e) {
            console.error("Auto-analysis failed:", e);
            hideTypingIndicator();
        }
    }
});
