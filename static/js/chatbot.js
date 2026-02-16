document.addEventListener('DOMContentLoaded', () => {
    
    // --- 0. SECURITY: CSRF Token Setup ---
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

    // Helper to send authorized requests
    async function fetchWithAuth(url, options = {}) {
        const headers = {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken,
            'X-Session-ID': currentSessionId, // Send session ID if available
            ...options.headers
        };
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
        confirmRenameBtn: document.getElementById('confirm-rename')
    };

    // --- 3. State Variables ---
    let selectedFile = null;
    let isProcessing = false;
    let currentSessionId = null; 
    let sessionToRename = null;
    let isPinning = false;
    let allSessions = []; 
    let lastUserMessage = ""; 

    // --- 4. Command Center & Settings Logic ---

    ui.ccToggle.onclick = () => ui.commandCenter.classList.add('open');
    ui.ccClose.onclick = () => ui.commandCenter.classList.remove('open');

    // Clear Context (Keep session, wipe UI and backend history)
    ui.btnClearContext.onclick = async () => {
        if (confirm("Clear current analysis history? The AI context will be reset.")) {
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
        if (currentSessionId && confirm("Permanently delete this session?")) {
            await deleteSession(currentSessionId);
            ui.commandCenter.classList.remove('open');
        }
    };

    // Nuclear Wipe
    ui.btnWipeAll.onclick = async () => {
        if (confirm("DANGER: This will delete ALL past analysis sessions. This cannot be undone. Proceed?")) {
            try {
                await fetchWithAuth('/chatbot/delete_all_sessions', { method: 'POST' });
                clearView();
                loadSessionList();
                ui.commandCenter.classList.remove('open');
            } catch (e) { console.error(e); }
        }
    };

    // Export Transcript
    ui.btnDownloadTranscript.onclick = () => {
        const rows = document.querySelectorAll('.msg-row');
        let transcript = `NetShield AI Analysis Transcript\nDate: ${new Date().toLocaleString()}\n\n`;
        
        rows.forEach(row => {
            const role = row.classList.contains('user') ? 'HUMAN' : 'AI';
            const bubble = row.querySelector('.msg-bubble');
            const text = bubble.innerText.replace(/content_copyrefreshthumb_upthumb_down/g, ''); // Clean actions
            transcript += `[${role}]: ${text}\n\n`;
        });

        const blob = new Blob([transcript], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `NetShield_Transcript_${new Date().getTime()}.txt`;
        a.click();
        URL.revokeObjectURL(url);
    };

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

            const result = await response.json();

            if (result.message || result.summary) {
                // Sync session ID if returned
                if (result.session_id) currentSessionId = result.session_id;

                ui.uploadStatus.textContent = "Success. Analysis incoming.";
                
                // Add AI summary message
                addMessage('ai', result.summary || result.message);
                
                // Reset view
                selectedFile = null;
                if (ui.fileInput) ui.fileInput.value = '';
                switchView('upload');
                updateContextStatus(true, "Report Loaded");
                loadSessionList();
            } else {
                throw new Error(result.error || "Upload failed");
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
        const patterns = {
            'CRITICAL': /critical/gi,
            'HIGH': /high/gi,
            'MEDIUM': /medium/gi,
            'LOW': /low/gi,
            'INFO': /info/gi
        };
        
        let highlighted = text;
        // Simple word replacement for common security terms
        highlighted = highlighted.replace(/\b(critical|high|medium|low|info)\b/gi, (match) => {
            const cls = `threat-${match.toLowerCase()}`;
            return `<span class="${cls}">${match}</span>`;
        });
        return highlighted;
    }

    // Custom Markdown parsing with threat highlighting
    function parseContent(text) {
        if (!text) return "";
        try {
            let html = marked.parse(text);
            return highlightThreats(html);
        } catch (e) {
            console.error("Markdown parsing error:", e);
            return text; // Fallback to raw text
        }
    }

    function addMessage(role, text, animate = true) {
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
             handleAction(metadataAction, true);
             return;
        }

        const row = document.createElement('div');
        row.className = `msg-row ${role}`;
        
        const bubble = document.createElement('div');
        bubble.className = 'msg-bubble';
        
        // Define labels based on role
        let label = 'NetShield AI';
        if (role === 'user') label = 'Human Analyst';
        else if (role === 'system') label = 'System Core';

        bubble.setAttribute('data-label', label);
        
        // Create content container
        const contentDiv = document.createElement('div');
        contentDiv.className = 'markdown-content';
        
        let displayContext = cleanText;
        if (role === 'system' && displayContext.includes("SYSTEM_NOTIFICATION:")) {
            displayContext = displayContext.replace("SYSTEM_NOTIFICATION:", "**STATUS:**")
                                          .replace("successfully synchronized.", "Analysis Online.")
                                          .replace("Summary: ", "\n\n---\n\n");
        }

        contentDiv.innerHTML = parseContent(displayContext);
        bubble.appendChild(contentDiv);

        if (role === 'ai' || role === 'assistant' || role === 'system') {
            if (role !== 'system') {
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
            }
        } else {
            lastUserMessage = cleanText;
        }
        
        row.appendChild(bubble);
        ui.chatHistory.appendChild(row);
        
        // If it's a restore (not animated) and has metadata, trigger the action card
        if (metadataAction && !animate) {
            handleAction(metadataAction, true);
        }

        if (animate) scrollToBottom();
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

        // Cmd/Ctrl + Enter to send
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'enter' && document.activeElement === ui.userInput) {
            sendMessage();
        }
    });

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
                
                // Store active scans dictionary for lookup
                const activeScans = data.active_scans || {};

                data.chat_history.forEach(msg => {
                    const role = msg.role === 'assistant' ? 'ai' : msg.role;
                    
                    let cleanText = msg.content;
                    let metadataAction = null;
                    if (msg.content.includes("__METADATA_ACTION__:")) {
                        const parts = msg.content.split("__METADATA_ACTION__:");
                        cleanText = parts[0].trim();
                        try {
                            metadataAction = JSON.parse(parts[1]);
                        } catch(e) {}
                    }

                    if (metadataAction) {
                        // Check if this specific tool is currently active for this user
                        const activeInfo = activeScans[metadataAction.tool];
                        if (activeInfo) {
                            if (cleanText) addMessage(role, cleanText, false);
                            // Re-attach to the live telemetry stream
                            handleAction(metadataAction, false, activeInfo.stream_url); 
                        } else {
                            // If finished, do a normal static restore
                            addMessage(role, msg.content, false);
                        }
                    } else {
                        addMessage(role, msg.content, false); 
                    }
                });
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
    async function handleAction(action, isRestore = false, reattachStreamUrl = null) {
        if (!action || !action.tool) return;

        const displayTool = action.tool.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
        const statusMsg = isRestore ? `[HISTORY]: ${displayTool} Module was deployed.` : 
                         (reattachStreamUrl ? `[ACTIVE]: Synchronizing ${displayTool} Telemetry...` : `[ANALYSIS]: Deploying ${displayTool} Module...`);
        
        // Format Parameters nicely
        let paramsHtml = '<div style="display: grid; grid-template-columns: auto 1fr; gap: 8px 16px; margin-top: 10px;">';
        if (action.parameters) {
            for (const [key, value] of Object.entries(action.parameters)) {
                paramsHtml += `
                    <span style="color:var(--neo-blue); font-weight:700; text-transform:uppercase; font-size:0.6rem; letter-spacing:0.05em; align-self: center;">${key.replace(/_/g, ' ')}:</span>
                    <span style="color:#adbac7; word-break:break-all; font-family:var(--font-code); font-size:0.75rem; background: rgba(255,255,255,0.03); padding: 2px 6px; border-radius: 4px;">${value}</span>
                `;
            }
        }
        paramsHtml += '</div>';

        // Add a system-style message to the chat
        const row = document.createElement('div');
        row.className = 'msg-row system-action';
        row.innerHTML = `
            <div class="msg-bubble action-bubble ${isRestore ? 'success' : ''}" style="border-color: rgba(59, 130, 246, 0.5) !important;">
                <div class="action-header" style="display: flex; align-items: center; gap: 10px; color: var(--neo-blue); font-weight: 700; font-size: 0.85rem; letter-spacing: 0.02em;">
                    <span class="material-symbols-outlined ${isRestore ? '' : 'spin'}" style="font-size: 1.2rem;">${isRestore ? 'check_circle' : 'sync'}</span>
                    <span class="header-text">${isRestore ? `[COMPLETE]: ${displayTool.toUpperCase()} DATA ACQUIRED.` : statusMsg}</span>
                </div>
                <div class="action-details">
                    ${paramsHtml}
                    <div style="margin-top: 1.25rem; display: flex; gap: 0.75rem;">
                        <button class="action-btn btn-redirect" style="flex:1; border-radius: 6px; font-size: 0.65rem; height: 32px;">VIEW MODULE PAGE</button>
                        <button class="action-btn btn-download" style="flex:1; border-radius: 6px; font-size: 0.65rem; height: 32px; ${isRestore ? 'display: block;' : 'display: none;'}">DOWNLOAD PDF REPORT</button>
                    </div>
                </div>
                <div class="terminal-container" style="${isRestore ? 'display:none;' : (reattachStreamUrl ? 'display:flex;' : 'display:none;')} margin-top: 1.5rem; border: 1px solid rgba(255,255,255,0.05);">
                    <div class="terminal-header" style="background: rgba(255,255,255,0.05); height: 36px; display: flex; align-items: center; padding: 0 1rem; gap: 1.5rem;">
                        <div class="terminal-title" style="flex-shrink: 0;">
                            <span class="material-symbols-outlined" style="font-size: 0.9rem;">terminal</span>
                            TELEMETRY
                        </div>
                        
                        <div class="progress-container" style="display: none; flex: 1; align-items: center; gap: 1rem;">
                            <div style="flex: 1; height: 4px; background: rgba(255,255,255,0.05); border-radius: 10px; overflow: hidden; border: 1px solid rgba(255,255,255,0.05);">
                                <div class="progress-fill" style="width: 0%; height: 100%; background: linear-gradient(90deg, var(--neo-blue), var(--neo-cyan)); transition: width 0.4s ease;"></div>
                            </div>
                            <span class="progress-percent" style="font-size: 0.65rem; color: var(--neo-blue); font-weight: 700; font-family: var(--font-code); min-width: 30px; text-align: right;">0%</span>
                        </div>
                    </div>
                    <div class="terminal-body"></div>
                </div>
                <div class="action-footer" style="${isRestore ? 'display:flex;' : 'display:none;'} margin-top:1rem; justify-content:space-between; align-items:center; border-top:1px solid rgba(255,255,255,0.05); padding-top:0.75rem;">
                    <span class="status-badge" style="font-size:0.65rem; color:#10b981; font-family:var(--font-code); display: flex; align-items: center; gap: 6px;">
                        <span class="material-symbols-outlined" style="font-size: 1rem;">insights</span>
                        ${isRestore ? 'DATASET LOADED FROM CACHE.' : 'SYNCHRONIZING ANALYTICS...'}
                    </span>
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
            'semgrep_sast_scan': '/semgrep_scanner/'
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

        if (isRestore) return;

        // If we are re-attaching, we go straight to streaming
        if (reattachStreamUrl) {
            setupStreaming(reattachStreamUrl, row, displayTool, action.tool, btnDownload);
            return;
        }

        try {
            const response = await fetchWithAuth('/chatbot/execute_action', {
                method: 'POST',
                body: JSON.stringify(action)
            });
            const result = await response.json();

            if (result.status === 'success') {
                setupStreaming(result.stream_url, row, displayTool, action.tool, btnDownload);
            } else {
                bubble.classList.remove('success');
                bubble.classList.add('error');
                icon.textContent = 'error';
                icon.classList.remove('spin');
                headerText.textContent = `[FAILED]: ${displayTool.toUpperCase()} CORE OFFLINE.`;
                const errorDiv = document.createElement('div');
                errorDiv.className = 'action-error-text';
                errorDiv.textContent = result.message || "Unknown scanner initialization error.";
                row.querySelector('.action-details').appendChild(errorDiv);
            }
        } catch (e) {
            console.error("Action execution failed:", e);
        }
    }

    /**
     * Internal helper to manage the SSE stream for terminal output
     */
    function setupStreaming(streamUrl, row, displayTool, toolName, btnDownload) {
        const bubble = row.querySelector('.msg-bubble');
        const icon = row.querySelector('.action-header .material-symbols-outlined');
        const headerText = row.querySelector('.header-text');
        const terminalContainer = row.querySelector('.terminal-container');
        const terminalBody = row.querySelector('.terminal-body');

        bubble.classList.add('success');
        icon.textContent = 'check_circle';
        icon.classList.remove('spin');
        headerText.textContent = `[SUCCESS]: ${displayTool.toUpperCase()} CORE ACTIVE.`;
        
        terminalContainer.style.display = 'flex';
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

            const line = document.createElement('div');
            line.className = 'terminal-line';
            if (isProgress) {
                line.classList.add('progress-line');
                // Remove previous progress lines to keep terminal clean
                terminalBody.querySelectorAll('.progress-line').forEach(el => el.remove());
            }
            line.className = 'terminal-line';
            
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
                headerText.textContent = `[COMPLETE]: ${displayTool.toUpperCase()} DATA ACQUIRED.`;
                row.querySelector('.status-badge').innerHTML = `
                    <span class="material-symbols-outlined" style="font-size: 1rem;">analytics</span>
                    DATASET READY. INITIATING AI REASONING...
                `;
                row.querySelector('.action-footer').style.display = 'flex';
                btnDownload.style.display = 'block';
                triggerAutoAnalysis(toolName);
            }
        };

        eventSource.onerror = () => {
            eventSource.close();
        };
    }

    async function triggerAutoAnalysis(tool) {
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

                // Backend has injected the summary as a SYSTEM_NOTIFICATION in history.
                // We send a matching trigger to get the AI to analyze it.
                ui.userInput.value = `[ANALYSIS_TRIGGER]`;
                sendMessage();
            }
        } catch (e) {
            console.error("Auto-analysis failed:", e);
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

        addMessage('user', text); 

        isProcessing = true;
        
        ui.typingIndicator.style.display = 'block';
        scrollToBottom();

        let aiRow = null;
        let contentDiv = null;
        let fullMarkdownText = "";
        let displayedText = "";
        let isStreamActive = true;
        let metadataAction = null;

        try {
            const response = await fetchWithAuth('/chatbot/chat_stream', {
                method: 'POST',
                body: JSON.stringify({ 
                    message: text,
                    verbosity: verbosity,
                    is_incognito: isIncognito,
                    llm_mode: llmMode
                })
            });

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
                        aiBubble.setAttribute('data-label', 'NetShield AI');
                        contentDiv = document.createElement('div');
                        contentDiv.className = 'markdown-content';
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
            if(!aiRow) addMessage('ai', `_Error: ${err.message}_`);
            isProcessing = false;
            ui.userInput.focus();
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
    });

    ui.sendBtn.addEventListener('click', sendMessage);
    ui.userInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') sendMessage(); });
    
    const suggestions = [
        { title: "Vulnerability Analysis", desc: "Analyze the severity of SQL Injection." },
        { title: "Remediation", desc: "How do I fix XSS vulnerabilities?" },
        { title: "Network Audit", desc: "Risks of open Port 23 (Telnet)." },
        { title: "Compliance", desc: "Check password policy against NIST." }
    ];
    ui.suggestionGrid.innerHTML = '';
    suggestions.forEach(s => {
        const card = document.createElement('div');
        card.className = 'suggestion-card';
        card.innerHTML = `<h5>${s.title}</h5><p>${s.desc}</p>`;
        card.onclick = () => { ui.userInput.value = s.desc; ui.userInput.focus(); };
        ui.suggestionGrid.appendChild(card);
    });

    // --- 11. INITIALIZATION LOGIC ---
    async function init() {
        const urlParams = new URLSearchParams(window.location.search);
        const urlSessionId = urlParams.get('session_id');
        
        if (urlSessionId) {
            console.log(`[*] Initializing with URL Session ID: ${urlSessionId}`);
            try {
                // Inform backend to switch to this session
                await fetchWithAuth('/chatbot/switch_session', {
                    method: 'POST',
                    body: JSON.stringify({ session_id: urlSessionId })
                });
                currentSessionId = urlSessionId;
            } catch (e) { console.error("Failed to switch session on init:", e); }
        }

        await loadSessionList();
        await restoreSession();
        
        // [NEW] If redirected with a summary but history is empty, show the summary
        const urlSummary = urlParams.get('summary');
        if (urlSummary && ui.chatHistory.children.length === 0) {
            addMessage('ai', urlSummary, true);
        }

        // Clean up URL after successful load
        if (urlSessionId) {
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    }

    init();
});