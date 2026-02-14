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
            const language = highlight.getLanguage(lang) ? lang : 'plaintext';
            return highlight.highlight(code, { language }).value;
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

        // Status & Workflow ... (remaining keep same)
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
        let html = marked.parse(text);
        return highlightThreats(html);
    }

    function addMessage(role, text, animate = true) {
        ui.welcomeState.style.display = 'none';
        const row = document.createElement('div');
        row.className = `msg-row ${role}`;
        
        const bubble = document.createElement('div');
        bubble.className = 'msg-bubble';
        bubble.setAttribute('data-label', role === 'user' ? 'Human Analyst' : 'NetShield AI');
        
        if (role === 'ai' || role === 'assistant' || role === 'system') {
            const contentDiv = document.createElement('div');
            contentDiv.className = 'markdown-content';
            contentDiv.innerHTML = parseContent(text);
            bubble.appendChild(contentDiv);

            // Add Actions
            const actions = document.createElement('div');
            actions.className = 'msg-actions';
            actions.innerHTML = `
                <button class="action-btn copy-btn" title="Copy response"><span class="material-symbols-outlined" style="font-size:14px">content_copy</span></button>
                <button class="action-btn regen-btn" title="Regenerate"><span class="material-symbols-outlined" style="font-size:14px">refresh</span></button>
                <button class="action-btn feedback-btn up" title="Helpful"><span class="material-symbols-outlined" style="font-size:14px">thumb_up</span></button>
                <button class="action-btn feedback-btn down" title="Not helpful"><span class="material-symbols-outlined" style="font-size:14px">thumb_down</span></button>
            `;
            
            actions.querySelector('.copy-btn').onclick = () => {
                navigator.clipboard.writeText(text);
                const icon = actions.querySelector('.copy-btn span');
                icon.textContent = 'check';
                setTimeout(() => icon.textContent = 'content_copy', 2000);
            };

            actions.querySelector('.regen-btn').onclick = () => {
                if (lastUserMessage) {
                    ui.userInput.value = lastUserMessage;
                    sendMessage();
                }
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
            bubble.textContent = text;
            lastUserMessage = text;
        }
        
        row.appendChild(bubble);
        ui.chatHistory.appendChild(row);
        
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
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            if (ui.layout.classList.contains('sidebar-collapsed')) {
                ui.sidebarToggle.click();
            }
            ui.sessionSearch.focus();
        }
        
        // Ctrl + B to toggle sidebar
        if ((e.ctrlKey || e.metaKey) && e.key === 'b') {
            e.preventDefault();
            ui.sidebarToggle.click();
        }

        // Ctrl + M for new chat
        if ((e.ctrlKey || e.metaKey) && e.key === 'm') {
            e.preventDefault();
            ui.newChatBtn.click();
        }

        // Cmd/Ctrl + Enter to send
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && document.activeElement === ui.userInput) {
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
            ui.hiddenModelInput.value = 'local';
            ui.customTrigger.querySelector('span').textContent = 'NetShield Local';
            ui.customOptions.forEach(opt => opt.classList.remove('selected'));
            document.querySelector('.custom-option[data-value="local"]')?.classList.add('selected');
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
                data.chat_history.forEach(msg => {
                    const role = msg.role === 'assistant' ? 'ai' : msg.role;
                    addMessage(role, msg.content, false); 
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
    if(ui.customSelect) {
        // Ensure default state is set correctly
        ui.hiddenModelInput.value = 'local';
        ui.customTrigger.querySelector('span').textContent = 'NetShield Local';
        document.querySelector('.custom-option[data-value="local"]')?.classList.add('selected');

        ui.customTrigger.addEventListener('click', (e) => {
            e.stopPropagation();
            ui.customSelect.classList.toggle('open');
        });

        ui.customOptions.forEach(option => {
            option.addEventListener('click', function(e) {
                e.stopPropagation();
                ui.customOptions.forEach(opt => opt.classList.remove('selected'));
                this.classList.add('selected');
                const mainText = this.querySelector('.option-title').textContent;
                ui.customTrigger.querySelector('span').textContent = mainText;
                ui.hiddenModelInput.value = this.getAttribute('data-value');
                ui.customSelect.classList.remove('open');
                ui.startBtn.disabled = false;
            });
        });

        window.addEventListener('click', (e) => {
            if (ui.customSelect && !ui.customSelect.contains(e.target)) {
                ui.customSelect.classList.remove('open');
            }
            document.querySelectorAll('.context-menu').forEach(m => m.classList.remove('show'));
            document.querySelectorAll('.session-item').forEach(si => si.classList.remove('menu-open'));
        });
    }

    // --- 9. STREAMING MESSAGE LOGIC (WITH VISUAL SMOOTHING) ---
    async function sendMessage() {
        const text = ui.userInput.value.trim();
        if (!text || isProcessing) return;
        
        const verbosity = ui.settingVerbosity.value;
        const isIncognito = ui.settingIncognito.checked;
        const typeSpeed = parseInt(ui.settingSpeed.value);

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

        try {
            const response = await fetchWithAuth('/chatbot/chat_stream', {
                method: 'POST',
                body: JSON.stringify({ 
                    message: text,
                    verbosity: verbosity,
                    is_incognito: isIncognito
                })
            });

            if (!response.body) throw new Error('ReadableStream not supported.');

            const reader = response.body.getReader();
            const decoder = new TextDecoder();

            const networkLoop = async () => {
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    const chunk = decoder.decode(value, { stream: true });
                    fullMarkdownText += chunk;
                    
                    if (!aiRow) {
                        ui.typingIndicator.style.display = 'none';
                        aiRow = document.createElement('div');
                        aiRow.className = 'msg-row ai';
                        const aiBubble = document.createElement('div');
                        aiBubble.className = 'msg-bubble';
                        aiBubble.setAttribute('data-label', 'NetShield AI');
                        contentDiv = document.createElement('div');
                        contentDiv.className = 'markdown-content';
                        aiBubble.appendChild(contentDiv);
                        
                        // Action buttons... (Add them here as well for streaming messages)
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

                        // Attach listeners
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
                        scrollToBottom();
                    }
                }

                if (isStreamActive || displayedText.length < fullMarkdownText.length) {
                    setTimeout(renderLoop, typeSpeed);
                } else {
                    if (contentDiv) {
                        contentDiv.innerHTML = parseContent(fullMarkdownText);
                        if (!isIncognito) loadSessionList(); // Don't refresh sidebar in incognito
                        isProcessing = false;
                        ui.userInput.focus();
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

    loadSessionList();
    restoreSession();
});