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
        
        // Chat Interface
        chatHistory: document.getElementById('chat-history'),
        messagesContainer: document.getElementById('messages-container'),
        welcomeState: document.getElementById('welcome-state'),
        typingIndicator: document.getElementById('typing-indicator'),
        userInput: document.getElementById('user-input'),
        sendBtn: document.getElementById('send-btn'),
        suggestionGrid: document.getElementById('suggestion-grid'),
        sessionList: document.getElementById('session-list'),
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

    // --- 4. Helper Functions ---

    function scrollToBottom() {
        requestAnimationFrame(() => {
            ui.messagesContainer.scrollTop = ui.messagesContainer.scrollHeight;
        });
    }

    function updateContextStatus(hasFile, title = null) {
        const isLight = document.body.classList.contains('light-mode');
        
        if (hasFile) {
            // [CHANGED] Use consistent Green/Gray theme instead of Cyan to match default page
            ui.statusText.textContent = title ? `Active: ${title}` : `Active: KB + Report`;
            ui.statusText.style.color = "#10b981"; // Keep Green
            ui.statusDot.style.background = "#10b981";
            ui.statusDot.style.boxShadow = "0 0 8px rgba(16, 185, 129, 0.5)";
        } else {
            ui.statusText.textContent = "SYSTEM ONLINE";
            ui.statusText.style.color = isLight ? "#64748b" : "#9ca3af"; // Slate in light, Gray in dark
            ui.statusDot.style.background = "#10b981"; 
            ui.statusDot.style.boxShadow = "none";
        }
    }

    function switchView(mode) {
        if (mode === 'config') {
            ui.workflowPanel.classList.add('mode-config');
        } else {
            ui.workflowPanel.classList.remove('mode-config');
            // Reset config inputs
            ui.hiddenModelInput.value = 'local';
            ui.customTrigger.querySelector('span').textContent = 'NetShield Local';
            ui.customTrigger.style.color = 'white';
            ui.customOptions.forEach(opt => opt.classList.remove('selected'));
            document.querySelector('.custom-option[data-value="local"]')?.classList.add('selected');
            
            ui.startBtn.disabled = true;
            ui.uploadStatus.textContent = '';
        }
    }

    function addMessage(role, text, animate = true) {
        ui.welcomeState.style.display = 'none';
        const row = document.createElement('div');
        row.className = `msg-row ${role}`;
        
        const bubble = document.createElement('div');
        bubble.className = 'msg-bubble';
        
        if (role === 'ai' || role === 'assistant') {
            const contentDiv = document.createElement('div');
            contentDiv.className = 'markdown-content';
            contentDiv.innerHTML = marked.parse(text);
            bubble.appendChild(contentDiv);
        } else {
            bubble.textContent = text;
        }
        
        row.appendChild(bubble);
        ui.chatHistory.appendChild(row);
        
        if (animate) scrollToBottom();
    }

    // --- 5. Session List & Context Menu Logic ---

    // [NEW] Helper function to render the session list DOM elements
    // This allows us to reuse the logic for both pre-loaded data and fetched data
    function renderSessionList(sessions) {
        ui.sessionList.innerHTML = ''; 
        
        if (sessions && sessions.length > 0) {
            sessions.forEach(sess => {
                const item = document.createElement('div');
                item.className = `session-item ${sess.is_pinned ? 'pinned' : ''} ${sess.session_id === currentSessionId ? 'active' : ''}`;
                item.dataset.id = sess.session_id;
                
                item.innerHTML = `
                    <div class="session-info">
                        <span class="session-title">${sess.title}</span>
                        <span class="session-date">${sess.subtitle}</span>
                    </div>
                    <span class="pin-icon material-symbols-outlined" style="font-size:14px; ${sess.is_pinned ? '' : 'display:none'}">push_pin</span>
                    <button class="session-menu-btn"><span class="material-symbols-outlined" style="font-size:16px">more_vert</span></button>
                    
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

                // Click Logic: Switch Session
                item.addEventListener('click', (e) => {
                    if (!e.target.closest('.session-menu-btn') && !e.target.closest('.context-menu')) {
                        switchSession(sess.session_id);
                    }
                });

                // Menu Toggle Logic
                const menuBtn = item.querySelector('.session-menu-btn');
                const menu = item.querySelector('.context-menu');
                
                menuBtn.addEventListener('click', (e) => {
                    e.stopPropagation(); 
                    document.querySelectorAll('.context-menu').forEach(m => m.classList.remove('show'));
                    menu.classList.toggle('show');
                });

                // Action Listeners
                item.querySelector('.action-pin').addEventListener('click', (e) => {
                    e.stopPropagation();
                    menu.classList.remove('show');
                    togglePin(sess.session_id, !sess.is_pinned);
                });
                
                item.querySelector('.action-rename').addEventListener('click', (e) => {
                    e.stopPropagation();
                    openRenameModal(sess.session_id, sess.title);
                    menu.classList.remove('show');
                });
                
                item.querySelector('.action-delete').addEventListener('click', (e) => {
                    e.stopPropagation();
                    menu.classList.remove('show');
                    // [CHANGED] Removed confirm() check for instant deletion
                    deleteSession(sess.session_id);
                });

                ui.sessionList.appendChild(item);
            });
        } else {
            ui.sessionList.innerHTML = '<p style="color:#444; font-size:0.7rem; padding:0.5rem; font-style:italic;">No history available.</p>';
        }
    }

    async function loadSessionList() {
        try {
            // [NEW] Check for Server-Side Pre-loaded Data
            // If the window variable exists, use it immediately to avoid network lag.
            if (window.PRELOADED_SESSIONS) {
                renderSessionList(window.PRELOADED_SESSIONS);
                
                // Clear the variable so subsequent updates (like after a pin/delete)
                // perform a fresh network fetch to get the latest state.
                window.PRELOADED_SESSIONS = null;
                return;
            }

            // Fallback: Standard Network Fetch
            const response = await fetchWithAuth('/chatbot/get_sessions');
            const data = await response.json();
            renderSessionList(data.sessions);

        } catch (e) { console.error("Error loading sessions:", e); }
    }

    window.addEventListener('click', () => {
        document.querySelectorAll('.context-menu').forEach(m => m.classList.remove('show'));
    });

    // --- 6. Session Actions (Optimistic Updates) ---

    async function togglePin(sessionId, newStatus) {
        if (isPinning) return; 
        isPinning = true;

        const item = document.querySelector(`.session-item[data-id="${sessionId}"]`);
        if (item) {
            if (newStatus) {
                item.classList.add('pinned');
                item.querySelector('.pin-icon').style.display = 'inline-block';
            } else {
                item.classList.remove('pinned');
                item.querySelector('.pin-icon').style.display = 'none';
            }
        }

        try {
            await fetchWithAuth('/chatbot/toggle_pin', {
                method: 'POST',
                body: JSON.stringify({ session_id: sessionId, is_pinned: newStatus })
            });
            setTimeout(() => loadSessionList(), 300);
        } catch (e) { console.error(e); } 
        finally { isPinning = false; }
    }

    // [NEW] Optimistic Delete Function
    async function deleteSession(sessionId) {
        // 1. Instant UI Update: Remove from DOM immediately
        const item = document.querySelector(`.session-item[data-id="${sessionId}"]`);
        if (item) {
            item.remove(); // Removes element instantly
        }

        // 2. If deleting the current active session, clear the chat view immediately
        if (sessionId === currentSessionId) {
            clearView();
        }

        // 3. Send Network Request in Background
        try {
            await fetchWithAuth('/chatbot/delete_session', {
                method: 'POST',
                body: JSON.stringify({ session_id: sessionId })
            });
            // We do NOT reload the list here to keep the UI stable.
            // If the delete succeeded, the item is already gone.
        } catch (e) { 
            console.error("Delete failed:", e); 
            // Only if it FAILS do we reload the list to restore the item (sync with server)
            loadSessionList();
            alert("Failed to delete session due to a network error.");
        }
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
                loadSessionList();
            } catch (e) { console.error(e); }
        }
    });

    // --- 7. Core Workflows ---

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
            loadSessionList(); 
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
                    
                    // --- [CHANGED] Unify Appearance with Default Theme ---
                    
                    // 1. Show the 'X' button so users can close history and go back to upload
                    ui.removeFileBtn.style.display = 'flex'; 
                    
                    // 2. Keep the button consistent with the Blue Theme (vs Green/History Mode)
                    ui.startBtn.disabled = true;
                    ui.startBtn.style.background = 'var(--neo-blue)'; // Use standard theme
                    ui.startBtn.style.opacity = '0.8'; // Slight dim to show it's state
                    
                    // 3. Update Text to be professional
                    ui.startBtn.querySelector('.btn-text').textContent = "ANALYSIS LOADED";
                    ui.startBtn.querySelector('.icon').textContent = 'inventory_2'; // Archive icon
                    
                    updateContextStatus(true, data.session_metadata.title);
                } else {
                    switchView('upload');
                    updateContextStatus(false);
                }
            } else {
                ui.welcomeState.style.display = 'block';
                updateContextStatus(false);
            }
        } catch (err) {
            console.error("Failed to restore session:", err);
        }
    }

    function clearView() {
        currentSessionId = null;
        ui.chatHistory.innerHTML = '';
        ui.welcomeState.style.display = 'block';
        
        switchView('upload');
        selectedFile = null;
        ui.fileInput.value = '';
        ui.removeFileBtn.style.display = 'flex'; 
        
        ui.startBtn.style.background = 'var(--neo-blue)';
        ui.startBtn.querySelector('.btn-text').textContent = "Analyze";
        ui.startBtn.querySelector('.icon').textContent = 'bolt';
        ui.startBtn.disabled = true; 
        
        document.querySelectorAll('.session-item').forEach(i => i.classList.remove('active'));
        updateContextStatus(false);
    }

    // --- 8. Event Listeners ---

    // === CRITICAL FIX: ENABLE BUTTON ON FILE SELECT ===
    ui.fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            selectedFile = e.target.files[0];
            ui.selectedFilename.textContent = selectedFile.name;
            switchView('config');
            ui.removeFileBtn.style.display = 'flex'; 
            
            // Check if default model ('local') is present and enable button immediately
            if (ui.hiddenModelInput.value) {
                ui.startBtn.disabled = false;
            }
        }
    });

    ui.removeFileBtn.addEventListener('click', () => {
        selectedFile = null;
        ui.fileInput.value = '';
        switchView('upload');
        updateContextStatus(false);
    });

    if(ui.customSelect) {
        // Ensure default state is set correctly
        ui.hiddenModelInput.value = 'local';
        ui.customTrigger.querySelector('span').textContent = 'NetShield Local';
        ui.customTrigger.style.color = 'white';
        document.querySelector('.custom-option[data-value="local"]')?.classList.add('selected');

        ui.customTrigger.addEventListener('click', () => ui.customSelect.classList.toggle('open'));
        ui.customOptions.forEach(option => {
            option.addEventListener('click', function() {
                ui.customOptions.forEach(opt => opt.classList.remove('selected'));
                this.classList.add('selected');
                const mainText = this.querySelector('span:first-child').textContent;
                ui.customTrigger.querySelector('span').textContent = mainText;
                ui.customTrigger.style.color = 'white';
                ui.hiddenModelInput.value = this.getAttribute('data-value');
                ui.customSelect.classList.remove('open');
                ui.startBtn.disabled = false;
            });
        });
        window.addEventListener('click', (e) => {
            if (!ui.customSelect.contains(e.target)) ui.customSelect.classList.remove('open');
        });
    }

    ui.startBtn.addEventListener('click', async () => {
        const modelValue = ui.hiddenModelInput.value;
        if (!selectedFile || !modelValue) return;

        // Visual Feedback for User
        ui.startBtn.disabled = true;
        ui.startBtn.querySelector('.btn-text').textContent = "ANALYZING...";
        ui.startBtn.querySelector('.icon').style.display = 'none';
        ui.startBtn.querySelector('.spinner').style.display = 'block';
        ui.uploadStatus.textContent = "Processing packet stream...";
        ui.uploadStatus.style.color = "var(--neo-blue)";

        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('llm_mode', modelValue);

        try {
            const headers = {'X-CSRFToken': csrfToken};
            const response = await fetch('/chatbot/upload_report', { 
                method: 'POST', 
                body: formData,
                headers: headers
            });
            const data = await response.json();

            if (response.ok && !data.error) {
                ui.uploadStatus.textContent = "ANALYSIS COMPLETE";
                ui.uploadStatus.style.color = "#10b981";
                
                ui.startBtn.querySelector('.btn-text').textContent = "ACTIVE";
                ui.startBtn.querySelector('.spinner').style.display = 'none';
                ui.startBtn.querySelector('.icon').style.display = 'block';
                ui.startBtn.querySelector('.icon').textContent = 'check_circle';
                ui.startBtn.style.background = '#10b981';
                
                updateContextStatus(true, selectedFile.name);
                
                ui.chatHistory.innerHTML = ''; 
                addMessage('ai', `**Analysis Protocol Initiated**\n\nTarget: \`${selectedFile.name}\`\nCore: \`${modelValue.toUpperCase()}\`\n\n${data.message || 'System ready.'}\n\n${data.summary || ''}`);
                
                currentSessionId = data.session_id; 
                loadSessionList(); 
            } else {
                throw new Error(data.error || 'Upload failed');
            }
        } catch (err) {
            ui.uploadStatus.textContent = "ERROR: " + err.message;
            ui.uploadStatus.style.color = "#ef4444";
            ui.startBtn.disabled = false;
            ui.startBtn.querySelector('.btn-text').textContent = "RETRY";
            ui.startBtn.querySelector('.spinner').style.display = 'none';
            ui.startBtn.querySelector('.icon').style.display = 'block';
        }
    });

    // --- 9. STREAMING MESSAGE LOGIC (WITH VISUAL SMOOTHING) ---
    async function sendMessage() {
        const text = ui.userInput.value.trim();
        if (!text || isProcessing) return;
        
        ui.userInput.value = '';
        addMessage('user', text); 
        isProcessing = true;
        
        // SHOW DOTS IMMEDIATELY
        ui.typingIndicator.style.display = 'block';
        scrollToBottom();

        let aiRow = null;
        let contentDiv = null;
        
        // State for Visual Smoothing
        let fullMarkdownText = ""; // The complete text received from server so far
        let displayedText = "";    // The text currently shown on screen
        let isStreamActive = true; // Flag to track if network is still sending

        try {
            const response = await fetchWithAuth('/chatbot/chat_stream', {
                method: 'POST',
                body: JSON.stringify({ message: text })
            });

            if (!response.body) throw new Error('ReadableStream not supported.');

            const reader = response.body.getReader();
            const decoder = new TextDecoder();

            // 1. START THE NETWORK LOOP (Background)
            const networkLoop = async () => {
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;
                    const chunk = decoder.decode(value, { stream: true });
                    fullMarkdownText += chunk; // Just append to buffer, don't render yet
                    
                    // Initialize bubble on first chunk
                    if (!aiRow) {
                        ui.typingIndicator.style.display = 'none';
                        aiRow = document.createElement('div');
                        aiRow.className = 'msg-row ai';
                        const aiBubble = document.createElement('div');
                        aiBubble.className = 'msg-bubble';
                        contentDiv = document.createElement('div');
                        contentDiv.className = 'markdown-content';
                        aiBubble.appendChild(contentDiv);
                        aiRow.appendChild(aiBubble);
                        ui.chatHistory.appendChild(aiRow);
                    }
                }
                isStreamActive = false; // Network finished
            };

            networkLoop();

            // 2. START THE RENDER LOOP (Foreground - Typewriter Effect)
            const typeSpeed = 10; // ms per character (Lower = Faster)
            
            const renderLoop = () => {
                // If displayed text is shorter than received text, "type" the next characters
                if (displayedText.length < fullMarkdownText.length) {
                    
                    // Calculate how many chars to add this frame (speed up if behind)
                    const lag = fullMarkdownText.length - displayedText.length;
                    const step = lag > 50 ? 5 : (lag > 20 ? 2 : 1); 
                    
                    displayedText = fullMarkdownText.substring(0, displayedText.length + step);
                    
                    if (contentDiv) {
                        contentDiv.innerHTML = marked.parse(displayedText);
                        scrollToBottom();
                    }
                }

                // Continue loop if network is active OR we still have text to type
                if (isStreamActive || displayedText.length < fullMarkdownText.length) {
                    setTimeout(renderLoop, typeSpeed);
                } else {
                    // Final pass to ensure everything matches exactly
                    if (contentDiv) {
                        contentDiv.innerHTML = marked.parse(fullMarkdownText);
                        loadSessionList(); // Refresh sidebar when done
                        isProcessing = false;
                        ui.userInput.focus();
                    }
                }
            };

            renderLoop();

        } catch (err) {
            ui.typingIndicator.style.display = 'none';
            if(!aiRow) addMessage('ai', `_Error: ${err.message}_`);
            else if(contentDiv) contentDiv.innerHTML += `<br><em style="color:red">[Error: ${err.message}]</em>`;
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