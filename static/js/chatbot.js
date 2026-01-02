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
        if (hasFile) {
            ui.statusText.textContent = title ? `Context: ${title}` : `Context: KB + Report`;
            ui.statusText.style.color = "var(--neo-cyan)";
            ui.statusDot.style.background = "var(--neo-cyan)";
            ui.statusDot.style.boxShadow = "0 0 10px rgba(0, 247, 255, 0.5)";
        } else {
            ui.statusText.textContent = "Context: NetShield KB";
            ui.statusText.style.color = "#e5e5e5"; 
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

    async function loadSessionList() {
        try {
            const response = await fetchWithAuth('/chatbot/get_sessions');
            const data = await response.json();
            ui.sessionList.innerHTML = ''; 
            
            if (data.sessions && data.sessions.length > 0) {
                data.sessions.forEach(sess => {
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
                        if(confirm('Are you sure you want to delete this session?')) {
                            deleteSession(sess.session_id);
                        }
                    });

                    ui.sessionList.appendChild(item);
                });
            } else {
                ui.sessionList.innerHTML = '<p style="color:#444; font-size:0.7rem; padding:0.5rem; font-style:italic;">No history available.</p>';
            }
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

    async function deleteSession(sessionId) {
        try {
            await fetchWithAuth('/chatbot/delete_session', {
                method: 'POST',
                body: JSON.stringify({ session_id: sessionId })
            });
            
            if (sessionId === currentSessionId) {
                clearView();
            }
            loadSessionList();
        } catch (e) { console.error(e); }
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
                    ui.selectedFilename.textContent = data.session_metadata.title || "History Mode";
                    ui.removeFileBtn.style.display = 'none'; 
                    
                    ui.startBtn.disabled = true;
                    ui.startBtn.style.background = '#10b981';
                    ui.startBtn.querySelector('.btn-text').textContent = "HISTORY MODE";
                    ui.startBtn.querySelector('.icon').textContent = 'history';
                    
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