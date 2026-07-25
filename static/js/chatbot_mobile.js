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

    // Custom Markdown parsing with threat highlighting and report sectioning
    function parseContent(text) {
        if (!text) return "";
        try {
            // COLLECTION: Extract follow-up suggestions and actions before markdown parsing
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
                    const before = processedText.substring(0, firstIdx).replace(/[━─]+[\s\n]*$/, '').trimEnd();
                    const pathsBlock = processedText.substring(firstIdx);

                    const sections = pathsBlock.split(/(?=\bPATH\s*\d+\s*[—–\-])/m).filter(s => s.trim());
                    let hubHtml = '<div class="decision-grid">';

                    sections.forEach(section => {
                        const nlIdx = section.indexOf('\n');
                        if (nlIdx === -1) return;
                        const headerLine = section.substring(0, nlIdx).replace(/[━─]/g, '').trim();
                        const bodyText   = section.substring(nlIdx + 1);

                        const hm = headerLine.match(/PATH\s*(\d+)\s*[—–\-]\s*(.+?)(?:\s*\[([^\]]*)\])?\s*$/i);
                        if (!hm) return;

                        const [, num, rawStatus, metadata] = hm;
                        const cleanStatus = rawStatus.trim();
                        const isActive    = (metadata || '').toUpperCase().includes('YOU ARE HERE');
                        const sevClass    = _pathSevClass(cleanStatus);

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

            let rawHtml = marked.parse(processedText);
            let html = typeof DOMPurify !== 'undefined' ? DOMPurify.sanitize(rawHtml, { ADD_ATTR: ['target', 'style', 'class'] }) : rawHtml;
            const tempDiv = document.createElement('div');
            tempDiv.innerHTML = html;

            // ===================================================================
            // IMMERSIVE REPORT RENDERER Enrichment Passes
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

            tempDiv.querySelectorAll('h3, h4').forEach(hx => {
                const rawText = hx.innerText.trim();
                const m = rawText.match(/Finding\s+#?(\d+)\s*[\u2014\u2013-]\s*(.+?)\s*\|\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)/i);
                if (!m) return;
                const card = _buildFindingCard(m[1], m[2], m[3], _collectSiblings(hx));
                hx.replaceWith(card);
            });

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
                if (/^[a-z][\.\)]\s+/i.test(text) || /^<strong>[a-z][\.\)]\s*<\/strong>/i.test(p.innerHTML)) {
                    p.classList.add('llm-context-item');
                }
            });

            // --- PASS 2.6: Remediation Action Cards (Issue, Action, Benefit, Owner) ---
            tempDiv.querySelectorAll('p').forEach(p => {
                const text = p.innerText.trim();
                if (text.startsWith('Issue:')) {
                    const card = document.createElement('div');
                    card.className = 'llm-remediation-card';
                    
                    const siblings = [p];
                    let next = p.nextElementSibling;
                    const stopKeywords = ['Issue:', 'Finding #', '1. ', '2. '];
                    const fields = ['Action:', 'Benefit:', 'Owner:'];
                    
                    while (next && next.tagName === 'P') {
                        const nextText = next.innerText.trim();
                        if (fields.some(f => nextText.startsWith(f))) {
                            siblings.push(next);
                            next = next.nextElementSibling;
                        } else if (stopKeywords.some(k => nextText.startsWith(k))) {
                            break; 
                        } else {
                            break;
                        }
                    }
                    
                    if (siblings.length > 1) {
                        p.parentNode.insertBefore(card, p);
                        siblings.forEach(s => {
                            s.innerHTML = s.innerHTML.replace(/^(Issue|Action|Benefit|Owner):/i, '<span class="remediation-label">$1:</span>');
                            card.appendChild(s);
                        });
                    }
                }
            });

            // --- PASS 3: Table Panel Wrapping ---
            const _panelVariants = ['variant-meta', 'variant-stat', 'variant-compare', 'variant-action'];
            let _tableIdx = 0;
            tempDiv.querySelectorAll('table').forEach(table => {
                if (table.closest('.llm-table-panel')) return;
                const variant = _panelVariants[_tableIdx % _panelVariants.length];
                _tableIdx++;

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
            const _riskClassMap = {
                'critical': 'critical', 'high': 'high', 'at risk': 'high',
                'moderate': 'moderate', 'medium': 'moderate',
                'low': 'low', 'safe': 'safe', 'info': 'safe'
            };
            tempDiv.querySelectorAll('td').forEach(td => {
                if (td.querySelector('.llm-risk-label')) return;
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
            tempDiv.querySelectorAll('td').forEach(td => {
                if (td.querySelector('.llm-risk-label,.llm-score-bar')) return;
                const txt = td.innerText.trim();
                const score = parseFloat(txt);
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
                requestAnimationFrame(() => {
                    setTimeout(() => { bar.style.width = (score * 10) + '%'; }, 80);
                });
            });

            // --- PASS 7: Code Container Standardization ---
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
            tempDiv.querySelectorAll('p, div, h4').forEach(el => {
              const text = el.innerText.trim();
              if (text.includes('[MISSION_PRESETS]')) {
                let ul = el.nextElementSibling;
                while (ul && ul.tagName !== 'UL' && ul.tagName !== 'OL') {
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
                  
                  el.style.display = 'none';
                  ul.replaceWith(grid);
                }
              }
            });

            // --- PASS 8.5: Security Tools Grid (Multi-Category) ---
            tempDiv.querySelectorAll('p, div, h4').forEach(el => {
              const text = el.innerText.trim();
              if (text.includes('[SCAN_PRESETS]')) {
                let next = el.nextElementSibling;
                const groups = [];
                let currentCategory = null;

                while (next) {
                    if (['H2', 'DIV'].includes(next.tagName) && (next.className.includes('divider') || next.className.includes('msg-actions'))) break;
                    
                    const inner = next.innerText.trim();
                    if (!inner) {
                        next = next.nextElementSibling;
                        continue;
                    }

                    if ((next.tagName === 'P' && next.querySelector('strong') && inner.length < 60) || (next.tagName === 'H4' || next.tagName === 'H5')) {
                        currentCategory = inner.replace(/^\*+|\*+$/g, '');
                        next.style.display = 'none';
                    } else if (next.tagName === 'UL' || next.tagName === 'OL') {
                        groups.push({ category: currentCategory, ul: next });
                        currentCategory = null; 
                        next.style.display = 'none';
                    } else if (inner.includes('[SCAN_PRESETS]')) {
                        next.style.display = 'none';
                    } else if (next.tagName === 'P' && inner.length < 50 && !inner.includes(':')) {
                        currentCategory = inner;
                        next.style.display = 'none';
                    } else {
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
                .replace(/\[SCAN_PRESETS\]/g, '');

            // --- Cleanup: Remove empty paragraphs ---
            tempDiv.querySelectorAll('p').forEach(p => {
                if (!p.innerText.trim() && !p.querySelector('img, video, iframe, .ai-suggestion-chip, .memory-updated-chip')) {
                    p.remove();
                }
            });

            // --- Font Sanitization ---
            const FONT_UI   = "var(--font-primary)";
            const FONT_MONO = "var(--font-code)";
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

    // Tool icon map for the action card header
    const _toolIconMap = {
        'nmap_scan': 'radar', 'zap_scan': 'bolt', 'ssl_scan': 'lock',
        'sql_injection_scan': 'database', 'packet_sniffer': 'wifi_tethering',
        'api_security_scan': 'api', 'killchain_audit': 'account_tree',
        'semgrep_sast_scan': 'code', 'schedule_scan': 'calendar_month'
    };

    async function handleAction(action, isRestore = false, reattachStreamUrl = null, isCompleted = false) {
        if (!action || !action.tool) return;
        
        // Resolve actual status via DB if restoring
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
        row.setAttribute('data-tool', action.tool);
        row.innerHTML = `
            <div class="action-card ${stateClass}">
                <div class="ac-header">
                    <div class="ac-title-group">
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
            'killchain_audit': '/killchain/download_report',
            'semgrep_sast_scan': '/semgrep_scanner/download_pdf'
        };

        const btnRedirect = row.querySelector('.btn-redirect');
        const btnDownload = row.querySelector('.btn-download');

        const setupButtons = () => {
            btnRedirect.onclick = (e) => {
                const url = toolUrlMap[action.tool];
                if (url) window.location.href = url;
            };
            btnDownload.onclick = () => {
                const url = toolDownloadMap[action.tool];
                if (url) window.open(url, '_blank');
            };
        };

        setupButtons();

        if (isRestore && !isCompleted) return;

        if (isCompleted) {
            promptForAnalysis(action.tool);
            return;
        }

        if (reattachStreamUrl) {
            setupStreaming(reattachStreamUrl, row, displayTool, action.tool);
            return;
        }

        // Special handling for Scheduling
        if (action.tool === 'schedule_scan') {
            try {
                const response = await fetchWithAuth('/chatbot/execute_schedule', {
                    method: 'POST',
                    body: JSON.stringify(action.parameters)
                });
                if (!response.ok) throw new Error("Scheduling request failed");
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
            const result = await response.json();

            if (result.status === 'success') {
                setupStreaming(result.stream_url, row, displayTool, action.tool);
            } else {
                const card = row.querySelector('.action-card');
                const stateIcon = row.querySelector('.ac-state-icon');
                const stateBadge = row.querySelector('.ac-state-badge');
                if (card) { card.classList.remove('state-deploy'); card.classList.add('state-error'); }
                if (stateIcon) { stateIcon.textContent = 'error'; stateIcon.classList.remove('spin'); }
                if (stateBadge) stateBadge.querySelector('span:last-child').textContent = 'OFFLINE';
            }
        } catch (e) { 
            console.error("Action execution failed:", e);
            const card = row.querySelector('.action-card');
            const stateIcon = row.querySelector('.ac-state-icon');
            const stateBadge = row.querySelector('.ac-state-badge');
            if (card) { card.classList.remove('state-deploy'); card.classList.add('state-error'); }
            if (stateIcon) { stateIcon.textContent = 'error'; stateIcon.classList.remove('spin'); }
            if (stateBadge) stateBadge.querySelector('span:last-child').textContent = 'OFFLINE';
        }
    }

    function setupStreaming(streamUrl, row, displayTool, toolName, btnDownloadParam = null) {
        const card        = row.querySelector('.action-card');
        const stateIcon   = row.querySelector('.ac-state-icon');
        const stateBadge  = row.querySelector('.ac-state-badge span:last-child');
        const terminalEl  = row.querySelector('.ac-terminal');
        const terminalBody = row.querySelector('.terminal-body');
        const progressContainer = row.querySelector('.progress-container');
        const progressFill = row.querySelector('.progress-fill');
        const progressText = row.querySelector('.progress-percent');
        const btnDownload = btnDownloadParam || row.querySelector('.btn-download');

        if (card)      { card.classList.remove('state-deploy'); card.classList.add('state-active'); }
        if (stateIcon) { stateIcon.textContent = 'check_circle'; stateIcon.classList.remove('spin'); }
        if (stateBadge) stateBadge.textContent = 'CORE ACTIVE';

        if (terminalEl) terminalEl.style.display = '';
        const eventSource = new EventSource(streamUrl);
        
        eventSource.onmessage = (e) => {
            if (e.data === ': keep-alive') return;

            let isProgress = false;
            // Handle Progress Updates
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

            // Check for text-based progress bars
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
                
                const titleNode = row.querySelector('.ac-tool-name');
                if (titleNode) titleNode.textContent = `[COMPLETE]: ${displayTool.toUpperCase()}`;
                
                const footerBadge = row.querySelector('.status-badge');
                if (footerBadge) {
                    footerBadge.innerHTML = `
                        <span class="material-symbols-outlined" style="font-size: 1rem;">analytics</span>
                        DATASET READY.
                    `;
                }
                
                const footer = row.querySelector('.ac-footer');
                if (footer) footer.style.display = 'flex';
                
                if (btnDownload) btnDownload.style.display = 'block';
                promptForAnalysis(toolName);
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

    // [NEW] Global listener for Interactive Security Grid Cards and Suggestions
    document.addEventListener('click', (e) => {
        // Hide menus on outside click
        document.querySelectorAll('.context-menu').forEach(m => m.classList.remove('show'));

        // [PHASE 5: Enhanced Follow-up Cards]
        const followupCard = e.target.closest('.ai-followup-card');
        if (followupCard && ui.userInput) {
            const isAction = followupCard.classList.contains('action');
            const dataAttr = isAction ? 'data-prompt' : 'data-suggestion';
            const messageText = decodeURIComponent(followupCard.getAttribute(dataAttr));
            
            ui.userInput.value = messageText;
            ui.userInput.focus();
            ui.userInput.style.height = 'auto';
            ui.userInput.style.height = (ui.userInput.scrollHeight) + 'px';
            
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

        if (template) {
            ui.userInput.value = template;
            ui.userInput.focus();
            ui.userInput.style.height = 'auto';
            ui.userInput.style.height = (ui.userInput.scrollHeight) + 'px';
        }
    });

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
        grid.innerHTML = '';
        
        // Match icon names
        const iconMap = {
            'Nmap': 'radar', 'ZAP': 'bolt', 'SSL': 'lock', 'SQL': 'database',
            'Capture': 'wifi_tethering', 'API': 'api', 'Kill': 'account_tree', 'Semgrep': 'code'
        };

        const shuffled = [...suggestionPool].sort(() => 0.5 - Math.random());
        shuffled.slice(0, 4).forEach(s => {
            const card = document.createElement('div');
            card.className = 'suggestion-card';
            
            let iconName = 'security';
            for (const [key, icon] of Object.entries(iconMap)) {
                if (s.title.includes(key)) { iconName = icon; break; }
            }
            
            card.innerHTML = `
                <div class="suggestion-header-row">
                    <span class="material-symbols-outlined suggestion-icon">${iconName}</span>
                    <h5>${s.title}</h5>
                </div>
                <p>${s.desc}</p>
            `;
            card.onclick = () => {
                setInput(s.desc);
            };
            grid.appendChild(card);
        });
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
