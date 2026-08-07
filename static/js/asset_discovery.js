document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Element Selectors ---
    const elements = {
        // Control
        targetDomainInput:   document.getElementById('targetDomain'),
        startDiscoveryBtn:   document.getElementById('startDiscoveryBtn'),
        stopDiscoveryBtn:    document.getElementById('stopDiscoveryBtn'),
        btnSpinner:          document.getElementById('btnSpinner'),
        scanStatus:          document.getElementById('scanStatus'),
        targetDisplay:       document.getElementById('targetDisplay'),

        // Metrics
        totalAssetsCount:    document.getElementById('totalAssetsCount'),
        subdomainCount:      document.getElementById('subdomainCount'),
        rootDomainCount:     document.getElementById('rootDomainCount'),

        // Tabs
        inventoryTabBtn:     document.getElementById('inventoryTabBtn'),
        domainsTabBtn:       document.getElementById('domainsTabBtn'),
        subdomainsTabBtn:    document.getElementById('subdomainsTabBtn'),
        endpointsTabBtn:     document.getElementById('endpointsTabBtn'),
        techStackTabBtn:     document.getElementById('techStackTabBtn'),
        jsonTabBtn:          document.getElementById('jsonTabBtn'),
        
        inventoryContent:    document.getElementById('inventoryContent'),
        jsonContent:         document.getElementById('jsonContent'),
        jsonViewer:          document.getElementById('jsonViewer'),
        copyJsonBtn:         document.getElementById('copyJsonBtn'),

        // Asset Grid
        assetCardGrid:       document.getElementById('assetCardGrid'),
        rawLogContent:       document.getElementById('rawLogContent'),

        // Terminal
        logOutput:           document.getElementById('logOutput'),
        clearLogBtn:         document.getElementById('clearLogBtn'),

        // Intelligence Actions
        analyzeReportDropdown: null,
        llmAnalysisOptions:    null,
        downloadReportBtn:     document.getElementById('downloadReportBtn'),
        execSummaryBtn:        null,
        execSummaryLabel:      null,
        execSummaryIcon:       null,
        execSummarySpinner:    null,
        refreshResultsBtn:     document.getElementById('refreshResultsBtn'),
        downloadJsonBtn:       document.getElementById('downloadJsonBtn'),
        discoveryHistoryBtn:   document.getElementById('discoveryHistoryBtn'),

        // Intel Panel
        intelTargetDisplay:   document.getElementById('intelTargetDisplay'),
        intelStatusDisplay:   document.getElementById('intelStatusDisplay'),
        discoveryInsights:    null,
        intelDomainCount:     document.getElementById('intelDomainCount'),
        intelSubdomainCount:  document.getElementById('intelSubdomainCount'),

        // AI Overlay
        aiProcessingOverlay:  null,
        aiProcessingText:     null,

        // Posture Badges
        mailPostureBadge:     document.getElementById('mailPostureBadge'),
        sslPostureBadge:      document.getElementById('sslPostureBadge'),
        cloudPostureBadge:    document.getElementById('cloudPostureBadge'),

        // Modals
        historyModal:         document.getElementById('historyModal'),
        historyTableBody:     document.getElementById('historyTableBody'),
        closeHistoryModal:    document.getElementById('closeHistoryModal'),
        authModal:            document.getElementById('authModal'),
        authModalMessage:     document.getElementById('authModalMessage'),
        confirmAuthBtn:       document.getElementById('confirmAuthBtn'),
        cancelAuthBtn:        document.getElementById('cancelAuthBtn'),
        blockedModal:         document.getElementById('blockedModal'),
        blockedModalMessage:  document.getElementById('blockedModalMessage'),
        closeBlockedModalBtn: document.getElementById('closeBlockedModalBtn'),

        // Intel Drawer
        intelDrawer:          document.getElementById('intelDrawer'),
        intelDrawerOverlay:   document.getElementById('intelDrawerOverlay'),
        drawerContent:        document.getElementById('drawerContent'),
        drawerAssetTitle:     document.getElementById('drawerAssetTitle'),
        drawerAssetType:      document.getElementById('drawerAssetType'),
        drawerAssetIcon:      document.getElementById('drawerAssetIcon'),
        closeIntelDrawer:     document.getElementById('closeIntelDrawer'),
    };

    // --- State Management ---
    const API_BASE_URL = '/asset_discovery';
    let isActionInProgress = false;
    let eventSource = null;
    let currentTarget = null;
    let currentCategory = 'all';
    let cachedAssets = [];
    let rawLogLines = [];
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

    // ─────────────────────────────────────────────
    // UI Helpers
    // ─────────────────────────────────────────────

    function toggleSpinner(isLoading) {
        isActionInProgress = isLoading;
        elements.startDiscoveryBtn.disabled = isLoading;
        if (isLoading) {
            elements.btnSpinner?.classList.remove('hidden');
            elements.startDiscoveryBtn.classList.add('opacity-70', 'cursor-not-allowed');
            elements.stopDiscoveryBtn?.classList.remove('hidden');
        } else {
            elements.btnSpinner?.classList.add('hidden');
            elements.startDiscoveryBtn.classList.remove('opacity-70', 'cursor-not-allowed');
            elements.stopDiscoveryBtn?.classList.add('hidden');
        }
    }

    function appendLog(message) {
        if (!elements.logOutput) return;
        rawLogLines.push(message);
        // Live stream is handled by elements.logOutput

        const now = new Date();
        const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

        const line = document.createElement('div');
        line.className = 'log-line';

        let color = '#999';
        let icon = 'radio_button_checked';

        if (message.includes('[!]') || message.includes('[x]') || message.includes('ERROR')) { color = '#ef4444'; icon = 'error'; }
        else if (message.includes('[STAGE]')) { color = '#a78bfa'; icon = 'layers'; }
        else if (message.includes('[SUCCESS]') || message.includes('[✓]') || message.includes('[+]')) { color = '#10b981'; icon = 'check_circle'; }
        else if (message.includes('[*]') || message.includes('[BLOCKED]')) { color = '#3b82f6'; icon = 'info'; }

        const cleaned = message
            .replace(/\[\!\]|\[x\]|\[✓\]|\[\+\]|\[\*\]|\[STAGE\]|\[SUCCESS\]|\[BLOCKED\]/g, '')
            .trim();

        line.innerHTML = `
            <div class="log-time">${timeStr}</div>
            <div class="log-content" style="color: ${color}; display: flex; align-items: center; gap: 8px;">
                <span class="material-symbols-outlined" style="font-size: 0.9rem; opacity: 0.6;">${icon}</span>
                <span>${cleaned.toUpperCase()}</span>
            </div>
        `;

        elements.logOutput.appendChild(line);
        elements.logOutput.scrollTop = elements.logOutput.scrollHeight;
    }

    function setStatus(text, type = 'ready') {
        if (!elements.scanStatus) return;
        elements.scanStatus.textContent = text.toUpperCase();

        const badge = elements.scanStatus.closest?.('.badge-pill') || elements.scanStatus.parentElement;
        if (type === 'busy') {
            badge.style.background = 'rgba(234, 179, 8, 0.1)';
            badge.style.borderColor = 'rgba(234, 179, 8, 0.3)';
            badge.style.color = '#eab308';
        } else if (type === 'success') {
            badge.style.background = 'rgba(16, 185, 129, 0.1)';
            badge.style.borderColor = 'rgba(16, 185, 129, 0.3)';
            badge.style.color = '#10b981';
        } else if (type === 'error') {
            badge.style.background = 'rgba(239, 68, 68, 0.1)';
            badge.style.borderColor = 'rgba(239, 68, 68, 0.3)';
            badge.style.color = '#ef4444';
        } else {
            badge.style.background = '';
            badge.style.borderColor = '';
            badge.style.color = '';
        }
    }

    function enableReportButtons(target) {
        elements.downloadReportBtn.disabled = false;
        elements.downloadReportBtn.style.opacity = '1';
        if (elements.downloadJsonBtn) {
            elements.downloadJsonBtn.disabled = false;
            elements.downloadJsonBtn.style.opacity = '1';
        }

        // Wire up downloads
        elements.downloadReportBtn.onclick = () => {
            window.location.href = `${API_BASE_URL}/download_pdf?target=${encodeURIComponent(target)}`;
        };
        if (elements.downloadJsonBtn) {
            elements.downloadJsonBtn.onclick = () => {
                window.location.href = `${API_BASE_URL}/get_json_report?target=${encodeURIComponent(target)}`;
            };
        }
    }

    function updateIntelPanel(target, stats) {
        if (elements.intelTargetDisplay) elements.intelTargetDisplay.textContent = target || '---';
        if (elements.intelStatusDisplay) {
            elements.intelStatusDisplay.textContent = isActionInProgress ? 'SCANNING...' : 'COMPLETE';
            elements.intelStatusDisplay.style.color = isActionInProgress ? '#eab308' : '#10b981';
        }

        if (stats) {
            if (elements.intelDomainCount) elements.intelDomainCount.textContent = stats.domains || 0;
            if (elements.intelSubdomainCount) elements.intelSubdomainCount.textContent = stats.subdomains || 0;
        }

        // Trigger posture summary update if target exists
        if (target) {
            updatePostureSummary();
        }
    }

    async function updatePostureSummary() {
        try {
            // 1. Mail Posture
            const mailRes = await fetch(`${API_BASE_URL}/mail_posture_summary`);
            if (mailRes.ok) {
                const md = await mailRes.json();
                if (md.total > 0) {
                    const passRate = (md.spf_pass + md.dmarc_pass) / (md.total * 2);
                    if (passRate >= 1) setPostureBadge(elements.mailPostureBadge, 'SECURE', 'success');
                    else if (passRate >= 0.5) setPostureBadge(elements.mailPostureBadge, 'PARTIAL', 'warning');
                    else setPostureBadge(elements.mailPostureBadge, 'RISK', 'danger');
                }
            }

            // 2. SSL Digest
            const sslRes = await fetch(`${API_BASE_URL}/ssl_digest`);
            if (sslRes.ok) {
                const sd = await sslRes.json();
                const totalCerts = sd.counts.Valid + sd.counts["Expiring Soon"] + sd.counts.Expired;
                if (totalCerts > 0) {
                    if (sd.counts.Expired > 0) setPostureBadge(elements.sslPostureBadge, `${sd.counts.Expired} EXPIRED`, 'danger');
                    else if (sd.counts["Expiring Soon"] > 0) setPostureBadge(elements.sslPostureBadge, `${sd.counts["Expiring Soon"]} EXPIRING`, 'warning');
                    else setPostureBadge(elements.sslPostureBadge, 'HEALTHY', 'success');
                } else {
                    setPostureBadge(elements.sslPostureBadge, 'NO SSL', 'neutral');
                }
            }

            // 3. Cloud Exposure
            const cloudRes = await fetch(`${API_BASE_URL}/cloud_exposure`);
            if (cloudRes.ok) {
                const cd = await cloudRes.json();
                if (cd.total > 0) {
                    setPostureBadge(elements.cloudPostureBadge, `${cd.total} EXPOSURES`, 'danger');
                } else {
                    setPostureBadge(elements.cloudPostureBadge, 'NONE', 'success');
                }
            }
        } catch (err) {
            console.error('Posture update failed:', err);
        }
    }

    function setPostureBadge(el, text, type) {
        if (!el) return;
        const classMap = {
            'success': 'posture-chip chip-success',
            'warning': 'posture-chip chip-warning',
            'danger':  'posture-chip chip-danger',
            'neutral': 'posture-chip chip-neutral',
        };
        // Preserve the icon span, just update the text node
        const icon = el.querySelector('.material-symbols-outlined');
        el.textContent = text.toUpperCase();
        if (icon) el.prepend(icon);
        el.className = classMap[type] || 'posture-chip chip-neutral';
    }

    // ─────────────────────────────────────────────
    // Asset Card Rendering
    // ─────────────────────────────────────────────

    function formatTechStack(techObj) {
        if (!techObj) return 'GENERAL HTTP/S';
        let techItems = [];
        if (typeof techObj === 'object') {
            for (const [key, val] of Object.entries(techObj)) {
                if (['endpoints', 'forms', 'cloud_assets', 'ssl_detail'].includes(key)) continue;
                if (typeof val === 'string' && val.trim()) {
                    techItems.push(val.trim());
                } else if (Array.isArray(val) && val.length > 0) {
                    const strVals = val.filter(v => typeof v === 'string' && v.trim());
                    if (strVals.length > 0) techItems.push(...strVals);
                } else if (typeof val === 'object' && val !== null) {
                    const subVals = Object.values(val).filter(v => typeof v === 'string' && v.trim());
                    if (subVals.length > 0) techItems.push(...subVals);
                }
            }
        } else if (typeof techObj === 'string' && techObj.trim()) {
            techItems.push(techObj.trim());
        }
        return techItems.length > 0 ? techItems.join(', ') : 'GENERAL HTTP/S';
    }

    function renderAssetCard(asset, index = 0) {
        const critScore = asset.criticality || 0;
        const critPct = Math.min(100, (critScore / 10) * 100);

        let riskClass = 'risk-safe';
        if (critScore >= 8) { riskClass = 'risk-critical'; }
        else if (critScore >= 6) { riskClass = 'risk-high'; }
        else if (critScore >= 4) { riskClass = 'risk-medium'; }
        else if (critScore >= 2) { riskClass = 'risk-low'; }

        const d = asset.details || {};
        const ip = d.ip || '—';
        const formattedTech = formatTechStack(d.tech);

        // Posture Indicators
        const ssl = d.ssl || {};
        const mail = d.mail_posture || {};
        const cloud = d.cloud_exposure || [];

        const sslClass = ssl.status === 'Valid' ? 'active-success' : (ssl.status === 'No SSL' ? '' : 'active-danger');
        const mailClass = mail.spf && mail.dmarc ? 'active-success' : (mail.spf || mail.dmarc ? 'active-warning' : '');
        const cloudClass = cloud && cloud.length > 0 ? 'active-danger' : '';

        // Badges
        const endpointCount = d.tech?.endpoints?.length || 0;
        const formCount = d.tech?.forms?.length || 0;
        const versionInfo = d.tech?.versions ? Object.entries(d.tech.versions).map(([k,v]) => `${k} v${v}`).join(', ') : '';

        const iconName = asset.type === 'domain' ? 'domain' : 'lan';
        const typeLabel = asset.type ? asset.type.toUpperCase() : 'ASSET';

        let badgesHtml = '';
        if (endpointCount > 0) {
            badgesHtml += `<span class="badge-pill" style="font-size: 0.55rem; padding: 2px 6px;">${endpointCount} ENDPOINTS</span>`;
        }
        if (formCount > 0) {
            badgesHtml += `<span class="badge-pill" style="font-size: 0.55rem; padding: 2px 6px;">${formCount} FORMS</span>`;
        }
        if (versionInfo) {
            badgesHtml += `<span class="badge-pill" style="font-size: 0.55rem; padding: 2px 6px;">${escapeHtml(versionInfo)}</span>`;
        }

        const card = document.createElement('div');
        card.className = `discovery-card ${riskClass} animate-card`;
        card.style.animationDelay = `${index * 0.05}s`;
        card.innerHTML = `
            <div class="card-header">
                <div class="asset-badge">
                    <span class="material-symbols-outlined" style="font-size: 1.3rem; color: var(--card-accent); margin-bottom: 2px;">${iconName}</span>
                    <span class="protocol-label" style="color: var(--card-accent); opacity: 0.9;">${typeLabel}</span>
                </div>
                <div class="service-main" style="text-align: right; overflow: hidden; flex: 1; margin-left: 0.75rem;">
                    <span class="service-title" style="word-break: break-all; line-height: 1.2;" title="${escapeHtml(asset.value)}">${escapeHtml(asset.value)}</span>
                    <span class="service-ver">IP ${escapeHtml(ip)}</span>
                </div>
            </div>

            <div class="risk-section">
                <div class="risk-header">
                    <span style="color: var(--neo-text-muted);">CRITICALITY SCORE</span>
                    <span class="risk-val" style="font-family: var(--font-mono); color: var(--card-accent); font-weight: 800;">${critScore.toFixed(1)} / 10.0</span>
                </div>
                <div class="risk-score-bar">
                    <div class="risk-score-fill" style="width: ${critPct}%;"></div>
                </div>
            </div>

            ${badgesHtml ? `<div style="display: flex; gap: 0.35rem; flex-wrap: wrap; margin-top: -0.25rem;">${badgesHtml}</div>` : ''}

            <div class="analysis-footer">
                <div style="margin-bottom: 0.35rem;"><span style="color: var(--card-accent); font-weight: 800; font-size: 0.6rem;">[TECH STACK] </span>${escapeHtml(formattedTech)}</div>
                <div style="display: flex; justify-content: space-between; align-items: center; padding-top: 0.35rem; border-top: 1px dashed var(--neo-border);">
                    <span style="font-size: 0.6rem; color: var(--neo-text-muted); font-weight: 700;">POSTURE</span>
                    <div style="display: flex; gap: 8px;">
                        <span class="material-symbols-outlined posture-mini-icon ${sslClass}" style="font-size: 1rem;" title="SSL: ${ssl.status || 'Unknown'}">verified_user</span>
                        <span class="material-symbols-outlined posture-mini-icon ${mailClass}" style="font-size: 1rem;" title="Mail: ${mail.spf ? 'SPF-READY' : 'EXPOSED'}">alternate_email</span>
                        <span class="material-symbols-outlined posture-mini-icon ${cloudClass}" style="font-size: 1rem;" title="Cloud Exposure: ${cloud.length || 0}">cloud</span>
                    </div>
                </div>
            </div>
        `;

        card.addEventListener('click', () => openAssetDetail(asset.value));
        return card;
    }

    function renderInventory(assets) {
        if (!elements.assetCardGrid) return;
        
        // Cache assets if provided (usually from API)
        if (assets) {
            cachedAssets = assets;
        }

        elements.assetCardGrid.innerHTML = '';

        // Apply Filtering based on currentCategory
        let filtered = [...cachedAssets];
        if (currentCategory === 'domains') {
            filtered = filtered.filter(a => a.type === 'domain');
        } else if (currentCategory === 'subdomains') {
            filtered = filtered.filter(a => a.type === 'subdomain');
        } else if (currentCategory === 'endpoints') {
            filtered = filtered.filter(a => {
                const endpoints = a.details?.tech?.endpoints || [];
                const forms = a.details?.tech?.forms || [];
                return endpoints.length > 0 || forms.length > 0;
            });
        } else if (currentCategory === 'techStack') {
            filtered = filtered.filter(a => {
                const tech = a.details?.tech || {};
                return tech.CMS || tech.versions || tech.Framework || tech.Language;
            });
        }

        if (filtered.length === 0) {
            const msg = currentCategory === 'all' ? 'NO ASSETS DISCOVERED YET' : `NO ASSETS FOUND IN ${currentCategory.toUpperCase()} CATEGORY`;
            elements.assetCardGrid.innerHTML = `
                <div class="empty-state">
                    <div style="position: relative; width: 64px; height: 64px; display: flex; align-items: center; justify-content: center; opacity: 0.35;">
                        <span class="material-symbols-outlined" style="font-size: 2.5rem; color: var(--neo-text-muted); position: relative; z-index: 2;">inventory_2</span>
                    </div>
                    <div style="font-family: var(--font-mono); font-size: 0.85rem; color: var(--neo-text-muted); text-transform: uppercase; letter-spacing: 0.2em; text-align: center;">
                        ${msg}
                    </div>
                </div>`;
            return;
        }

        // Sort: domains first, then by criticality desc
        filtered.sort((a, b) => {
            if (a.type === 'domain' && b.type !== 'domain') return -1;
            if (b.type === 'domain' && a.type !== 'domain') return 1;
            return (b.criticality || 0) - (a.criticality || 0);
        });

        filtered.forEach((asset, index) => {
            elements.assetCardGrid.appendChild(renderAssetCard(asset, index));
        });
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    // ─────────────────────────────────────────────
    // Tab Switching
    // ─────────────────────────────────────────────

    async function switchTab(category) {
        currentCategory = category;
        
        // Update button active states
        const tabs = [
            { id: 'all', btn: elements.inventoryTabBtn },
            { id: 'domains', btn: elements.domainsTabBtn },
            { id: 'subdomains', btn: elements.subdomainsTabBtn },
            { id: 'endpoints', btn: elements.endpointsTabBtn },
            { id: 'techStack', btn: elements.techStackTabBtn },
            { id: 'json', btn: elements.jsonTabBtn }
        ];

        tabs.forEach(t => {
            if (t.id === category) t.btn?.classList.add('active');
            else t.btn?.classList.remove('active');
        });

        // Content visibility
        if (category === 'json') {
            if (elements.inventoryContent) elements.inventoryContent.style.display = 'none';
            if (elements.jsonContent) elements.jsonContent.style.display = 'flex';
            if (currentTarget) {
                await loadJsonViewer();
            }
        } else {
            if (elements.jsonContent) elements.jsonContent.style.display = 'none';
            if (elements.inventoryContent) elements.inventoryContent.style.display = 'block';
            // Re-render inventory with filter
            renderInventory();
        }
    }

    async function loadJsonViewer() {
        if (!currentTarget || !elements.jsonViewer) return;
        elements.jsonViewer.textContent = "// LOADING RAW INTELLIGENCE...";
        try {
            const res = await fetch(`${API_BASE_URL}/get_json_report?target=${encodeURIComponent(currentTarget)}`);
            if (res.ok) {
                const data = await res.json();
                elements.jsonViewer.textContent = JSON.stringify(data, null, 4);
            } else {
                elements.jsonViewer.textContent = "// NO REPORT FOUND FOR THIS TARGET";
            }
        } catch (e) {
            elements.jsonViewer.textContent = "// FAILED TO LOAD JSON DATA";
        }
    }

    elements.inventoryTabBtn?.addEventListener('click', () => switchTab('all'));
    elements.domainsTabBtn?.addEventListener('click', () => switchTab('domains'));
    elements.subdomainsTabBtn?.addEventListener('click', () => switchTab('subdomains'));
    elements.endpointsTabBtn?.addEventListener('click', () => switchTab('endpoints'));
    elements.techStackTabBtn?.addEventListener('click', () => switchTab('techStack'));
    elements.jsonTabBtn?.addEventListener('click', () => switchTab('json'));

    elements.copyJsonBtn?.addEventListener('click', () => {
        const text = elements.jsonViewer?.textContent;
        if (text) {
            navigator.clipboard.writeText(text);
            const originalText = elements.copyJsonBtn.innerHTML;
            elements.copyJsonBtn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 0.9rem;">check</span> COPIED';
            setTimeout(() => elements.copyJsonBtn.innerHTML = originalText, 2000);
        }
    });

    // ─────────────────────────────────────────────
    // Deep Intel Side Panel Logic
    // ─────────────────────────────────────────────

    function openAssetDetail(value) {
        const asset = cachedAssets.find(a => a.value === value);
        if (!asset) return;

        elements.drawerAssetTitle.textContent = asset.value.toUpperCase();
        elements.drawerAssetType.textContent = (asset.type || 'subdomain').toUpperCase().replace('_', ' ');
        elements.drawerAssetIcon.style.color = asset.type === 'domain' ? 'var(--neo-blue)' : 'var(--neo-green)';

        const d = asset.details || {};
        const tech = d.tech || {};
        const dns = d.dns || {};
        const ssl = d.ssl || {};
        const mail = d.mail_posture || {};
        const whois = {
            registrar: d.registrar || '—',
            created: d.created || '—',
            expires: d.expires || '—'
        };

        let html = '';

        // SECTION 1: NETWORK & INFRASTRUCTURE
        html += `
        <div class="intel-section">
            <div class="section-label"><span class="material-symbols-outlined" style="font-size:1rem;">router</span> NETWORK INFRASTRUCTURE</div>
            <div class="data-grid">
                <div class="data-item"><span class="data-label">Primary IP</span><span class="data-value">${escapeHtml(d.ip || '—')}</span></div>
                <div class="data-item"><span class="data-label">ASN / Provider</span><span class="data-value">${escapeHtml(d.asn || '—')}</span></div>
                <div class="data-item"><span class="data-label">Disc. Method</span><span class="data-value">${escapeHtml(asset.discovery_method || 'automated')}</span></div>
                <div class="data-item"><span class="data-label">Last Seen</span><span class="data-value">${asset.last_seen ? new Date(asset.last_seen).toLocaleDateString() : '—'}</span></div>
            </div>
        </div>`;

        // SECTION 2: WHOIS & DOMAIN GOVERNANCE
        html += `
        <div class="intel-section">
            <div class="section-label"><span class="material-symbols-outlined" style="font-size:1rem;">badge</span> DOMAIN GOVERNANCE</div>
            <div class="data-grid">
                <div class="data-item"><span class="data-label">Registrar</span><span class="data-value">${escapeHtml(whois.registrar)}</span></div>
                <div class="data-item"><span class="data-label">Created At</span><span class="data-value">${escapeHtml(whois.created)}</span></div>
                <div class="data-item"><span class="data-label">Expiry Date</span><span class="data-value">${escapeHtml(whois.expires)}</span></div>
                <div class="data-item"><span class="data-label">Criticality</span><span class="data-value" style="color:${getCriticalityColor(asset.criticality || 0)}">${(asset.criticality || 0).toFixed(1)} / 10.0</span></div>
            </div>
        </div>`;

        // SECTION 3: DNS ARCHITECTURE
        let dnsHtml = '';
        const dnsTypes = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'];
        dnsTypes.forEach(type => {
            const records = dns[type] || [];
            if (records.length > 0) {
                dnsHtml += `<div class="dns-group"><div class="dns-type" style="font-size: 0.6rem; font-weight: 800; color: var(--neo-blue); margin-bottom: 4px; border-bottom: 1px solid rgba(59, 130, 246, 0.2);">${type} RECORDS</div>`;
                records.forEach(r => {
                    dnsHtml += `<div class="dns-record" style="font-family: var(--font-mono); font-size: 0.65rem; color: var(--neo-text-secondary); margin-bottom: 2px;">${escapeHtml(r)}</div>`;
                });
                dnsHtml += `</div>`;
            }
        });

        if (dnsHtml) {
            html += `
            <div class="intel-section">
                <div class="section-label"><span class="material-symbols-outlined" style="font-size:1rem;">lan</span> DNS INFRASTRUCTURE</div>
                <div class="data-item" style="background: rgba(0,0,0,0.2); padding: 0.75rem;">
                    ${dnsHtml}
                </div>
            </div>`;
        }

        // SECTION 4: SECURITY POSTURE (SSL & MAIL)
        html += `
        <div class="intel-section">
            <div class="section-label"><span class="material-symbols-outlined" style="font-size:1rem;">verified_user</span> SECURITY POSTURE</div>
            <div class="data-grid">
                <div class="data-item">
                    <span class="data-label">SSL Status</span>
                    <span class="data-value" style="color: ${ssl.status === 'Valid' ? 'var(--neo-green)' : 'var(--neo-red)'}">${escapeHtml(ssl.status || 'Unknown')}</span>
                </div>
                <div class="data-item"><span class="data-label">SSL Expiry</span><span class="data-value">${ssl.expiry_date || '—'}</span></div>
                <div class="data-item"><span class="data-label">SSL Issuer</span><span class="data-value">${escapeHtml(ssl.issuer || '—')}</span></div>
                <div class="data-item"><span class="data-label">SSL Days Left</span><span class="data-value">${ssl.days_remaining || '—'}</span></div>
            </div>

            <div class="data-grid" style="margin-top: 8px;">
                <div class="data-item"><span class="data-label">SPF Integrity</span><span class="data-value" style="color: ${mail.spf ? 'var(--neo-green)' : 'var(--neo-red)'}">${mail.spf ? 'PASSED' : 'MISSING'}</span></div>
                <div class="data-item"><span class="data-label">DMARC Policy</span><span class="data-value" style="color: ${mail.dmarc ? 'var(--neo-green)' : 'var(--neo-red)'}">${mail.dmarc ? 'PASSED' : 'MISSING'}</span></div>
                <div class="data-item"><span class="data-label">DKIM Sign.</span><span class="data-value" style="color: ${mail.dkim ? 'var(--neo-green)' : 'var(--neo-muted)'}">${mail.dkim ? 'PASSED' : 'UNKNOWN'}</span></div>
                <div class="data-item"><span class="data-label">MX Servers</span><span class="data-value">${mail.mx_count || 0} SEVER(S)</span></div>
            </div>

            ${mail.spf_record ? `
            <div class="data-item" style="margin-top: 8px;">
                <span class="data-label">SPF RECORD</span>
                <span class="data-value" style="font-size: 0.6rem; opacity: 0.7; font-family: var(--font-mono);">${escapeHtml(mail.spf_record)}</span>
            </div>` : ''}
            
            ${mail.dmarc_record ? `
            <div class="data-item" style="margin-top: 4px;">
                <span class="data-label">DMARC RECORD</span>
                <span class="data-value" style="font-size: 0.6rem; opacity: 0.7; font-family: var(--font-mono);">${escapeHtml(mail.dmarc_record)}</span>
            </div>` : ''}
        </div>`;

        // SECTION 5: CLOUD EXPOSURE
        const cloud = d.cloud_exposure || [];
        if (cloud && cloud.length > 0) {
            html += `
            <div class="intel-section">
                <div class="section-label"><span class="material-symbols-outlined" style="font-size:1rem;">cloud_done</span> CLOUD EXPOSURE</div>
                <div class="endpoint-list" style="border-color: var(--neo-red);">
                    ${cloud.map(c => `<div class="endpoint-item" style="color: var(--neo-red); font-weight: 600;">DETECTED: ${escapeHtml(c)}</div>`).join('')}
                </div>
            </div>`;
        }

        // SECTION 6: TECHNOLOGY STACK
        let stackHtml = '';
        if (tech) {
            const items = [
                { label: 'Server', val: tech.Server },
                { label: 'CMS', val: tech.CMS },
                { label: 'Framework', val: tech.Framework },
                { label: 'Language', val: tech.Language }
            ];
            items.forEach(i => {
                if (i.val) stackHtml += `<div class="data-item"><span class="data-label">${i.label}</span><span class="data-value">${Array.isArray(i.val) ? i.val.join(', ') : i.val}</span></div>`;
            });

            if (tech.versions) {
                Object.entries(tech.versions).forEach(([app, ver]) => {
                    stackHtml += `<div class="data-item" style="border-color: var(--neo-amber);"><span class="data-label" style="color:var(--neo-amber)">${app} Version</span><span class="data-value">${ver}</span></div>`;
                });
            }
        }

        if (stackHtml) {
            html += `
            <div class="intel-section">
                <div class="section-label"><span class="material-symbols-outlined" style="font-size:1rem;">settings_ethernet</span> FINGERPRINTED TECH STACK</div>
                <div class="data-grid">
                    ${stackHtml}
                </div>
            </div>`;
        }

        // SECTION 7: CRAWLER FINDINGS (ENDPOINTS, FORMS, SENSITIVE PATHS)
        const endpoints = tech.endpoints || [];
        const forms = tech.forms || [];
        const sensitive = tech.sensitive_paths || [];

        if (endpoints.length > 0 || forms.length > 0 || sensitive.length > 0) {
            html += `
            <div class="intel-section">
                ${sensitive.length > 0 ? `
                    <div class="section-label" style="color: var(--neo-red);"><span class="material-symbols-outlined" style="font-size:1rem;">warning</span> SENSITIVE PATHS DETECTED (${sensitive.length})</div>
                    <div class="endpoint-list" style="border-color: var(--neo-red); margin-bottom: 8px;">
                        ${sensitive.map(s => `<div class="endpoint-item" style="color: var(--neo-red); font-weight: 600;">EXPOSED: ${escapeHtml(s)}</div>`).join('')}
                    </div>
                ` : ''}

                <div class="section-label"><span class="material-symbols-outlined" style="font-size:1rem;">link</span> CRAWLER ENDPOINTS (${endpoints.length})</div>
                <div class="endpoint-list">
                    ${endpoints.map(e => `<div class="endpoint-item" title="${escapeHtml(e)}">${escapeHtml(e)}</div>`).join('')}
                </div>

                ${forms.length > 0 ? `
                    <div class="section-label" style="margin-top: 8px;"><span class="material-symbols-outlined" style="font-size:1rem;">input</span> INPUT FORMS (${forms.length})</div>
                    <div class="endpoint-list" style="max-height: 100px;">
                        ${forms.map(f => `<div class="endpoint-item" style="color: var(--neo-green);">${escapeHtml(f)}</div>`).join('')}
                    </div>
                ` : ''}
            </div>`;
        }

        elements.drawerContent.innerHTML = html;
        elements.intelDrawer.classList.add('active');
        elements.intelDrawerOverlay.classList.add('active');
    }

    function closeIntelDrawer() {
        elements.intelDrawer?.classList.remove('active');
        elements.intelDrawerOverlay?.classList.remove('active');
    }

    elements.closeIntelDrawer?.addEventListener('click', closeIntelDrawer);
    elements.intelDrawerOverlay?.addEventListener('click', closeIntelDrawer);

    // ─────────────────────────────────────────────
    // API Interactions
    // ─────────────────────────────────────────────

    async function initDashboard() {
        try {
            const response = await fetch(`${API_BASE_URL}/init_data`);
            const data = await response.json();

            if (data.stats) {
                elements.totalAssetsCount.textContent = data.stats.total || 0;
                elements.subdomainCount.textContent    = data.stats.subdomains || 0;
                elements.rootDomainCount.textContent   = data.stats.domains || 0;
                updateIntelPanel(null, data.stats);
            }

            if (data.is_running) {
                setStatus('DISCOVERY IN PROGRESS', 'busy');
                toggleSpinner(true);
                setupSSE();
            }

            if (data.latest_discovery && data.latest_discovery.length > 0) {
                const latest = data.latest_discovery[0];
                if (latest.value) {
                    currentTarget = data.latest_discovery.find(d => d.type === 'domain')?.value || latest.value;
                    elements.targetDisplay.textContent = currentTarget.toUpperCase();
                    enableReportButtons(currentTarget);
                    updateIntelPanel(currentTarget, data.stats);
                }
            }

            // Load inventory on init
            await loadAssetInventory();

        } catch (error) {
            console.error('Initial data fetch failed:', error);
        }
    }

    async function loadAssetInventory() {
        try {
            const response = await fetch(`${API_BASE_URL}/assets`);
            const data = await response.json();
            if (data.assets) {
                renderInventory(data.assets);
            }
        } catch (err) {
            console.error('Failed to load asset inventory:', err);
        }
    }

    function setupSSE() {
        if (eventSource) eventSource.close();
        appendLog('[*] SSE stream connected. Monitoring discovery engine...');
        eventSource = new EventSource(`${API_BASE_URL}/log_stream`);

        eventSource.onmessage = async (event) => {
            const data = event.data.trim();
            if (!data) return;

            if (data.includes('SYSTEM_EVENT: READY_FOR_ANALYSIS')) {
                appendLog('[✓] Discovery & enrichment pipeline complete. Loading inventory...');
                setStatus('COMPLETE', 'success');
                toggleSpinner(false);
                eventSource.close();
                eventSource = null;
                await initDashboard();
                if (currentTarget) enableReportButtons(currentTarget);
                return;
            }

            if (data.includes('DISCOVERY_COMPLETE') || data.includes('PDF generated') || data.includes('complete')) {
                appendLog('[✓] Discovery sequence finalized.');
                setStatus('SYNC READY', 'success');
                toggleSpinner(false);
                eventSource.close();
                eventSource = null;
                await initDashboard();
                return;
            }

            appendLog(data);
        };

        eventSource.onerror = () => {
            if (isActionInProgress) {
                appendLog('[!] SSE stream interrupted. Retrying...');
            }
            eventSource?.close();
            eventSource = null;
        };
    }

    async function startDiscovery(domain, userConfirmed = false) {
        if (isActionInProgress) return;

        toggleSpinner(true);
        setStatus('DISCOVERY INITIATED', 'busy');
        currentTarget = domain;
        elements.targetDisplay.textContent = domain.toUpperCase();
        updateIntelPanel(domain, null);
        elements.assetCardGrid.innerHTML = `
            <div class="empty-state">
                <div style="position: relative; width: 64px; height: 64px; display: flex; align-items: center; justify-content: center;">
                    <span class="material-symbols-outlined" style="font-size: 2rem; color: var(--neo-blue); position: relative; z-index: 2; animation: text-fade 1.5s ease-in-out infinite alternate;">explore</span>
                </div>
                <div style="font-family: var(--font-mono); font-size: 0.85rem; color: var(--neo-text-muted); text-transform: uppercase; letter-spacing: 0.2em; text-align: center;">
                    RUNNING DISCOVERY ENGINES...
                </div>
            </div>`;
        appendLog(`[*] Target Domain: ${domain}`);

        try {
            const response = await fetch(`${API_BASE_URL}/discover`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({
                    domain: domain,
                    user_confirmed_auth: userConfirmed
                })
            });

            const data = await response.json();

            if (response.status === 403 && data.status === 'auth_required') {
                showAuthModal(data.message, () => startDiscovery(domain, true));
                toggleSpinner(false);
                return;
            }

            if (response.status === 403 && data.status === 'blocked') {
                showBlockedModal(data.message);
                toggleSpinner(false);
                setStatus('SCAN BLOCKED', 'error');
                appendLog(`[!] ${data.message}`);
                return;
            }

            if (data.status === 'success') {
                appendLog(`[✓] ${data.message}`);
                setupSSE();
            } else {
                throw new Error(data.message || 'Discovery initiation failed');
            }
        } catch (error) {
            appendLog(`[x] Error: ${error.message}`);
            setStatus('FAULT DETECTED', 'error');
            toggleSpinner(false);
        }
    }

    async function loadReportHistory() {
        if (!elements.historyTableBody) return;
        elements.historyTableBody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 2rem; color: var(--neo-text-muted);">LOADING...</td></tr>';

        try {
            const response = await fetch(`${API_BASE_URL}/report_history`);
            const data = await response.json();

            if (!data.history || data.history.length === 0) {
                elements.historyTableBody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 2rem; color: var(--neo-text-muted);">NO HISTORY FOUND</td></tr>';
                return;
            }

            elements.historyTableBody.innerHTML = '';
            data.history.forEach(item => {
                const tr = document.createElement('tr');
                const date = item.date ? new Date(item.date).toLocaleString() : '—';
                const target = item.target || '—';
                const findings = item.finding_count ?? '—';
                tr.innerHTML = `
                    <td style="color: var(--neo-text-muted);">${date}</td>
                    <td style="font-family: var(--font-mono); color: var(--neo-blue);">${escapeHtml(target)}</td>
                    <td style="color: var(--neo-green);">${findings}</td>
                    <td style="text-align: right;">
                        <a href="${API_BASE_URL}/download_pdf?target=${encodeURIComponent(target)}"
                           class="btn-dash btn-secondary"
                           style="height:28px; padding: 0 0.75rem; font-size: 0.65rem; display: inline-flex; align-items: center; gap: 4px; text-decoration: none;">
                            <span class="material-symbols-outlined" style="font-size: 0.9rem;">download</span>
                            PDF
                        </a>
                    </td>`;
                elements.historyTableBody.appendChild(tr);
            });
        } catch (err) {
            elements.historyTableBody.innerHTML = `<tr><td colspan="4" style="text-align: center; padding: 2rem; color: #ef4444;">ERROR LOADING HISTORY</td></tr>`;
        }
    }

    // ─────────────────────────────────────────────
    // Modal Handlers
    // ─────────────────────────────────────────────

    function showAuthModal(message, onConfirm) {
        elements.authModalMessage.textContent = message;
        elements.authModal.classList.remove('hidden');

        elements.confirmAuthBtn.onclick = () => {
            elements.authModal.classList.add('hidden');
            onConfirm();
        };
        elements.cancelAuthBtn.onclick = () => {
            elements.authModal.classList.add('hidden');
            toggleSpinner(false);
            setStatus('SYNC READY');
        };
    }

    function showBlockedModal(message) {
        elements.blockedModalMessage.textContent = message;
        elements.blockedModal.classList.remove('hidden');
        elements.closeBlockedModalBtn.onclick = () => {
            elements.blockedModal.classList.add('hidden');
        };
    }

    // ─────────────────────────────────────────────
    // Event Listeners
    // ─────────────────────────────────────────────

    elements.startDiscoveryBtn?.addEventListener('click', () => {
        const domain = elements.targetDomainInput?.value.trim();
        if (!domain) {
            appendLog('[!] Error: Primary domain identifier required.');
            elements.targetDomainInput?.focus();
            return;
        }
        startDiscovery(domain);
    });

    elements.targetDomainInput?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') elements.startDiscoveryBtn?.click();
    });

    elements.clearLogBtn?.addEventListener('click', () => {
        if (elements.logOutput) elements.logOutput.innerHTML = '';
        rawLogLines = [];
        appendLog('[*] Console buffer cleared.');
    });

    elements.refreshResultsBtn?.addEventListener('click', async () => {
        elements.refreshResultsBtn.classList.add('opacity-50');
        elements.refreshResultsBtn.disabled = true;
        await loadAssetInventory();
        await fetch(`${API_BASE_URL}/init_data`)
            .then(r => r.json())
            .then(data => {
                if (data.stats) {
                    elements.totalAssetsCount.textContent = data.stats.total || 0;
                    elements.subdomainCount.textContent    = data.stats.subdomains || 0;
                    elements.rootDomainCount.textContent   = data.stats.domains || 0;
                    updateIntelPanel(currentTarget, data.stats);
                }
            }).catch(() => {});
        setTimeout(() => {
            elements.refreshResultsBtn.classList.remove('opacity-50');
            elements.refreshResultsBtn.disabled = false;
        }, 800);
    });


    elements.discoveryHistoryBtn?.addEventListener('click', () => {
        elements.historyModal?.classList.remove('hidden');
        loadReportHistory();
    });

    elements.closeHistoryModal?.addEventListener('click', () => {
        elements.historyModal?.classList.add('hidden');
    });

    elements.historyModal?.addEventListener('click', (e) => {
        if (e.target === elements.historyModal) elements.historyModal.classList.add('hidden');
    });

    elements.authModal?.addEventListener('click', (e) => {
        if (e.target === elements.authModal) {
            elements.authModal.classList.add('hidden');
            toggleSpinner(false);
        }
    });

    elements.blockedModal?.addEventListener('click', (e) => {
        if (e.target === elements.blockedModal) elements.blockedModal.classList.add('hidden');
    });


    // ─────────────────────────────────────────────
    // Initialization
    // ─────────────────────────────────────────────
    initDashboard();
});
