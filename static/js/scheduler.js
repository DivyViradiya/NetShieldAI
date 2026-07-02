// ===== State =====
let moduleSchemas = {};
let moduleList = [];
let draftMissions = []; // [{ module, step, config, target, targetDesc, scheduleType, ... }]
let activeDraftIndex = -1; // Which draft is currently open in the drawer
let currentHistoryFilters = {
    jobId: null,
    scanner: 'all',
    target: '',
    isGlobal: false
};
let allProfiles = [];
window.fillRegistrationEmail = function(draftIndex) {
    if (window.USER_EMAIL) {
        window.updateDraftState(draftIndex, 'consentEmail', window.USER_EMAIL);
        const input = document.getElementById('field-consent-email');
        if (input) {
            input.value = window.USER_EMAIL;
            clearFieldError(input);
        }
    }
};

// ===== Security Utility =====
const escapeHTML = (str) => {
    if (!str) return '';
    return str.toString().replace(/[&<>'"]/g, 
        tag => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            "'": '&#39;',
            '"': '&quot;'
        }[tag])
    );
};

 
 const parseDateSafe = (dateStr) => {
     if (!dateStr) return 'N/A';
     if (typeof dateStr === 'string') {
         const hasT = dateStr.includes('T');
         const hasSpace = dateStr.includes(' ');
         const hasZ = dateStr.endsWith('Z');
         const hasOffset = /([+-]\d{2}:\d{2})$/.test(dateStr); 
         if ((hasSpace || hasT) && !hasZ && !hasOffset) {
             let clean = dateStr;
             if (hasSpace) clean = clean.replace(' ', 'T');
             return new Date(clean + 'Z').toLocaleString();
         }
     }
     return new Date(dateStr).toLocaleString();
 };



// ===== Icon / Color Maps (shared) =====
const ICON_MAP = {
    nmap: 'target',
    sql: 'database',
    zap: 'security',
    sniffer: 'wifi_tethering',
    semgrep: 'code_blocks',
    api: 'api',
    ssl: 'shield_lock',
    killchain: 'account_tree'
};

const COLOR_MAP = {
    nmap:      'var(--neo-blue)',
    sql:       'var(--neo-amber)',
    zap:       'var(--neo-red)',
    sniffer:   'var(--neo-green)',
    semgrep:   'var(--neo-purple)',
    api:       'var(--neo-cyan)',
    ssl:       'var(--neo-blue)',
    killchain: 'var(--neo-red)'
};

const MODULE_NAMES = {
    nmap: 'Nmap Scanner',
    sniffer: 'Sniffer',
    zap: 'OWASP ZAP',
    sql: 'SQLi Probe',
    api: 'API Scanner',
    semgrep: 'Semgrep SAST',
    ssl: 'SSL Audit',
    killchain: 'Kill Chain'
};

// ===== Schedule labels =====
const SCHEDULE_LABELS = {
    once:     'Run Once',
    periodic: 'Interval',
    daily:    'Daily',
    weekly:   'Weekly',
    monthly:  'Monthly',
    cron:     'Advanced Cron'
};

const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const DAY_VALUES = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];

// ===== API helpers =====
const API = '/scheduler/api';

async function apiFetch(url, opts = {}) {
    const defaults = {
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.content
        }
    };
    const res = await fetch(url, { ...defaults, ...opts });
    const data = await res.json();
    if (!res.ok) {
        throw new Error(data.message || `API error: ${res.status}`);
    }
    return data;
}

// ===== Toast =====
function toast(msg, type = 'success') {
    const el = document.createElement('div');
    el.style.cssText = `
        position: fixed; bottom: 2rem; right: 2rem; z-index: 1000;
        padding: 1rem 1.5rem; border-radius: 8px; font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem; text-transform: uppercase; display: flex; align-items: center; gap: 12px;
        background: ${type === 'success' ? 'rgba(16, 185, 129, 0.9)' : 'rgba(239, 68, 68, 0.9)'};
        color: #fff; border: 1px solid rgba(255,255,255,0.1); backdrop-filter: blur(8px);
        box-shadow: 0 8px 32px rgba(0,0,0,0.4); transition: all 0.3s ease; opacity: 0; transform: translateY(20px);
    `;
    el.innerHTML = `<span class="material-symbols-outlined">${type === 'success' ? 'check_circle' : 'error'}</span> <span>${escapeHTML(msg)}</span>`;
    document.body.appendChild(el);
    setTimeout(() => { el.style.opacity = '1'; el.style.transform = 'translateY(0)'; }, 10);
    setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateY(20px)'; setTimeout(() => el.remove(), 300); }, 3000);
}

// ===== Custom Confirm Modal =====
window.showConfirm = function({ title, message, confirmText, icon = 'warning', type = 'danger' }) {
    return new Promise((resolve) => {
        const overlay = document.getElementById('confirmOverlay');
        const titleEl = document.getElementById('confirmTitle');
        const msgEl = document.getElementById('confirmMessage');
        const iconEl = document.getElementById('modalIcon');
        const primaryBtn = document.getElementById('confirmPrimaryBtn');
        const cancelBtn = document.getElementById('confirmCancelBtn');

        if (!overlay || !primaryBtn) {
            // Fallback if elements missing
            resolve(confirm(message));
            return;
        }

        titleEl.textContent = title || 'Confirm Action';
        msgEl.textContent = message || 'Are you sure you want to proceed?';
        iconEl.textContent = icon;
        primaryBtn.textContent = confirmText || (type === 'danger' ? 'Confirm Deletion' : 'Confirm');
        
        primaryBtn.className = type === 'danger' ? 'btn-dash btn-danger' : 'btn-dash btn-primary';

        const close = (res) => {
            overlay.classList.remove('open');
            // Clean up event listeners to prevent memory leaks and double-triggers
            primaryBtn.onclick = null;
            cancelBtn.onclick = null;
            overlay.onclick = null;
            resolve(res);
        };

        primaryBtn.onclick = () => close(true);
        cancelBtn.onclick = () => close(false);
        overlay.onclick = (e) => { if (e.target === overlay) close(false); };

        overlay.classList.add('open');
    });
};

// ===== Mobile View Tab Switcher =====
window.switchMobileTab = function(tab) {
    const wrapper = document.querySelector('.dashboard-wrapper');
    const btnMissions = document.getElementById('tabBtnMissions');
    const btnArsenal = document.getElementById('tabBtnArsenal');
    
    if (!wrapper) return;
    
    if (tab === 'missions') {
        wrapper.classList.add('view-missions');
        if (btnMissions) btnMissions.classList.add('active');
        if (btnArsenal) btnArsenal.classList.remove('active');
    } else {
        wrapper.classList.remove('view-missions');
        if (btnArsenal) btnArsenal.classList.add('active');
        if (btnMissions) btnMissions.classList.remove('active');
    }
};

// ===== Load modules schema =====
async function loadModules() {
    const data = await apiFetch(`${API}/modules`);
    if (data.status === 'success') {
        moduleList = data.modules;
        moduleSchemas = data.schemas;
    }
}

// ===== CRUD: Profiles =====
async function loadProfiles() {
    const data = await apiFetch(`${API}/profiles`);
    return data.profiles || [];
}

// ===== Render Mission Canvas =====
async function renderAll() {
    allProfiles = await loadProfiles();
    const profiles = allProfiles;
    const container = document.getElementById('missionCanvas');
    const emptyState = document.getElementById('emptyState');

    if (profiles.length === 0) {
        container.innerHTML = '';
        emptyState.style.display = 'flex';
        return;
    }

    emptyState.style.display = 'none';

    // Render deployed missions + persistent drop bar at the end
    container.innerHTML = profiles.map(p => renderMissionCard(p)).join('') + renderDropBar();
}

function renderDropBar() {
    return `
        <div class="drop-zone-bar" id="persistentDropBar" onclick="if(window.innerWidth <= 1024) { switchMobileTab('arsenal'); toast('Select a module from the Arsenal to configure', 'info'); }">
            <span class="material-symbols-outlined" style="font-size: 1rem; opacity:0.5;">add_circle</span>
            Drop module here to add mission
        </div>
    `;
}

// ===== Mission Card (deployed) =====
function renderMissionCard(p) {
    const primaryModule = p.configs.length > 0 ? p.configs[0].module : 'nmap';
    const primaryTarget = p.targets.length > 0 ? p.targets[0].target_url : 'NO TARGET';
    const icon = ICON_MAP[primaryModule] || 'settings';
    const accentColor = COLOR_MAP[primaryModule] || 'var(--neo-text-muted)';

    const jobsHtml = p.jobs.map(j => {
        const isEnabled = j.is_enabled;
        const schedLabel = SCHEDULE_LABELS[j.schedule_type] || j.schedule_type?.toUpperCase();
        const nextRun = j.next_run_at ? parseDateSafe(j.next_run_at) : 'N/A';


        return `
            <div class="job-row">
                <div class="flex items-center gap-2">
                    <span class="material-symbols-outlined" style="font-size: 0.9rem; color: ${accentColor};">schedule</span>
                    <span style="font-size: 0.65rem; font-family: var(--font-mono);">${escapeHTML(schedLabel)}</span>
                    <span style="font-size: 0.6rem; color: var(--neo-text-muted); font-family: var(--font-mono);">▸ ${escapeHTML(nextRun)}</span>
                </div>
                <div class="flex items-center gap-2">
                    <button class="btn-dash btn-icon" title="${isEnabled ? 'Pause schedule' : 'Resume schedule'}" onclick="toggleJob(${j.id}, this)" style="color: ${isEnabled ? 'var(--neo-green)' : 'var(--neo-text-muted)'}; border-color: ${isEnabled ? 'rgba(52,211,153,0.3)' : 'var(--neo-border)'};">
                        <span class="material-symbols-outlined" style="font-size: 0.95rem;">${isEnabled ? 'pause' : 'play_arrow'}</span>
                    </button>
                    <button class="btn-dash btn-icon btn-danger" title="Remove schedule" onclick="deleteJob(${j.id})">
                        <span class="material-symbols-outlined" style="font-size: 0.95rem;">close</span>
                    </button>
                </div>
            </div>
        `;
    }).join('') || `<p style="font-size: 0.65rem; color: var(--neo-text-muted); text-align: center; padding: 0.5rem 0;">No active schedules</p>`;

    // Determine overall card status (any enabled job = active)
    const anyEnabled = p.jobs.some(j => j.is_enabled);
    const pillClass = anyEnabled ? 'active' : 'paused';
    const pillLabel = anyEnabled ? 'Active' : 'Paused';
    const hasPendingConsent = p.targets?.some(t => t.consent_pending);

    return `
        <div class="mission-card fade-in" id="profile-${p.id}">
            <div class="mission-header" style="margin-bottom: 0.3rem;">
                <div style="flex:1; padding-left: 0.4rem;">
                    <div style="display:flex; align-items:center; gap: 0.4rem; margin-bottom: 0.1rem;">
                        <div class="mission-title" style="color: ${accentColor}; font-size: 0.8rem;">${escapeHTML(p.name).toUpperCase()}</div>
                        ${p.jobs.length > 0 ? `<span class="status-pill ${pillClass}" style="padding: 1px 5px; font-size: 0.5rem;"><span class="status-dot" style="width:3px; height:3px;"></span>${escapeHTML(pillLabel)}</span>` : ''}
                        ${hasPendingConsent ? `<span class="status-pill" style="padding: 1px 5px; font-size: 0.5rem; color: var(--neo-amber); background: rgba(245,158,11,0.1); border: 1px solid rgba(245,158,11,0.25);"><span class="status-dot" style="background:var(--neo-amber); width:4px; height:4px; animation:blink 1s infinite;"></span>Awaiting Consent</span>` : ''}
                    </div>
                    <div class="mission-target" style="font-size: 0.65rem; margin-bottom: 0.3rem;">${escapeHTML(primaryTarget)}</div>
                </div>
                <div class="template-icon" style="width: 24px; height: 24px; color: ${accentColor}; background: ${accentColor}15; border: 1px solid ${accentColor}33; flex-shrink:0;">
                    <span class="material-symbols-outlined" style="font-size: 0.9rem;">${icon}</span>
                </div>
            </div>
            <p style="font-size: 0.68rem; color: var(--neo-text-muted); min-height: 1rem; margin-bottom: 0.5rem; padding-left: 0.4rem; line-height: 1.3;">${escapeHTML(p.description) || 'Continuous monitoring of infrastructure endpoints.'}</p>
            <div style="background: var(--neo-bg); opacity: 0.8; padding: 0.3rem; border-radius: 5px; border: 1px solid var(--neo-border); margin-bottom: 0.5rem;">
                ${jobsHtml}
            </div>
            <div class="mission-actions" style="gap: 0.3rem;">
                <button class="btn-dash btn-danger" onclick="deleteProfile(${p.id})" style="padding: 0 0.5rem;" title="Delete Profile">
                    <span class="material-symbols-outlined" style="font-size:0.8rem;">delete</span>
                </button>
                <button class="btn-dash" onclick="editMission(${p.id})" style="padding: 0 0.5rem;" title="Edit Mission">
                    <span class="material-symbols-outlined" style="font-size:0.8rem;">edit</span>
                </button>
                <button class="btn-dash" onclick="openHistoryDrawer(${p.jobs[0]?.id || 0})" ${p.jobs.length === 0 ? 'disabled' : ''} style="flex:1; justify-content:center;">
                    <span class="material-symbols-outlined" style="font-size:0.8rem;">history</span>Logs
                </button>
                <button class="btn-dash btn-primary" id="exec-btn-${p.id}" onclick="triggerJob(${p.id})" style="flex:1.2; justify-content:center;">
                    <span class="material-symbols-outlined" style="font-size:0.8rem;">rocket_launch</span>Execute
                </button>
            </div>
        </div>
    `;
}

// ===== DRAWER =====
function openDrawer(index) {
    activeDraftIndex = index;
    document.getElementById('configDrawer').classList.add('open');
    document.getElementById('drawerOverlay').classList.add('open');
    renderDrawer();
}

function closeDrawer() {
    document.getElementById('configDrawer').classList.remove('open');
    document.getElementById('drawerOverlay').classList.remove('open');
    activeDraftIndex = -1;
    if (window.innerWidth <= 1024) {
        window.switchMobileTab('missions');
    }
}

window.openHistoryDrawer = async function(jobId) {
    currentHistoryFilters = { jobId, scanner: 'all', target: '', isGlobal: false };
    await fetchAndRenderHistory();
};

window.openGlobalReportsDrawer = async function() {
    currentHistoryFilters = { jobId: null, scanner: 'all', target: '', isGlobal: true };
    await fetchAndRenderHistory();
};

async function fetchAndRenderHistory() {
    const { jobId, scanner, target, isGlobal } = currentHistoryFilters;
    const drawer = document.getElementById('configDrawer');
    const overlay = document.getElementById('drawerOverlay');
    
    // Clear Banner for non-mission views
    const bannerEl = document.getElementById('drawerBanner');
    if (bannerEl) bannerEl.innerHTML = '';

    // Set loading state if not already open
    if (!drawer.classList.contains('open')) {
        document.getElementById('drawerModuleLabel').textContent = 'Mission Intelligence';
        document.getElementById('drawerTitle').textContent = isGlobal ? 'Intelligence Archive' : 'Mission Logs';
        document.getElementById('stepBar').innerHTML = ''; 
        document.getElementById('drawerBody').innerHTML = `
            <div style="display:flex; flex-direction:column; align-items:center; justify-content:center; height:200px; color:var(--neo-text-muted);">
                <span class="material-symbols-outlined spin" style="font-size:2rem; margin-bottom:1rem;">sync</span>
                <div style="font-family:var(--font-mono); font-size:0.7rem; text-transform:uppercase;">Retrieving Logs...</div>
            </div>
        `;
        document.getElementById('drawerFooter').innerHTML = `
            <button class="btn-dash" onclick="closeDrawer()" style="width:100%; justify-content:center;">Close</button>
        `;
        drawer.classList.add('open');
        overlay.classList.add('open');
    }

    try {
        let url = isGlobal ? `${API}/reports` : `${API}/jobs/${jobId}/history`;
        const params = new URLSearchParams();
        if (scanner !== 'all') params.append('scanner_type', scanner);
        if (target) params.append('target_q', target);
        
        const queryString = params.toString();
        if (queryString) url += `?${queryString}`;

        const data = await apiFetch(url);
        if (data.status === 'success') {
            renderHistory(data.history);
        } else {
            toast('Failed to load history', 'error');
        }
    } catch (e) {
        toast('History retrieval failed', 'error');
    }
}

function renderHistory(history) {
    const body = document.getElementById('drawerBody');
    const { scanner, target, isGlobal } = currentHistoryFilters;

    const filterHtml = `
        <div style="margin-bottom: 1.5rem; background: var(--neo-card); border: 1px solid var(--neo-border); border-radius: 12px; padding: 1rem;">
            <div style="font-size: 0.65rem; color: var(--neo-text-muted); text-transform: uppercase; font-family: var(--font-mono); margin-bottom: 0.75rem; letter-spacing: 0.05em;">Tactical Filters</div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem;">
                <div class="form-group" style="margin:0;">
                    <select class="form-input" style="height: 32px; font-size: 0.7rem; padding: 0 0.75rem;" onchange="applyHistoryFilter('scanner', this.value)">
                        <option value="all" ${scanner === 'all' ? 'selected' : ''}>All Scanners</option>
                        ${moduleList.map(m => `<option value="${escapeHTML(m)}" ${scanner === m ? 'selected' : ''}>${escapeHTML(m.toUpperCase())}</option>`).join('')}
                    </select>
                </div>
                <div class="form-group" style="margin:0;">
                    <input type="text" class="form-input" style="height: 32px; font-size: 0.7rem; padding: 0 0.75rem;" placeholder="Search Target..." value="${escapeHTML(target)}" oninput="applyHistoryFilter('target', this.value)">
                </div>
            </div>
        </div>
    `;

    if (!history || history.length === 0) {
        body.innerHTML = `
            ${filterHtml}
            <div style="text-align:center; padding: 4rem 2rem; color:var(--neo-text-muted);">
                <span class="material-symbols-outlined" style="font-size:3rem; margin-bottom:1rem; opacity:0.2;">history</span>
                <p style="font-size:0.8rem; font-family:var(--font-mono);">No execution logs match your filters.</p>
            </div>
        `;
        return;
    }

    const logsHtml = history.map(log => {
        const dateStr = parseDateSafe(log.start_time);
        const accentCol = COLOR_MAP[log.tool_name.toLowerCase()] || 'var(--neo-blue)';
        
        const deliveryHtml = log.delivery_logs && log.delivery_logs.length > 0 ? `
            <div style="margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid var(--neo-border);">
                <div style="font-size: 0.6rem; color: var(--neo-text-muted); text-transform: uppercase; font-family: var(--font-mono); margin-bottom: 0.4rem; display: flex; align-items: center; gap: 4px;">
                    <span class="material-symbols-outlined" style="font-size: 0.8rem; color: var(--neo-green);">mail</span>
                    Recipient Delivery Log
                </div>
                <div style="display: flex; flex-direction: column; gap: 4px; font-family: var(--font-mono); font-size: 0.65rem;">
                    ${log.delivery_logs.map(d => `
                        <div style="display: flex; justify-content: space-between; align-items: center; background: var(--neo-bg); padding: 4px 6px; border-radius: 4px;">
                            <span style="color: var(--neo-text-main); font-weight: 600;">${escapeHTML(d.email)}</span>
                            <span style="font-size: 0.6rem; color: ${d.opened_at ? 'var(--neo-green)' : 'var(--neo-text-muted)'}; display: flex; align-items: center; gap: 4px;" title="${d.ip ? 'IP: ' + d.ip : ''}">
                                <span class="status-dot" style="background: ${d.opened_at ? 'var(--neo-green)' : 'var(--neo-text-muted)'}; width: 4px; height: 4px;"></span>
                                ${d.opened_at ? `Opened ${parseDateSafe(d.opened_at)}` : 'Delivered / Unopened'}
                            </span>
                        </div>
                    `).join('')}
                </div>
            </div>
        ` : '';
        
        return `
            <div class="log-entry" style="background: var(--neo-card); border: 1px solid var(--neo-border); border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem; position: relative; overflow: hidden;">
                <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:0.75rem;">
                    <div>
                        <div style="font-family:var(--font-mono); font-size:0.8rem; font-weight:700; color:${accentCol}; text-transform:uppercase; display:flex; align-items:center; gap:6px;">
                            <span class="material-symbols-outlined" style="font-size:0.9rem;">${ICON_MAP[log.tool_name.toLowerCase()] || 'terminal'}</span>
                            ${log.tool_name}
                        </div>
                        <div style="font-size:0.65rem; color:var(--neo-text-muted); font-family:var(--font-mono); margin-top:2px;">${dateStr}</div>
                    </div>
                    <span class="status-pill ${log.status === 'Completed' ? 'active' : 'paused'}" style="font-size:0.55rem; padding: 2px 6px;">
                        <span class="status-dot"></span>${log.status}
                    </span>
                </div>
                
                <div style="font-size:0.72rem; color:var(--neo-text-muted); margin-bottom:0.75rem; border-left:2px solid var(--neo-border); padding-left:0.75rem; font-family:var(--font-mono); word-break: break-all;">
                    Target: <span style="color:var(--neo-text-main)">${escapeHTML(log.target)}</span><br>
                    Type: <span style="color:var(--neo-text-main)">${escapeHTML(log.scan_type || 'Discovery')}</span>
                </div>

                <div style="display:flex; gap:0.5rem; flex-wrap:wrap; margin-bottom:0.75rem; font-family:var(--font-mono); font-size:0.65rem;">
                    <div style="background:var(--neo-bg); padding:4px 8px; border-radius:4px; border: 1px solid var(--neo-border);">Findings: <span style="color:var(--neo-amber)">${log.finding_count || 0}</span></div>
                    <div style="background:var(--neo-bg); padding:4px 8px; border-radius:4px; border: 1px solid var(--neo-border);">Duration: ${log.duration || 0}s</div>
                </div>

                ${deliveryHtml}

                ${log.has_report ? `
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; margin-top: 8px;">
                        <button class="btn-dash btn-solid" onclick="downloadReport(${log.id})" style="justify-content:center; background:var(--neo-blue); color:#000; border:none; height:36px; font-weight:700; border-radius:8px; box-shadow: 0 4px 12px rgba(59,130,246,0.15);">
                            <span class="material-symbols-outlined" style="font-size:0.95rem; margin-right:4px;">cloud_download</span>
                            Technical
                        </button>
                        <button class="btn-dash btn-solid" onclick="downloadExecutiveSummary(${log.id}, this)" style="justify-content:center; background:linear-gradient(135deg, var(--neo-blue-accent, #3b82f6), #2563eb); color:white; border:none; height:36px; font-weight:700; border-radius:8px; box-shadow: 0 4px 12px rgba(59,130,246,0.25);">
                            <span class="material-symbols-outlined" style="font-size:0.95rem; margin-right:4px;">insights</span>
                            Executive
                        </button>
                    </div>
                ` : `
                    <button class="btn-dash" disabled style="width:100%; justify-content:center; height:36px; opacity:0.3; cursor:not-allowed; border-radius:8px; margin-top:8px;">
                        <span class="material-symbols-outlined" style="font-size:1.1rem; margin-right:8px;">block</span>
                        Report Missing
                    </button>
                `}
            </div>
        `;
    }).join('');

    body.innerHTML = `
        <div class="phase-heading">${isGlobal ? 'Intelligence Archive' : 'Mission History'}</div>
        ${filterHtml}
        <div style="display: flex; flex-direction: column;">
            ${logsHtml}
        </div>
    `;
}

let historyFilterTimeout;
window.applyHistoryFilter = function(key, val) {
    currentHistoryFilters[key] = val;
    clearTimeout(historyFilterTimeout);
    historyFilterTimeout = setTimeout(() => {
        fetchAndRenderHistory();
    }, key === 'target' ? 400 : 0);
};

function renderDrawer() {
    const i = activeDraftIndex;
    if (i < 0 || i >= draftMissions.length) return;
    const d = draftMissions[i];

    // Header labels
    document.getElementById('drawerModuleLabel').textContent = d.isEdit ? 'Edit Mission' : (d.module.toUpperCase() + ' Module');
    document.getElementById('drawerTitle').textContent = d.profileName || (d.isEdit ? 'Update Mission' : `Draft Mission`);

    // Render Banner above Step Bar
    const bannerEl = document.getElementById('drawerBanner');
    if (bannerEl) {
        const icon = ICON_MAP[d.module] || 'settings';
        const color = COLOR_MAP[d.module] || 'var(--neo-text-muted)';
        const niceName = MODULE_NAMES[d.module] || d.module.toUpperCase();
        
        bannerEl.innerHTML = `
            <div style="background: var(--neo-bg); border-bottom: 1px solid var(--neo-border); padding: 0.65rem 1.75rem; display: flex; align-items: center; gap: 0.75rem;">
                <div class="template-icon" style="width: 24px; height: 24px; color: ${color}; background: ${color}15; border: 1px solid ${color}33; border-radius: 6px; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                    <span class="material-symbols-outlined" style="font-size: 0.95rem;">${icon}</span>
                </div>
                <div style="font-family: var(--font-mono); font-size: 0.78rem; font-weight: 700; color: ${color}; text-transform: uppercase; letter-spacing: 0.02em;">${escapeHTML(niceName)}</div>
            </div>
        `;
    }

    // Step bar (5 steps total)
    const stepLabels = ['Target', 'Params', 'Schedule', 'Identify', 'Review'];
    const stepBar = document.getElementById('stepBar');
    stepBar.innerHTML = stepLabels.map((label, idx) => {
        const stepNum = idx + 1;
        let cls = 'step-item';
        if (d.step > stepNum) cls += ' completed';
        else if (d.step === stepNum) cls += ' active';
        return `
            <div class="${cls}">
                <div class="step-circle">
                    ${d.step > stepNum ? '<span class="material-symbols-outlined" style="font-size:0.75rem;">check</span>' : stepNum}
                </div>
                <div class="step-label">${label}</div>
            </div>
        `;
    }).join('');

    // Body content
    const body = document.getElementById('drawerBody');
    body.innerHTML = buildStepContent(d, i);

    // Footer buttons
    const footer = document.getElementById('drawerFooter');
    const isLast = d.step === 5;
    const isFirst = d.step === 1;
    footer.innerHTML = `
        <button class="btn-dash btn-danger" onclick="discardDraft(${i})">
            <span class="material-symbols-outlined" style="font-size:0.9rem;">delete</span>Discard
        </button>
        <div class="flex gap-2">
            ${!isFirst ? `
                <button class="btn-dash" onclick="window.updateDraftStep(${i}, ${d.step - 1})">
                    <span class="material-symbols-outlined" style="font-size:0.9rem;">arrow_back</span>Back
                </button>` : ''}
            <button class="btn-dash btn-primary" style="background: ${isLast ? 'var(--neo-green)' : 'var(--neo-blue)'}; color: #fff;" id="drawerNextBtn" onclick="${isLast ? `saveDraft(${i})` : `tryAdvanceStep(${i}, ${d.step + 1})`}">
                ${isLast
                    ? `<span class="material-symbols-outlined" style="font-size:0.9rem;">rocket_launch</span>${d.isEdit ? 'Update Mission' : 'Deploy Mission'}`
                    : 'Next<span class="material-symbols-outlined" style="font-size:0.9rem;">arrow_forward</span>'}
            </button>
        </div>
    `;
}

// Build step content for the drawer body
function getStepHtml(d, i) {
    if (d.step === 1) {
        // Phase 01: Target
        const placeholders = {
            nmap: "192.168.1.1 or 192.168.1.0/24",
            sniffer: "192.168.1.1 (Target IP)",
            zap: "https://example.com/ (Target URL)",
            sql: "https://example.com/vulnerable_page.php (Target URL)",
            api: "https://api.example.com/v1/ (API Endpoint Root)",
            semgrep: "https://github.com/user/repo (Git URL) or /path/to/code.zip",
            ssl: "example.com (Domain Name)",
            killchain: "domain.com"
        };
        const placeholder = placeholders[d.module] || "192.168.1.1 or domain.com";
        const helpText = {
            semgrep: "Provide a Git repository HTTP(S) URL or paths to a local ZIP file.",
            api: "Verify you include the full protocol (e.g., https://) and API version root.",
            zap: "Enter the base URL of the web app.",
            sql: "Enter the base URL or specific endpoint suspect of vulnerability.",
            ssl: "Enter the absolute domain name without protocols or paths."
        }[d.module] || "";

        return `
            <div class="phase-heading">Phase 01 — Targeting</div>
            <div class="form-group">
                <label class="form-label">Target Address <span class="req-star">*</span></label>
                <input type="text" id="field-target" class="form-input" placeholder="${escapeHTML(placeholder)}" value="${escapeHTML(d.target)}" oninput="window.updateDraftState(${i}, 'target', this.value); clearFieldError(this)">
                ${helpText ? `<p style="font-size: 0.65rem; color: var(--neo-text-muted); margin-top: 0.4rem; font-family: var(--font-ui);">${helpText}</p>` : ''}
                <div class="field-error" id="err-target"></div>
            </div>
            <div class="form-group">
                <label class="form-label">Description <span style="opacity:0.5;">(optional)</span></label>
                <input type="text" class="form-input" placeholder="Production server" value="${escapeHTML(d.targetDesc)}" oninput="window.updateDraftState(${i}, 'targetDesc', this.value)">
            </div>
        `;
    }

    if (d.step === 2) {
        // Phase 02: Module Parameters
        const schema = moduleSchemas[d.module] || {};
        const entries = Object.entries(schema);
        const fieldsHtml = entries.map(([key, def]) => {
            const currentVal = d.config[key] !== undefined ? d.config[key] : (def.default || '');
            let input;
            if (def.type === 'select') {
                const opts = def.options.map(o => `<option value="${escapeHTML(o)}" ${o == currentVal ? 'selected' : ''}>${escapeHTML(o)}</option>`).join('');
                input = `<select class="form-input" onchange="window.updateDraftConfig(${i}, '${key}', this.value, 'select')">${opts}</select>`;
            } else if (def.type === 'number') {
                input = `<input type="number" class="form-input" value="${escapeHTML(currentVal)}" oninput="window.updateDraftConfig(${i}, '${key}', this.value, 'number')" min="${def.min||0}" max="${def.max||9999}">`;
            } else {
                input = `<input type="text" class="form-input" value="${escapeHTML(currentVal)}" oninput="window.updateDraftConfig(${i}, '${key}', this.value, 'text')">`;
            }
            return `<div class="form-group"><label class="form-label">${escapeHTML(def.label || key)}</label>${input}</div>`;
        }).join('');

        return `
            <div class="phase-heading">Phase 02 — Parameters</div>
            ${fieldsHtml || '<p style="font-size:0.75rem; color:var(--neo-text-muted);">No extra parameters required for this module.</p>'}
        `;
    }

    if (d.step === 3) {
        // Phase 3: Scheduling — full 6-option support
        let extraFields = '';

        // Run Once variants
        if (d.scheduleType === 'once') {
            extraFields = `
                <div class="form-group fade-in">
                    <label class="form-label">Execution Timing</label>
                    <div style="display:grid; grid-template-columns: 1fr 1.5fr; gap:0.5rem;">
                        <select class="form-input" onchange="window.updateDraftState(${i}, 'onceType', this.value); renderDrawer();">
                            <option value="immediate" ${d.onceType === 'immediate' ? 'selected' : ''}>Immediate</option>
                            <option value="delayed"   ${d.onceType === 'delayed'   ? 'selected' : ''}>After Delay</option>
                            <option value="specific"  ${d.onceType === 'specific'  ? 'selected' : ''}>Specific Date/Time</option>
                        </select>
                        ${d.onceType === 'delayed' ? `
                            <div class="flex gap-2">
                                <input type="number" class="form-input" value="${d.delayVal || 1}" min="1" oninput="window.updateDraftState(${i}, 'delayVal', parseInt(this.value)||1)">
                                <select class="form-input" onchange="window.updateDraftState(${i}, 'delayUnit', this.value)">
                                    <option value="min" ${d.delayUnit==='min'?'selected':''}>Min</option>
                                    <option value="hour" ${d.delayUnit==='hour'?'selected':''}>Hrs</option>
                                </select>
                            </div>
                        ` : ''}
                        ${d.onceType === 'specific' ? `
                            <input type="datetime-local" class="form-input" value="${d.specificTime || ''}" oninput="window.updateDraftState(${i}, 'specificTime', this.value)">
                        ` : ''}
                    </div>
                </div>
            `;
        } else if (d.scheduleType === 'periodic') {
            extraFields = `
                <div class="form-group fade-in">
                    <label class="form-label">Repeat Every</label>
                    <div style="display:flex; gap:0.5rem;">
                        <input type="number" class="form-input" value="${d.intervalVal || 60}" min="1" oninput="window.updateDraftState(${i}, 'intervalVal', parseInt(this.value)||60)">
                        <select class="form-input" onchange="window.updateDraftState(${i}, 'intervalUnit', this.value)">
                            <option value="min" ${d.intervalUnit==='min'?'selected':''}>Minutes</option>
                            <option value="hour" ${d.intervalUnit==='hour'?'selected':''}>Hours</option>
                            <option value="day" ${d.intervalUnit==='day'?'selected':''}>Days</option>
                        </select>
                    </div>
                </div>
            `;
        } else if (d.scheduleType === 'daily') {
            extraFields = `
                <div class="flex gap-2 fade-in">
                    <div class="form-group" style="flex:1;">
                        <label class="form-label">Hour (0–23)</label>
                        <input type="number" class="form-input" value="${d.cronHour}" min="0" max="23" oninput="window.updateDraftState(${i}, 'cronHour', parseInt(this.value)||0)">
                    </div>
                    <div class="form-group" style="flex:1;">
                        <label class="form-label">Minute (0–59)</label>
                        <input type="number" class="form-input" value="${d.cronMinute}" min="0" max="59" oninput="window.updateDraftState(${i}, 'cronMinute', parseInt(this.value)||0)">
                    </div>
                </div>
            `;
        } else if (d.scheduleType === 'weekly') {
            const dayChips = DAYS.map((day, idx) => {
                const val = DAY_VALUES[idx];
                const isSelected = (d.cronDayOfWeek || []).includes(val);
                return `<button type="button" class="day-chip ${isSelected ? 'selected' : ''}" onclick="window.toggleDay(${i}, '${val}', this)">${day}</button>`;
            }).join('');
            extraFields = `
                <div class="form-group fade-in">
                    <label class="form-label">Days of Week</label>
                    <div class="day-chip-group">${dayChips}</div>
                </div>
                <div class="flex gap-2 fade-in">
                    <div class="form-group" style="flex:1;">
                        <label class="form-label">Hour (0–23)</label>
                        <input type="number" class="form-input" value="${d.cronHour}" min="0" max="23" oninput="window.updateDraftState(${i}, 'cronHour', parseInt(this.value)||0)">
                    </div>
                    <div class="form-group" style="flex:1;">
                        <label class="form-label">Minute (0–59)</label>
                        <input type="number" class="form-input" value="${d.cronMinute}" min="0" max="59" oninput="window.updateDraftState(${i}, 'cronMinute', parseInt(this.value)||0)">
                    </div>
                </div>
            `;
        } else if (d.scheduleType === 'monthly') {
            // Multi-day selector for monthly
            const monthDays = [];
            for (let j=1; j<=31; j++) monthDays.push(j);
            const isSelected = (day) => (d.cronDayOfMonthArr || [1]).includes(day);
            
            const dayGrid = monthDays.map(day => `
                <div onclick="window.toggleMonthDay(${i}, ${day}, this)" 
                     class="day-chip ${isSelected(day) ? 'selected' : ''}" 
                     style="width: 32px; height: 32px; padding: 0; display: flex; align-items: center; justify-content: center; font-size: 0.65rem;">
                    ${day}
                </div>
            `).join('');

            extraFields = `
                <div class="form-group fade-in">
                    <label class="form-label">Days of Month</label>
                    <div style="display: grid; grid-template-columns: repeat(7, 1fr); gap: 4px; margin-top: 5px;">
                        ${dayGrid}
                    </div>
                </div>
                <div class="flex gap-2 fade-in" style="margin-top: 1rem;">
                    <div class="form-group" style="flex:1;">
                        <label class="form-label">Hour (0–23)</label>
                        <input type="number" class="form-input" value="${d.cronHour}" min="0" max="23" oninput="window.updateDraftState(${i}, 'cronHour', parseInt(this.value)||0)">
                    </div>
                    <div class="form-group" style="flex:1;">
                        <label class="form-label">Minute (0–59)</label>
                        <input type="number" class="form-input" value="${d.cronMinute}" min="0" max="59" oninput="window.updateDraftState(${i}, 'cronMinute', parseInt(this.value)||0)">
                    </div>
                </div>
            `;
        } else if (d.scheduleType === 'cron') {
            extraFields = `
                <div class="form-group fade-in">
                    <label class="form-label">Cron Expression</label>
                    <input type="text" class="form-input" placeholder="0 0 * * *" value="${escapeHTML(d.cronExpr)}" oninput="window.updateDraftState(${i}, 'cronExpr', this.value)">
                    <p style="font-size:0.65rem; color: var(--neo-text-muted); margin-top:0.4rem; font-family: var(--font-mono);">Format: minute hour day-of-month month day-of-week</p>
                </div>
            `;
        }

        return `
            <div class="phase-heading">Phase 03 — Scheduling</div>
            <div class="form-group">
                <label class="form-label">Frequency / Pattern</label>
                <select class="form-input" onchange="window.updateDraftSchedule(${i}, this.value)">
                    <option value="once"     ${d.scheduleType==='once'     ? 'selected':''}>Run Once (Snapshot)</option>
                    <option value="periodic" ${d.scheduleType==='periodic' ? 'selected':''}>Continuous Interval</option>
                    <option value="daily"    ${d.scheduleType==='daily'    ? 'selected':''}>Daily Cycle</option>
                    <option value="weekly"   ${d.scheduleType==='weekly'   ? 'selected':''}>Weekly Cycle</option>
                    <option value="monthly"  ${d.scheduleType==='monthly'  ? 'selected':''}>Monthly Cycle</option>
                    <option value="cron"     ${d.scheduleType==='cron'     ? 'selected':''}>Advanced Orchestration (Cron)</option>
                </select>
            </div>
            ${extraFields}
        `;
    }

    if (d.step === 4) {
        // Phase 4: Identify
        return `
            <div class="phase-heading">Phase 04 — Identification</div>
            <div class="form-group">
                <label class="form-label">Mission Name <span class="req-star">*</span></label>
                <input type="text" id="field-profileName" class="form-input" placeholder="Nightly Sweep" value="${escapeHTML(d.profileName)}" oninput="window.updateDraftState(${i}, 'profileName', this.value); document.getElementById('drawerTitle').textContent = this.value || 'Draft Mission'; clearFieldError(this);">
                <div class="field-error" id="err-profileName"></div>
            </div>
            <div class="form-group">
                <label class="form-label">Mission Briefing <span style="opacity:0.5;">(optional)</span></label>
                <textarea class="form-input" rows="3" oninput="window.updateDraftState(${i}, 'profileDesc', this.value)">${escapeHTML(d.profileDesc)}</textarea>
            </div>
        `;
    }

    if (d.step === 5) {
        // Phase 5: Review summary
        const schedSummary = buildScheduleSummary(d);
        const moduleLabel = d.module.toUpperCase();
        const icon = ICON_MAP[d.module] || 'settings';
        const color = COLOR_MAP[d.module] || 'var(--neo-text-muted)';

        return `
            <div class="phase-heading">Phase 05 — Review</div>
            <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--glass-border); border-radius: 12px; padding: 1.25rem; margin-bottom: 1.25rem;">
                <div style="display:flex; align-items: center; gap: 0.85rem; margin-bottom: 1.25rem; padding-bottom: 1rem; border-bottom: 1px solid var(--glass-border);">
                    <div class="template-icon" style="width: 40px; height: 40px; color: ${color}; background: ${color}15; border: 1px solid ${color}33;">
                        <span class="material-symbols-outlined">${icon}</span>
                    </div>
                    <div>
                        <div style="font-family: var(--font-mono); font-size: 0.9rem; font-weight: 700; color: ${color}; text-transform: uppercase;">${moduleLabel}</div>
                        <div style="font-size: 0.7rem; color: var(--neo-text-muted); font-family: var(--font-mono);">${escapeHTML(d.profileName) || 'Unnamed Mission'}</div>
                    </div>
                </div>
                <table class="review-table">
                    <tr>
                        <td>Module</td>
                        <td>${escapeHTML(moduleLabel)}</td>
                    </tr>
                    <tr>
                        <td>Target</td>
                        <td>${escapeHTML(d.target) || '<span style="color: var(--neo-red);">Not set</span>'}</td>
                    </tr>
                    ${d.targetDesc ? `<tr><td>Description</td><td>${escapeHTML(d.targetDesc)}</td></tr>` : ''}
                    <tr>
                        <td>Schedule</td>
                        <td>${escapeHTML(schedSummary)}</td>
                    </tr>
                    <tr>
                        <td>Name</td>
                        <td>${escapeHTML(d.profileName) || '<span style="opacity:0.5;">Auto-generated</span>'}</td>
                    </tr>
                    ${d.profileDesc ? `<tr><td>Briefing</td><td>${escapeHTML(d.profileDesc)}</td></tr>` : ''}
                </table>
            </div>

            <div style="margin-top:1.5rem; padding-top:1.25rem; border-top:1px solid var(--neo-border);">
                <div style="font-family:var(--font-mono); font-size:0.65rem; color:var(--neo-text-muted); text-transform:uppercase; letter-spacing:0.1em; margin-bottom:0.75rem; display:flex; align-items:center; gap:8px;">
                    <span class="material-symbols-outlined" style="font-size:0.9rem; color:var(--neo-blue);">description</span>
                    Reporting Options
                </div>
                <div class="form-group" style="display:flex; align-items:center; gap:10px; margin-bottom:0.25rem;">
                    <input type="checkbox" id="field-exec-summary" style="width:16px; height:16px; accent-color:var(--neo-blue);" ${(d.config && d.config.executive_summary) ? 'checked' : ''} onchange="window.updateDraftConfig(${i}, 'executive_summary', this.checked); renderDrawer()">
                    <label for="field-exec-summary" style="font-size:0.75rem; color:var(--neo-text-main); cursor:pointer;">Generate Executive Summary PDF (AI Enhanced)</label>
                </div>

                <div class="form-group" style="display:flex; align-items:center; gap:10px; margin-top: 0.5rem;">
                    <input type="checkbox" id="field-send-report-email" style="width:16px; height:16px; accent-color:var(--neo-blue);" ${d.sendReportEmail !== false ? 'checked' : ''} onchange="window.updateDraftState(${i}, 'sendReportEmail', this.checked); renderDrawer()">
                    <label for="field-send-report-email" style="font-size:0.75rem; color:var(--neo-text-main); cursor:pointer;">Email secure delivery links on completion</label>
                </div>
                ${d.sendReportEmail !== false ? `
                <div class="form-group fade-in" style="margin-top: 0.5rem; margin-bottom: 0;">
                    <label class="form-label" style="font-size: 0.65rem;">Report Recipient Email <span class="req-star">*</span></label>
                    <input type="email" id="field-report-email" class="form-input" placeholder="reports@company.com" value="${escapeHTML(d.reportEmail !== undefined ? d.reportEmail : (window.USER_EMAIL || ''))}" oninput="window.updateDraftState(${i}, 'reportEmail', this.value); clearFieldError(this)">
                    <div class="field-error" id="err-reportEmail"></div>
                </div>
                ` : ''}
            </div>

            <div style="margin-top:1.5rem; padding-top:1.25rem; border-top:1px solid var(--neo-border);">
                <div style="font-family:var(--font-mono); font-size:0.65rem; color:var(--neo-text-muted); text-transform:uppercase; letter-spacing:0.1em; margin-bottom:0.75rem; display:flex; align-items:center; gap:8px;">
                    <span class="material-symbols-outlined" style="font-size:0.9rem; color:var(--neo-amber);">gavel</span>
                    Governance & Consent
                </div>
                
                ${d.scheduleType === 'once' ? `
                <div style="padding: 0.75rem; background: rgba(255,193,7,0.05); border: 1px dashed rgba(255,193,7,0.2); border-radius: 8px; font-size: 0.65rem; color: var(--neo-amber); font-family: var(--font-ui);">
                    <span class="material-symbols-outlined" style="font-size: 0.85rem; vertical-align: middle; margin-right: 0.3rem;">info</span>
                    Consent not required for one-shot missions.
                </div>
                ` : `
                <div class="form-group" style="display:flex; align-items:center; gap:10px; margin-bottom:0.75rem;">
                    <input type="checkbox" id="field-consent-req" style="width:16px; height:16px; accent-color:var(--neo-amber);" ${d.requiresConsent ? 'checked' : ''} onchange="window.updateDraftState(${i}, 'requiresConsent', this.checked); renderDrawer()">
                    <label for="field-consent-req" style="font-size:0.75rem; color:var(--neo-text-main); cursor:pointer;">Require authorization before scanning</label>
                </div>
                ${d.requiresConsent ? `
                <div class="form-group fade-in" style="margin-bottom: 0;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.45rem;">
                        <label class="form-label" style="margin-bottom:0;">Consent Email <span class="req-star">*</span></label>
                        <button type="button" class="btn-dash" onclick="window.fillRegistrationEmail(${i})" style="height:20px; font-size:0.55rem; padding:0 0.4rem; border-color:rgba(59,130,246,0.3); color:var(--neo-blue);">
                            <span class="material-symbols-outlined" style="font-size:0.75rem;">person</span> Use mine
                        </button>
                    </div>
                    <input type="email" id="field-consent-email" class="form-input" placeholder="owner@target.com" value="${escapeHTML(d.consentEmail || '')}" oninput="window.updateDraftState(${i}, 'consentEmail', this.value); clearFieldError(this)">
                    <p style="font-size:0.6rem; color:var(--neo-text-muted); margin-top:0.4rem; font-family:var(--font-ui);">An authorization link will be sent 30 minutes before each run.</p>
                    <div class="field-error" id="err-consentEmail"></div>
                </div>
                ` : ''}
                `}
            </div>

            ${!d.target ? `<div style="padding: 0.75rem 1rem; background: rgba(239,68,68,0.08); border: 1px solid rgba(239,68,68,0.25); border-radius: 8px; font-family: var(--font-mono); font-size: 0.72rem; color: var(--neo-red); margin-top: 1rem;">
                <span class="material-symbols-outlined" style="font-size: 0.95rem; vertical-align: middle; margin-right: 0.35rem;">warning</span>
                Target address is required — go back to Phase 01.
            </div>` : ''}
        `;
    }

    return '';
}

function buildStepContent(d, i) {
    return getStepHtml(d, i);
}

function buildScheduleSummary(d) {
    switch (d.scheduleType) {
        case 'once':     
            if (d.onceType === 'immediate') return 'Immediate Execution';
            if (d.onceType === 'delayed') return `Run after ${d.delayVal} ${d.delayUnit}`;
            if (d.onceType === 'specific') return `Scheduled at ${d.specificTime ? parseDateSafe(d.specificTime) : '??'}`;

            return 'Run Once';
        case 'periodic': 
            return `Every ${d.intervalVal} ${d.intervalUnit}${d.intervalVal > 1 ? 's' : ''}`;
        case 'daily':    return `Daily at ${String(d.cronHour||0).padStart(2,'0')}:${String(d.cronMinute||0).padStart(2,'0')}`;
        case 'weekly': {
            const days = (d.cronDayOfWeek || []).map(v => DAYS[DAY_VALUES.indexOf(v)]).join(', ') || 'Mon';
            return `Weekly on ${days} at ${String(d.cronHour||0).padStart(2,'0')}:${String(d.cronMinute||0).padStart(2,'0')}`;
        }
        case 'monthly':  {
            const days = (d.cronDayOfMonthArr || [1]).join(', ');
            return `Monthly on days ${days} at ${String(d.cronHour||0).padStart(2,'0')}:${String(d.cronMinute||0).padStart(2,'0')}`;
        }
        case 'cron':     return `Cron: ${d.cronExpr || '0 0 * * *'}`;
        default:         return d.scheduleType;
    }
}

// ===== Step Validation =====
function validateCurrentStep(d) {
    switch (d.step) {
        case 1:
            if (!d.target || !d.target.trim()) {
                return { field: 'target', message: 'Target address is required to continue.' };
            }
            break;
        case 3:
            if (d.scheduleType === 'periodic') {
                const totalMins = d.intervalUnit === 'day' ? d.intervalVal * 1440 : (d.intervalUnit === 'hour' ? d.intervalVal * 60 : d.intervalVal);
                if (!d.intervalVal || d.intervalVal < 1) {
                    return { field: 'intervalVal', message: 'Interval must be at least 1 unit.' };
                }
                if (totalMins < 30) {
                    return { field: 'intervalVal', message: 'Continuous interval must be at least 30 minutes.' };
                }
            } else if (d.scheduleType === 'once' && d.onceType === 'specific') {
                if (!d.specificTime) {
                    return { field: 'specificTime', message: 'Please select a specific execution time.' };
                }
                if (new Date(d.specificTime) <= new Date()) {
                    return { field: 'specificTime', message: 'Execution time must be in the future.' };
                }
            } else if (d.scheduleType === 'cron') {
                if (!d.cronExpr || !d.cronExpr.trim()) {
                    return { field: 'cronExpr', message: 'Cron expression is required for advanced scheduling.' };
                }
            } else if (d.scheduleType === 'weekly') {
                if (!d.cronDayOfWeek || d.cronDayOfWeek.length === 0) {
                    return { field: 'cronDayOfWeek', message: 'Select at least one day for weekly scheduling.' };
                }
            }
            break;
        case 4:
            if (!d.profileName || !d.profileName.trim()) {
                return { field: 'profileName', message: 'Mission name is required.' };
            }
            break;
        case 5:
            if (d.requiresConsent && d.scheduleType !== 'once') {
                if (!d.consentEmail || !d.consentEmail.trim()) {
                    return { field: 'consentEmail', message: 'Consent recipient email is required.' };
                }
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (!emailRegex.test(d.consentEmail)) {
                    return { field: 'consentEmail', message: 'Enter a valid email address.' };
                }
            }
            if (d.sendReportEmail !== false) {
                const email = d.reportEmail !== undefined ? d.reportEmail : (window.USER_EMAIL || '');
                if (!email || !email.trim()) {
                     return { field: 'reportEmail', message: 'Report recipient email is required.' };
                }
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (!emailRegex.test(email.trim())) {
                     return { field: 'reportEmail', message: 'Enter a valid report email address.' };
                }
            }
            break;
    }
    return null; // valid
}

function showFieldError(fieldId, errorId, message) {
    const input = document.getElementById(fieldId);
    const errEl = document.getElementById(errorId);
    if (input) {
        input.classList.add('input-error');
        input.classList.add('shake');
        input.addEventListener('animationend', () => input.classList.remove('shake'), { once: true });
    }
    if (errEl) {
        errEl.textContent = message;
        errEl.style.display = 'block';
    }
    // Scroll to the error
    if (input) input.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function clearFieldError(input) {
    if (!input) return;
    input.classList.remove('input-error');
    const errEl = input.closest('.form-group')?.querySelector('.field-error');
    if (errEl) errEl.style.display = 'none';
}

function showStepBanner(message) {
    // Show a top-of-drawer error banner
    let banner = document.getElementById('stepValidationBanner');
    if (!banner) {
        banner = document.createElement('div');
        banner.id = 'stepValidationBanner';
        banner.style.cssText = [
            'position: sticky', 'top: 0', 'z-index: 10',
            'display: flex', 'align-items: center', 'gap: 0.6rem',
            'padding: 0.7rem 1rem',
            'background: rgba(239,68,68,0.12)',
            'border-bottom: 1px solid rgba(239,68,68,0.35)',
            'font-family: var(--font-mono)', 'font-size: 0.72rem',
            'color: var(--neo-red)', 'margin: -1.25rem -1.25rem 1rem -1.25rem',
            'animation: shake 0.35s ease'
        ].join(';');
        banner.innerHTML = `<span class="material-symbols-outlined" style="font-size:1rem;">error</span><span id="bannerMsg"></span>`;
        document.getElementById('drawerBody').prepend(banner);
    }
    document.getElementById('bannerMsg').textContent = message;
    banner.style.display = 'flex';
    banner.style.animation = 'none';
    requestAnimationFrame(() => { banner.style.animation = 'shake 0.35s ease'; });
    setTimeout(() => { if (banner) banner.style.display = 'none'; }, 4000);
}

function tryAdvanceStep(i, nextStep) {
    const d = draftMissions[i];
    const err = validateCurrentStep(d);
    if (!err) {
        window.updateDraftStep(i, nextStep);
        return;
    }
    // Show inline field error if element exists, otherwise show banner
    const fieldMap = {
        target: ['field-target', 'err-target'],
        consentEmail: ['field-consent-email', 'err-consentEmail'],
        profileName: ['field-profileName', 'err-profileName'],
        reportEmail: ['field-report-email', 'err-reportEmail']
    };
    if (fieldMap[err.field]) {
        showFieldError(fieldMap[err.field][0], fieldMap[err.field][1], err.message);
    } else {
        showStepBanner(err.message);
    }
    toast(err.message, 'error');
}

// ===== Drag & Drop Engine =====
document.addEventListener('DOMContentLoaded', () => {
    const arsenal = document.querySelector('.arsenal-sidebar');
    const canvasWrapper = document.getElementById('canvasWrapper');

    // Allow tap/click to deploy (especially on mobile touch screens)
    if (arsenal) {
        arsenal.addEventListener('click', (e) => {
            const card = e.target.closest('.template-card');
            if (card) {
                const module = card.dataset.module;
                if (module) {
                    deployDraft(module);
                }
            }
        });
    }

    arsenal.addEventListener('dragstart', (e) => {
        const card = e.target.closest('.template-card');
        if (card) {
            const module = card.dataset.module;
            e.dataTransfer.setData('text/plain', module);
            e.dataTransfer.effectAllowed = 'copy';
            card.style.opacity = '0.5';

            // Use the persistent drag ghost element
            let ghost = document.getElementById('drag-ghost-el');
            if (ghost) {
                const iconSpan = card.querySelector('.material-symbols-outlined');
                const icon = iconSpan ? iconSpan.textContent : 'settings';
                ghost.innerHTML = `<span class="material-symbols-outlined">${icon}</span>`;
                
                // Use setDragImage with offset to center the 48x48 ghost
                e.dataTransfer.setDragImage(ghost, 24, 24);
            }
        }
    });

    arsenal.addEventListener('dragend', (e) => {
        const card = e.target.closest('.template-card');
        if (card) card.style.opacity = '1';
    });

    const canvasPanel = document.querySelector('.canvas-panel');

    canvasWrapper.addEventListener('dragover', (e) => {
        e.preventDefault();
        canvasPanel.classList.add('active');
    });

    canvasWrapper.addEventListener('dragleave', (e) => {
        if (!canvasPanel.contains(e.relatedTarget)) {
            canvasPanel.classList.remove('active');
        }
    });

    canvasWrapper.addEventListener('drop', (e) => {
        e.preventDefault();
        canvasPanel.classList.remove('active');
        const mod = e.dataTransfer.getData('text/plain');
        if (mod) deployDraft(mod);
    });

    // Arsenal search filter
    const searchInput = document.getElementById('moduleSearch');
    if (searchInput) {
        searchInput.addEventListener('input', () => filterModules(searchInput.value));
    }
});

function filterModules(query) {
    const q = query.trim().toLowerCase();
    const cards = document.querySelectorAll('.template-card');
    const categories = document.querySelectorAll('.arsenal-title[data-category]');
    const noMsg = document.getElementById('noModulesMsg');
    let anyVisible = false;

    cards.forEach(card => {
        const searchText = (card.dataset.search || '') + ' ' + card.textContent;
        const matches = !q || searchText.toLowerCase().includes(q);
        card.classList.toggle('hidden', !matches);
        if (matches) anyVisible = true;
    });

    // Hide category headers if all their cards are hidden
    categories.forEach(cat => {
        const catName = cat.dataset.category;
        const catCards = document.querySelectorAll(`.template-card[data-category="${catName}"]`);
        const anyCatVisible = [...catCards].some(c => !c.classList.contains('hidden'));
        cat.style.display = anyCatVisible ? '' : 'none';
    });

    noMsg.style.display = anyVisible ? 'none' : 'block';
}

// ===== Deploy Draft =====
function deployDraft(mod) {
    const newIndex = draftMissions.length;
    draftMissions.push({
        module: mod,
        step: 1,
        config: {},
        target: '',
        targetDesc: '',
        scheduleType: 'once',
        onceType: 'immediate', // immediate, delayed, specific
        delayVal: 5,
        delayUnit: 'min',      // min, hour
        specificTime: '',
        intervalVal: 60,
        intervalUnit: 'min',   // min, hour, day
        cronHour: 0,
        cronMinute: 0,
        cronDayOfWeek: ['mon'],
        cronDayOfMonthArr: [1],
        cronExpr: '0 0 * * *',
        profileName: '',
        profileDesc: '',
        requiresConsent: false,
        consentEmail: ''
    });
    openDrawer(newIndex);
    toast(`DRAFT: ${mod.toUpperCase()} — configure in drawer`, 'success');
}

// ===== Edit Existing Mission =====
function editMission(profileId) {
    const p = allProfiles.find(x => x.id === profileId);
    if (!p) return;

    const config = p.configs[0] || {};
    const target = p.targets[0] || {};
    const job = p.jobs[0] || {};
    
    // Convert DB job state to Draft state
    let onceType = 'immediate';
    let delayVal = 5;
    let delayUnit = 'min';
    let specificTime = '';

    if (job.schedule_type === 'once' && job.one_shot_at) {
        onceType = 'specific';
        specificTime = job.one_shot_at;
    }

    const draft = {
        isEdit: true,
        profileId: p.id,
        configId: config.id,
        targetId: target.id,
        jobId: job.id,
        module: config.module || 'nmap',
        step: 1,
        config: config.config || {},
        target: target.target_url || '',
        targetDesc: '',
        scheduleType: job.schedule_type || 'once',
        onceType: onceType,
        delayVal: delayVal,
        delayUnit: delayUnit,
        specificTime: specificTime,
        intervalVal: job.interval_minutes || 60,
        intervalUnit: 'min',
        cronHour: job.cron_hour || 0,
        cronMinute: job.cron_minute || 0,
        cronDayOfWeek: job.cron_day_of_week ? job.cron_day_of_week.split(',') : ['mon'],
        cronDayOfMonthArr: job.cron_day_of_month ? job.cron_day_of_month.split(',').map(Number) : [1],
        cronExpr: job.cron_expression || '0 0 * * *',
        profileName: p.name,
        profileDesc: p.description,
        requiresConsent: target.requires_consent || false,
        consentEmail: target.consent_email || '',
        reportEmail: p.recipients && p.recipients.length > 0 ? p.recipients[0].email : '',
        sendReportEmail: job.send_report_email !== undefined ? job.send_report_email : true
    };

    const newIndex = draftMissions.length;
    draftMissions.push(draft);
    openDrawer(newIndex);
    toast(`EDITING: ${p.name}`, 'info');
}

// ===== State Management Helpers =====
window.updateDraftState = function(index, key, val) {
    draftMissions[index][key] = val;
};

window.updateDraftConfig = function(index, key, val, type) {
    draftMissions[index].config[key] = type === 'number' ? (parseInt(val) || 0) : val;
};

window.updateDraftStep = function(index, newStep) {
    draftMissions[index].step = newStep;
    activeDraftIndex = index;
    renderDrawer();
};

window.updateDraftSchedule = function(index, val) {
    draftMissions[index].scheduleType = val;
    renderDrawer(); // Re-render so sub-fields appear/disappear
};

window.toggleDay = function(index, dayVal, btn) {
    const d = draftMissions[index];
    if (!d.cronDayOfWeek) d.cronDayOfWeek = [];
    const idx = d.cronDayOfWeek.indexOf(dayVal);
    if (idx >= 0) {
        if (d.cronDayOfWeek.length > 1) { // keep at least 1 day
            d.cronDayOfWeek.splice(idx, 1);
            btn.classList.remove('selected');
        }
    } else {
        d.cronDayOfWeek.push(dayVal);
        btn.classList.add('selected');
    }
    window.updateDraftState(index, 'cronDayOfWeek', d.cronDayOfWeek);
};

window.toggleMonthDay = function(index, day, btn) {
    const d = draftMissions[index];
    if (!d.cronDayOfMonthArr) d.cronDayOfMonthArr = [1];
    const idx = d.cronDayOfMonthArr.indexOf(day);
    if (idx >= 0) {
        if (d.cronDayOfMonthArr.length > 1) {
            d.cronDayOfMonthArr.splice(idx, 1);
            btn.classList.remove('selected');
        }
    } else {
        d.cronDayOfMonthArr.push(day);
        btn.classList.add('selected');
    }
    d.cronDayOfMonthArr.sort((a,b) => a-b);
    window.updateDraftState(index, 'cronDayOfMonthArr', d.cronDayOfMonthArr);
};

window.discardDraft = async function(index) {
    const confirmed = await window.showConfirm({
        title: 'Discard Draft',
        message: 'Are you sure you want to discard this mission draft? All configuration will be lost.',
        confirmText: 'Discard Draft',
        type: 'danger'
    });
    if (!confirmed) return;

    draftMissions.splice(index, 1);
    closeDrawer();
    renderAll();
    toast('Draft mission discarded');
}

// ===== Save Draft (Deploy) =====
async function saveDraft(index) {
    const d = draftMissions[index];

    if (!d.target) {
        toast('Target address required — go back to Phase 01', 'error');
        // Navigate back to targeting step
        window.updateDraftStep(index, 1);
        return;
    }

    const btn = document.querySelector('.drawer-footer .btn-primary');
    const originalBtnHtml = btn ? btn.innerHTML : (d.isEdit ? 'Update Mission' : 'Deploy Mission');

    try {
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = `<span class="material-symbols-outlined spin" style="font-size:1rem;">sync</span> ${d.isEdit ? 'Updating' : 'Deploying'}…`;
        }

        const pName = d.profileName || `${d.module.toUpperCase()} Mission — ${new Date().toLocaleDateString()}`;
        
        let pId = d.profileId;
        if (d.isEdit) {
            await apiFetch(`${API}/profiles/${pId}`, {
                method: 'PUT', body: JSON.stringify({ name: pName, description: d.profileDesc })
            });
        } else {
            const pRes = await apiFetch(`${API}/profiles`, {
                method: 'POST', body: JSON.stringify({ name: pName, description: d.profileDesc })
            });
            pId = pRes.profile.id;
        }

        // Small delay
        await new Promise(r => setTimeout(r, 100));

        if (d.isEdit && d.configId) {
            await apiFetch(`${API}/profiles/${pId}/configs/${d.configId}`, {
                method: 'PUT', body: JSON.stringify({ config: d.config })
            });
        } else {
            await apiFetch(`${API}/profiles/${pId}/configs`, {
                method: 'POST', body: JSON.stringify({ module: d.module, config: d.config })
            });
        }

        await new Promise(r => setTimeout(r, 100));

        if (d.isEdit && d.targetId) {
             await apiFetch(`${API}/profiles/${pId}/targets/${d.targetId}`, {
                method: 'PUT', body: JSON.stringify({ 
                    target_url: d.target,
                    requires_consent: d.requiresConsent,
                    consent_email: d.consentEmail
                })
            });
        } else {
            await apiFetch(`${API}/profiles/${pId}/targets`, {
                method: 'POST', body: JSON.stringify({ 
                    target_url: d.target,
                    requires_consent: d.requiresConsent,
                    consent_email: d.consentEmail
                })
            });
        }

        await new Promise(r => setTimeout(r, 100));

        // Recipients Logic
        const reportEmailToSave = d.reportEmail !== undefined ? d.reportEmail : (window.USER_EMAIL || '');
        if (d.sendReportEmail !== false && reportEmailToSave && reportEmailToSave.trim()) {
             const p_found = allProfiles.find(x => x.id === pId);
             const existingRecipients = (d.isEdit && p_found) ? (p_found.recipients || []) : [];
             for (const r of existingRecipients) {
                  try { await apiFetch(`${API}/profiles/${pId}/recipients/${r.id}`, { method: 'DELETE' }); } catch(e){}
             }
             await apiFetch(`${API}/profiles/${pId}/recipients`, {
                  method: 'POST', body: JSON.stringify({ email: reportEmailToSave.trim(), role: 'technical' })
             });
        }

        // Schedule Logic
        let jobPayload = {
            profile_id: pId,
            schedule_type: d.scheduleType,
            send_report_email: d.sendReportEmail !== false
        };
        
        if (d.scheduleType === 'once') {
            let startAt = new Date();
            if (d.onceType === 'delayed') {
                const ms = d.delayVal * (d.delayUnit === 'hour' ? 3600000 : 60000);
                startAt = new Date(Date.now() + ms);
            } else if (d.onceType === 'specific') {
                startAt = new Date(d.specificTime);
            }
            jobPayload.one_shot_at = startAt.toISOString();
        } else if (d.scheduleType === 'periodic') {
            jobPayload.interval_minutes = d.intervalUnit === 'hour' ? d.intervalVal*60 : (d.intervalUnit === 'day' ? d.intervalVal*1440 : d.intervalVal);
        } else {
            jobPayload.cron_hour = d.cronHour;
            jobPayload.cron_minute = d.cronMinute;
            if (d.scheduleType === 'weekly') jobPayload.cron_day_of_week = d.cronDayOfWeek.join(',');
            if (d.scheduleType === 'monthly') jobPayload.cron_day_of_month = d.cronDayOfMonthArr.join(',');
            if (d.scheduleType === 'cron') jobPayload.cron_expression = d.cronExpr;
        }

        if (d.isEdit && d.jobId) {
            await apiFetch(`${API}/jobs/${d.jobId}`, {
                method: 'PUT', body: JSON.stringify(jobPayload)
            });
        } else {
            await apiFetch(`${API}/jobs`, {
                method: 'POST', body: JSON.stringify(jobPayload)
            });
        }

        toast(d.isEdit ? 'Mission updated successfully' : 'Mission deployed successfully!', 'success');
        
        draftMissions.splice(index, 1);
        closeDrawer();
        renderAll();

    } catch (err) {
        console.error('FAILED TO SAVE MISSION:', err);
        toast(err.message || 'Operation failed', 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalBtnHtml;
        }
    }
}

// ===== Toggle Job (enable/disable) =====
async function toggleJob(jobId, btn) {
    try {
        const data = await apiFetch(`${API}/jobs/${jobId}/toggle`, { method: 'PUT' });
        if (data.status === 'success') {
            const isEnabled = data.is_enabled;
            btn.style.color = isEnabled ? 'var(--neo-green)' : 'var(--neo-text-muted)';
            btn.style.borderColor = isEnabled ? 'rgba(52,211,153,0.3)' : 'var(--neo-border)';
            btn.querySelector('.material-symbols-outlined').textContent = isEnabled ? 'pause' : 'play_arrow';
            btn.title = isEnabled ? 'Pause schedule' : 'Resume schedule';
            toast(isEnabled ? 'Schedule resumed' : 'Schedule paused');
            // Re-render to update the status pill
            renderAll();
        } else {
            toast(data.message || 'Toggle failed', 'error');
        }
    } catch (e) {
        toast('Toggle failed', 'error');
    }
}

// ===== Delete Profile =====
async function deleteProfile(id) {
    const confirmed = await window.showConfirm({
        title: 'Abort Mission Profile',
        message: 'Are you sure you want to permanently terminate this mission profile and all associated data?',
        confirmText: 'Terminate Mission',
        type: 'danger'
    });
    if (!confirmed) return;

    try {
        await apiFetch(`${API}/profiles/${id}`, { method: 'DELETE' });
        toast('Mission terminated');
        renderAll();
    } catch (e) { toast('Termination failed', 'error'); }
}

// ===== Delete Job =====
async function deleteJob(id) {
    const confirmed = await window.showConfirm({
        title: 'Halt Schedule',
        message: 'Are you sure you want to stop this specific execution schedule?',
        confirmText: 'Remove Schedule',
        type: 'danger'
    });
    if (!confirmed) return;

    try {
        await apiFetch(`${API}/jobs/${id}`, { method: 'DELETE' });
        toast('Schedule removed');
        renderAll();
    } catch (e) { toast('Failed', 'error'); }
}

// ===== Execute Now (with loading state) =====
async function triggerJob(profileId) {
    const card = document.getElementById(`profile-${profileId}`);
    const btn = document.getElementById(`exec-btn-${profileId}`);

    // Optimistic loading state
    if (card) card.classList.add('executing');
    if (btn) {
        btn.innerHTML = '<span class="material-symbols-outlined" style="font-size:0.9rem; animation: spin 1s linear infinite;">sync</span>Running…';
        btn.disabled = true;
    }

    // Add spin keyframe if not already added
    if (!document.getElementById('spinKeyframe')) {
        const style = document.createElement('style');
        style.id = 'spinKeyframe';
        style.textContent = '@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }';
        document.head.appendChild(style);
    }

    try {
        const data = await apiFetch(`${API}/profiles/${profileId}/trigger`, { method: 'POST' });
        if (data.status === 'success') {
            toast('Mission execution initiated', 'success');
        } else {
            toast(data.message || 'Execution failed', 'error');
        }
    } catch (e) {
        toast('Failed to trigger mission', 'error');
    } finally {
        // Restore card after 2.5s to simulate "scan launched"
        setTimeout(() => {
            if (card) card.classList.remove('executing');
            if (btn) {
                btn.innerHTML = '<span class="material-symbols-outlined" style="font-size:0.9rem;">rocket_launch</span>Execute Now';
                btn.disabled = false;
            }
        }, 2500);
    }
}

// ===== Download Report (Silent) =====
window.downloadReport = function(logId) {
    const downloadUrl = `${API}/reports/${logId}/download`;
    // Using window.location.href for silent download (triggers browser download behavior)
    window.location.href = downloadUrl;
};

// ===== Download Executive Summary (With Loader) =====
window.downloadExecutiveSummary = async function(logId, btn) {
    if (btn.classList.contains('loading')) return;
    
    const originalHtml = btn.innerHTML;
    btn.classList.add('loading');
    btn.disabled = true;
    btn.innerHTML = `<span class="material-symbols-outlined spin" style="font-size:1rem; margin-right:4px;">sync</span> Loading...`;

    try {
        const downloadUrl = `${API}/reports/${logId}/executive_summary`;
        const response = await fetch(downloadUrl, {
             headers: {
                 'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.content
             }
        });
        
        if (!response.ok) {
             const errData = await response.json();
             throw new Error(errData.message || 'Generation failed');
        }
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        
        const disposition = response.headers.get('content-disposition');
        let filename = `Executive_Summary_${logId}.pdf`;
        if (disposition && disposition.indexOf('attachment') !== -1) {
            const filenameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;
            const matches = filenameRegex.exec(disposition);
            if (matches != null && matches[1]) { 
                filename = matches[1].replace(/["]/g, '');
            }
        }
        
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
        toast('Executive Summary downloaded');
    } catch (e) {
        toast(`Error: ${e.message}`, 'error');
    } finally {
        btn.classList.remove('loading');
        btn.disabled = false;
        btn.innerHTML = originalHtml;
    }
};

// ===== Init =====
document.addEventListener('DOMContentLoaded', async () => {
    await loadModules();
    await renderAll();

    document.getElementById('refreshJobsBtn')?.addEventListener('click', async () => {
        await renderAll();
        toast('Systems synchronized');
    });
});