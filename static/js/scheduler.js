// ===== State =====
let moduleSchemas = {};
let moduleList = [];
let draftMissions = []; // [{ module, step, config, target, targetDesc, scheduleType, ... }]
let activeDraftIndex = -1; // Which draft is currently open in the drawer

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
        color: white; border: 1px solid rgba(255,255,255,0.1); backdrop-filter: blur(8px);
        box-shadow: 0 8px 32px rgba(0,0,0,0.4); transition: all 0.3s ease; opacity: 0; transform: translateY(20px);
    `;
    el.innerHTML = `<span class="material-symbols-outlined">${type === 'success' ? 'check_circle' : 'error'}</span> <span>${escapeHTML(msg)}</span>`;
    document.body.appendChild(el);
    setTimeout(() => { el.style.opacity = '1'; el.style.transform = 'translateY(0)'; }, 10);
    setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateY(20px)'; setTimeout(() => el.remove(), 300); }, 3000);
}

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
    const profiles = await loadProfiles();
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
        <div class="drop-zone-bar" id="persistentDropBar">
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
        const nextRun = j.next_run_at ? new Date(j.next_run_at).toLocaleString() : 'N/A';

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

    return `
        <div class="mission-card fade-in" id="profile-${p.id}">
            <div class="mission-status-strip" style="background: ${accentColor};"></div>
            <div class="mission-header">
                <div style="flex:1; padding-left: 0.75rem;">
                    <div style="display:flex; align-items:center; gap: 0.6rem; margin-bottom: 0.25rem;">
                        <div class="mission-title" style="color: ${accentColor}; font-size: 0.9rem;">${escapeHTML(p.name).toUpperCase()}</div>
                        ${p.jobs.length > 0 ? `<span class="status-pill ${pillClass}"><span class="status-dot"></span>${escapeHTML(pillLabel)}</span>` : ''}
                    </div>
                    <div class="mission-target">${escapeHTML(primaryTarget)}</div>
                </div>
                <div class="template-icon" style="width: 32px; height: 32px; color: ${accentColor}; background: ${accentColor}15; border: 1px solid ${accentColor}33; flex-shrink:0;">
                    <span class="material-symbols-outlined" style="font-size: 1.1rem;">${icon}</span>
                </div>
            </div>
            <p style="font-size: 0.73rem; color: var(--neo-text-muted); min-height: 2rem; margin-bottom: 0.75rem; padding-left: 0.75rem;">${escapeHTML(p.description) || 'Continuous monitoring of infrastructure endpoints.'}</p>
            <div style="background: rgba(0,0,0,0.15); padding: 0.6rem; border-radius: 8px; border: 1px solid rgba(255,255,255,0.03); margin-bottom: 0.85rem;">
                ${jobsHtml}
            </div>
            <div class="mission-actions">
                <button class="btn-dash btn-danger" onclick="deleteProfile(${p.id})">
                    <span class="material-symbols-outlined" style="font-size:0.9rem;">delete</span>Delete
                </button>
                <button class="btn-dash btn-primary" id="exec-btn-${p.id}" onclick="triggerJob(${p.id})">
                    <span class="material-symbols-outlined" style="font-size:0.9rem;">rocket_launch</span>Execute Now
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
}

function renderDrawer() {
    const i = activeDraftIndex;
    if (i < 0 || i >= draftMissions.length) return;
    const d = draftMissions[i];

    // Header labels
    document.getElementById('drawerModuleLabel').textContent = d.module.toUpperCase() + ' Module';
    document.getElementById('drawerTitle').textContent = d.profileName || `Draft Mission`;

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
            <button class="btn-dash btn-primary" style="background: ${isLast ? 'var(--neo-green)' : 'var(--neo-blue)'}; color: #000;" id="drawerNextBtn" onclick="${isLast ? `saveDraft(${i})` : `tryAdvanceStep(${i}, ${d.step + 1})`}">
                ${isLast
                    ? '<span class="material-symbols-outlined" style="font-size:0.9rem;">rocket_launch</span>Deploy Mission'
                    : 'Next<span class="material-symbols-outlined" style="font-size:0.9rem;">arrow_forward</span>'}
            </button>
        </div>
    `;
}

// Build step content for the drawer body
function buildStepContent(d, i) {
    if (d.step === 1) {
        // Phase 01: Target
        return `
            <div class="phase-heading">Phase 01 — Targeting</div>
            <div class="form-group">
                <label class="form-label">Target Address <span class="req-star">*</span></label>
                <input type="text" id="field-target" class="form-input" placeholder="192.168.1.1 or domain.com" value="${escapeHTML(d.target)}" oninput="window.updateDraftState(${i}, 'target', this.value); clearFieldError(this)">
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

        if (d.scheduleType === 'periodic') {
            extraFields = `
                <div class="form-group fade-in">
                    <label class="form-label">Interval (minutes)</label>
                    <input type="number" class="form-input" value="${d.intervalMins}" min="1" oninput="window.updateDraftState(${i}, 'intervalMins', parseInt(this.value)||60)">
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
            extraFields = `
                <div class="form-group fade-in">
                    <label class="form-label">Day of Month (1–31)</label>
                    <input type="number" class="form-input" value="${d.cronDayOfMonth}" min="1" max="31" oninput="window.updateDraftState(${i}, 'cronDayOfMonth', parseInt(this.value)||1)">
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
                <label class="form-label">Pattern</label>
                <select class="form-input" onchange="window.updateDraftSchedule(${i}, this.value)">
                    <option value="once"     ${d.scheduleType==='once'     ? 'selected':''}>Run Once (Now)</option>
                    <option value="periodic" ${d.scheduleType==='periodic' ? 'selected':''}>Periodic Interval</option>
                    <option value="daily"    ${d.scheduleType==='daily'    ? 'selected':''}>Daily</option>
                    <option value="weekly"   ${d.scheduleType==='weekly'   ? 'selected':''}>Weekly</option>
                    <option value="monthly"  ${d.scheduleType==='monthly'  ? 'selected':''}>Monthly</option>
                    <option value="cron"     ${d.scheduleType==='cron'     ? 'selected':''}>Advanced Cron</option>
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
            ${!d.target ? `<div style="padding: 0.75rem 1rem; background: rgba(239,68,68,0.08); border: 1px solid rgba(239,68,68,0.25); border-radius: 8px; font-family: var(--font-mono); font-size: 0.72rem; color: var(--neo-red);">
                <span class="material-symbols-outlined" style="font-size: 0.95rem; vertical-align: middle; margin-right: 0.35rem;">warning</span>
                Target address is required — go back to Phase 01.
            </div>` : ''}
        `;
    }

    return '';
}

function buildScheduleSummary(d) {
    switch (d.scheduleType) {
        case 'once':     return 'Run Once (immediately)';
        case 'periodic': return `Every ${d.intervalMins || 60} minutes`;
        case 'daily':    return `Daily at ${String(d.cronHour||0).padStart(2,'0')}:${String(d.cronMinute||0).padStart(2,'0')}`;
        case 'weekly': {
            const days = (d.cronDayOfWeek || []).map(v => DAYS[DAY_VALUES.indexOf(v)]).join(', ') || 'Mon';
            return `Weekly on ${days} at ${String(d.cronHour||0).padStart(2,'0')}:${String(d.cronMinute||0).padStart(2,'0')}`;
        }
        case 'monthly':  return `Monthly on day ${d.cronDayOfMonth||1} at ${String(d.cronHour||0).padStart(2,'0')}:${String(d.cronMinute||0).padStart(2,'0')}`;
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
                if (!d.intervalMins || d.intervalMins < 1) {
                    return { field: 'intervalMins', message: 'Interval must be at least 1 minute.' };
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
        profileName: ['field-profileName', 'err-profileName'],
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

    canvasWrapper.addEventListener('dragover', (e) => {
        e.preventDefault();
        canvasWrapper.classList.add('active');
    });

    canvasWrapper.addEventListener('dragleave', (e) => {
        // Only remove if leaving the canvasWrapper entirely
        if (!canvasWrapper.contains(e.relatedTarget)) {
            canvasWrapper.classList.remove('active');
        }
    });

    canvasWrapper.addEventListener('drop', (e) => {
        e.preventDefault();
        canvasWrapper.classList.remove('active');
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
        intervalMins: 60,
        cronHour: 0,
        cronMinute: 0,
        cronDayOfWeek: ['mon'],
        cronDayOfMonth: 1,
        cronExpr: '0 0 * * *',
        profileName: '',
        profileDesc: ''
    });
    openDrawer(newIndex);
    toast(`DRAFT: ${mod.toUpperCase()} — configure in drawer`, 'success');
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

function discardDraft(index) {
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
    const originalBtnHtml = btn ? btn.innerHTML : 'Deploy Mission';

    try {
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<span class="material-symbols-outlined spin" style="font-size:1rem;">sync</span> Deploying…';
        }

        const pName = d.profileName || `${d.module.toUpperCase()} Mission — ${new Date().toLocaleDateString()}`;
        const pRes = await apiFetch(`${API}/profiles`, {
            method: 'POST', body: JSON.stringify({ name: pName, description: d.profileDesc })
        });
        const pId = pRes.profile.id;

        // Small delay between calls for SQLite stability
        await new Promise(r => setTimeout(r, 100));

        await apiFetch(`${API}/profiles/${pId}/targets`, {
            method: 'POST', body: JSON.stringify({ target_url: d.target, description: d.targetDesc })
        });

        await new Promise(r => setTimeout(r, 100));

        await apiFetch(`${API}/profiles/${pId}/configs`, {
            method: 'POST', body: JSON.stringify({ module: d.module, config: d.config, display_label: `${d.module.toUpperCase()} Config` })
        });

        await new Promise(r => setTimeout(r, 100));

        // Build job body based on schedule type
        const jobBody = { profile_id: pId, schedule_type: d.scheduleType };
        if (d.scheduleType === 'periodic') {
            jobBody.interval_minutes = d.intervalMins;
        } else if (d.scheduleType === 'once') {
            jobBody.one_shot_at = new Date(Date.now() + 5000).toISOString();
        } else if (d.scheduleType === 'cron') {
            jobBody.cron_expression = d.cronExpr;
        } else if (d.scheduleType === 'daily') {
            jobBody.cron_hour = d.cronHour;
            jobBody.cron_minute = d.cronMinute;
        } else if (d.scheduleType === 'weekly') {
            jobBody.cron_hour = d.cronHour;
            jobBody.cron_minute = d.cronMinute;
            jobBody.cron_day_of_week = (d.cronDayOfWeek || ['mon']).join(',');
        } else if (d.scheduleType === 'monthly') {
            jobBody.cron_hour = d.cronHour;
            jobBody.cron_minute = d.cronMinute;
            jobBody.cron_day_of_month = d.cronDayOfMonth;
        }

        await apiFetch(`${API}/jobs`, { method: 'POST', body: JSON.stringify(jobBody) });

        toast('Mission deployed successfully!');
        
        // UI Clean up
        draftMissions.splice(index, 1);
        closeDrawer();
        renderAll();
    } catch (e) {
        console.error(e);
        toast(`Deployment failed: ${e.message}`, 'error');
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
    if (!confirm('Abort this mission profile permanently?')) return;
    try {
        await apiFetch(`${API}/profiles/${id}`, { method: 'DELETE' });
        toast('Mission terminated');
        renderAll();
    } catch (e) { toast('Termination failed', 'error'); }
}

// ===== Delete Job =====
async function deleteJob(id) {
    if (!confirm('Halt this specific schedule?')) return;
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

// ===== Init =====
document.addEventListener('DOMContentLoaded', async () => {
    await loadModules();
    await renderAll();

    document.getElementById('refreshJobsBtn')?.addEventListener('click', async () => {
        await renderAll();
        toast('Systems synchronized');
    });
});