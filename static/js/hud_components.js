/**
 * NetShieldAI HUD Components JS
 * Centralized logic for custom HUD selects and other interactive elements.
 */

function initCustomSelect(select) {
    if (!select || select.dataset.customized) return;
    
    // Hide original but keep it functional for forms/events
    select.style.display = 'none';
    select.dataset.customized = 'true';

    const wrapper = document.createElement('div');
    wrapper.className = 'custom-select-wrapper';
    
    const trigger = document.createElement('div');
    trigger.className = 'custom-select-trigger';
    const triggerSpan = document.createElement('span');
    triggerSpan.textContent = select.options[select.selectedIndex]?.text || 'Select...';
    trigger.appendChild(triggerSpan);
    
    const optionsCont = document.createElement('div');
    optionsCont.className = 'custom-options';
    
    function buildOptions() {
        optionsCont.innerHTML = '';
        triggerSpan.textContent = select.options[select.selectedIndex]?.text || 'Select...';
        
        Array.from(select.options).forEach((opt, idx) => {
            const oDiv = document.createElement('div');
            oDiv.className = `custom-option ${select.selectedIndex === idx ? 'selected' : ''}`;
            oDiv.textContent = opt.text;
            oDiv.addEventListener('click', (e) => {
                e.stopPropagation();
                if (select.selectedIndex !== idx) {
                    select.selectedIndex = idx;
                    select.dispatchEvent(new Event('change', { bubbles: true }));
                }
                optionsCont.classList.remove('show');
                trigger.classList.remove('open');
                buildOptions();
            });
            optionsCont.appendChild(oDiv);
        });
    }

    buildOptions();

    trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = optionsCont.classList.contains('show');
        
        // Close all other instances first
        document.querySelectorAll('.custom-options').forEach(c => {
            if (c !== optionsCont) c.classList.remove('show');
        });
        document.querySelectorAll('.custom-select-trigger').forEach(c => {
            if (c !== trigger) c.classList.remove('open');
        });
        
        optionsCont.classList.toggle('show');
        trigger.classList.toggle('open');
        
        if (optionsCont.classList.contains('show')) {
            buildOptions(); // Sync state on open
        }
    });

    wrapper.appendChild(trigger);
    wrapper.appendChild(optionsCont);
    select.parentNode.insertBefore(wrapper, select);

    // Watch for dynamic changes to original select options
    const observer = new MutationObserver(() => buildOptions());
    observer.observe(select, { childList: true, subtree: true, characterData: true });
}

// Global closer for custom selects
window.addEventListener('click', () => {
    document.querySelectorAll('.custom-options.show').forEach(c => c.classList.remove('show'));
    document.querySelectorAll('.custom-select-trigger.open').forEach(c => c.classList.remove('open'));
});
