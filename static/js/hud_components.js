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
    trigger.innerHTML = `<span>${select.options[select.selectedIndex]?.text || 'Select...'}</span>`;
    
    const optionsCont = document.createElement('div');
    optionsCont.className = 'custom-options';
    
    function buildOptions() {
        optionsCont.innerHTML = '';
        Array.from(select.options).forEach((opt, idx) => {
            const oDiv = document.createElement('div');
            oDiv.className = `custom-option ${select.selectedIndex === idx ? 'selected' : ''}`;
            oDiv.textContent = opt.text;
            oDiv.addEventListener('click', (e) => {
                e.stopPropagation();
                select.selectedIndex = idx;
                trigger.querySelector('span').textContent = opt.text;
                optionsCont.classList.remove('show');
                trigger.classList.remove('open');
                
                // Trigger change event for original select
                select.dispatchEvent(new Event('change'));
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
        document.querySelectorAll('.custom-options').forEach(c => c.classList.remove('show'));
        document.querySelectorAll('.custom-select-trigger').forEach(c => c.classList.remove('open'));
        
        if (!isOpen) {
            optionsCont.classList.add('show');
            trigger.classList.add('open');
            buildOptions(); // Re-sync in case options changed
        }
    });

    wrapper.appendChild(trigger);
    wrapper.appendChild(optionsCont);
    select.parentNode.insertBefore(wrapper, select);

    // Watch for dynamic changes to original select options
    const observer = new MutationObserver(() => buildOptions());
    observer.observe(select, { childList: true });
}

// Global closer for custom selects
window.addEventListener('click', () => {
    document.querySelectorAll('.custom-options').forEach(c => c.classList.remove('show'));
    document.querySelectorAll('.custom-select-trigger').forEach(c => c.classList.remove('open'));
});
