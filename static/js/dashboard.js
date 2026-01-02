document.addEventListener('DOMContentLoaded', function() {
    
    // --- 1. NETWORK (NMAP) ---
    fetch(apiEndpoints.network)
        .then(r => r.json())
        .then(data => {
            const available = data.status === "Scanned";
            const countEl = document.getElementById('nmap-count');
            if(countEl) countEl.textContent = available ? data.open_ports_count : '--';
            
            if(available) {
                const targetEl = document.getElementById('nmap-target');
                if(targetEl) targetEl.textContent = `Target: ${data.target}`;
                
                const osEl = document.getElementById('nmap-os');
                if(osEl) osEl.textContent = data.os_detected || 'Unknown';

                const listEl = document.getElementById('nmap-service-list');
                if(listEl) {
                    listEl.innerHTML = '';
                    if(data.top_services && data.top_services.length > 0) {
                        data.top_services.forEach(svcString => {
                            const firstColonIndex = svcString.indexOf(':');
                            let port = "??";
                            let desc = svcString;
                            if(firstColonIndex !== -1) {
                                port = svcString.substring(0, firstColonIndex);
                                desc = svcString.substring(firstColonIndex + 1);
                            }
                            listEl.innerHTML += `
                                <li class="service-item">
                                    <span class="port">PORT ${port}</span>
                                    <span style="color:#aaa;">${desc}</span>
                                </li>
                            `;
                        });
                    } else {
                        listEl.innerHTML = '<li style="text-align:center; color:#666; padding:1rem;">No open ports found.</li>';
                    }
                }
                const btn = document.getElementById('btn-nmap-pdf');
                if(btn) { btn.classList.remove('disabled'); btn.href = reportUrls.network; }
            }
        })
        .catch(console.error);

    // --- 2. ZAP (VULNERABILITIES) ---
    fetch(apiEndpoints.zap)
        .then(r => r.json())
        .then(data => {
            const available = data.status === "Scanned";
            const totalRisks = (data.alerts_summary?.high || 0) + (data.alerts_summary?.medium || 0);
            const countEl = document.getElementById('zap-count-total');
            if(countEl) countEl.textContent = available ? totalRisks : '--';

            // --- UPDATED: Set Target URL ---
            const zapTargetEl = document.getElementById('zap-target');
            if (zapTargetEl && available) {
                zapTargetEl.textContent = `Target: ${data.target || 'Unknown'}`;
                // Optional: make it clickable if it's a URL
                if (data.target && data.target.startsWith('http')) {
                    zapTargetEl.style.cursor = 'pointer';
                    zapTargetEl.onclick = () => window.open(data.target, '_blank');
                }
            }

            const listEl = document.getElementById('zap-vuln-list');
            if(listEl && available) {
                if(data.top_risks && data.top_risks.length > 0) {
                    listEl.innerHTML = '';
                    
                    data.top_risks.forEach((vuln, index) => {
                        const riskClass = vuln.risk === 'High' ? 'risk-high' : (vuln.risk === 'Medium' ? 'risk-med' : 'risk-low');
                        const uid = `vuln-${index}`;
                        
                        // UPDATED HTML Structure matches the new CSS Grid layout
                        listEl.innerHTML += `
                            <div class="vuln-item">
                                <div class="vuln-header" onclick="document.getElementById('${uid}').classList.toggle('active')">
                                    <span class="vuln-title">${vuln.name}</span>
                                    <span class="risk-badge ${riskClass}">${vuln.risk}</span>
                                </div>
                                <div id="${uid}" class="vuln-body">
                                    <strong style="color:var(--neo-green); display:block; margin-bottom:0.5rem;">Suggested Fix:</strong>
                                    ${vuln.solution}
                                </div>
                            </div>
                        `;
                    });
                    const btn = document.getElementById('btn-zap-pdf');
                    if(btn) { btn.classList.remove('disabled'); btn.href = reportUrls.zap; }
                } else {
                    listEl.innerHTML = '<div style="text-align:center; padding:2rem; color:#444;">System Secure. No risks found.</div>';
                }
            }
        })
        .catch(console.error);

    // --- 3. SSL (ENCRYPTION) ---
    fetch(apiEndpoints.ssl)
        .then(r => r.json())
        .then(data => {
            const available = data.status === "Scanned";
            if(available) {
                const daysEl = document.getElementById('ssl-days');
                if(daysEl) daysEl.textContent = data.days_left;
                
                const keyEl = document.getElementById('ssl-key-info');
                if(keyEl) keyEl.textContent = data.key_info || 'Unknown';
                
                const protoEl = document.getElementById('ssl-protocols');
                if(protoEl) {
                    if(data.weak_protocols && data.weak_protocols.length > 0) {
                        protoEl.textContent = data.weak_protocols.join(', ');
                        protoEl.style.color = '#f43f5e';
                    } else {
                        protoEl.textContent = 'Modern (TLS 1.2+)';
                        protoEl.style.color = '#10b981';
                    }
                }
                const btn = document.getElementById('btn-ssl-pdf');
                if(btn) { btn.classList.remove('disabled'); btn.href = reportUrls.ssl; }
            }
        })
        .catch(console.error);

    // --- 4. SNIFFER (TRAFFIC) ---
    fetch(apiEndpoints.sniffer)
        .then(r => r.json())
        .then(data => {
            const available = data.status === "Analyzed";
            const countEl = document.getElementById('sniffer-packet-count');
            if(countEl) countEl.textContent = available ? data.total_packets : '--';
            
            if(available) {
                const durEl = document.getElementById('sniffer-duration');
                if(durEl) durEl.textContent = `Duration: ${data.duration}`;
                const tbody = document.getElementById('sniffer-table-body');
                if(tbody && data.top_talkers && data.top_talkers.length > 0) {
                    tbody.innerHTML = '';
                    data.top_talkers.forEach(t => {
                        tbody.innerHTML += `
                            <tr>
                                <td>${t.display}</td>
                                <td style="text-align:right; color:var(--neo-blue);">${t.bytes} B</td>
                            </tr>
                        `;
                    });
                }
                const btn = document.getElementById('btn-sniffer-pdf');
                if(btn) { btn.classList.remove('disabled'); btn.href = reportUrls.sniffer; }
            }
        })
        .catch(console.error);
});