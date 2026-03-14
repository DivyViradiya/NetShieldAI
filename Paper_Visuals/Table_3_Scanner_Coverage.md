### Table 3 — NetShieldAI Multi-Scanner Suite Coverage

| Scanner Module | Underlying Tool | Vulnerability Classes Detected | Kill-Chain Phase | Avg Latency | TCTR Output |
|---|---|---|---|---|---|
| Network Scanner | Nmap (python-nmap) | Port Exposure, Service Fingerprint, OS Detection | Recon / Delivery | 8.2s | TCTR P0–P3 |
| Web Vulnerability | OWASP ZAP | XSS, CSRF, Injection, Broken Auth, SSRF | Exploitation | 47.6s | TCTR P0–P3 |
| SSL / TLS Audit | SSLScan | Weak Ciphers, Cert Validity, Protocol Violations | Delivery / Installation | 4.1s | TCTR P0–P2 |
| Packet Sniffer | TShark / Scapy | ARP poisoning, Unusual DNS, Cleartext Creds | C2 / Exfiltration | 30.0s | TCTR P0–P3 |
| SQL Injection | SQLMap | Error-/Union-/Blind-based SQLi, DBMS Fingerprint | Exploitation | 63.4s | TCTR P0–P1 |
| Kill Chain | Custom (12 tools) | Recon → Weaponization → Exploitation (5 phases) | Full Kill Chain | 92.7s | TCTR P0–P3 |
| API Security | ZAP + OpenAPI parser | Broken Object-Level Auth, Mass Assignment, BOLA | Exploitation | 52.1s | TCTR P0–P2 |
| SAST (Semgrep) | Semgrep OSS | Hardcoded Secrets, Code Injection, Insecure Libs | Weaponization | 15.3s | TCTR P0–P2 |
