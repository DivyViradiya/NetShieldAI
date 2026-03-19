<div align="center">

# NetShieldAI 🛡️

*A Comprehensive, AI-Orchestrated Cyber Posture Management & Penetration Testing Platform.*

[![Python](https://img.shields.io/badge/Python-3.13+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-Web%20Framework-black)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/Machine%20Learning-TCTR%20Engine-orange)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

NetShieldAI is not just a vulnerability scanner; it is a full-fledged Security Orchestration, Automation, and Response (SOAR) platform integrated with a state-of-the-art Natural Language AI Action Model.

</div>

---

## 📖 Table of Contents
1. [Core Capabilities & Architecture](#-core-capabilities--architecture)
2. [🤖 The AI Security Orchestrator (Action Model)](#-the-ai-security-orchestrator-action-model)
3. [⚔️ Cyber Kill Chain Automation](#️-cyber-kill-chain-automation)
4. [🧠 TCTR Machine Learning Engine](#-tctr-machine-learning-engine)
5. [⚖️ Compliance & Governance](#️-compliance--governance)
6. [🔍 Detailed Scanning Modules](#-detailed-scanning-modules)
7. [⚙️ Scheduling & Automations](#️-scheduling--automations)
8. [📡 API Reference](#-api-reference)
9. [🎨 Frontend UI & Reporting](#-frontend-ui--reporting)
10. [📂 Project Structure](#-project-structure)
11. [🔧 Installation & Deployment](#-installation--deployment)

---

## 🌟 Core Capabilities & Architecture

NetShieldAI aggregates multiple industry-standard security tools (Nmap, OWASP ZAP, Wireshark/TShark, Semgrep) behind a unified Python/Flask backend and an intuitive "Neo-Futurism" UI. 

### Key Architectural Pillars:
*   **Asynchronous Execution Pipeline:** All scans run via background threaded workers (`ThreadPoolExecutor`) enabling non-blocking execution while streaming logs back to the browser via **Server-Sent Events (SSE)**.
*   **Multi-tenant Isolation:** Complete data separation for concurrent users. Results, `.pcap` files, and JSON summaries are segregated in specific `results/<user_id>` directories.
*   **Modular Blueprint Logic:** All routes (`routes/`) are separated into cleanly defined blueprints, invoking core logic housed dynamically inside `Services/`.

---

## 🤖 The AI Security Orchestrator (Action Model)

Unlike traditional chatbots, NetShieldAI's agent implements a **ReAct (Reasoning and Acting)** capability to act as an autonomous security analyst.

*   **Natural Language Execution:** Users can type commands like *"Run a stealth web audit on example.com and email me the report."*
*   **Intent Recognition:** The LLM extracts the target URL, dynamically configures scanning parameters (e.g., Aggression level: Stealth, Phases: Recon, Crawler), and executes the backend Flask endpoints via internal API proxying.
*   **Contextual Vulnerability Remediation:** When a scan finishes, the generator feeds the PDF/JSON logic directly into the AI's context window. You can immediately ask: *"How do I patch the SQL Injection found on line 14?"*

---

## ⚔️ Cyber Kill Chain Automation

The `killchain_service.py` engine is capable of executing sequential chained attacks mapped to the Lockheed Martin Cyber Kill Chain. It supports multiple profiles (`Recon Only`, `Network Audit`, `Web Audit`, `Full Scan`, `Reconfigure`) and aggression tunings (`Stealth`, `Normal`, `Attack`).

1.  **Reconnaissance Phase:** Subdomain enumeration, DNS resolving, and Technology Stack finger-printing using dynamic payload lists.
2.  **Network Audit Phase:** Uses configured Nmap profiles (stealth vs aggressive) combined with a custom `NetworkExploiter` to attempt credential brute-forcing on exposed ports (SSH, FTP, DBs).
3.  **WAF Detection Phase:** Probes the edge using known malicious payloads to identify Web Application Firewalls preventing false positives.
4.  **Web Audit Phase:** Multi-threaded web crawler that extracts API endpoints and forms, coupled with recursive directory fuzzing and custom logic parameter injection.
5.  **Traffic Analysis Phase:** Automatically launches a background `TShark` daemon to capture network telemetry during the attack, allowing post-scan deep inspection to see exactly what triggered the WAF.

---

## 🧠 TCTR Machine Learning Engine

The **Threat Context & Triage Ranking (TCTR)** pipeline transcends traditional CVSS base scoring by bringing in real-world exploitability and complex semantic understanding.

**How TCTR Works (`tctr_engine.py`):**
1.  **Feature Extraction:** Translates vulnerabilities into 10 structured vectors including asset context, threat velocity (CVE age scaling factors), semantic centrality, and affected product ratios.
2.  **Sentence Transformer NLP:** Unmapped vulnerabilities undergo Zero-Shot Classification. The description is encoded via `all-MiniLM-L6-v2` and mapped to known CWE patterns using pure **Cosine Similarity matrix operations**.
3.  **XGBoost / LightGBM Ranker:** Evaluates the vectors to predict an exact "Exploitability Risk Score" resulting in a standardized Tier output:
    *   `P0 (Critical)`: >0.85
    *   `P1 (High)`: 0.65 - 0.84
    *   `P2 (Medium)`: 0.35 - 0.64
    *   `P3 (Low)`: <0.35
4.  **Heuristic Multipliers:** Penalizes bugs found within the OWASP Top 10 or SANS Top 25 frameworks with dynamic weighting.

---

## ⚖️ Compliance & Governance

The internal `compliance_engine.py` automatically maps any vulnerability across any scanner into Board-Ready compliance assessments.

*   **PCI-DSS v4.0:** Verifies Strong Cryptography (TLS 1.2+), Injection Preventions (6.2.4), and Security Headers (6.3.2).
*   **GDPR (EU):** Validates Art-32 (Encryption & Confidentiality) alerting instantly on IDORs and Cleartext transmissions.
*   **ISO-27001 & SOC-2:** Ensures logical access boundaries, secure coding (A.8.28), and prevention of malicious software.
*   Outputs aggregated pass/fail ratios for easy Executive summarization via the Dashboard API.

---

## 🔍 Detailed Scanning Modules

NetShieldAI is composed of over 7 independent scanner services located in `/Services/`.

### 1. API Scanner (`api_scanner.py`)
Targeted REST, OpenAPI, and GraphQL auditing. It launches a headless OWASP ZAP Daemon on a dynamic port, imports standard OpenAPI JSON configurations, injects Bearer/Token auth parameters automatically, and executes rapid active scans specifically calibrated for RESTful API structures.

### 2. Semgrep SAST (`semgrep_scanner.py`)
Static Application Security Testing integration. You provide a repository or zip file; the webapp executes predefined lightweight rulesets to catch Hardcoded Secrets, Insecure Configurations, and broken access controls directly at the source code level before execution.

### 3. ZAP Web Scanner (`zap_scanner.py`)
A generalized wrapper for OWASP ZAP targeting web frontends. Maps ZAP's internal alert definitions against our TCTR ML mapping to refine alert fatigue and eliminate "Informational" bloat.

### 4. Network Scanner (`network_scanner.py`)
Highly threaded Nmap wrapper automating Service Version Detection (`-sV`), OS Fingerprinting (`-O`), Fragmented routing (`-f`), and UDP mapping (`-sU`). Integrates automatic **Port Blocking** (`netsh/ufw`) commands as quick remediation actions.

### 5. PDF & Reporting (`pdf_generator.py`)
Takes the raw decoupled JSON trees of every scanner and renders pixel-perfect, beautifully engineered PDF architectures utilizing `WeasyPrint` and highly nested `Jinja2` templates.

### 6. Packet Sniffer / Traffic Analysis (`packet_sniffer.py`)
Hooks into interface adapters using TShark. Executes live deep packet regex indexing to identify out-of-band data leakage, ARP Spoofing characteristics, and anomalous DNS tunneling queries.

### 7. SQL Scanner (`sql_scanner.py` & others)
Specific modules mapped directly to identifying SQLi structures via Time-Based Blind and Boolean testing metrics.

---

## ⚙️ Scheduling & Automations

Powered by *APScheduler* within `scheduler_service.py`.

*   **Cron-style Granularity:** Schedule scans to run Daily, Weekly, or on explicit calendar bounds.
*   **Automated Email Dispatching:** Built-in `email_service.py` manages SMTP dispatching. It transforms the `.pdf` reports into formatted email HTML (`Services/PDF_templates/`) combined with actionable metadata highlights. Supports bypassing email functionality per job dynamically.
*   **Asynchronous Background Execution:** Runs completely silently in the background of identical Flask workers ensuring zero blocking on user UX.

---

## 📡 API Reference

All services operate on explicit Blueprint routing topologies.

| Blueprint | Endpoint Route | Methods | Description |
| :--- | :--- | :--- | :--- |
| **`auth_bp`** | `/login`, `/admin` | GET/POST | JWT/Session logic, user access validations, and system monitoring. |
| **`killchain_bp`** | `/killchain/start` | POST | Triggers the multi-tool orchestrated Cyber Attack chain. |
| **`dashboard_bp`** | `/api/stats/*` | GET (AJAX)| Realtime retrieval of compliance scores, total vulnerabilities, etc. |
| **`scanner_bps`**| `/*/scan` | POST | Unified target injection system (applies to ZAP, SSL, SQL). |
| **`scanner_bps`**| `/*/log_stream` | GET (SSE) | Maintains streaming text/event connection for the UI terminal. |
| **`chatbot_bp`** | `/chat_stream` | POST | Streams token-by-token LLM conversational replies and function flags. |

---

## 🎨 Frontend UI & Reporting

The entire UI is built on a highly custom "Neo-Futurism" aesthetic mapping.

*   **Interactivity & State:** Vanilla JS with aggressive `fetch()` integrations ensures zero page reloads. DOM elements are mutated asynchronously utilizing EventListeners attached to SSE streams.
*   **Design Language:** Uses `.css` structural mapping defining variable blocks: Night-Black backgrounds (`#050505`), glass-morphism panels, vivid blue highlights (`#3b82f6`), and drop-down responsive transitions.
*   **Terminals:** Integrated dark-mode terminals on each scanner view provide real-time STDOUT piping, generating exact transparency to what the backend python scripts are doing.

---

## 📂 Project Structure

```text
NetShieldAI/
├── Data/                       # Base dictionaries & CWE mapping config JSONs
├── models/                     # Compiled TCTR Machine learning artifacts (.pkl)
├── core/
│   ├── extensions.py           # Configs for Flask SQL Alchemy etc.
│   ├── logger_setup.py         # Advanced rotating file logger configurations
│   ├── forms.py                # WTForms validations
│   └── packet_invoker.py       # TShark invoker abstraction
├── scripts/
│   ├── init_db.py              # Bootstraps initial DB admin state
│   ├── update_banners.py       # Fetching newest vulnerabilities dynamically
│   └── migrate_scheduler_db.py # DB Schema mutation configurations
├── routes/                     # Application Blueprints
│   ├── api_scanner_bp.py       # REST API Scanning routes
│   ├── chatbot_bp.py           # The LLM Integration and Proxy routes
│   ├── killchain_bp.py         # Orchestration phase configurations
│   ├── scheduler_bp.py         # Job and automation management APIs
│   └── ... (Other Scanners)
├── Services/                   # Business Logic & Backend Engines
│   ├── compliance_engine.py    # Standard mappings (PCI/GDPR)
│   ├── killchain_service.py    # Profile orchestration logic
│   ├── pdf_generator.py        # PDF WeasyPrint integration logic
│   ├── scheduler_service.py    # APScheduler management
│   ├── tctr_engine.py          # Machine learning logic and SentenceTransformers
│   ├── pentest_modules/        # Specific logic modules (Crawler, Fuzzer_
│   └── PDF_templates/          # Jinja2 HTML views for reporting / emails
├── static/                     # CSS architecture, Fonts, Images
├── templates/                  # Frontend UI views
├── .env                        # System environment bindings
├── requirements.txt            # System python dependencies
├── run.py                      # Main deployment server initiator
└── run_ngrok.py                # Wrapper for publicly proxying Webhooks
```

---

## 🔧 Installation & Deployment

### Prerequisites:
1.  **Python 3.13+**
2.  **External Binaries:** You MUST install [Nmap](https://nmap.org/download.html), [OWASP ZAP](https://www.zaproxy.org/download/), and [Wireshark/TShark](https://www.wireshark.org/download.html). Ensure they are declared in your OS `PATH`.
3.  **GTK3 Library:** Required natively by WeasyPrint for PDF generation. See [GTK Installation Docs](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation).

### 1. Repository Setup
```bash
git clone https://github.com/DivyViradiya07/NetShield.git
cd NetShieldAI
python -m venv venv
```

### 2. Enter Environment & Install
**Windows:**
```bash
venv\Scripts\activate
pip install -r requirements.txt
```
**Linux / MacOS:**
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Initialize Databases
```bash
# This injects your Base Admin credentials
python scripts/init_db.py
```

### 4. Running the Ecosystem
```bash
# Default mode
python run.py

# Public webhook / Demonstration mode
python run_ngrok.py
```
> **Notice:** Scanners utilizing raw sockets (Nmap OS Fingerprinting, Packet Sniffing APIs) require running the application environment utilizing Administrator/Root privilege elevations.

Access the application via your browser at **http://localhost:5100**. Login using `admin` for comprehensive control over the entire SOAR pipeline.
