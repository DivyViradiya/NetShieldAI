# NetShieldAI 🛡️

NetShieldAI is a comprehensive, AI-powered network security and vulnerability assessment platform. It provides a suite of advanced tools for network scanning, packet analysis, SSL/TLS auditing, and web application security testing, all integrated into a modern, user-friendly web interface.

## 🚀 Key Features

- **Network Scanner:** High-performance port scanning and service detection using Nmap. Identifies open ports, running services, and OS versions.
- **Packet Sniffer & Analyzer:** Captures live network traffic and provides deep packet inspection (DPI) with detailed analysis of protocols, traffic patterns, and potential anomalies.
- **SSL/TLS Auditor:** Evaluates the security configuration of SSL/TLS certificates and identifies weak ciphers, expired certificates, and misconfigurations.
- **Web Application Scanner (ZAP):** Integrates OWASP ZAP for automated security testing of web applications, uncovering common vulnerabilities like SQL injection, XSS, and more.
- **AI-Powered Chatbot:** A specialized security assistant capable of answering queries, interpreting scan results, and providing remediation advice.
- **Vulnerability Ranking:** Employs Machine Learning models to analyze and rank discovered vulnerabilities based on severity and potential impact.
- **Professional PDF Reporting:** Generates detailed, well-structured PDF reports for all security scans, suitable for compliance and technical reviews.
- **Multi-User Dashboard:** Secure user authentication and a personalized dashboard to manage scan history and download reports.

## 🧠 AI & Machine Learning Pipeline

NetShieldAI utilizes a sophisticated Hybrid Machine Learning pipeline to assess and rank the risk of discovered vulnerabilities, moving beyond simple CVSS scores.

### 1. Data Processing (Phase 1)
*   **Source:** Aggregates over 150,000 CVE records from the National Vulnerability Database (NVD).
*   **Profiling:** Groups individual CVEs by their underlying Weakness Type (CWE) to create comprehensive "CWE Profiles."
*   **Custom Risk Metric:** Calculates an "Actual Risk Score" that weighs the base severity against real-world exploitability factors like Attack Vector (Network vs. Physical) and Privilege Requirements.

### 2. Hybrid Model Architecture (Phase 2)
The core prediction engine is an **XGBoost Regressor** that learns from two distinct types of data:
*   **Structured Features:** Statistical aggregates of CVSS scores (Mean, Max, Std Dev), Impact metrics (Confidentiality, Integrity, Availability), and frequency counts.
*   **Unstructured Text (NLP):** Utilizes **Sentence Transformers (`all-MiniLM-L6-v2`)** to generate high-dimensional semantic embeddings from vulnerability descriptions.

### 3. Optimization & Performance
To ensure efficiency and accuracy, the pipeline employs:
*   **PCA (Principal Component Analysis):** Reduces noise in text embeddings.
*   **Smart Feature Selection (`SelectKBest`):** Identifies the top 30 most predictive semantic features using Mutual Information Regression.
*   **Result:** The "Elite" Hybrid model achieves an **R² score of ~0.76**, significantly outperforming standard structured-data models.

### 📓 Notebooks
*   `Phase_1_Data_preparation.ipynb`: Data cleaning, feature engineering, and CWE profiling.
*   `Phase_2_Model_training.ipynb`: Baseline XGBoost model training on structured data.
*   `Phase_2_Hybrid_Model.ipynb`: Advanced model training with NLP embeddings, PCA, and Feature Selection.

## 📡 API Endpoints & Functionality

NetShieldAI is built on a modular Flask Blueprint architecture.

### 🔐 Authentication (`auth_bp`)
*   `/login`, `/register`, `/logout`: Standard user session management.
*   `/admin`: Administrator dashboard for user management and system stats.
*   `/account/settings`: Profile updates and password changes.

### 📊 Dashboard (`dashboard_bp`)
*   `/dashboard`: Main user interface.
*   `/api/stats/*`: Asynchronous endpoints fetching aggregated JSON statistics for Network, ZAP, SSL, and Sniffer modules to populate the UI.

### 🤖 AI Chatbot (`chatbot_bp`)
*   `/chat`, `/chat_stream`: Real-time interaction with the security assistant (supports streaming responses).
*   `/upload_report`: Analyzes uploaded PDF security reports using the LLM.
*   `/scanner_analysis`: Proxies internally generated scan reports directly to the AI for analysis.
*   **Session Management:** Supports creating, renaming, deleting, and pinning chat sessions.

### 🔍 Scanners
All scanner modules follow a consistent pattern:
1.  **Initiate:** `POST /scan` (threaded execution).
2.  **Monitor:** `GET /log_stream` (Server-Sent Events for real-time logs).
3.  **Report:** `GET /download_pdf`, `GET /get_json_report`.
4.  **AI Integration:** `POST /trigger_ai_analysis`.

*   **Network Scanner (`network_scanner_bp`):** Supports 'default', 'os', 'aggressive', 'tcp_syn', and 'udp' scan types. Includes port blocking capabilities.
*   **Packet Sniffer (`packet_sniffer_bp`):** Captures traffic on selected interfaces, generates `.pcap` files, and performs deep packet inspection.
*   **SSL Scanner (`ssl_scanner_bp`):** Checks for weak protocols (SSLv2/3, TLS 1.0/1.1) and certificate validity.
*   **ZAP Scanner (`zap_scanner_bp`):** Automated web vulnerability scanning with ML-based risk scoring.

## ⚙️ Core Services & Logic

The `Services/` directory contains the heavy-lifting logic, independent of the web framework.

### 1. Network Scanner (`network_scanner.py`)
*   **Engine:** Wraps the `nmap` CLI.
*   **Features:**
    *   OS Detection (`-O`), Aggressive Scan (`-A`), Fragmentation (`-f`), TCP SYN (`-sS`).
    *   **Port Blocking:** Uses system-level commands (`netsh` on Windows, `ufw` on Linux) to block risky ports found during scans.
    *   **Reporting:** Parses Nmap's Grepable output (`-oG`) into structured JSON for the frontend and PDF generation.

### 2. Packet Sniffer (`packet_sniffer.py`)
*   **Engine:** Wraps `tshark` (Wireshark command line).
*   **Features:**
    *   Captures live traffic to `.pcap` files.
    *   **Analysis:** Performs deep inspection to detect:
        *   **ARP Spoofing:** Detects multiple MAC addresses claiming the same IP.
        *   **DNS Tunneling:** Flags unusually long DNS queries.
        *   **SQL Injection & Credential Leaks:** Inspects HTTP payloads for patterns.
    *   **Statistics:** Generates protocol hierarchy and conversation stats.

### 3. SSL/TLS Scanner (`ssl_scanner.py`)
*   **Engine:** Wraps `sslscan.exe`.
*   **Features:**
    *   Evaluates server SSL/TLS configuration.
    *   **Vulnerability Checks:** Heartbleed, CRIME (TLS Compression), Insecure Renegotiation, Weak Ciphers (RC4, 3DES), and Deprecated Protocols (SSLv2/3).
    *   **Certificate Analysis:** Checks for weak signatures (SHA1) and expiry.

### 4. ZAP Web Scanner (`zap_scanner.py`)
*   **Engine:** Wraps OWASP ZAP (Zed Attack Proxy) in headless mode.
*   **Features:**
    *   **ML Integration:** Maps ZAP alerts to CWE IDs and uses the trained XGBoost model to predict a refined "Risk Score" based on the vulnerability context.
    *   **User Isolation:** Manages separate log queues for concurrent users.

### 5. PDF Generator (`pdf_generator.py`)
*   **Engine:** `WeasyPrint` + `Jinja2`.
    *   **Function:** Converts the raw JSON results from all scanners into professional, styled PDF reports. It uses HTML templates found in `Services/PDF_templates/`.

## 🎨 Frontend & User Interface

The user interface is built on a custom "Neo-Futurism" design system, prioritizing clarity, efficiency, and a modern aesthetic.

### Design System (`style.css` & `base.html`)
*   **Theme:** Dark mode by default, featuring deep black backgrounds (`#050505`), subtle card surfaces (`#0f0f11`), and vibrant blue accents (`#3b82f6`).
*   **Typography:** Uses the **Inter** font family for clean, highly readable text.
*   **Components:**
    *   **Navbar:** Glassmorphism effect with blur filters, sticky positioning, and a dynamic profile dropdown.
    *   **Cards:** "Neo-Cards" with glowing corner accents and hover lift effects.
    *   **Alerts:** Contextual flash messages (Success, Danger, Warning, Info) for user feedback.

### Key Pages
*   **Home (`home.html`):** A high-impact landing page featuring a hero section, system status indicators, and quick-launch cards for all security modules.
*   **Tools Hub:** A centralized dashboard to access Network, ZAP, SSL, and Sniffer tools.
*   **Scanner Interfaces:** Each scanner (Network, Packet Sniffer, etc.) has a dedicated page with:
    *   **Control Panel:** For setting target IPs/URLs and scan options.
    *   **Live Logs:** A real-time terminal-like view streaming server logs via SSE.
    *   **Results View:** Tabbed interfaces to switch between raw text results, visual tables, and PDF downloads.
*   **AI Chatbot:** A chat interface featuring code syntax highlighting, typing indicators, and session management.

### JavaScript Interactivity (`script.js`)
The frontend is powered by vanilla JavaScript for a lightweight footprint:
*   **Event Listeners:** Handles button clicks, form submissions, and tab switching.
*   **SSE (Server-Sent Events):** Listens to `/log_stream` endpoints to update the "Live Log" panels in real-time without page reloads.
*   **Async/Await:** Uses `fetch` for non-blocking API calls to start scans and retrieve results.
*   **Dynamic DOM Updates:** Automatically populates tables (e.g., Open Ports) and status indicators based on JSON responses.

## 🔄 System Workflow & Functionality

This section illustrates the lifecycle of a standard user interaction with NetShieldAI.

### 1. User Onboarding & Session
*   **Entry:** Users register or login via the secure `auth_bp` routes.
*   **Isolation:** Upon login, a unique composite identifier (`username_id`) is generated. This ensures that all scan results, logs, and generated PDFs are stored in a private directory (`Services/results/<user_id>/`), preventing data leakage between users.

### 2. The Scanning Lifecycle
When a user initiates a scan (e.g., Nmap or ZAP) from the "Tools Hub":
1.  **Request:** The frontend sends a `POST` request to the specific scanner's API (e.g., `/network_scanner/scan`) with the target IP/URL.
2.  **Async Execution:** The backend spawns a background **Thread** to run the heavy CLI tool (Nmap/ZAP/TShark/SSLScan). This prevents the UI from freezing.
3.  **Real-Time Feedback:**
    *   The background thread writes progress updates to a user-specific log queue.
    *   The frontend's `EventSource` connects to the `/log_stream` endpoint, receiving these updates via **Server-Sent Events (SSE)** and displaying them in the "Live Log" terminal.
4.  **Completion & Reporting:**
    *   Once the tool finishes, the raw output (XML/Text) is parsed into structured JSON.
    *   A PDF report is immediately generated using `WeasyPrint`.
    *   Key metrics (e.g., open ports count) are saved to the database to update the user's dashboard stats.

### 3. AI Analysis Integration
After a scan is complete, the user can click **"Analyze with AI"**:
1.  **Trigger:** The scanner page calls the `/trigger_ai_analysis` endpoint.
2.  **Proxying:** The system locates the user's specific PDF report and proxies it to the `chatbot_bp`.
3.  **Processing:** The report content is fed into the LLM context.
4.  **Interaction:** The user is redirected to the Chatbot interface, where the AI has already ingested the report context and is ready to answer questions like "How do I fix the high-risk vulnerability on port 80?"

## 🛠️ Tech Stack
- **Backend:** Python 3.13+, Flask
- **Database:** SQLAlchemy (SQLite)
- **Frontend:** HTML5, CSS3 (Tailwind CSS, Glassmorphism), JavaScript
- **AI/ML:** Scikit-learn, Pandas, Joblib
- **Security Tools:** Nmap, OWASP ZAP, TShark (Wireshark)
- **PDF Generation:** WeasyPrint, Jinja2
- **Authentication:** Flask-Login

## 📋 Prerequisites

Before running NetShieldAI, ensure you have the following installed on your system:

1.  **Python 3.13+**
2.  **Nmap:** [Download Nmap](https://nmap.org/download.html)
3.  **Wireshark/TShark:** [Download Wireshark](https://www.wireshark.org/download.html) (Ensure TShark is in your PATH)
4.  **OWASP ZAP:** [Download OWASP ZAP](https://www.zaproxy.org/download/)
5.  **GTK3 (for WeasyPrint):** WeasyPrint requires the GTK+ library. Follow the [installation instructions](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation) for your OS.
6.  **System Utilities (Linux):** `ufw`, `lsof`, `net-tools` (typically pre-installed on most distributions).

## 🔧 Installation

1.  **Clone the Repository:**

    ```bash
    git clone https://github.com/DivyViradiya07/NetShield.git
    cd NetShieldAI
    ```

2.  **Create a Virtual Environment:**

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install Dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Initialize the Database:**
    ```bash
    python init_db.py
    ```
    _(This will create an admin user: `admin` / `admin123` and a test user: `testuser` / `user123`)_

## 🖥️ Usage

1.  **Start the Application:**
    ```bash
    python run.py
    ```
2.  **Access the Interface:**
    Open your web browser and navigate to `http://localhost:5100`.
3.  **Elevated Privileges:**
    Some features (like Nmap OS detection and Packet Sniffing) require Administrative/Root privileges. The application will attempt to elevate if necessary.

## 📂 Project Structure

```text
NetShieldAI/
├── Data/               # Datasets and processed CVE data
├── models/             # Pre-trained ML models for vulnerability ranking
├── notebooks/          # Data analysis and model training notebooks
├── routes/             # Flask Blueprints for different modules
├── Services/           # Core scanning and analysis logic
│   ├── results/        # User-specific scan results and PDFs
│   └── PDF_templates/  # HTML templates for PDF reports
├── static/             # CSS, JS, and image assets
├── templates/          # Jinja2 HTML templates for the web UI
├── run.py              # Application entry point
└── models.py           # Database models
```
