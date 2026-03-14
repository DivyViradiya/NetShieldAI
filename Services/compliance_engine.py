import os
import json
from datetime import datetime
from logger_setup import logger
from Services import report_manager

# --- CONFIGURATION & MAPPINGS ---
# This dictionary acts as the "Brain" of the compliance engine.
COMPLIANCE_MAP = {
    "PCI-DSS": {
        "description": "Payment Card Industry Data Security Standard (v4.0)",
        "requirements": {
            "4.2.1": {"name": "Strong Cryptography (TLS 1.2+)", "keywords": ["TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3", "Weak Cipher", "Cleartext"]},
            "6.2.4": {"name": "Prevention of Injection Attacks", "keywords": ["SQL Injection", "SQLi", "Blind SQL", "Injection"]},
            "6.2.4.1": {"name": "Prevention of Cross-Site Scripting", "keywords": ["Cross Site Scripting", "XSS", "Reflected XSS", "Stored XSS"]},
            "6.3.2": {"name": "Security Headers & Config", "keywords": ["X-Frame-Options", "Content-Security-Policy", "Clickjacking", "HSTS", "Strict-Transport-Security"]},
            "6.4.1": {"name": "Public Facing Web Vulnerabilities", "keywords": ["SSRF", "RCE", "Remote Code Execution", "Directory Traversal"]},
            "5.3.3": {"name": "Sensitive Data Exposure", "keywords": ["Information Leak", "Version Leak", "Timestamp Disclosure", "IDOR"]}
        }
    },
    "GDPR": {
        "description": "General Data Protection Regulation (EU)",
        "requirements": {
            "Art-32-1-a": {"name": "Encryption of Personal Data", "keywords": ["TLSv1.0", "TLSv1.1", "Weak Cipher", "HTTP Only", "Cleartext"]},
            "Art-32-1-b": {"name": "Confidentiality & Integrity", "keywords": ["SQL Injection", "IDOR", "Access Control", "Authentication Bypass", "SSRF"]},
            "Art-32-Security": {"name": "State of the Art Security", "keywords": ["XSS", "CSRF", "Clickjacking", "Outdated Component", "Vulnerable Dependency"]},
            "Art-25": {"name": "Data Protection by Design", "keywords": ["Debug Mode", "Verbose Error", "Information Leak", "Stack Trace"]}
        }
    },
    "ISO-27001": {
        "description": "ISO/IEC 27001:2022 Information Security",
        "requirements": {
            "A.8.24": {"name": "Use of Cryptography", "keywords": ["TLSv1.0", "TLSv1.1", "Weak Cipher", "HTTP Only"]},
            "A.8.28": {"name": "Secure Coding", "keywords": ["SQL Injection", "XSS", "Injection", "CSRF", "Input Validation"]},
            "A.8.12": {"name": "Data Leakage Prevention", "keywords": ["Information Leak", "IDOR", "Sensitive Data", "Banner Grabbing"]},
            "A.5.15": {"name": "Access Control", "keywords": ["Authentication Bypass", "Weak Password", "IDOR", "Broken Access Control"]}
        }
    },
    "SOC-2": {
        "description": "SOC 2 Trust Services Criteria (Security)",
        "requirements": {
            "CC-6.1": {"name": "Logical Access Security", "keywords": ["Authentication", "SQL Injection", "Bypass", "IDOR"]},
            "CC-6.6": {"name": "Boundary Protection (Encryption)", "keywords": ["TLSv1.0", "Weak Cipher", "HTTP Only"]},
            "CC-7.1": {"name": "System Configuration (Hardening)", "keywords": ["Missing Headers", "Clickjacking", "CSP", "Banner Leak"]},
            "CC-6.8": {"name": "Prevention of Malicious Software", "keywords": ["XSS", "RCE", "Malware", "Upload"]}
        }
    }
}

def normalize_target(target):
    if not target: return "Global"
    # Basic normalization to domain/IP
    t = target.replace("http://", "").replace("https://", "").split('/')[0].split(':')[0]
    return t

class ComplianceEngine:
    def __init__(self, user_results_dir):
        self.base_dir = user_results_dir
        self.report_data = {
            "compliance_summary": {},
            "standards": {},
            "targets": {},
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Load Raw Data
        self.killchain = self._load_latest_json("killchain/reports", ["killchain_*.json", "killchain_report*.json"])
        self.zap = self._load_latest_json("zap_scanner", ["zap_scanner_*.json", "zap_report*.json"])
        self.ssl = self._load_latest_json("ssl_scanner", ["ssl_report*.json"])
        self.sql = self._load_latest_json("sql_scanner", ["sql_scanner_*.json", "sql_report*.json"])
        self.nmap = self._load_latest_json("network_scanner", ["network_scanner_*.json", "nmap_report*.json"])
        self.api = self._load_latest_json("api_scanner", ["api_scanner_*.json", "api_scan_report*.json"])
        self.semgrep = self._load_latest_json("semgrep_scanner", ["semgrep_scanner_*.json", "semgrep_report*.json"])

        # Consolidated list of all technical findings
        self.all_findings = self._consolidate_findings()

    def _load_json(self, rel_path):
        """Helper to safely load JSON files."""
        if not self.base_dir:
            return {}
        path = os.path.join(self.base_dir, rel_path)
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}
        
    def _load_latest_json(self, scanner_folder, patterns):
        """Helper to find and load the latest JSON file matching any of the patterns."""
        if not self.base_dir:
            return {}
            
        import glob
        target_dir = os.path.join(self.base_dir, scanner_folder)
        if not os.path.exists(target_dir):
            return {}
            
        if not isinstance(patterns, list):
            patterns = [patterns]
            
        candidates = []
        for pattern in patterns:
            candidates.extend(glob.glob(os.path.join(target_dir, pattern)))
            
        if candidates:
            latest_path = max(candidates, key=os.path.getmtime)
            try:
                with open(latest_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _consolidate_findings(self):
        """
        Normalizes findings from all scanners into a single list of findings with target info.
        """
        findings = []

        # 1. Killchain Findings
        if self.killchain:
            target = self.killchain.get('target', 'Unknown')
            if 'vulns' in self.killchain:
                for v in self.killchain['vulns']:
                    findings.append({
                        "target": target,
                        "source": "Killchain",
                        "title": v.get('type', ''),
                        "description": v.get('description', ''),
                        "severity": v.get('severity', 'Low')
                    })

        # 2. ZAP Findings
        if self.zap:
            for f in self.zap.get('findings', []):
                findings.append({
                    "target": f.get('url', 'Unknown'),
                    "source": "ZAP Scanner",
                    "title": f.get('name', ''),
                    "description": f.get('description', ''),
                    "severity": f.get('risk', 'Low')
                })

        # 3. SQLMap Findings
        if self.sql:
            target = self.sql.get('target', 'Unknown')
            for s in self.sql.get('vulnerabilities', []):
                findings.append({
                    "target": target,
                    "source": "SQL Scanner",
                    "title": s.get('title', 'SQL Injection'),
                    "description": f"Payload: {s.get('payload', '')}",
                    "severity": "Critical"
                })

        # 4. SSL Findings
        if self.ssl:
            target = self.ssl.get('target', 'Unknown')
            for proto in self.ssl.get('protocols', []):
                if proto.get('enabled') and proto.get('name') in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', '1.0', '1.1']:
                    findings.append({
                        "target": target,
                        "source": "SSL Scanner",
                        "title": f"Weak Protocol Enabled: {proto.get('name')}",
                        "description": "Legacy SSL/TLS protocol detected.",
                        "severity": "High"
                    })
            for v in self.ssl.get('vulnerabilities', []):
                findings.append({
                    "target": target,
                    "source": "SSL Scanner",
                    "title": v.get('name', ''),
                    "description": v.get('description', ''),
                    "severity": v.get('severity', 'Medium')
                })
        
        # 5. Nmap Findings
        if self.nmap:
            target = self.nmap.get('target_ip', 'Unknown')
            for port in self.nmap.get('ports', []):
                vuln_notes = port.get('vulnerability_notes', '')
                if vuln_notes:
                     findings.append({
                        "target": target,
                        "source": "Network Scanner",
                        "title": f"Vulnerability on Port {port.get('port')}",
                        "description": vuln_notes,
                        "severity": "High"
                    })

        # 6. API Scanner Findings
        if self.api:
            for f in self.api.get('findings', []):
                findings.append({
                    "target": f.get('url', 'API Endpoint'),
                    "source": "API Scanner",
                    "title": f.get('name', ''),
                    "description": f.get('description', ''),
                    "severity": f.get('risk', 'Low')
                })

        # 7. Semgrep SAST Findings
        if self.semgrep:
            for f in self.semgrep.get('findings', []):
                findings.append({
                    "target": "Source Code",
                    "source": "Semgrep SAST",
                    "title": f.get('check_id', ''),
                    "description": f.get('message', ''),
                    "severity": f.get('severity', 'INFO')
                })

        return findings

    def run_assessment(self):
        """
        Main logic: Iterates through standards, checks requirements against findings, 
        and calculates scores, grouped by target.
        """
        # Group findings by target
        findings_by_target = {}
        for f in self.all_findings:
            t = normalize_target(f['target'])
            if t not in findings_by_target:
                findings_by_target[t] = []
            findings_by_target[t].append(f)
            
        self.report_data["targets"] = {}
        
        if not findings_by_target:
             # Just run global assessment with empty findings if none found
             self.report_data["targets"]["Global"] = self._assess_findings([])
        else:
            for target, target_findings in findings_by_target.items():
                self.report_data["targets"][target] = self._assess_findings(target_findings)
            
        # Global Aggregate for backwards compatibility
        global_results = self._assess_findings(self.all_findings)
        self.report_data["standards"] = global_results["standards"]
        self.report_data["compliance_summary"] = global_results["compliance_summary"]
        
        # Save the report
        self._save_report()
        return self.report_data

    def _assess_findings(self, findings):
        """Helper to run assessment against a specific set of findings."""
        summary_scores = {}
        standards_report = {}

        for std_key, std_data in COMPLIANCE_MAP.items():
            std_report = {
                "name": std_data["description"],
                "total_requirements": len(std_data["requirements"]),
                "passed_requirements": 0,
                "failed_requirements": 0,
                "score_percentage": 100,
                "details": []
            }

            failures = 0

            # Check each requirement in the standard
            for req_id, req_info in std_data["requirements"].items():
                status = "PASS"
                evidence = []

                # Scan consolidated findings for keywords
                for finding in findings:
                    title = str(finding.get('title', '') or '')
                    description = str(finding.get('description', '') or '')
                    
                    title_match = any(k.lower() in title.lower() for k in req_info['keywords'])
                    desc_match = any(k.lower() in description.lower() for k in req_info['keywords'])
                    
                    if title_match or desc_match:
                        status = "FAIL"
                        evidence.append({
                            "issue": title,
                            "source": finding['source'],
                            "severity": finding['severity']
                        })

                if status == "FAIL":
                    failures += 1
                    # Remove duplicates from evidence based on 'issue' name
                    unique_evidence = {v['issue']:v for v in evidence}.values()
                    std_report["details"].append({
                        "id": req_id,
                        "requirement": req_info["name"],
                        "status": "FAIL",
                        "evidence": list(unique_evidence)
                    })
                else:
                    std_report["passed_requirements"] += 1
                    std_report["details"].append({
                        "id": req_id,
                        "requirement": req_info["name"],
                        "status": "PASS",
                        "evidence": []
                    })

            std_report["failed_requirements"] = failures
            if std_report["total_requirements"] > 0:
                score = ((std_report["total_requirements"] - failures) / std_report["total_requirements"]) * 100
                std_report["score_percentage"] = round(score, 1)
            
            standards_report[std_key] = std_report
            summary_scores[std_key] = std_report["score_percentage"]

        return {
            "compliance_summary": summary_scores,
            "standards": standards_report
        }

    def _save_report(self):
        """Saves the generated compliance report to disk."""
        if not self.base_dir:
            return
        output_path = os.path.join(self.base_dir, "compliance_report.json")
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.report_data, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving compliance report: {e}")

# --- Standalone Execution Helper ---
def generate_compliance_report(user_dir):
    """
    Called by dashboard.py
    """
    engine = ComplianceEngine(user_dir)
    return engine.run_assessment()
