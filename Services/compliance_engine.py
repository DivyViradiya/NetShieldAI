import os
import json
from datetime import datetime

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

class ComplianceEngine:
    def __init__(self, user_results_dir):
        self.base_dir = user_results_dir
        self.report_data = {
            "compliance_summary": {},
            "standards": {},
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Load Raw Data
        self.killchain = self._load_json("killchain/reports/killchain_report.json")
        self.zap = self._load_json("zap_scanner/zap_report.json")
        self.ssl = self._load_json("ssl_scanner/ssl_report.json")
        self.sql = self._load_json("sql_scanner/sql_report.json")
        self.nmap = self._load_json("network_scanner/nmap_report.json")

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

    def _consolidate_findings(self):
        """
        Normalizes findings from all scanners into a single list of text strings 
        (Title/Description) to make keyword matching easier.
        """
        findings = []

        # 1. Killchain Findings
        if self.killchain and 'vulns' in self.killchain:
            for v in self.killchain['vulns']:
                findings.append({
                    "source": "Killchain",
                    "title": v.get('type', ''),
                    "description": v.get('description', ''),
                    "severity": v.get('severity', 'Low')
                })

        # 2. ZAP Findings
        if self.zap and 'findings' in self.zap:
            for f in self.zap['findings']:
                findings.append({
                    "source": "ZAP Scanner",
                    "title": f.get('name', ''),
                    "description": f.get('description', ''),
                    "severity": f.get('risk', 'Low')
                })

        # 3. SQLMap Findings
        if self.sql and 'vulnerabilities' in self.sql:
            for s in self.sql['vulnerabilities']:
                findings.append({
                    "source": "SQL Scanner",
                    "title": s.get('title', 'SQL Injection'),
                    "description": f"Payload: {s.get('payload', '')}",
                    "severity": "Critical"
                })

        # 4. SSL Findings (Protocols & Vulnerabilities)
        if self.ssl:
            # Check Protocols
            for proto in self.ssl.get('protocols', []):
                if proto.get('enabled') and proto.get('name') in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', '1.0', '1.1']:
                    findings.append({
                        "source": "SSL Scanner",
                        "title": f"Weak Protocol Enabled: {proto.get('name')}",
                        "description": "Legacy SSL/TLS protocol detected.",
                        "severity": "High"
                    })
            # Check Vulns
            for v in self.ssl.get('vulnerabilities', []):
                findings.append({
                    "source": "SSL Scanner",
                    "title": v.get('name', ''),
                    "description": v.get('description', ''),
                    "severity": v.get('severity', 'Medium')
                })

        return findings

    def run_assessment(self):
        """
        Main logic: Iterates through standards, checks requirements against findings, 
        and calculates scores.
        """
        summary_scores = {}

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
                for finding in self.all_findings:
                    # Check if any keyword matches the finding title or description
                    # Using case-insensitive matching
                    title_match = any(k.lower() in finding['title'].lower() for k in req_info['keywords'])
                    
                    if title_match:
                        status = "FAIL"
                        evidence.append({
                            "issue": finding['title'],
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
            
            self.report_data["standards"][std_key] = std_report
            summary_scores[std_key] = std_report["score_percentage"]

        self.report_data["compliance_summary"] = summary_scores
        
        # Save the report
        self._save_report()
        return self.report_data

    def _save_report(self):
        """Saves the generated compliance report to disk."""
        if not self.base_dir:
            return
        output_path = os.path.join(self.base_dir, "compliance_report.json")
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.report_data, f, indent=4)
        except Exception as e:
            # In a production app, use logging instead of print
            print(f"Error saving compliance report: {e}")

# --- Standalone Execution Helper ---
def generate_compliance_report(user_dir):
    """
    Called by dashboard.py
    """
    engine = ComplianceEngine(user_dir)
    return engine.run_assessment()