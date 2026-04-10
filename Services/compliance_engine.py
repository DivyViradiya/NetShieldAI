import os
import json
from core.time_utils import get_now_ist_str
from core.logger_setup import logger
from Services import report_manager

# --- CONFIGURATION & MAPPINGS ---
# This dictionary acts as the "Brain" of the compliance engine.
COMPLIANCE_MAP = {
    "PCI-DSS": {
        "description": "Payment Card Industry Data Security Standard (v4.0)",
        "requirements": {
            "4.2.1": {
                "name": "Strong Cryptography (TLS 1.2+)", 
                "keywords": ["TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3", "Weak Cipher", "Cleartext"],
                "remediation": "Disable legacy SSL/TLS protocols (SSLv2, SSLv3, TLS 1.0, 1.1) on the server. Enforce TLS 1.2 or 1.3 with strong, modern cipher suites (e.g., ECDHE-RSA-AES256-GCM-SHA384)."
            },
            "6.2.4": {
                "name": "Prevention of Injection Attacks", 
                "keywords": ["SQL Injection", "SQLi", "Blind SQL", "Injection"],
                "remediation": "Implement parameterized queries (prepared statements) for all database interactions. Use an ORM where possible and ensure input validation is enforced at the application layer."
            },
            "6.2.4.1": {
                "name": "Prevention of Cross-Site Scripting", 
                "keywords": ["Cross Site Scripting", "XSS", "Reflected XSS", "Stored XSS"],
                "remediation": "Apply context-aware output encoding for all user-supplied data. Implement a strong Content Security Policy (CSP) and use the 'HttpOnly' flag on sensitive cookies."
            },
            "6.3.2": {
                "name": "Security Headers & Config", 
                "keywords": ["X-Frame-Options", "Content-Security-Policy", "Clickjacking", "HSTS", "Strict-Transport-Security"],
                "remediation": "Configure missing security headers: Strict-Transport-Security (HSTS), X-Frame-Options (DENY/SAMEORIGIN), and Content-Security-Policy (CSP)."
            },
            "6.4.1": {
                "name": "Public Facing Web Vulnerabilities", 
                "keywords": ["SSRF", "RCE", "Remote Code Execution", "Directory Traversal"],
                "remediation": "Patch all server-side components and frameworks. Implement strict file permission policies and perform regular vulnerability scans using SAST/DAST tools."
            },
            "5.3.3": {
                "name": "Sensitive Data Exposure", 
                "keywords": ["Information Leak", "Version Leak", "Timestamp Disclosure", "IDOR"],
                "remediation": "Disable verbose error messages in production. Remove version numbers from server headers (e.g., Server, X-Powered-By) and ensure secure direct object references."
            }
        }
    },
    "GDPR": {
        "description": "General Data Protection Regulation (EU)",
        "requirements": {
            "Art-32-1-a": {
                "name": "Encryption of Personal Data", 
                "keywords": ["TLSv1.0", "TLSv1.1", "Weak Cipher", "HTTP Only", "Cleartext"],
                "remediation": "Ensure all personal data transit occurs over HTTPS with strong encryption. Implement 'Secure' and 'HttpOnly' flags for session cookies."
            },
            "Art-32-1-b": {
                "name": "Confidentiality & Integrity", 
                "keywords": ["SQL Injection", "IDOR", "Access Control", "Authentication Bypass", "SSRF"],
                "remediation": "Enforce strict access control lists (ACLs). Use multi-factor authentication for administrative access and audit all internal data transfers."
            },
            "Art-32-Security": {
                "name": "State of the Art Security", 
                "keywords": ["XSS", "CSRF", "Clickjacking", "Outdated Component", "Vulnerable Dependency"],
                "remediation": "Maintain a regular patching schedule for all infrastructure. Perform automated security audits and integrate security into the CI/CD pipeline."
            },
            "Art-25": {
                "name": "Data Protection by Design", 
                "keywords": ["Debug Mode", "Verbose Error", "Information Leak", "Stack Trace"],
                "remediation": "Adopt 'Privacy by Design' principles. Minimize data collection to the absolute necessary and mask sensitive information in logs and debugging outputs."
            }
        }
    },
    "ISO-27001": {
        "description": "ISO/IEC 27001:2022 Information Security",
        "requirements": {
            "A.8.24": {
                "name": "Use of Cryptography", 
                "keywords": ["TLSv1.0", "TLSv1.1", "Weak Cipher", "HTTP Only"],
                "remediation": "Develop and implement a policy on the use of cryptographic controls for protection of information. Use industry-standard algorithms and key lengths."
            },
            "A.8.28": {
                "name": "Secure Coding", 
                "keywords": ["SQL Injection", "XSS", "Injection", "CSRF", "Input Validation"],
                "remediation": "Establish secure coding principles and ensure they are applied to all software development. Conduct code reviews and vulnerability testing."
            },
            "A.8.12": {
                "name": "Data Leakage Prevention", 
                "keywords": ["Information Leak", "IDOR", "Sensitive Data", "Banner Grabbing"],
                "remediation": "Apply data leakage prevention measures to systems, networks and any other devices that process, store or transmit sensitive information."
            },
            "A.5.15": {
                "name": "Access Control", 
                "keywords": ["Authentication Bypass", "Weak Password", "IDOR", "Broken Access Control"],
                "remediation": "Enforce registration, authentication and authorization for all users. Implement a 'Least Privilege' policy for system administrative accounts."
            }
        }
    },
    "SOC-2": {
        "description": "SOC 2 Trust Services Criteria (Security)",
        "requirements": {
            "CC-6.1": {
                "name": "Logical Access Security", 
                "keywords": ["Authentication", "SQL Injection", "Bypass", "IDOR"],
                "remediation": "Authorize and manage logical access to the system. Implement robust identity management and strictly control external system access."
            },
            "CC-6.6": {
                "name": "Boundary Protection (Encryption)", 
                "keywords": ["TLSv1.0", "Weak Cipher", "HTTP Only"],
                "remediation": "Implement boundary protection measures, including firewalls and encrypted tunnels (VPN/TLS), to prevent unauthorized access to internal networks."
            },
            "CC-7.1": {
                "name": "System Configuration (Hardening)", 
                "keywords": ["Missing Headers", "Clickjacking", "CSP", "Banner Leak"],
                "remediation": "Establish baseline security configurations (Hardening) for all infrastructure. Regularly review configurations against industry benchmarks like CIS."
            },
            "CC-6.8": {
                "name": "Prevention of Malicious Software", 
                "keywords": ["XSS", "RCE", "Malware", "Upload"],
                "remediation": "Implement controls to prevent, detect, and respond to malicious software. Use endpoint protection and perform regular system file integrity checks."
            }
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
            "generated_at": get_now_ist_str()
        }
        
        # Load Raw Data - Fetching the latest report PER TARGET
        self.killchain = self._load_latest_per_target("killchain/reports", ["*.json"])
        self.zap = self._load_latest_per_target("zap_scanner", ["*.json"])
        self.ssl = self._load_latest_per_target("ssl_scanner", ["*.json"])
        self.sql = self._load_latest_per_target("sql_scanner", ["*.json"])
        self.nmap = self._load_latest_per_target("network_scanner", ["*.json"])
        self.api = self._load_latest_per_target("api_scanner", ["*.json"])
        self.semgrep = self._load_latest_per_target("semgrep_scanner", ["*.json"])

        # Consolidated list of all technical findings
        self.all_findings = self._consolidate_findings()

    def _load_latest_per_target(self, scanner_folder, patterns=["*.json"]):
        """Helper to find and load the latest JSON file PER TARGET matching any of the patterns."""
        if not self.base_dir:
            return []
            
        import glob
        target_dir = os.path.join(self.base_dir, scanner_folder)
        if not os.path.exists(target_dir):
            return []
            
        if not isinstance(patterns, list):
            patterns = [patterns]
            
        candidates = []
        for pattern in patterns:
            candidates.extend(glob.glob(os.path.join(target_dir, pattern)))
            
        reports_by_target = {}
        for candidate in candidates:
            try:
                with open(candidate, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Try standard properties where targets are usually defined
                target = data.get('target') or data.get('target_ip') or data.get('target_url') or data.get('url')
                
                # Fallback to checking the first finding if no target in root
                if not target and 'findings' in data and len(data['findings']) > 0:
                     f_target = data['findings'][0].get('url') or data['findings'][0].get('path')
                     if f_target:
                         # basic normalization
                         target = f_target.replace("http://", "").replace("https://", "").split('/')[0].split(':')[0]
                
                target = target or "Unknown"

                # Normalize target string just in case it's a list or dict
                if isinstance(target, list):
                    target = str(target[0]) if target else "Unknown"
                elif isinstance(target, dict):
                    target = "Unknown"
                    
                target = str(target)
                    
                mtime = os.path.getmtime(candidate)
                
                if target not in reports_by_target or mtime > reports_by_target[target]['mtime']:
                    reports_by_target[target] = {'mtime': mtime, 'data': data}
                    
            except Exception:
                continue
                
        return [item['data'] for item in reports_by_target.values()]

    def _consolidate_findings(self):
        """
        Normalizes findings from all scanners into a single list of findings with target info.
        """
        findings = []

        # 1. Killchain Findings
        for report in self.killchain:
            target = report.get('target', 'Unknown')
            vulns = report.get('all_findings', report.get('vulns', []))
            for v in vulns:
                findings.append({
                    "target": target,
                    "source": "Killchain",
                    "title": v.get('type', ''),
                    "description": v.get('description', v.get('evidence', '')),
                    "severity": v.get('severity', 'Low')
                })

        # 2. ZAP Findings
        for report in self.zap:
            for f in report.get('findings', []):
                findings.append({
                    "target": f.get('url', report.get('target_url', report.get('target', 'Unknown'))),
                    "source": "ZAP Scanner",
                    "title": f.get('name', ''),
                    "description": f.get('description', ''),
                    "severity": f.get('risk', 'Low')
                })

        # 3. SQLMap Findings
        for report in self.sql:
            target = report.get('target', 'Unknown')
            for s in report.get('vulnerabilities', []):
                findings.append({
                    "target": target,
                    "source": "SQL Scanner",
                    "title": s.get('title', 'SQL Injection'),
                    "description": f"Payload: {s.get('payload', '')}",
                    "severity": "Critical"
                })

        # 4. SSL Findings
        for report in self.ssl:
            target = report.get('target', 'Unknown')
            for proto in report.get('protocols', []):
                if proto.get('enabled') and proto.get('name') in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', '1.0', '1.1']:
                    findings.append({
                        "target": target,
                        "source": "SSL Scanner",
                        "title": f"Weak Protocol Enabled: {proto.get('name')}",
                        "description": "Legacy SSL/TLS protocol detected.",
                        "severity": "High"
                    })
            for v in report.get('vulnerabilities', []):
                findings.append({
                    "target": target,
                    "source": "SSL Scanner",
                    "title": v.get('name', ''),
                    "description": v.get('description', ''),
                    "severity": v.get('severity', 'Medium')
                })
        
        # 5. Nmap Findings
        for report in self.nmap:
            target = report.get('target_ip', 'Unknown')
            for port in report.get('ports', []):
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
        for report in self.api:
            for f in report.get('findings', []):
                findings.append({
                    "target": f.get('url', report.get('target', 'API Endpoint')),
                    "source": "API Scanner",
                    "title": f.get('name', ''),
                    "description": f.get('description', ''),
                    "severity": f.get('risk', 'Low')
                })

        # 7. Semgrep SAST Findings
        for report in self.semgrep:
            for f in report.get('findings', []):
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
        self.report_data["overall_health_score"] = global_results.get("health_score", 100)
        
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
                            "severity": finding['severity'],
                            "description": description
                        })

                if status == "FAIL":
                    failures += 1
                    # Remove duplicates from evidence based on 'issue' name
                    unique_evidence = {v['issue']:v for v in evidence}.values()
                    std_report["details"].append({
                        "id": req_id,
                        "requirement": req_info["name"],
                        "status": "FAIL",
                        "evidence": list(unique_evidence),
                        "remediation": req_info.get("remediation", "Apply security patches and update server configuration.")
                    })
                else:
                    std_report["passed_requirements"] += 1
                    std_report["details"].append({
                        "id": req_id,
                        "requirement": req_info["name"],
                        "status": "PASS",
                        "evidence": [],
                        "remediation": req_info.get("remediation", "No action required.")
                    })

            std_report["failed_requirements"] = failures
            if std_report["total_requirements"] > 0:
                score = ((std_report["total_requirements"] - failures) / std_report["total_requirements"]) * 100
                std_report["score_percentage"] = round(score, 1)
            
            standards_report[std_key] = std_report
            summary_scores[std_key] = std_report["score_percentage"]

        # Unified Health Score Logic
        avg_comp = sum(summary_scores.values()) / len(summary_scores) if summary_scores else 100.0
        criticals = sum(1 for f in findings if str(f.get('severity', '')).lower() == 'critical')
        highs = sum(1 for f in findings if str(f.get('severity', '')).lower() == 'high')
        
        penalty = (criticals * 10) + (highs * 5)
        health_score = max(0, round(avg_comp - penalty, 1))

        return {
            "compliance_summary": summary_scores,
            "standards": standards_report,
            "health_score": health_score
        }

    def _save_report(self):
        """Saves the generated compliance report to disk."""
        if not self.base_dir:
            return
        os.makedirs(self.base_dir, exist_ok=True)
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
