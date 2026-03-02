import os
import json
import logging
import threading
import numpy as np
import joblib
from pathlib import Path
from datetime import datetime

# Set up logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR.parent / "models" / "TCTR"
LGB_MODEL_PATH = MODELS_DIR / "lgb_ranker.pkl"

class TCTREngine:
    _instance = None
    _ranker = None
    _sentence_model = None
    
    # CWE to CVSS Base Score Mapping (Industry Averages)
    CWE_MAP = {
        "89": 9.8,   # SQL Injection
        "78": 9.8,   # OS Command Injection
        "79": 6.1,   # XSS (Reflected)
        "434": 8.8,  # Unrestricted Upload
        "352": 8.8,  # CSRF
        "22": 7.5,   # Path Traversal
        "94": 9.8,   # Code Injection
        "287": 9.1,  # Improper Authentication
        "200": 5.0,  # Information Exposure
        "310": 5.0,  # Cryptographic Issues
        "285": 7.5,  # Improper Authorization (BOLA/BUEA)
        "611": 7.5,  # XXE
        "918": 8.3,  # SSRF
        "522": 7.5,  # Insufficiently Protected Credentials
        "117": 10.0, # Log4Shell
        "943": 9.0,  # NoSQL Injection
        "319": 7.5,  # Cleartext Transmission
        "311": 7.5,  # Missing Encryption
        "601": 6.1,  # Open Redirect
        "120": 9.8,  # Buffer Overflow
        "190": 7.5,  # Integer Overflow
        "1336": 9.0, # SSTI
        "1230": 9.0, # Cloud Metadata Exposure
        "693": 5.5,  # Protection Mechanism Failure (CSP etc)
        "1021": 5.3, # Anti-clickjacking
        "548": 5.3,  # Directory Browsing
        "201": 5.0,  # Sensitive Info Leak
        "1275": 4.3, # SameSite
        "524": 4.3,  # Caching Issues
        "345": 4.3,  # Header Missing
        "16": 4.3,   # Configuration
        "933": 3.3,  # Version Header
        "615": 3.3,  # Comments
    }

    # Reference mapping for tools that don't provide CWE IDs (primarily ZAP alerts)
    VULN_TO_CWE_MAP = {
        'Directory Browsing': 'CWE-548',
        'Private IP Disclosure': 'CWE-497',
        'Session ID in URL Rewrite': 'CWE-598',
        'Referer Exposes Session ID': 'CWE-598',
        'Path Traversal': 'CWE-22',
        'Remote File Inclusion': 'CWE-98',
        'Source Code Disclosure - Git': 'CWE-541',
        'Source Code Disclosure - SVN': 'CWE-541',
        'Source Code Disclosure - File Inclusion': 'CWE-541',
        'Vulnerable JS Library': 'CWE-1395',
        'In Page Banner Information Leak': 'CWE-497',
        'Cookie No HttpOnly Flag': 'CWE-1004',
        'Cookie Without Secure Flag': 'CWE-614',
        'Cross-Domain JavaScript Source File Inclusion': 'CWE-829',
        'Content-Type Header Missing': 'CWE-345',
        'Content-Type Header Empty': 'CWE-345',
        'Missing Anti-clickjacking Header': 'CWE-1021',
        'Multiple X-Frame-Options Header Entries': 'CWE-1021',
        'X-Frame-Options Defined via META (Non-compliant with Spec)': 'CWE-1021',
        'X-Frame-Options Setting Malformed': 'CWE-1021',
        'X-Content-Type-Options Header Missing': 'CWE-693',
        'Information Disclosure - Debug Error Messages': 'CWE-1295',
        'Information Disclosure - Sensitive Information in URL': 'CWE-598',
        'Information Disclosure - Sensitive Information in HTTP Referrer Header': 'CWE-598',
        'HTTP Parameter Override': 'CWE-20',
        'Information Disclosure - Suspicious Comments': 'CWE-615',
        'Off-site Redirect': 'CWE-601',
        'Cookie Poisoning': 'CWE-565',
        'User Controllable Charset': 'CWE-20',
        'User Controllable HTML Element Attribute (Potential XSS)': 'CWE-20',
        'Potential IP Addresses Found in the Viewstate': 'CWE-642',
        'Emails Found in the Viewstate': 'CWE-642',
        'Old Asp.Net Version in User': 'CWE-642',
        'Viewstate without MAC Signature (Unsure)': 'CWE-642',
        'Viewstate without MAC Signature (Sure)': 'CWE-642',
        'Split Viewstate in User': 'CWE-642',
        'Heartbleed OpenSSL Vulnerability (Indicative)': 'CWE-119',
        'Strict-Transport-Security Header Not Set': 'CWE-319',
        'Strict-Transport-Security Disabled': 'CWE-319',
        'Strict-Transport-Security Multiple Header Entries (Non-compliant with Spec)': 'CWE-319',
        'Strict-Transport-Security Header on Plain HTTP Response': 'CWE-319',
        'Strict-Transport-Security Missing Max-Age (Non-compliant with Spec)': 'CWE-319',
        'Strict-Transport-Security Defined via META (Non-compliant with Spec)': 'CWE-319',
        'Strict-Transport-Security Max-Age Malformed (Non-compliant with Spec)': 'CWE-319',
        'Strict-Transport-Security Malformed Content (Non-compliant with Spec)': 'CWE-319',
        'Server Leaks its Webserver Application via "Server" HTTP Response Header Field': 'CWE-497',
        'Server Leaks Version Information via "Server" HTTP Response Header Field': 'CWE-497',
        'Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)': 'CWE-497',
        'Content Security Policy (CSP) Header Not Set': 'CWE-693',
        'Obsolete Content Security Policy (CSP) Header Found': 'CWE-693',
        'Content Security Policy (CSP) Report-Only Header Found': 'CWE-693',
        'X-Backend-Server Header Information Leak': 'CWE-497',
        'Secure Pages Include Mixed Content': 'CWE-311',
        'HTTP to HTTPS Insecure Transition in Form Post': 'CWE-319',
        'HTTPS to HTTP Insecure Transition in Form Post': 'CWE-319',
        'User Controllable JavaScript Event (XSS)': 'CWE-20',
        'Big Redirect Detected (Potential Sensitive Information Leak)': 'CWE-201',
        'Multiple HREFs Redirect Detected (Potential Sensitive Information Leak)': 'CWE-201',
        'Source Code Disclosure - /WEB-INF Folder': 'CWE-541',
        'Properties File Disclosure - /WEB-INF folder': 'CWE-541',
        'HTTPS Content Available via HTTP': 'CWE-311',
        'Remote Code Execution - Shell Shock': 'CWE-78',
        'Non-Storable Content': 'CWE-524',
        'Storable but Non-Cacheable Content': 'CWE-524',
        'Storable and Cacheable Content': 'CWE-524',
        'Relative Path Confusion': 'CWE-20',
        'X-ChromeLogger-Data (XCOLD) Header Information Leak': 'CWE-532',
        'Cookie without SameSite Attribute': 'CWE-1275',
        'Cookie with SameSite Attribute None': 'CWE-1275',
        'Cookie with Invalid SameSite Attribute': 'CWE-1275',
        'CSP: X-Content-Security-Policy': 'CWE-693',
        'CSP: X-WebKit-CSP': 'CWE-693',
        'CSP: Notices': 'CWE-693',
        'CSP: Wildcard Directive': 'CWE-693',
        'CSP: script-src unsafe-inline': 'CWE-693',
        'CSP: style-src unsafe-inline': 'CWE-693',
        'CSP: script-src unsafe-hashes': 'CWE-693',
        'CSP: style-src unsafe-hashes': 'CWE-693',
        'CSP: Malformed Policy (Non-ASCII)': 'CWE-693',
        'CSP: script-src unsafe-eval': 'CWE-693',
        'CSP: Meta Policy Invalid Directive': 'CWE-693',
        'CSP: Header & Meta': 'CWE-693',
        'CSP: Failure to Define Directive with No Fallback': 'CWE-693',
        'X-Debug-Token Information Leak': 'CWE-489',
        'Username Hash Found': 'CWE-284',
        'GET for POST': 'CWE-16',
        'X-AspNet-Version Response Header': 'CWE-933',
        'PII Disclosure': 'CWE-359',
        'Permissions Policy Header Not Set': 'CWE-693',
        'Deprecated Feature Policy Header Set': 'CWE-16',
        'ASP.NET ViewState Disclosure': 'CWE-319',
        'ASP.NET ViewState Integrity': 'CWE-642',
        'Base64 Disclosure': 'CWE-319',
        'Backup File Disclosure': 'CWE-530',
        'Timestamp Disclosure - Unix': 'CWE-497',
        'Hash Disclosure - MD4 / MD5': 'CWE-497',
        'Cross-Domain Misconfiguration': 'CWE-264',
        'Source Code Disclosure - PHP': 'CWE-540',
        'Access Control Issue - Improper Authentication': 'CWE-287',
        'Access Control Issue - Improper Authorization': 'CWE-205',
        'Image Exposes Location or Privacy Data': 'CWE-200',
        'Authentication Credentials Captured': 'CWE-287',
        'Weak Authentication Method': 'CWE-326',
        'HTTP Only Site': 'CWE-311',
        'Httpoxy - Proxy Header Misuse': 'CWE-20',
        'Reverse Tabnabbing': 'CWE-1022',
        'Dangerous JS Functions': 'CWE-749',
        'Script Served From Malicious Domain (polyfill)': 'CWE-829',
        'Absence of Anti-CSRF Tokens': 'CWE-352',
        'Anti-CSRF Tokens Check': 'CWE-352',
        'HTTP Parameter Pollution': 'CWE-20',
        'Heartbleed OpenSSL Vulnerability': 'CWE-119',
        'Source Code Disclosure - CVE-2012-1823': 'CWE-20',
        'Remote Code Execution - CVE-2012-1823': 'CWE-20',
        'External Redirect': 'CWE-601',
        'Buffer Overflow': 'CWE-120',
        'Format String Error': 'CWE-134',
        'Integer Overflow Error': 'CWE-190',
        'CRLF Injection': 'CWE-113',
        'Parameter Tampering': 'CWE-472',
        'Server Side Include': 'CWE-97',
        'Cross Site Scripting (Reflected)': 'CWE-79',
        'Session Fixation': 'CWE-384',
        'Cross Site Scripting (Persistent)': 'CWE-79',
        'LDAP Injection': 'CWE-90',
        'SQL Injection': 'CWE-89',
        'SQL Injection - MySQL (Time Based)': 'CWE-89',
        'SQL Injection - Hypersonic SQL (Time Based)': 'CWE-89',
        'SQL Injection - Oracle (Time Based)': 'CWE-89',
        'SQL Injection - PostgreSQL (Time Based)': 'CWE-89',
        'Possible Username Enumeration': 'CWE-204',
        'SQL Injection - SQLite (Time Based)': 'CWE-89',
        'Proxy Disclosure': 'CWE-204',
        'Cross Site Scripting (DOM Based)': 'CWE-79',
        'SQL Injection - MsSQL (Time Based)': 'CWE-89',
        'ELMAH Information Leak': 'CWE-941',
        'Trace.axd Information Leak': 'CWE-215',
        'Out of Band XSS': 'CWE-79',
        '.htaccess Information Leak': 'CWE-941',
        'NoSQL Injection - MongoDB': 'CWE-943',
        '.env Information Leak': 'CWE-215',
        'Hidden File Found': 'CWE-538',
        'JWT Scan Rule': 'CWE-348',
        'Web Cache Deception': 'CWE-451',
        'CORS Misconfiguration': 'CWE-942',
        'File Upload': 'CWE-434',
        'Spring Actuator Information Leak': 'CWE-215',
        'Log4Shell (CVE-2021-44228)': 'CWE-117',
        'Log4Shell (CVE-2021-45046)': 'CWE-117',
        'Exponential Entity Expansion (Billion Laughs Attack)': 'CWE-776',
        'Spring4Shell': 'CWE-78',
        'Server Side Request Forgery': 'CWE-918',
        'Text4shell (CVE-2022-42889)': 'CWE-117',
        'GraphQL Endpoint Supports Introspection': 'CWE-16',
        'GraphQL Server Implementation Identified': 'CWE-205',
        'Insecure JSF ViewState': 'CWE-642',
        'Java Serialization Object': 'CWE-502',
        'Sub Resource Integrity Attribute Missing': 'CWE-345',
        'Insufficient Site Isolation Against Spectre Vulnerability': 'CWE-693',
        'Sec-Fetch-Site Header is Missing': 'CWE-352',
        'Sec-Fetch-Mode Header is Missing': 'CWE-352',
        'Sec-Fetch-Dest Header is Missing': 'CWE-352',
        'Sec-Fetch-User Header is Missing': 'CWE-352',
        'Sec-Fetch-Site Header Has an Invalid Value': 'CWE-352',
        'Sec-Fetch-Mode Header Has an Invalid Value': 'CWE-352',
        'Sec-Fetch-Dest Header Has an Invalid Value': 'CWE-352',
        'Sec-Fetch-User Header Has an Invalid Value': 'CWE-352',
        'Charset Mismatch': 'CWE-436',
        'XSLT Injection': 'CWE-91',
        'Advanced SQL Injection': 'CWE-89',
        'Server Side Code Injection - PHP Code Injection': 'CWE-94',
        'Server Side Code Injection - ASP Code Injection': 'CWE-94',
        'Remote OS Command Injection': 'CWE-78',
        'XPath Injection': 'CWE-643',
        'XML External Entity Attack': 'CWE-611',
        'Generic Padding Oracle': 'CWE-209',
        'Expression Language Injection': 'CWE-917',
        'SOAP Action Spoofing': 'CWE-451',
        'Cookie Slack Detector': 'CWE-205',
        'Insecure HTTP Method': 'CWE-749',
        'SOAP XML Injection': 'CWE-91',
        'Loosely Scoped Cookie': 'CWE-565',
        'Cloud Metadata Potentially Exposed': 'CWE-1230',
        'Server Side Template Injection': 'CWE-1336',
        'Server Side Template Injection (Blind)': 'CWE-1336',
        'Remote OS Command Injection (Time Based)': 'CWE-78',
        'NoSQL Injection - MongoDB (Time Based)': 'CWE-943',
        'Retrieved from Cache': 'CWE-524',
    }

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(TCTREngine, cls).__new__(cls)
            cls._load_models()
        return cls._instance

    @classmethod
    def _load_models(cls):
        """Lazily loads the LightGBM Ranker and Sentence Transformer."""
        if cls._ranker is None:
            try:
                if LGB_MODEL_PATH.exists():
                    logger.info(f"Loading TCTR LightGBM Ranker from {LGB_MODEL_PATH}...")
                    cls._ranker = joblib.load(LGB_MODEL_PATH)
                else:
                    logger.error(f"LightGBM Ranker not found at {LGB_MODEL_PATH}")
                
                try:
                    from sentence_transformers import SentenceTransformer
                    cls._sentence_model = SentenceTransformer('all-MiniLM-L6-v2')
                except ImportError:
                    logger.warning("sentence_transformers not installed. NLP features disabled.")
            except Exception as e:
                logger.error(f"Failed to load TCTR components: {e}")

    def get_base_score(self, cwe_id):
        """Returns the base CVSS score for a given CWE ID."""
        if not cwe_id:
            return 5.0
        # Clean ID (e.g., "CWE-89" -> "89")
        clean_id = str(cwe_id).upper().replace("CWE-", "")
        return self.CWE_MAP.get(clean_id, 5.0)

    def extract_features(self, name, description, cwe_id=None):
        """Extracts the 10 features expected by the TCTR LightGBM model."""
        base_score = self.get_base_score(cwe_id)
        desc = description if description else ""
        
        desc_length = len(desc)
        num_keywords = len(name.split()) + min(len([w for w in desc.split() if len(w) > 5]), 15)
        
        num_platforms = 1
        num_affected_products = 1
        days_since_pub = 2.0 
        days_to_modify = 1.0 
        
        # Velocity/Acceleration derived from severity proxy (0-10)
        velocity = base_score / days_since_pub
        acceleration = velocity / days_since_pub
        semantic_centrality = 0.0
        
        features_raw = [
            float(desc_length), float(num_keywords), float(num_platforms), float(num_affected_products),
            float(days_since_pub), float(days_to_modify), float(velocity),
            float(acceleration), float(semantic_centrality), float(base_score)
        ]
        
        try:
            import pandas as pd
            feature_names = [
                "desc_length", "num_keywords", "num_platforms", "num_affected_products",
                "days_since_pub_at_horizon", "days_to_last_modify", "mock_threat_velocity",
                "mock_threat_acceleration", "semantic_centrality", "base_score"
            ]
            return pd.DataFrame([features_raw], columns=feature_names)
        except ImportError:
            return np.array([features_raw])

    def predict_risk(self, name, description, cwe_id=None):
        """Returns a rich prediction object for SOC Dashboard."""
        # Fallback to internal mapping if cwe_id is missing or generic
        if not cwe_id or cwe_id == "-1" or str(cwe_id) == "0":
            cwe_id = self.VULN_TO_CWE_MAP.get(name) or cwe_id

        features = self.extract_features(name, description, cwe_id)
        base_score = self.get_base_score(cwe_id)
        
        heuristic_multiplier = 1.0
        name_lower = name.lower()
        if "reflected" in name_lower: heuristic_multiplier *= 0.85
        if "banner" in name_lower or "version" in name_lower: heuristic_multiplier *= 0.7
        
        tctr_priority = 0.0
        try:
            if self._ranker:
                tctr_priority = float(self._ranker.predict(features)[0])
                # Scaling tctr_priority (usually 0-4 range for rankers)
                # To a 0.0 - 1.0 risk score
                risk_score = np.clip(tctr_priority / 4.0, 0.1, 1.0)
                final_score = round(float(risk_score * heuristic_multiplier), 4)
            else:
                final_score = round((base_score / 10.0) * heuristic_multiplier, 4)
                tctr_priority = final_score * 4.0
        except Exception as e:
            logger.error(f"Inference failed for {name}: {e}")
            final_score = round((base_score / 10.0) * heuristic_multiplier, 4)
            tctr_priority = final_score * 4.0

        # Determine Level (P0-P3)
        if final_score >= 0.85:
            level = "P0 (Critical)"
        elif final_score >= 0.65:
            level = "P1 (High)"
        elif final_score >= 0.35:
            level = "P2 (Medium)"
        else:
            level = "P3 (Low)"

        # Generate Justification
        reasons = []
        if base_score >= 9.0: reasons.append("Critical base impact")
        if "injection" in name_lower or "rce" in name_lower: reasons.append("Highly exploitable vulnerability class")
        if "disclosure" in name_lower or "exposure" in name_lower: reasons.append("Data leak potential")
        if "broken" in name_lower or "improper" in name_lower: reasons.append("Authentication/Authorization flaw")
        
        justification = " | ".join(reasons) if reasons else "General security concern"
        if final_score > 0.75 and not reasons:
            justification = "High priority based on feature analysis"

        return {
            "score": final_score,
            "tctr_priority": round(tctr_priority, 4),
            "base_score": base_score,
            "priority_level": level,
            "risk_justification": justification
        }

# [PERF FIX] Do NOT instantiate at module level — this caused the model to load once
# per Python process, which with Flask debug mode + UAC re-exec = 3 loads.
# Use get_engine() which creates the singleton only on first actual use.
_engine_instance = None
_engine_lock = threading.Lock()

def get_engine() -> "TCTREngine":
    """Returns the singleton TCTREngine, loading models only on first call."""
    global _engine_instance
    if _engine_instance is None:
        with _engine_lock:
            if _engine_instance is None:  # double-checked locking
                _engine_instance = TCTREngine.__new__(TCTREngine)
                TCTREngine._instance = _engine_instance
                TCTREngine._load_models()
    return _engine_instance

# Backward-compatible lazy proxy so that:
#   from .tctr_engine import tctr_engine
#   tctr_engine.predict_risk(...)
# still works without change in other modules.
class _LazyEngineProxy:
    """Transparent proxy that defers TCTREngine instantiation until first attribute access."""
    def __getattr__(self, name):
        return getattr(get_engine(), name)

tctr_engine = _LazyEngineProxy()

