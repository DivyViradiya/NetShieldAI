import sys
import os
import json
from pathlib import Path

# Add project root to path
sys.path.append(os.path.abspath("."))

from Services.threat_reranker import rerank_findings, predict_threat_risk

# Sample findings that mimic ZAP data
findings = [
    {
        "name": "Cross Site Scripting (Reflected)",
        "risk": "High",
        "description": "A reflected XSS attack was found."
    },
    {
        "name": "SQL Injection",
        "risk": "High",
        "description": "A potential SQL injection was identified."
    },
    {
        "name": "Server Leaks Information via 'Server' HTTP Response Header Field",
        "risk": "Low",
        "description": "Version information leak."
    }
]

print("--- Testing Re-ranking Logic ---")
print(f"Original order: {[f['name'] for f in findings]}")

reranked = rerank_findings(findings)

print("\nReranked Results:")
for f in reranked:
    print(f"Name: {f['name']} | Risk: {f['risk']} | Score: {f['predicted_risk_score']}")

# Verification assertions
sql_score = next(f['predicted_risk_score'] for f in reranked if "SQL" in f['name'])
xss_score = next(f['predicted_risk_score'] for f in reranked if "Reflected" in f['name'])

print(f"\nSQL Score: {sql_score}")
print(f"Reflected XSS Score: {xss_score}")

if sql_score > xss_score:
    print("\nSUCCESS: SQL Injection ranked higher than Reflected XSS (as both were 'High' risk original).")
else:
    print("\nFAILURE: Reflected XSS was not downranked compared to SQL Injection.")
