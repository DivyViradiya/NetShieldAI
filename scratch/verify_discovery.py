import sys
import os
import threading
from pathlib import Path

# Add project root to sys.path
sys.path.append(os.getcwd())

# Mocking Flask app context if needed
from flask import Flask
app = Flask(__name__)

from Services.asset_discovery_service import (
    _query_hackertarget, 
    _query_threatcrowd, 
    _query_alienvault, 
    _query_anubis,
    run_subfinder,
    run_assetfinder,
    run_amass,
    discover_via_crtsh
)

def test_discovery(domain):
    user_id = 1
    print(f"Testing Discovery for: {domain}")
    
    # Test individual native queries
    print("\n--- Testing Native Queries ---")
    sources = [
        ("HackerTarget", _query_hackertarget),
        ("ThreatCrowd", _query_threatcrowd),
        ("AlienVault", _query_alienvault),
        ("Anubis", _query_anubis),
        ("crt.sh", discover_via_crtsh)
    ]
    
    all_found = set()
    for name, func in sources:
        try:
            found = func(domain, user_id)
            print(f"[+] {name} found {len(found)} subdomains.")
            all_found.update(found)
        except Exception as e:
            print(f"[!] {name} failed: {e}")

    print(f"\nTotal Unique Subdomains Found: {len(all_found)}")
    if all_found:
        print(f"Sample: {list(all_found)[:5]}")

    # Test Wrappers
    print("\n--- Testing Wrappers ---")
    subfinder_res = run_subfinder(domain, user_id)
    print(f"[+] run_subfinder (native) found: {len(subfinder_res)}")
    
    assetfinder_res = run_assetfinder(domain, user_id)
    print(f"[+] run_assetfinder (native) found: {len(assetfinder_res)}")
    
    amass_res = run_amass(domain, user_id)
    print(f"[+] run_amass (native) found: {len(amass_res)}")

if __name__ == "__main__":
    test_domain = "google.com" # Use a high-visibility domain for testing
    test_discovery(test_domain)
