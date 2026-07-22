import pytest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Services.target_validator import (
    validate_target, validate_ip_target,
    TargetBlockedError, AuthorizationRequiredError
)

# ── Hard block cases ──────────────────────────────────────────────────
@pytest.mark.parametrize("target", [
    "sbi.co.in", "https://sbi.co.in/login",
    "rbi.org.in", "hdfc.com", "icicibank.com",
    "paypal.com", "visa.com",
    "test.gov", "army.mil", "uidai.gov.in",
    "irctc.co.in", "npci.org.in",
])
def test_hard_blocked_targets(target):
    with pytest.raises(TargetBlockedError):
        validate_target(target)

# ── Auth required cases ───────────────────────────────────────────────
@pytest.mark.parametrize("target", [
    "staging.hdfc.com", "dev.sbi.co.in",
    "uat.icicibank.com", "test.paytm.com",
])
def test_auth_required_without_confirmation(target):
    with pytest.raises(AuthorizationRequiredError):
        validate_target(target, user_confirmed_auth=False)

def test_auth_confirmed_staging_passes():
    assert validate_target("staging.hdfc.com", user_confirmed_auth=True) is True

# ── Clean targets ─────────────────────────────────────────────────────
@pytest.mark.parametrize("target", [
    "example.com", "scanme.nmap.org",
    "testphp.vulnweb.com", "192.168.1.1",
    "http://mycompany-dev.com",
])
def test_clean_targets_pass(target):
    assert validate_target(target) is True

# ── IP range validation ───────────────────────────────────────────────
def test_blocked_ip_range():
    with pytest.raises(TargetBlockedError):
        validate_ip_target("192.0.2.1")   # TEST-NET-1

def test_private_ip_passes():
    assert validate_ip_target("192.168.1.100") is True

# ── Edge cases ────────────────────────────────────────────────────────
def test_empty_target_raises():
    with pytest.raises(TargetBlockedError):
        validate_target("")

def test_target_with_path_still_blocked():
    with pytest.raises(TargetBlockedError):
        validate_target("https://sbi.co.in/personal/accounts/savings")
