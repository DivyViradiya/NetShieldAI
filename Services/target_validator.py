import re
import ipaddress
from urllib.parse import urlparse

# ── Hard blocks — no confirmation can override these ──────────────────
BLOCKED_TLDS = [
    ".gov", ".mil", ".gov.in", ".nic.in", ".ac.in",
    ".gov.uk", ".gov.au", ".gc.ca"
]

BLOCKED_KEYWORDS = [
    # Indian banking & finance
    "sbi", "rbi", "hdfc", "icici", "axis", "kotak", "pnb", "bob",
    "canarabank", "unionbank", "nbfc", "nabard", "sidbi", "mudra",
    "npci", "upi", "rupay", "bhim", "paytm", "phonepe", "gpay",
    "sebi", "irdai", "pfrda", "amfi",
    # Global finance
    "paypal", "stripe", "visa", "mastercard", "swift", "iban",
    # Critical infrastructure
    "hospital", "aiims", "apollo", "fortis", "medanta",
    "police", "cbi", "nia", "raw.gov",
    "army", "navy", "airforce", "drdo", "isro",
    "railway", "irctc", "nhai", "nhpc", "ntpc", "ongc",
    "aadhaar", "uidai", "digilocker", "cowin",
    "election", "eci.gov",
    # Telecom
    "bsnl", "trai",
]

# ── Staging indicators — require auth confirmation ────────────────────
STAGING_INDICATORS = [
    "staging", "stage", "dev", "develop", "test", "uat",
    "qa", "sandbox", "demo", "preprod", "pre-prod", "local"
]

# ── Blocked IP ranges (IANA special-purpose + private + known critical infra) ───
BLOCKED_IP_RANGES = [
    "0.0.0.0/8",        # "This" network
    "127.0.0.0/8",      # Loopback (127.0.0.1 etc)
    "10.0.0.0/8",       # Private-Use
    "172.16.0.0/12",    # Private-Use
    "192.168.0.0/16",   # Private-Use
    "169.254.0.0/16",   # Link Local
    "100.64.0.0/10",    # Shared address space
    "192.0.0.0/24",     # IETF Protocol Assignments
    "192.0.2.0/24",     # TEST-NET-1
    "198.51.100.0/24",  # TEST-NET-2
    "203.0.113.0/24",   # TEST-NET-3
    "224.0.0.0/4",      # Multicast Address Space
    "240.0.0.0/4",      # Reserved
]


class TargetBlockedError(Exception):
    """Raised when a target is unconditionally blocked. Do not scan."""
    pass


class AuthorizationRequiredError(Exception):
    """Raised when a target needs explicit written authorization confirmation."""
    pass


def _extract_hostname(target: str) -> str:
    target = target.strip()
    if "://" not in target:
        target = f"http://{target}"
    parsed = urlparse(target)
    return (parsed.hostname or "").lower()


def _is_blocked_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        for cidr in BLOCKED_IP_RANGES:
            if ip in ipaddress.ip_network(cidr):
                return True
    except ValueError:
        pass
    return False


def validate_target(target: str, user_confirmed_auth: bool = False) -> bool:
    """
    Primary validation gate. Call this before any scan starts.

    Args:
        target: URL, hostname, or IP address to scan.
        user_confirmed_auth: True if user has explicitly confirmed they
                             hold written authorization for this target.

    Returns:
        True if safe to scan.

    Raises:
        TargetBlockedError: Target is unconditionally prohibited.
        AuthorizationRequiredError: Target needs explicit auth confirmation
                                    before proceeding (staging/dev envs of
                                    regulated orgs).
    """
    hostname = _extract_hostname(target)

    if not hostname:
        raise TargetBlockedError("Invalid or empty target — cannot determine hostname.")

    if hostname in ["localhost", "127.0.0.1", "::1"]:
        raise TargetBlockedError("Scanning the local host is not permitted.")

    # Check blocked TLDs
    for tld in BLOCKED_TLDS:
        if hostname.endswith(tld):
            raise TargetBlockedError(
                f"Scanning government or regulated domains ({tld}) is not permitted. "
                f"This tool is for authorized security testing only."
            )

    # Check if it resolves to a blocked IP range
    if _is_blocked_ip(hostname):
        raise TargetBlockedError(
            f"Target IP {hostname} falls within a reserved or protected range."
        )

    # Check blocked keywords
    matched_keywords = [kw for kw in BLOCKED_KEYWORDS if kw in hostname]
    if matched_keywords:
        is_staging = any(s in hostname for s in STAGING_INDICATORS)

        if is_staging:
            if user_confirmed_auth:
                return True  # Developer confirmed authorization — allow
            raise AuthorizationRequiredError(
                f"Target appears to be a staging/dev environment of a regulated "
                f"organization (matched: {matched_keywords}). You must confirm you "
                f"hold written authorization from the organization before scanning."
            )
        else:
            raise TargetBlockedError(
                f"Scanning financial institutions, payment systems, or regulated "
                f"entities is not permitted. Matched: {matched_keywords}. "
                f"If you have explicit written authorization, contact support to "
                f"enable authorized testing mode."
            )

    return True


def validate_ip_target(ip_str: str) -> bool:
    """
    Variant for scanners that take raw IP addresses (packet sniffer,
    network scanner). Checks blocked IP ranges only — no keyword matching.

    Raises:
        TargetBlockedError: IP is in a blocked range.
    """
    if _is_blocked_ip(ip_str):
        raise TargetBlockedError(
            f"Target IP {ip_str} falls within a reserved or protected address range."
        )
    return True
