import os
import socket
import requests
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"
IP_CHECK_URL      = "https://api.ipify.org"

class AnonymityVerificationError(Exception):
    pass

@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str

@dataclass
class VerificationResult:
    checks: list[CheckResult]

    @property
    def all_passed(self) -> bool:
        return all(c.passed for c in self.checks)

    def summary(self) -> str:
        lines = []
        for c in self.checks:
            status = "PASS" if c.passed else "FAIL"
            lines.append(f"[{status}] {c.name}: {c.detail}")
        return "\n".join(lines)


class IdentityVerifier:
    def __init__(self, proxy_url: str, strict: bool = True, is_tor: bool = True):
        self.proxy_url = proxy_url
        self.strict    = strict
        self.is_tor    = is_tor

        # socks5h:// ensures DNS is resolved by the proxy (not locally)
        # This prevents DNS leaks and ensures hostnames resolve through Tor
        h_url = proxy_url.replace("socks5://", "socks5h://").replace("socks4://", "socks4a://")
        self._session = requests.Session()
        self._session.proxies = {"http": h_url, "https": h_url}
        self._session.verify  = False   # avoid SSL issues from exit nodes

    def run_full_check(self) -> VerificationResult:
        checks = [
            self._check_proxy_alive(),
            self._check_public_ip(),
            self._check_ipv6_exposure(),
        ]

        # Only check Tor exit node list when actually using Tor
        if self.is_tor:
            checks.append(self._check_tor_exit_node())

        result = VerificationResult(checks)

        if self.strict and not result.all_passed:
            failed = [c.name for c in checks if not c.passed]
            if "proxy_alive" in failed:
                raise AnonymityVerificationError(
                    f"Proxy ({self.proxy_url}) is OFFLINE or unreachable. "
                    f"Scan aborted to protect your real IP."
                )
            raise AnonymityVerificationError(
                f"Anonymity check(s) failed: {failed}. Scan safely aborted."
            )
        return result

    def _check_proxy_alive(self) -> CheckResult:
        """Verify the proxy is reachable by making a request through it."""
        try:
            r = self._session.get(IP_CHECK_URL, timeout=20)
            r.raise_for_status()
            return CheckResult("proxy_alive", True, f"Proxy online. Exit IP: {r.text.strip()}")
        except Exception as e:
            return CheckResult("proxy_alive", False, f"Proxy unreachable: {e}")

    def _check_public_ip(self) -> CheckResult:
        """Verify the proxied IP differs from the real IP."""
        try:
            # Get real IP using a plain session (no proxy)
            plain = requests.Session()
            plain.verify = False
            real_ip    = plain.get(IP_CHECK_URL, timeout=10).text.strip()
            proxied_ip = self._session.get(IP_CHECK_URL, timeout=20).text.strip()
            passed = (real_ip != proxied_ip)
            return CheckResult(
                "ip_differs",
                passed,
                f"Real: {real_ip} | Proxied: {proxied_ip}"
            )
        except Exception as e:
            return CheckResult("ip_differs", False, str(e))

    def _check_tor_exit_node(self) -> CheckResult:
        """Check if the proxied IP is a known Tor exit node."""
        try:
            plain = requests.Session()
            plain.verify = False
            proxied_ip = self._session.get(IP_CHECK_URL, timeout=20).text.strip()
            exit_list  = plain.get(TOR_EXIT_LIST_URL, timeout=20).text
            is_exit    = proxied_ip in exit_list
            return CheckResult(
                "tor_exit_node",
                is_exit,
                f"{proxied_ip} {'IS' if is_exit else 'is NOT'} a Tor exit node"
            )
        except Exception as e:
            return CheckResult("tor_exit_node", False, str(e))

    def _check_ipv6_exposure(self) -> CheckResult:
        """Check if IPv6 is still reachable (leak risk)."""
        try:
            import _socket
            sock = _socket.socket(_socket.AF_INET6, _socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.connect(("2001:4860:4860::8888", 80))
            addr = sock.getsockname()[0]
            sock.close()
            return CheckResult("ipv6_disabled", False, f"IPv6 still reachable: {addr}")
        except Exception:
            return CheckResult("ipv6_disabled", True, "IPv6 unreachable — no leak risk")


def verifyanon():
    """CLI entry point. Run: python -m Services.anonymity.verifier"""
    load_dotenv()
    mode       = os.getenv("ANONYMITY_MODE", "off")
    socks_port = os.getenv("TOR_SOCKS_PORT", "9050")
    proxy_url  = f"socks5://127.0.0.1:{socks_port}"
    strict     = os.getenv("STRICT_MODE", "true").lower() == "true"
    is_tor     = (mode == "tor")

    print(f"\n=== verifyanon | mode={mode} | strict={strict} ===\n")
    verifier = IdentityVerifier(proxy_url=proxy_url, strict=False, is_tor=is_tor)
    result   = verifier.run_full_check()
    print(result.summary())
    print(f"\nOverall: {'ALL CHECKS PASSED' if result.all_passed else 'SOME CHECKS FAILED'}")


if __name__ == "__main__":
    verifyanon()
