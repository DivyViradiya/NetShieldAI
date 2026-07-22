import os
import subprocess
import logging
from contextlib import contextmanager
from dotenv import load_dotenv
import requests

_logger = logging.getLogger("anonymity")

from .capabilities import SCANNER_CAPABILITIES
from .leak_guard import (
    KillswitchGuard, build_proxy_env,
    disable_ipv6, restore_ipv6, patch_dns_over_socks
)
from .verifier import IdentityVerifier, AnonymityVerificationError

load_dotenv()


class AnonymityManager:
    def __init__(self):
        self.mode         = os.getenv("ANONYMITY_MODE", "off").lower()
        self.strict       = os.getenv("STRICT_MODE", "true").lower() == "true"
        self.verify_first = os.getenv("VERIFY_BEFORE_SCAN", "true").lower() == "true"
        self.socks_host   = os.getenv("PROXY_HOST", "127.0.0.1")
        self.socks_port   = int(os.getenv("TOR_SOCKS_PORT" if self.mode == "tor"
                                          else "PROXY_PORT", 9050))
        self.proxy_type   = os.getenv("PROXY_TYPE", "socks5").lower()
        self.proxy_url    = f"{self.proxy_type}://{self.socks_host}:{self.socks_port}"
        self.kill_enabled = os.getenv("ENABLE_KILLSWITCH", "true").lower() == "true"
        self.ipv6_disable = os.getenv("DISABLE_IPV6", "true").lower() == "true"
        self.rotation_min = int(os.getenv("TOR_CIRCUIT_ROTATION_MINUTES", 10))
        self.chain_config = os.getenv("PROXYCHAIN_CONFIG", "./proxychains.conf")

    @property
    def enabled(self) -> bool:
        return self.mode != "off"

    @contextmanager
    def apply(self):
        """
        Context manager. Enables leak guard, patches DNS, optionally
        verifies identity, runs killswitch, then tears everything down.
        Usage:
            with manager.apply():
                run_scan(...)
        """
        if not self.enabled:
            yield
            return

        # ── Step 1: Verify identity BEFORE patching sockets ──────────────
        # Must run first so _check_public_ip() can make a clean direct request
        # to compare against the proxied IP.
        if self.verify_first:
            verifier = IdentityVerifier(self.proxy_url, strict=self.strict, is_tor=(self.mode == "tor"))
            v_res = verifier.run_full_check()   # raises AnonymityVerificationError if strict + fail
            if v_res.all_passed:
                _logger.info("[🛡️] All anonymity checks PASSED. Proceeding with scan.")
            else:
                _logger.warning(f"[🛡️] Anonymity check failed/incomplete: {v_res.summary()}")

        # ── Step 2: Patch DNS and disable IPv6 ────────────────────────────
        if self.ipv6_disable:
            disable_ipv6()

        patch_dns_over_socks(self.socks_host, self.socks_port)

        with KillswitchGuard(enabled=self.kill_enabled):
            try:
                yield
            finally:
                restore_ipv6()

    def verify(self) -> None:
        """Explicit manual verification call (use outside of apply() if needed)."""
        if not self.enabled:
            return
        IdentityVerifier(self.proxy_url, strict=self.strict).run_full_check()

    def get_scan_flags(self, scanner: str) -> list[str]:
        """
        Returns the list of CLI flags to append to the scanner command.
        Handles nmap scan-type replacement and proxy port substitution.
        """
        if not self.enabled:
            return []

        cap = SCANNER_CAPABILITIES.get(scanner)
        if cap is None:
            return []

        # If scanner has no native SOCKS support, handle fallback
        if not cap.socks5:
            ssl_strict = os.getenv("SSL_SCANNER_STRICT", "true").lower() == "true"
            if ssl_strict and self.strict:
                raise RuntimeError(
                    f"Scanner '{scanner}' has no SOCKS5 support and SSL_SCANNER_STRICT=true. "
                    f"Use '{cap.fallback_tool}' via proxychains instead."
                )
            return []

        # Substitute actual host/port into flags
        flags = [
            f.replace("127.0.0.1", self.socks_host).replace("9050", str(self.socks_port))
            for f in cap.flags
        ]

        # [FIX] SQLMap unique handling
        if scanner == "sqlmap":
            if self.mode == "tor":
                # Ensure we pass the specific Tor port configured in .env
                # SQLMap native --tor uses 9050 by default, so we add explicit port
                flags = ["--tor", f"--tor-port={self.socks_port}", "--tor-type=SOCKS5", "--check-tor"]
                if self.socks_host != "127.0.0.1":
                    flags.append(f"--tor-address={self.socks_host}")
            else:
                flags = [f"--proxy={self.proxy_url}", "--batch", "--check-proxy"]

        # Prepend force_scan_type for nmap
        if cap.force_scan_type:
            flags = [cap.force_scan_type] + flags

        return flags

    def get_requests_session(self) -> requests.Session:
        """Returns a pre-configured requests.Session routed through the proxy."""
        session = requests.Session()
        if self.enabled:
            session.proxies = {
                "http":  self.proxy_url,
                "https": self.proxy_url,
            }
        return session

    def get_subprocess_env(self) -> dict:
        """Returns env dict for subprocess calls with proxy vars set."""
        if not self.enabled:
            return os.environ.copy()
        return build_proxy_env(self.proxy_url)

    def rotate_circuit(self) -> None:
        """Request a new Tor circuit (new exit node). Tor only."""
        if self.mode != "tor":
            return
        try:
            from stem import Signal
            from stem.control import Controller
            ctrl_port = int(os.getenv("TOR_CONTROL_PORT", 9051))
            ctrl_pass = os.getenv("TOR_CONTROL_PASSWORD", "")
            with Controller.from_port(port=ctrl_port) as ctrl:
                if ctrl_pass:
                    ctrl.authenticate(password=ctrl_pass)
                else:
                    ctrl.authenticate()   # cookie auth
                ctrl.signal(Signal.NEWNYM)
        except Exception as e:
            print(f"[AnonymityManager] Circuit rotation failed: {e}")

    def wrap_with_proxychains(self, cmd: list[str]) -> list[str]:
        """Prepend proxychains to a command array (for tools without native SOCKS support)."""
        if not self.enabled or self.mode != "chain":
            return cmd
        return ["proxychains4", "-f", self.chain_config] + cmd
