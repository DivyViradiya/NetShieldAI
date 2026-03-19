import os
import platform
import subprocess
import socket
import socks   # PySocks
from contextlib import contextmanager

# ── IPv6 disable ───────────────────────────────────────

def disable_ipv6() -> bool:
    """Returns True if successfully disabled, False if unsupported on this OS."""
    system = platform.system()
    if system == "Linux":
        try:
            subprocess.run(
                ["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"],
                check=True, capture_output=True
            )
            subprocess.run(
                ["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"],
                check=True, capture_output=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    elif system == "Windows":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
                0, winreg.KEY_SET_VALUE
            )
            winreg.SetValueEx(key, "DisabledComponents", 0, winreg.REG_DWORD, 0xFF)
            winreg.CloseKey(key)
            return True
        except Exception:
            return False
    return False

def restore_ipv6() -> None:
    system = platform.system()
    if system == "Linux":
        subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"], capture_output=True)
        subprocess.run(["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=0"], capture_output=True)

# ── Subprocess env injector ────────────────────────────

def build_proxy_env(proxy_url: str) -> dict:
    """
    Returns an env dict with proxy vars set.
    proxy_url example: 'socks5://127.0.0.1:9050'
    Merge with os.environ.copy() before passing to subprocess.
    """
    env = os.environ.copy()
    env["ALL_PROXY"]   = proxy_url
    env["HTTP_PROXY"]  = proxy_url
    env["HTTPS_PROXY"] = proxy_url
    env["SOCKS_PROXY"] = proxy_url
    return env

# ── DNS-over-SOCKS patcher ─────────────────────────────

def patch_dns_over_socks(host: str, port: int, proxy_type=socks.SOCKS5) -> None:
    """
    Monkeypatches socket.socket so all DNS resolution in this process
    goes through the SOCKS proxy, with local address bypass.
    """
    socks.set_default_proxy(proxy_type, host, port)
    
    class _BypassLocalSocket(socks.socksocket):
        def connect(self, address):
            h, p = address
            if h in ('127.0.0.1', 'localhost'):
                self.set_proxy(None)
            return super(_BypassLocalSocket, self).connect(address)
            
    socket.socket = _BypassLocalSocket

def unpatch_dns() -> None:
    """Restore the original socket."""
    socket.socket = socket._socketobject if hasattr(socket, "_socketobject") else socket.socket

# ── Killswitch context manager ─────────────────────────

_KILLSWITCH_RULES = [
    # Allow loopback
    ["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
    # Allow traffic to Tor SOCKS port
    ["-A", "OUTPUT", "-p", "tcp", "--dport", "9050", "-j", "ACCEPT"],
    # Allow traffic to Tor control port
    ["-A", "OUTPUT", "-p", "tcp", "--dport", "9051", "-j", "ACCEPT"],
    # Drop everything else outbound
    ["-A", "OUTPUT", "-j", "DROP"],
]

@contextmanager
def KillswitchGuard(enabled: bool = True):
    """
    Context manager. On Linux, adds iptables rules that drop all outbound
    traffic except to the Tor proxy ports. Removes them on exit.
    If the proxy drops mid-scan, traffic fails silently instead of leaking.
    """
    if not enabled or platform.system() != "Linux":
        yield
        return

    try:
        for rule in _KILLSWITCH_RULES:
            subprocess.run(["iptables"] + rule, check=True, capture_output=True)
        yield
    finally:
        # Remove every rule we added (same rules with -D instead of -A)
        for rule in _KILLSWITCH_RULES:
            delete_rule = [r if r != "-A" else "-D" for r in rule]
            subprocess.run(["iptables"] + delete_rule, capture_output=True)
