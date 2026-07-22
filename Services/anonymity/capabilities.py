from dataclasses import dataclass, field
from typing import Optional

@dataclass
class ProxySupport:
    socks5: bool
    dns_proxied: bool
    flags: list[str] = field(default_factory=list)
    force_scan_type: Optional[str] = None   # e.g. "-sT" for nmap
    fallback_tool: Optional[str] = None     # e.g. "testssl.sh" for sslscan

SCANNER_CAPABILITIES: dict[str, ProxySupport] = {
    "sqlmap": ProxySupport(
        socks5=True,
        dns_proxied=True,
        flags=["--tor", "--tor-type=SOCKS5", "--check-tor"],
    ),
    "zap": ProxySupport(
        socks5=True,
        dns_proxied=True,
        flags=[
            "-config", "network.connection.socksProxy.host=127.0.0.1",
            "-config", "network.connection.socksProxy.port=9050",
            "-config", "network.connection.socksProxy.version=5",
            "-config", "network.connection.socksProxy.enabled=true",
        ],
    ),
    "nmap": ProxySupport(
        socks5=True,
        dns_proxied=True,
        flags=["--proxies", "socks4://127.0.0.1:9050"],
        force_scan_type="-sT",
    ),
    "sslscan": ProxySupport(
        socks5=False,
        dns_proxied=False,
        fallback_tool="testssl.sh",
    ),
    "testssl": ProxySupport(
        socks5=True,
        dns_proxied=True,
        flags=[],   # wrapped by proxychains — no inline flags needed
    ),
}
