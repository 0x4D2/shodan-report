"""
Domain Scout — Passive OSINT IP-Discovery für eine Kundendomain.

Keine aktiven Scans. Ausschließlich:
 - DNS-Auflösung (A, MX, NS)
 - crt.sh Zertifikats-Historie
 - HackerTarget Subdomain-API
 - CDN-Erkennung anhand bekannter IP-Ranges

Gibt strukturierte AttackSurface-Daten zurück, die direkt in den Report-
Pipeline-Flow eingespeist werden können.
"""

import ipaddress
import json
import socket
import subprocess
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ─── CDN IP-Ranges ────────────────────────────────────────────────────────────

_CLOUDFLARE_RANGES = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
    "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
    "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
]

_CDN_RANGES: Dict[str, List[str]] = {
    "Akamai": ["23.32.0.0/11", "23.64.0.0/14", "104.64.0.0/10"],
    "Fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
        "103.245.222.0/23", "104.156.80.0/20", "151.101.0.0/16",
    ],
    "AWS CloudFront": [
        "13.32.0.0/15", "13.35.0.0/16", "52.84.0.0/15",
        "54.230.0.0/16", "54.239.128.0/18", "99.84.0.0/16",
        "205.251.192.0/19", "216.137.32.0/19",
    ],
}


def _build_cdn_networks() -> Dict[str, List[ipaddress.IPv4Network]]:
    nets: Dict[str, List[ipaddress.IPv4Network]] = {
        "Cloudflare": [ipaddress.ip_network(r, strict=False) for r in _CLOUDFLARE_RANGES]
    }
    for name, ranges in _CDN_RANGES.items():
        nets[name] = [ipaddress.ip_network(r, strict=False) for r in ranges]
    return nets


_CDN_NETWORKS = _build_cdn_networks()


def _check_cdn(ip_str: str) -> Optional[str]:
    """Gibt CDN-Namen zurück wenn IP in bekannter CDN-Range liegt, sonst None."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for name, nets in _CDN_NETWORKS.items():
            for net in nets:
                if ip in net:
                    return name
    except ValueError:
        pass
    return None


# ─── DNS ──────────────────────────────────────────────────────────────────────

def _resolve_a(domain: str) -> List[str]:
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        return list({r[4][0] for r in results})
    except Exception:
        return []


def _resolve_mx(domain: str) -> List[str]:
    ips: List[str] = []
    try:
        out = subprocess.check_output(
            ["nslookup", "-type=MX", domain],
            stderr=subprocess.DEVNULL, timeout=5, text=True,
        )
        for line in out.splitlines():
            if "mail exchanger" in line.lower():
                parts = line.strip().split()
                if parts:
                    for ip in _resolve_a(parts[-1].rstrip(".")):
                        ips.append(ip)
    except Exception:
        pass
    return list(set(ips))


def _resolve_ns(domain: str) -> List[str]:
    ips: List[str] = []
    try:
        out = subprocess.check_output(
            ["nslookup", "-type=NS", domain],
            stderr=subprocess.DEVNULL, timeout=5, text=True,
        )
        for line in out.splitlines():
            if "nameserver" in line.lower():
                parts = line.strip().split()
                if parts:
                    for ip in _resolve_a(parts[-1].rstrip(".")):
                        ips.append(ip)
    except Exception:
        pass
    return list(set(ips))


def _reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ─── OSINT APIs ───────────────────────────────────────────────────────────────

def _fetch_crtsh(domain: str, timeout: int = 20) -> List[str]:
    """Holt Subdomains aus crt.sh Zertifikats-Datenbank (passiv, kein Scan)."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "shodan-report-scout/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode())
        subdomains: set = set()
        for entry in data:
            for sub in entry.get("name_value", "").splitlines():
                sub = sub.strip().lstrip("*.")
                if sub.endswith(domain) and sub != domain:
                    subdomains.add(sub)
        return sorted(subdomains)
    except Exception as e:
        print(f"[Scout] Warnung: crt.sh nicht erreichbar ({e.__class__.__name__}) — Subdomains werden übersprungen")
        return []


def _fetch_hackertarget(domain: str) -> List[Tuple[str, str]]:
    """Gibt Liste von (subdomain, ip) aus HackerTarget zurück."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "shodan-report-scout/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            text = r.read().decode()
        results = []
        for line in text.splitlines():
            parts = line.split(",")
            if len(parts) == 2:
                results.append((parts[0].strip(), parts[1].strip()))
        return results
    except Exception:
        return []


# ─── Datenmodell ──────────────────────────────────────────────────────────────

@dataclass
class ScoutedIP:
    ip: str
    sources: List[str] = field(default_factory=list)
    cdn: Optional[str] = None
    reverse_dns: Optional[str] = None

    @property
    def is_cdn(self) -> bool:
        return self.cdn is not None

    @property
    def is_mail(self) -> bool:
        return any("MX" in s for s in self.sources)

    @property
    def is_nameserver(self) -> bool:
        return any("NS" in s for s in self.sources)


@dataclass
class AttackSurface:
    domain: str
    relevant_ips: List[ScoutedIP] = field(default_factory=list)
    cdn_ips: List[ScoutedIP] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)

    @property
    def total_found(self) -> int:
        return len(self.relevant_ips) + len(self.cdn_ips)

    @property
    def primary_ip(self) -> Optional[str]:
        """Beste IP für Shodan — bevorzugt A-Record (Webserver), dann Mailserver, dann ersten Treffer."""
        # 1. A-Record: direkte Domain-IP ist der eigene Server
        for sip in self.relevant_ips:
            if any("A-Record" in s and "www." not in s for s in sip.sources):
                return sip.ip
        # 2. www A-Record
        for sip in self.relevant_ips:
            if any("A-Record" in s for s in sip.sources):
                return sip.ip
        # 3. Mailserver als Fallback
        for sip in self.relevant_ips:
            if sip.is_mail:
                return sip.ip
        if self.relevant_ips:
            return self.relevant_ips[0].ip
        return None


# ─── Hauptfunktion ────────────────────────────────────────────────────────────

def scout_domain(domain: str, verbose: bool = False, max_subdomains: int = 30) -> AttackSurface:
    """
    Führt passive OSINT-Discovery für eine Domain durch.

    Args:
        domain: Ziel-Domain (z.B. 'example.com'), ohne Protokoll
        verbose: Fortschrittsausgaben auf stdout
        max_subdomains: Maximale Anzahl aufzulösender crt.sh-Subdomains

    Returns:
        AttackSurface mit allen gefundenen IPs, kategorisiert nach Relevanz.
    """
    # normalize
    domain = domain.strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0]

    findings: Dict[str, List[str]] = {}  # ip → [sources]

    def _add(ip: str, source: str) -> None:
        if ip not in findings:
            findings[ip] = []
        if source not in findings[ip]:
            findings[ip].append(source)

    if verbose:
        print(f"[Scout] Domain: {domain}")

    # A-Records
    for variant in [domain, f"www.{domain}"]:
        for ip in _resolve_a(variant):
            _add(ip, f"A-Record ({variant})")

    # MX
    if verbose:
        print("[Scout] -> MX-Records ...")
    for ip in _resolve_mx(domain):
        _add(ip, "MX-Record (Mailserver)")

    # NS
    if verbose:
        print("[Scout] -> NS-Records ...")
    for ip in _resolve_ns(domain):
        _add(ip, "NS-Record (Nameserver)")

    # crt.sh
    if verbose:
        print("[Scout] -> crt.sh ...")
    subdomains = _fetch_crtsh(domain)
    if verbose:
        print(f"[Scout]    {len(subdomains)} Subdomains aus Zertifikats-Historie")
    for sub in subdomains[:max_subdomains]:
        for ip in _resolve_a(sub):
            _add(ip, f"crt.sh -> {sub}")

    # HackerTarget
    if verbose:
        print("[Scout] -> HackerTarget ...")
    for subdomain, ip in _fetch_hackertarget(domain):
        _add(ip, f"HackerTarget -> {subdomain}")

    # Klassifizieren
    relevant: List[ScoutedIP] = []
    cdn: List[ScoutedIP] = []

    for ip, sources in sorted(findings.items()):
        cdn_name = _check_cdn(ip)
        rdns = _reverse_dns(ip)
        sip = ScoutedIP(ip=ip, sources=sources, cdn=cdn_name, reverse_dns=rdns)
        if cdn_name:
            cdn.append(sip)
        else:
            relevant.append(sip)

    return AttackSurface(
        domain=domain,
        relevant_ips=relevant,
        cdn_ips=cdn,
        subdomains=subdomains,
    )
