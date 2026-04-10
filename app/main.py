"""
Kali API — FastAPI wrapper around Kali Linux security tools.

Exposes nmap, whois, dig, ping, curl, traceroute, nikto, theharvester,
whatweb, sslscan, and amass as authenticated HTTP endpoints.
All subprocesses are run with explicit arg lists (no shell=True) and enforced timeouts.
"""

import asyncio
import os
import re
import tempfile
import time
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, field_validator

API_KEY = os.environ.get("KALI_API_KEY", "")

app = FastAPI(title="Kali API", version="1.0.0", docs_url="/docs")
bearer = HTTPBearer()

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def require_auth(credentials: HTTPAuthorizationCredentials = Security(bearer)) -> None:
    if not API_KEY:
        raise HTTPException(status_code=500, detail="KALI_API_KEY not configured on server")
    if credentials.credentials != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_IPV4_CIDR_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")
_URL_RE = re.compile(r"^https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$")


def validate_target(value: str, allow_cidr: bool = False) -> str:
    """Validate that a target is a safe IP, CIDR, or hostname. Raises ValueError on failure."""
    value = value.strip()
    if not value:
        raise ValueError("target must not be empty")
    if len(value) > 253:
        raise ValueError("target too long")
    if allow_cidr and _IPV4_CIDR_RE.match(value):
        return value
    if _IPV4_RE.match(value) or _HOSTNAME_RE.match(value):
        return value
    raise ValueError(f"invalid target: {value!r} — must be an IP address, CIDR (nmap only), or hostname")


def validate_url(value: str) -> str:
    value = value.strip()
    if not _URL_RE.match(value):
        raise ValueError(f"invalid URL: {value!r} — must start with http:// or https://")
    return value


# ---------------------------------------------------------------------------
# Subprocess runner
# ---------------------------------------------------------------------------

async def run_tool(args: list[str], timeout: float) -> dict:
    start = time.monotonic()
    timed_out = False
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            stdout_bytes, stderr_bytes = await proc.communicate()
            timed_out = True
        return_code = proc.returncode or 0
    except FileNotFoundError:
        return {
            "stdout": "",
            "stderr": f"tool not found: {args[0]}",
            "return_code": 127,
            "duration_seconds": round(time.monotonic() - start, 2),
            "timed_out": False,
        }

    return {
        "stdout": stdout_bytes.decode(errors="replace"),
        "stderr": stderr_bytes.decode(errors="replace"),
        "return_code": return_code,
        "duration_seconds": round(time.monotonic() - start, 2),
        "timed_out": timed_out,
    }


# ---------------------------------------------------------------------------
# Nmap
# ---------------------------------------------------------------------------

# Safe NSE script categories and individual scripts that are read-only/non-intrusive.
_ALLOWED_NSE_SCRIPTS = {
    # Categories
    "default", "safe", "discovery", "version", "auth",
    # Banner / service info
    "banner", "http-title", "http-server-header", "http-headers",
    "ssl-cert", "ssl-enum-ciphers", "tls-alpn",
    "ssh-hostkey", "ssh-auth-methods",
    "smtp-commands", "ftp-anon", "ftp-syst",
    "dns-nsid", "dns-service-discovery",
    "snmp-info", "snmp-sysdescr",
    "rdp-enum-encryption",
    "smb-security-mode", "smb2-security-mode",
    "mysql-info", "redis-info",
    "http-robots.txt", "http-methods",
    "whois-domain", "whois-ip",
    "traceroute-geolocation",
}


class NmapRequest(BaseModel):
    target: str

    # Port selection
    ports: str | None = None           # e.g. "22,80,443" or "1-1024"
    top_ports: int | None = None       # --top-ports N
    all_ports: bool = False            # -p- (all 65535 ports)

    # Scan type
    scan_type: Literal["syn", "connect", "udp", "ack", "window", "fin", "null", "xmas"] | None = None
    # syn=-sS (default for root), connect=-sT, udp=-sU, ack=-sA,
    # window=-sW, fin=-sF, null=-sN, xmas=-sX

    # Host / timing
    timing: Literal[0, 1, 2, 3, 4, 5] = 3   # -T<N>
    skip_host_discovery: bool = False  # -Pn
    ping_only: bool = False            # -sn (host discovery only, no port scan)
    no_dns: bool = False               # -n  (skip reverse DNS)
    min_rate: int | None = None        # --min-rate N packets/sec
    max_retries: int | None = None     # --max-retries N
    host_timeout: int | None = None    # --host-timeout Ns (seconds)

    # Detection
    version_detection: bool = False    # -sV
    version_intensity: Literal[0,1,2,3,4,5,6,7,8,9] | None = None  # --version-intensity
    os_detection: bool = False         # -O
    aggressive: bool = False           # -A (sV + sC + O + traceroute)

    # Scripts
    default_scripts: bool = False      # -sC
    scripts: list[str] | None = None   # --script <name,name,...> (whitelisted)

    # Output tweaks
    open_only: bool = False            # --open
    reason: bool = False               # --reason
    verbosity: Literal[0, 1, 2] = 0    # 0=normal, 1=-v, 2=-vv
    traceroute: bool = False           # --traceroute

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        return validate_target(v, allow_cidr=True)

    @field_validator("ports")
    @classmethod
    def _validate_ports(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not re.match(r"^[\d,\-]+$", v):
            raise ValueError("ports must contain only digits, commas, and hyphens")
        return v

    @field_validator("top_ports")
    @classmethod
    def _validate_top_ports(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 65535):
            raise ValueError("top_ports must be between 1 and 65535")
        return v

    @field_validator("min_rate")
    @classmethod
    def _validate_min_rate(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 10000):
            raise ValueError("min_rate must be between 1 and 10000")
        return v

    @field_validator("max_retries")
    @classmethod
    def _validate_max_retries(cls, v: int | None) -> int | None:
        if v is not None and not (0 <= v <= 10):
            raise ValueError("max_retries must be between 0 and 10")
        return v

    @field_validator("host_timeout")
    @classmethod
    def _validate_host_timeout(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 600):
            raise ValueError("host_timeout must be between 1 and 600 seconds")
        return v

    @field_validator("scripts")
    @classmethod
    def _validate_scripts(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        bad = [s for s in v if s not in _ALLOWED_NSE_SCRIPTS]
        if bad:
            raise ValueError(f"scripts not in allowlist: {bad}. Allowed: {sorted(_ALLOWED_NSE_SCRIPTS)}")
        return v


_SCAN_TYPE_FLAGS = {
    "syn": "-sS", "connect": "-sT", "udp": "-sU", "ack": "-sA",
    "window": "-sW", "fin": "-sF", "null": "-sN", "xmas": "-sX",
}


@app.post("/tools/nmap", dependencies=[Depends(require_auth)])
async def nmap(req: NmapRequest) -> dict:
    args = ["nmap", f"-T{req.timing}"]

    if req.scan_type:
        args.append(_SCAN_TYPE_FLAGS[req.scan_type])
    if req.verbosity == 1:
        args.append("-v")
    elif req.verbosity == 2:
        args.append("-vv")
    if req.skip_host_discovery:
        args.append("-Pn")
    if req.ping_only:
        args.append("-sn")
    if req.no_dns:
        args.append("-n")
    if req.version_detection:
        args.append("-sV")
    if req.version_intensity is not None:
        args += ["--version-intensity", str(req.version_intensity)]
    if req.os_detection:
        args.append("-O")
    if req.aggressive:
        args.append("-A")
    if req.default_scripts:
        args.append("-sC")
    if req.scripts:
        args += ["--script", ",".join(req.scripts)]
    if req.open_only:
        args.append("--open")
    if req.reason:
        args.append("--reason")
    if req.traceroute:
        args.append("--traceroute")
    if req.min_rate is not None:
        args += ["--min-rate", str(req.min_rate)]
    if req.max_retries is not None:
        args += ["--max-retries", str(req.max_retries)]
    if req.host_timeout is not None:
        args += ["--host-timeout", f"{req.host_timeout}s"]
    if req.all_ports:
        args += ["-p-"]
    elif req.ports:
        args += ["-p", req.ports]
    elif req.top_ports:
        args += ["--top-ports", str(req.top_ports)]
    args.append(req.target)

    # UDP scans take much longer — extend timeout
    timeout = 300.0 if req.scan_type == "udp" else 120.0
    if req.all_ports:
        timeout = 600.0

    result = await run_tool(args, timeout=timeout)
    result["tool"] = "nmap"
    result["target"] = req.target
    return result


# ---------------------------------------------------------------------------
# Whois
# ---------------------------------------------------------------------------

class WhoisRequest(BaseModel):
    target: str
    server: str | None = None  # e.g. "whois.nic.google" for .dev/.app/.page TLDs

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        return validate_target(v)

    @field_validator("server")
    @classmethod
    def _validate_server(cls, v: str | None) -> str | None:
        if v is not None:
            validate_target(v)
        return v


@app.post("/tools/whois", dependencies=[Depends(require_auth)])
async def whois(req: WhoisRequest) -> dict:
    args = ["whois"]
    if req.server:
        args += ["-h", req.server]
    args.append(req.target)
    result = await run_tool(args, timeout=30.0)
    result["tool"] = "whois"
    result["target"] = req.target
    return result


# ---------------------------------------------------------------------------
# Dig (DNS lookup)
# ---------------------------------------------------------------------------

_VALID_RECORD_TYPES = {
    "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "CAA", "ANY",
}


class DigRequest(BaseModel):
    target: str
    record_type: str = "A"
    nameserver: str | None = None    # e.g. "8.8.8.8" — query this resolver directly
    short: bool = True               # +short (just the answer values)
    trace: bool = False              # +trace (follow delegation from root)
    tcp: bool = False                # +tcp (force TCP instead of UDP)
    dnssec: bool = False             # +dnssec (request DNSSEC records)
    timeout: int = 5                 # +time=N seconds per query

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        return validate_target(v)

    @field_validator("record_type")
    @classmethod
    def _validate_record_type(cls, v: str) -> str:
        v = v.upper()
        if v not in _VALID_RECORD_TYPES:
            raise ValueError(f"record_type must be one of {sorted(_VALID_RECORD_TYPES)}")
        return v

    @field_validator("nameserver")
    @classmethod
    def _validate_nameserver(cls, v: str | None) -> str | None:
        if v is not None:
            validate_target(v)
        return v

    @field_validator("timeout")
    @classmethod
    def _validate_timeout(cls, v: int) -> int:
        if not (1 <= v <= 30):
            raise ValueError("timeout must be between 1 and 30 seconds")
        return v


@app.post("/tools/dig", dependencies=[Depends(require_auth)])
async def dig(req: DigRequest) -> dict:
    args = ["dig"]
    if req.nameserver:
        args.append(f"@{req.nameserver}")
    args += [req.target, req.record_type]
    if req.short:
        args.append("+short")
    else:
        args += ["+noall", "+answer", "+authority", "+additional"]
    if req.trace:
        args.append("+trace")
    if req.tcp:
        args.append("+tcp")
    if req.dnssec:
        args.append("+dnssec")
    args.append(f"+time={req.timeout}")
    result = await run_tool(args, timeout=float(req.timeout + 5))
    result["tool"] = "dig"
    result["target"] = req.target
    result["record_type"] = req.record_type
    return result


# ---------------------------------------------------------------------------
# Ping
# ---------------------------------------------------------------------------

class PingRequest(BaseModel):
    target: str
    count: int = 4                   # -c N
    interval: float = 1.0            # -i seconds between packets
    size: int = 56                   # -s payload bytes
    ttl: int | None = None           # -t TTL
    ipv6: bool = False               # use ping6

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        return validate_target(v)

    @field_validator("count")
    @classmethod
    def _validate_count(cls, v: int) -> int:
        if not (1 <= v <= 20):
            raise ValueError("count must be between 1 and 20")
        return v

    @field_validator("interval")
    @classmethod
    def _validate_interval(cls, v: float) -> float:
        if not (0.2 <= v <= 10.0):
            raise ValueError("interval must be between 0.2 and 10 seconds")
        return v

    @field_validator("size")
    @classmethod
    def _validate_size(cls, v: int) -> int:
        if not (1 <= v <= 1472):
            raise ValueError("size must be between 1 and 1472 bytes")
        return v

    @field_validator("ttl")
    @classmethod
    def _validate_ttl(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 255):
            raise ValueError("ttl must be between 1 and 255")
        return v


@app.post("/tools/ping", dependencies=[Depends(require_auth)])
async def ping(req: PingRequest) -> dict:
    binary = "ping6" if req.ipv6 else "ping"
    args = [binary, "-c", str(req.count), "-i", str(req.interval), "-s", str(req.size)]
    if req.ttl is not None:
        args += ["-t", str(req.ttl)]
    args.append(req.target)
    timeout = (req.count * req.interval) + 5
    result = await run_tool(args, timeout=timeout)
    result["tool"] = "ping"
    result["target"] = req.target
    return result


# ---------------------------------------------------------------------------
# Curl (HTTP probing)
# ---------------------------------------------------------------------------

_ALLOWED_METHODS = {"GET", "HEAD", "POST", "OPTIONS"}


class CurlRequest(BaseModel):
    url: str
    method: Literal["GET", "HEAD", "POST", "OPTIONS"] = "GET"
    headers: dict[str, str] | None = None   # extra request headers
    body: str | None = None                  # request body (POST etc.)
    follow_redirects: bool = True
    user_agent: str = "OSIA-Kali-API/1.0"
    max_time: int = 20                       # seconds before giving up
    insecure: bool = False                   # -k skip TLS cert verification
    http_version: Literal["1.0", "1.1", "2", "3"] | None = None

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        return validate_url(v)

    @field_validator("max_time")
    @classmethod
    def _validate_max_time(cls, v: int) -> int:
        if not (1 <= v <= 60):
            raise ValueError("max_time must be between 1 and 60 seconds")
        return v

    @field_validator("headers")
    @classmethod
    def _validate_headers(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        if v is not None and len(v) > 20:
            raise ValueError("too many headers (max 20)")
        return v


_HTTP_VERSION_FLAGS = {"1.0": "--http1.0", "1.1": "--http1.1", "2": "--http2", "3": "--http3"}


@app.post("/tools/curl", dependencies=[Depends(require_auth)])
async def curl(req: CurlRequest) -> dict:
    args = [
        "curl",
        "--silent", "--show-error",
        "--max-time", str(req.max_time),
        "--max-filesize", "524288",  # 512 KB cap
        "-X", req.method,
        "-A", req.user_agent,
        "-D", "-",                   # dump response headers to stdout
    ]
    if req.follow_redirects:
        args.append("-L")
    if req.insecure:
        args.append("-k")
    if req.http_version:
        args.append(_HTTP_VERSION_FLAGS[req.http_version])
    if req.headers:
        for k, v in req.headers.items():
            args += ["-H", f"{k}: {v}"]
    if req.body:
        args += ["--data-raw", req.body]
    args.append(req.url)
    result = await run_tool(args, timeout=float(req.max_time + 5))
    result["tool"] = "curl"
    result["url"] = req.url
    return result


# ---------------------------------------------------------------------------
# Traceroute
# ---------------------------------------------------------------------------

class TracerouteRequest(BaseModel):
    target: str
    max_hops: int = 30               # -m N
    protocol: Literal["icmp", "udp", "tcp"] = "icmp"  # -I / default / -T
    port: int | None = None          # destination port (tcp/udp modes)
    wait: float = 3.0                # -w seconds to wait per probe
    queries: int = 3                 # -q probes per hop

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        return validate_target(v)

    @field_validator("max_hops")
    @classmethod
    def _validate_max_hops(cls, v: int) -> int:
        if not (1 <= v <= 64):
            raise ValueError("max_hops must be between 1 and 64")
        return v

    @field_validator("port")
    @classmethod
    def _validate_port(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 65535):
            raise ValueError("port must be between 1 and 65535")
        return v

    @field_validator("wait")
    @classmethod
    def _validate_wait(cls, v: float) -> float:
        if not (0.5 <= v <= 10.0):
            raise ValueError("wait must be between 0.5 and 10 seconds")
        return v

    @field_validator("queries")
    @classmethod
    def _validate_queries(cls, v: int) -> int:
        if not (1 <= v <= 5):
            raise ValueError("queries must be between 1 and 5")
        return v


@app.post("/tools/traceroute", dependencies=[Depends(require_auth)])
async def traceroute(req: TracerouteRequest) -> dict:
    args = ["traceroute", "-m", str(req.max_hops), "-w", str(req.wait), "-q", str(req.queries)]
    if req.protocol == "icmp":
        args.append("-I")
    elif req.protocol == "tcp":
        args.append("-T")
    # udp is the default — no flag needed
    if req.port is not None:
        args += ["-p", str(req.port)]
    args.append(req.target)
    timeout = (req.max_hops * req.queries * req.wait) + 5
    result = await run_tool(args, timeout=timeout)
    if result["return_code"] == 127:
        # Fall back to tracepath (no protocol/port options but always available)
        result = await run_tool(["tracepath", req.target], timeout=timeout)
    result["tool"] = "traceroute"
    result["target"] = req.target
    return result


# ---------------------------------------------------------------------------
# Nikto
# ---------------------------------------------------------------------------

_NIKTO_TUNING = {
    "0": "File Upload",
    "1": "Interesting File / Seen in logs",
    "2": "Misconfiguration / Default File",
    "3": "Information Disclosure",
    "4": "Injection (XSS/Script/HTML)",
    "5": "Remote File Retrieval (Inside Web Root)",
    "6": "Denial of Service",
    "7": "Remote File Retrieval (Server Wide)",
    "8": "Command Execution / Remote Shell",
    "9": "SQL Injection",
    "a": "Authentication Bypass",
    "b": "Software Identification",
    "c": "Remote Source Inclusion",
    "x": "Reverse Tuning (exclude all except specified)",
}


class NiktoRequest(BaseModel):
    target: str                            # URL or hostname
    port: int | None = None               # override port
    ssl: bool = False                     # force SSL (-ssl)
    tuning: list[str] | None = None       # test categories to run (see _NIKTO_TUNING)
    max_time: int = 120                   # seconds before giving up
    no_404_check: bool = False            # skip 404 detection (-no404)
    user_agent: str = "OSIA-Kali-API/1.0"

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        # Allow full URLs or bare hosts
        if v.startswith("http://") or v.startswith("https://"):
            return validate_url(v)
        return validate_target(v)

    @field_validator("port")
    @classmethod
    def _validate_port(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 65535):
            raise ValueError("port must be between 1 and 65535")
        return v

    @field_validator("max_time")
    @classmethod
    def _validate_max_time(cls, v: int) -> int:
        if not (10 <= v <= 600):
            raise ValueError("max_time must be between 10 and 600 seconds")
        return v

    @field_validator("tuning")
    @classmethod
    def _validate_tuning(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        bad = [t for t in v if t not in _NIKTO_TUNING]
        if bad:
            raise ValueError(f"unknown tuning codes {bad}. Valid: {list(_NIKTO_TUNING.keys())}")
        return v


@app.post("/tools/nikto", dependencies=[Depends(require_auth)])
async def nikto(req: NiktoRequest) -> dict:
    args = ["nikto", "-host", req.target, "-maxtime", f"{req.max_time}s",
            "-useragent", req.user_agent, "-nointeractive"]
    if req.port:
        args += ["-port", str(req.port)]
    if req.ssl:
        args.append("-ssl")
    if req.tuning:
        args += ["-Tuning", "".join(req.tuning)]
    if req.no_404_check:
        args.append("-no404")
    result = await run_tool(args, timeout=float(req.max_time + 10))
    result["tool"] = "nikto"
    result["target"] = req.target
    return result


# ---------------------------------------------------------------------------
# theHarvester
# ---------------------------------------------------------------------------

# Passive sources that require no API key
_HARVESTER_FREE_SOURCES = {
    "anubis", "baidu", "bing", "bingapi", "certspotter", "crtsh",
    "dnsdumpster", "duckduckgo", "hackertarget", "otx", "rapiddns",
    "subdomainfinderc99", "threatminer", "urlscan", "yahoo",
}
# Sources that work better / exclusively with an API key (still accepted)
_HARVESTER_KEY_SOURCES = {
    "bevigil", "fullhunt", "github-code", "hunter", "intelx",
    "pentesttools", "rocketreach", "securityTrails", "shodan",
    "spyse", "virustotal", "zoomeye",
}
_ALL_HARVESTER_SOURCES = _HARVESTER_FREE_SOURCES | _HARVESTER_KEY_SOURCES


class HarvesterRequest(BaseModel):
    target: str                              # domain to harvest
    sources: list[str] = ["crtsh", "dnsdumpster", "hackertarget", "otx", "urlscan"]
    limit: int = 100                         # max results per source (-l)
    dns_resolve: bool = False                # resolve discovered hostnames (-r)
    dns_brute: bool = False                  # DNS brute-force subdomains (-b)
    take_screenshot: bool = False            # capture screenshots (slow, needs display)

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        return validate_target(v)

    @field_validator("sources")
    @classmethod
    def _validate_sources(cls, v: list[str]) -> list[str]:
        bad = [s for s in v if s not in _ALL_HARVESTER_SOURCES]
        if bad:
            raise ValueError(f"unknown sources {bad}. Free sources: {sorted(_HARVESTER_FREE_SOURCES)}")
        if not v:
            raise ValueError("at least one source required")
        return v

    @field_validator("limit")
    @classmethod
    def _validate_limit(cls, v: int) -> int:
        if not (10 <= v <= 500):
            raise ValueError("limit must be between 10 and 500")
        return v


@app.post("/tools/harvester", dependencies=[Depends(require_auth)])
async def harvester(req: HarvesterRequest) -> dict:
    args = [
        "theHarvester",
        "-d", req.target,
        "-b", ",".join(req.sources),
        "-l", str(req.limit),
        "-f", "/dev/null",   # suppress file output, we only want stdout
    ]
    if req.dns_resolve:
        args.append("-r")
    if req.dns_brute:
        args.append("-n")
    result = await run_tool(args, timeout=180.0)
    result["tool"] = "theharvester"
    result["target"] = req.target
    return result


# ---------------------------------------------------------------------------
# WhatWeb
# ---------------------------------------------------------------------------

class WhatWebRequest(BaseModel):
    target: str                              # URL or hostname
    aggression: Literal[1, 3] = 1           # 1=stealthy (1 req), 3=aggressive (more reqs)
    follow_redirect: bool = True
    user_agent: str = "OSIA-Kali-API/1.0"
    no_errors: bool = True                   # suppress error messages in output

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        if v.startswith("http://") or v.startswith("https://"):
            return validate_url(v)
        return validate_target(v)


@app.post("/tools/whatweb", dependencies=[Depends(require_auth)])
async def whatweb(req: WhatWebRequest) -> dict:
    args = [
        "whatweb",
        f"--aggression={req.aggression}",
        f"--user-agent={req.user_agent}",
        "--color=never",
    ]
    if not req.follow_redirect:
        args.append("--no-redirect")
    if req.no_errors:
        args.append("--no-errors")
    args.append(req.target)
    result = await run_tool(args, timeout=45.0)
    result["tool"] = "whatweb"
    result["target"] = req.target
    return result


# ---------------------------------------------------------------------------
# sslscan
# ---------------------------------------------------------------------------

class SSLScanRequest(BaseModel):
    target: str                              # hostname or hostname:port
    port: int = 443
    show_certificate: bool = True           # include full cert details
    no_fallback: bool = False               # disable fallback to lower TLS versions
    ipv4_only: bool = False                 # -4
    ipv6_only: bool = False                 # -6
    ocsp: bool = False                      # check OCSP stapling
    starttls: Literal["smtp", "ftp", "imap", "pop3", "xmpp", "ldap", "rdp", "none"] = "none"

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        # Strip port suffix if caller included it — we handle port separately
        host = v.split(":")[0]
        return validate_target(host)

    @field_validator("port")
    @classmethod
    def _validate_port(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError("port must be between 1 and 65535")
        return v


@app.post("/tools/sslscan", dependencies=[Depends(require_auth)])
async def sslscan(req: SSLScanRequest) -> dict:
    target_with_port = f"{req.target}:{req.port}"
    args = ["sslscan", "--no-colour"]
    if not req.show_certificate:
        args.append("--no-certificate")
    if req.no_fallback:
        args.append("--no-fallback")
    if req.ipv4_only:
        args.append("-4")
    if req.ipv6_only:
        args.append("-6")
    if req.ocsp:
        args.append("--ocsp")
    if req.starttls != "none":
        args.append(f"--starttls-{req.starttls}")
    args.append(target_with_port)
    result = await run_tool(args, timeout=30.0)
    result["tool"] = "sslscan"
    result["target"] = target_with_port
    return result


# ---------------------------------------------------------------------------
# Amass
# ---------------------------------------------------------------------------

class AmassRequest(BaseModel):
    target: str                              # domain to enumerate
    mode: Literal["passive", "active"] = "passive"
    # passive: only queries public data sources, no direct contact with target (default in v5)
    # active: also attempts zone transfers and certificate name grabs
    timeout: int = 5                         # minutes before stopping (1–30)

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        return validate_target(v)

    @field_validator("timeout")
    @classmethod
    def _validate_timeout(cls, v: int) -> int:
        if not (1 <= v <= 30):
            raise ValueError("timeout must be between 1 and 30 minutes")
        return v


@app.post("/tools/amass", dependencies=[Depends(require_auth)])
async def amass(req: AmassRequest) -> dict:
    # v5 writes progress bars / control codes to stdout which corrupt the output.
    # Write results to a temp file with -o, then read it back.
    fd, outfile = tempfile.mkstemp(suffix=".txt")
    os.close(fd)
    try:
        args = ["amass", "enum", "-d", req.target, "-timeout", str(req.timeout),
                "-o", outfile, "-nocolor"]
        if req.mode == "active":
            args.append("-active")
        result = await run_tool(args, timeout=float((req.timeout * 60) + 15))
        try:
            with open(outfile) as f:
                result["stdout"] = f.read()
        except OSError:
            pass  # file may not exist if amass found nothing
    finally:
        if os.path.exists(outfile):
            os.unlink(outfile)
    result["tool"] = "amass"
    result["target"] = req.target
    return result


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
