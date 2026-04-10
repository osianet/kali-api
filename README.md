# Kali API

A lightweight HTTP API that wraps Kali Linux security tools in a containerised, authenticated service. Built for programmatic use by the OSIA intelligence framework — designed to be called by agents and research workers, not humans directly.

## Architecture

- **Base image:** `kalilinux/kali-rolling`
- **API framework:** FastAPI + uvicorn
- **Auth:** Bearer token (`KALI_API_KEY`)
- **Binding:** `127.0.0.1:8100` on the host (never exposed publicly)
- **Capabilities:** `NET_ADMIN`, `NET_RAW` (required for nmap SYN scans and raw ICMP)

All subprocesses use explicit argument lists — no `shell=True`. Every tool endpoint validates its inputs with Pydantic before a process is spawned. Timeouts are enforced on all calls.

---

## Setup

```bash
cd /home/ubuntu/kali-api

# Generate initial API key and write .env
./rotate-key.sh

# Build image and start container
docker compose up -d --build
```

### Rotating the API key

```bash
./rotate-key.sh
```

Generates a new 64-char hex key via `openssl rand -hex 32`, writes it to `.env`, and restarts the container. The old key is immediately invalid.

---

## Authentication

Every tool endpoint requires a Bearer token:

```
Authorization: Bearer <KALI_API_KEY>
```

`GET /health` is unauthenticated.

---

## Response format

All tool endpoints return the same envelope:

```json
{
  "tool": "nmap",
  "target": "192.168.1.1",
  "stdout": "...",
  "stderr": "...",
  "return_code": 0,
  "duration_seconds": 12.4,
  "timed_out": false
}
```

`curl` and `dig` include additional fields (`url`, `record_type`) where relevant.

---

## Endpoints

### `GET /health`

Unauthenticated liveness check.

```json
{ "status": "ok" }
```

---

### `POST /tools/nmap`

Port scanner and service/OS fingerprinter.

| Field | Type | Default | Description |
|---|---|---|---|
| `target` | string | required | IP address, CIDR range, or hostname |
| `ports` | string | — | Port spec: `"22"`, `"22,80,443"`, `"1-1024"` |
| `top_ports` | int | — | Scan the N most common ports |
| `all_ports` | bool | false | Scan all 65535 ports (`-p-`) |
| `scan_type` | enum | — | `syn` `-sS`, `connect` `-sT`, `udp` `-sU`, `ack` `-sA`, `window` `-sW`, `fin` `-sF`, `null` `-sN`, `xmas` `-sX` |
| `timing` | 0–5 | 3 | Timing template (`-T<N>`). 0=paranoid, 3=normal, 5=insane |
| `skip_host_discovery` | bool | false | Treat host as online regardless of ping (`-Pn`) |
| `ping_only` | bool | false | Host discovery only, no port scan (`-sn`) |
| `no_dns` | bool | false | Skip reverse DNS resolution (`-n`) |
| `min_rate` | int | — | Minimum packet send rate (packets/sec) |
| `max_retries` | int | — | Max port scan probe retransmissions (0–10) |
| `host_timeout` | int | — | Give up on host after N seconds (1–600) |
| `version_detection` | bool | false | Probe open ports for service/version info (`-sV`) |
| `version_intensity` | 0–9 | — | Version detection intensity (0=light, 9=all probes) |
| `os_detection` | bool | false | Enable OS detection (`-O`) |
| `aggressive` | bool | false | Enable OS detection, version detection, script scanning, and traceroute (`-A`) |
| `default_scripts` | bool | false | Run default NSE scripts (`-sC`) |
| `scripts` | list[string] | — | Run specific whitelisted NSE scripts (see allowlist below) |
| `open_only` | bool | false | Only show open ports (`--open`) |
| `reason` | bool | false | Show reason each port is in its state (`--reason`) |
| `verbosity` | 0–2 | 0 | Output verbosity: 0=normal, 1=`-v`, 2=`-vv` |
| `traceroute` | bool | false | Trace hop path to host (`--traceroute`) |

**Allowed NSE scripts:** `banner`, `default`, `discovery`, `safe`, `version`, `auth`, `http-title`, `http-server-header`, `http-headers`, `http-robots.txt`, `http-methods`, `ssl-cert`, `ssl-enum-ciphers`, `tls-alpn`, `ssh-hostkey`, `ssh-auth-methods`, `smtp-commands`, `ftp-anon`, `ftp-syst`, `dns-nsid`, `dns-service-discovery`, `snmp-info`, `snmp-sysdescr`, `rdp-enum-encryption`, `smb-security-mode`, `smb2-security-mode`, `mysql-info`, `redis-info`, `whois-domain`, `whois-ip`, `traceroute-geolocation`

**Timeouts:** 120s standard, 300s for UDP scans, 600s for all-ports scans.

**Examples:**

```bash
# Quick service fingerprint of a host
POST /tools/nmap
{
  "target": "192.168.196.4",
  "top_ports": 100,
  "version_detection": true,
  "skip_host_discovery": true
}

# Full SYN scan with OS detection
POST /tools/nmap
{
  "target": "10.0.0.0/24",
  "scan_type": "syn",
  "os_detection": true,
  "timing": 4,
  "open_only": true
}

# TLS certificate check
POST /tools/nmap
{
  "target": "example.com",
  "ports": "443",
  "scripts": ["ssl-cert", "ssl-enum-ciphers"]
}
```

---

### `POST /tools/whois`

WHOIS registration lookup. For `.dev`, `.app`, `.page`, and other Google Registry TLDs that have no public WHOIS server, use `POST /tools/curl` against `https://pubapi.registry.google/rdap/domain/<domain>` instead.

| Field | Type | Default | Description |
|---|---|---|---|
| `target` | string | required | Domain name or IP address |
| `server` | string | — | Query this WHOIS server directly (e.g. `whois.arin.net` for IP ranges) |

**Example:**

```bash
POST /tools/whois
{ "target": "cloudflare.com" }

# IP WHOIS via ARIN
POST /tools/whois
{ "target": "1.1.1.1", "server": "whois.arin.net" }
```

---

### `POST /tools/dig`

DNS lookup.

| Field | Type | Default | Description |
|---|---|---|---|
| `target` | string | required | Domain name or IP (for PTR) |
| `record_type` | enum | `A` | `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, `PTR`, `SRV`, `CAA`, `ANY` |
| `nameserver` | string | — | Query this resolver directly (e.g. `8.8.8.8`) |
| `short` | bool | true | Return only answer values (`+short`) |
| `trace` | bool | false | Trace delegation from root nameservers (`+trace`) |
| `tcp` | bool | false | Force TCP transport instead of UDP |
| `dnssec` | bool | false | Request DNSSEC records (`+dnssec`) |
| `timeout` | int | 5 | Seconds to wait per query (1–30) |

**Examples:**

```bash
# MX records
POST /tools/dig
{ "target": "gmail.com", "record_type": "MX" }

# Check DNSSEC validation
POST /tools/dig
{ "target": "cloudflare.com", "record_type": "A", "dnssec": true, "short": false }

# Trace delegation chain from root
POST /tools/dig
{ "target": "osia.dev", "record_type": "NS", "trace": true }

# Reverse DNS
POST /tools/dig
{ "target": "1.1.1.1", "record_type": "PTR" }
```

---

### `POST /tools/ping`

ICMP echo probe.

| Field | Type | Default | Description |
|---|---|---|---|
| `target` | string | required | IP address or hostname |
| `count` | int | 4 | Number of packets to send (1–20) |
| `interval` | float | 1.0 | Seconds between packets (0.2–10.0) |
| `size` | int | 56 | Payload size in bytes (1–1472) |
| `ttl` | int | — | Set IP TTL (1–255) |
| `ipv6` | bool | false | Use `ping6` |

---

### `POST /tools/curl`

HTTP/HTTPS probe. Response includes raw headers and body in `stdout`.

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | string | required | Must start with `http://` or `https://` |
| `method` | enum | `GET` | `GET`, `HEAD`, `POST`, `OPTIONS` |
| `headers` | object | — | Extra request headers (max 20) |
| `body` | string | — | Request body |
| `follow_redirects` | bool | true | Follow `Location` redirects (`-L`) |
| `user_agent` | string | `OSIA-Kali-API/1.0` | User-Agent header |
| `max_time` | int | 20 | Total timeout in seconds (1–60) |
| `insecure` | bool | false | Skip TLS certificate verification (`-k`) |
| `http_version` | enum | — | Force HTTP version: `1.0`, `1.1`, `2`, `3` |

**Examples:**

```bash
# Check HTTP headers of a site
POST /tools/curl
{ "url": "https://example.com", "method": "HEAD" }

# RDAP lookup for a .dev domain
POST /tools/curl
{ "url": "https://pubapi.registry.google/rdap/domain/osia.dev" }

# POST with custom headers
POST /tools/curl
{
  "url": "https://api.example.com/endpoint",
  "method": "POST",
  "headers": { "Content-Type": "application/json", "X-Api-Key": "abc123" },
  "body": "{\"query\": \"test\"}"
}
```

---

### `POST /tools/traceroute`

Hop-by-hop path trace to a host.

| Field | Type | Default | Description |
|---|---|---|---|
| `target` | string | required | IP address or hostname |
| `max_hops` | int | 30 | Maximum TTL / hop count (1–64) |
| `protocol` | enum | `icmp` | `icmp` (`-I`), `udp` (default), `tcp` (`-T`) |
| `port` | int | — | Destination port for TCP/UDP probes |
| `wait` | float | 3.0 | Seconds to wait for a response per probe (0.5–10.0) |
| `queries` | int | 3 | Number of probes per hop (1–5) |

**Examples:**

```bash
# Standard ICMP traceroute
POST /tools/traceroute
{ "target": "8.8.8.8" }

# TCP traceroute to port 443 (bypasses ICMP-blocking firewalls)
POST /tools/traceroute
{ "target": "192.168.196.4", "protocol": "tcp", "port": 443 }
```

---

## Notes

### .dev / Google Registry TLDs
`.dev`, `.app`, `.page`, and other Google Registry TLDs do not have a public WHOIS server (`whois.nic.dev` does not resolve). Use RDAP via the `curl` endpoint:

```bash
POST /tools/curl
{ "url": "https://pubapi.registry.google/rdap/domain/<domain>" }
```

### nmap and root
The container runs as root. SYN scans (`scan_type: "syn"`) and OS detection (`os_detection: true`) require root and will work correctly.

### UDP scans
UDP scans (`scan_type: "udp"`) are slow by nature. The timeout is extended to 300s automatically. Use `top_ports` to limit scope.

### Interactive tools
Tools that require interactive input (john, hashcat in interactive mode) are not suitable for this API pattern. Hash cracking is exposed via a dedicated `POST /tools/crack` endpoint with file-based input.
