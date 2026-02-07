# GhostShift Recon

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/bash-5.0+-green.svg" alt="Bash">
  <img src="https://img.shields.io/badge/license-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg" alt="Platform">
</p>

A comprehensive, multi-phase reconnaissance framework built on [Project Discovery's](https://projectdiscovery.io/) tool suite and other reliable OSINT sources. Designed for security professionals conducting authorized penetration testing and bug bounty hunting.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Phases](#phases)
- [Output Structure](#output-structure)
- [Configuration](#configuration)
- [Examples](#examples)
- [SSL Organization Validation](#ssl-organization-validation)
- [Rate Limiting](#rate-limiting)
- [Troubleshooting](#troubleshooting)
- [Legal Disclaimer](#legal-disclaimer)

---

## Features

- **Multi-source subdomain aggregation** — Combines subfinder, assetfinder, amass, crt.sh, and chaos for maximum coverage
- **Intelligent deduplication** — Removes duplicates at every stage while preserving data integrity
- **4-layer SSL/TLS organization validation** — Verifies certificate ownership via Subject Org, Subject CN, SANs, and reverse SAN root-domain matching to eliminate false positives
- **SSL feedback loop (Phase 4B)** — Newly discovered subdomains from SSL SANs are fed back through Phase 1 enumeration and Phase 2 scanning automatically
- **ASN-based infrastructure expansion** — Discovers additional IP ranges owned by the target via asnmap and BGP.he.net
- **Always rate-limited nuclei** — Vulnerability scanning enforces `-rl` (rate limit) flag to prevent overwhelming targets
- **Severity-based reporting** — Results organized by Critical, High, Medium, Low, Info
- **Modular design** — Each phase can run independently via `--phase`
- **Comprehensive logging** — Timestamped log file tracks every action and error
- **Graceful degradation** — Optional tools (assetfinder, amass, chaos) are skipped if unavailable without breaking the pipeline

---

## Architecture

```
Input: targets.txt (root domains)
    │
    ▼
┌─────────────────────────────────┐
│  PHASE 1: SUBDOMAIN ENUMERATION │
│  subfinder │ assetfinder │ amass │
│  crt.sh API │ chaos               │
└──────────────┬──────────────────┘
               │ deduplicated subdomains
               ▼
┌─────────────────────────────────┐
│  PHASE 2: DNS & LIVE HOSTS      │
│  dnsx (A/AAAA/CNAME resolution) │
│  httpx (HTTP/HTTPS probing)     │
└──────────────┬──────────────────┘
               │ resolved hosts + live URLs
               ▼
┌─────────────────────────────────┐
│  PHASE 3: ASN DISCOVERY         │
│  asnmap │ BGP.he.net │ whois    │
│  mapcidr (CIDR expansion)       │
└──────────────┬──────────────────┘
               │ CIDRs + IPs
               ▼
┌─────────────────────────────────┐
│  PHASE 4: SSL/TLS VALIDATION    │
│  naabu (port scan)              │
│  tlsx (certificate extraction)  │
│  4-layer org verification       │
└──────────────┬──────────────────┘
               │ validated hosts + new SAN subs
               ▼
┌─────────────────────────────────┐
│  PHASE 4B: SSL FEEDBACK LOOP    │
│  Re-enumerate new SAN subs      │
│  → subfinder, crt.sh, assetfinder│
│  Re-resolve with dnsx           │
│  Re-probe with httpx            │
└──────────────┬──────────────────┘
               │ enriched master lists
               ▼
┌─────────────────────────────────┐
│  PHASE 5: VULNERABILITY SCAN    │
│  nuclei (rate-limited, all      │
│  templates, severity sorted)    │
└──────────────┬──────────────────┘
               │
               ▼
         RECON_REPORT.txt
```

---

## Prerequisites

### Required Tools

| Tool | Purpose | Install |
|------|---------|---------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain discovery (50+ sources) | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [dnsx](https://github.com/projectdiscovery/dnsx) | Fast DNS resolver | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP prober with tech detection | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [tlsx](https://github.com/projectdiscovery/tlsx) | TLS certificate data extraction | `go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest` |
| [naabu](https://github.com/projectdiscovery/naabu) | Port scanner | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Vulnerability scanner | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| [mapcidr](https://github.com/projectdiscovery/mapcidr) | CIDR manipulation | `go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest` |
| [asnmap](https://github.com/projectdiscovery/asnmap) | ASN discovery | `go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest` |
| [jq](https://stedolan.github.io/jq/) | JSON processing | `sudo apt install jq` |
| curl | HTTP client | `sudo apt install curl` |
| whois | WHOIS lookups | `sudo apt install whois` |

### Optional Tools (enhanced coverage)

| Tool | Purpose | Install |
|------|---------|---------|
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Additional subdomain finder | `go install -v github.com/tomnomnom/assetfinder@latest` |
| [amass](https://github.com/owasp-amass/amass) | OWASP subdomain enumeration | `go install -v github.com/owasp-amass/amass/v4/...@master` |
| [chaos](https://github.com/projectdiscovery/chaos-client) | ProjectDiscovery's public dataset | `go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest` |
| [anew](https://github.com/tomnomnom/anew) | Append unique lines | `go install -v github.com/tomnomnom/anew@latest` |

### Quick Install (All Required)

```bash
# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest

# Install optional tools
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# Install system dependencies
sudo apt install -y jq curl whois

# Update nuclei templates
nuclei -update-templates
```

### API Keys (Optional but Recommended)

Set these environment variables for enhanced coverage:

```bash
# Project Discovery Cloud Platform key (used by subfinder, chaos, etc.)
export PDCP_API_KEY="your-pdcp-api-key"

# Or individual keys in subfinder's provider config:
# ~/.config/subfinder/provider-config.yaml
```

---

## Installation

```bash
git clone https://github.com/ghostshift-content/ghostshift_recon.git
cd ghostshift_recon
chmod +x recon.sh
```

---

## Usage

### Basic

```bash
# Create a target file with root domains
echo "example.com" > targets.txt

# Run full reconnaissance
./recon.sh -f targets.txt
```

### All Options

```
Usage: ./recon.sh [OPTIONS]

Required:
  -f, --file FILE          Input file with root domains (one per line)

Options:
  -o, --output DIR         Output directory (default: ./recon_results_TIMESTAMP)
  -r, --rate-limit N       Nuclei rate limit in req/s (default: 150)
  -t, --threads N          Default thread count (default: 50)
  -p, --ports PORTS        Comma-separated ports for naabu (default: 80,443,8080,8443,8000,8888,9090,3000,5000,5443)
      --top-ports N        Use naabu top-ports mode instead of port list
      --phase N            Run only specific phase (1-5, or 4b for SSL re-scan)
      --skip-nuclei        Skip vulnerability scanning (Phase 5)
      --nuclei-severity S  Nuclei severity filter (default: info,low,medium,high,critical)
  -h, --help               Show this help message
```

### Input File Format

One root domain per line. Lines starting with `#` are treated as comments.

```
# targets.txt
example.com
target.org
company.io
```

---

## Phases

### Phase 1: Subdomain Enumeration

Runs all enumeration sources per domain, then merges and deduplicates.

| Source | Type | Notes |
|--------|------|-------|
| subfinder | Passive | 50+ data sources, `-all` flag for maximum coverage |
| assetfinder | Passive | Optional, `--subs-only` mode |
| amass | Passive | OWASP tool, passive mode with timeout |
| crt.sh | API | Certificate transparency logs via JSON API |
| chaos | API | Project Discovery's public dataset (needs API key) |

**Output:** `subdomains.txt` — deduplicated, scope-filtered subdomain list

### Phase 2: DNS Resolution & Live Host Detection

| Tool | Purpose |
|------|---------|
| dnsx | Resolves A, AAAA, CNAME records with multi-threaded DNS queries |
| httpx | Probes HTTP/HTTPS with status codes, titles, tech detection, content length |

**Output:** `resolved_hosts.txt`, `live_hosts.txt`, `live_hosts_full.txt` (with metadata)

### Phase 3: ASN Discovery & IP Enumeration

| Tool | Purpose |
|------|---------|
| asnmap | Maps IPs and domains to ASN numbers and CIDR ranges |
| BGP.he.net | Enriches ASN data with advertised prefixes |
| whois | Validates ASN ownership against target organization |
| mapcidr | Expands CIDR ranges to individual IPs (only /24+) |

**Output:** `asn_cidrs.txt`, `asn_ips.txt`, `phase3_asn/asn_info.txt`

### Phase 4: SSL/TLS Certificate Validation

| Tool | Purpose |
|------|---------|
| naabu | Port scans discovered IPs for open services |
| tlsx | Extracts SSL/TLS certificate data (CN, Org, SANs) in JSON |

Then performs [4-layer organization validation](#ssl-organization-validation) to verify each certificate belongs to the target.

**Output:** `phase4_ssl/validated_hosts.txt`, `phase4_ssl/unvalidated_hosts.txt`, `phase4_ssl/validation_report.txt`

### Phase 4B: SSL Feedback Loop (Re-Scan)

Automatically triggered after Phase 4. Takes newly discovered subdomains from SSL SANs and:

1. **Re-enumerates** — Runs subfinder, crt.sh, assetfinder on root domains of new subs to catch siblings
2. **Re-resolves** — Runs dnsx on all new unresolved subdomains
3. **Re-probes** — Runs httpx on newly resolved hosts

All results merge back into the master lists so Phase 5 has complete coverage.

### Phase 5: Vulnerability Scanning (Nuclei)

Runs nuclei against all live hosts with:

- **Rate limiting always enforced** via `-rl` flag (default: 150 req/s)
- Controlled bulk size and template concurrency
- Automatic template updates before scanning
- Results split by severity: `nuclei_critical.txt`, `nuclei_high.txt`, `nuclei_medium.txt`, `nuclei_low.txt`, `nuclei_info.txt`

**Output:** `phase5_vulns/nuclei_results.txt`, `phase5_vulns/nuclei_results.jsonl`

---

## Output Structure

```
recon_results_YYYYMMDD_HHMMSS/
├── RECON_REPORT.txt              # Full summary report
├── recon.log                     # Timestamped execution log
├── subdomains.txt                # All discovered subdomains (enriched)
├── resolved_hosts.txt            # DNS-resolved hostnames
├── live_hosts.txt                # Live HTTP/HTTPS URLs
├── live_hosts_full.txt           # httpx output with metadata
├── asn_cidrs.txt                 # Discovered CIDR ranges
├── asn_ips.txt                   # Enumerated IP addresses
├── ssl_validated_subdomains.txt  # Subdomains from validated SSL certs
├── org_names.txt                 # Organization names for validation
│
├── phase1_subdomains/            # Per-tool raw subdomain files
│   ├── subfinder_example.com.txt
│   ├── assetfinder_example.com.txt
│   ├── amass_example.com.txt
│   ├── crtsh_example.com.txt
│   ├── chaos_example.com.txt
│   └── all_subdomains_raw.txt
│
├── phase2_dns/
│   ├── dnsx_resolved.txt         # Full DNS resolution output
│   ├── resolved_ips.txt          # Extracted IP addresses
│   └── httpx_results.txt         # Full httpx probe output
│
├── phase3_asn/
│   ├── asnmap_results.txt        # asnmap CIDR output
│   ├── unique_asns.txt           # Unique ASN numbers
│   ├── asn_info.txt              # ASN details (name, country, range)
│   ├── bgp_cidrs.txt             # BGP.he.net CIDR ranges
│   ├── small_cidrs.txt           # CIDRs selected for expansion
│   ├── expanded_ips.txt          # IPs from CIDR expansion
│   └── org_names.txt             # Organization identifiers
│
├── phase4_ssl/
│   ├── naabu_results.txt         # Port scan results
│   ├── tlsx_targets.txt          # Targets sent to tlsx
│   ├── tlsx_json_raw.jsonl       # Raw TLS certificate JSON
│   ├── tlsx_readable.txt         # Human-readable cert output
│   ├── validated_hosts.txt       # Org-verified hosts
│   ├── unvalidated_hosts.txt     # Rejected hosts
│   ├── validation_report.txt     # Detailed validation log
│   ├── ssl_new_subs.txt          # New subs from SANs
│   ├── rescan_subs/              # Phase 4B enumeration files
│   ├── rescan_dnsx.txt           # Phase 4B DNS results
│   ├── rescan_resolved.txt       # Phase 4B resolved hosts
│   └── rescan_httpx.txt          # Phase 4B httpx results
│
└── phase5_vulns/
    ├── nuclei_targets.txt        # Final target list for nuclei
    ├── nuclei_results.txt        # Plain text results
    ├── nuclei_results.jsonl      # JSON Lines results
    ├── nuclei_critical.txt       # Critical findings
    ├── nuclei_high.txt           # High findings
    ├── nuclei_medium.txt         # Medium findings
    ├── nuclei_low.txt            # Low findings
    └── nuclei_info.txt           # Informational findings
```

---

## Configuration

### Default Settings

| Setting | Default | Flag |
|---------|---------|------|
| Nuclei rate limit | 150 req/s | `-r, --rate-limit` |
| Thread count | 50 | `-t, --threads` |
| Ports | 80,443,8080,8443,8000,8888,9090,3000,5000,5443 | `-p, --ports` |
| naabu rate | 1000 pps | (internal) |
| dnsx threads | 100 | (internal) |
| subfinder timeout | 30 min | (internal) |
| amass timeout | 30 min | (internal) |
| nuclei bulk size | 25 | (internal) |
| nuclei concurrency | 10 | (internal) |

### Environment Variables

```bash
# Project Discovery Cloud Platform API key
export PDCP_API_KEY="your-key"

# Chaos API key (legacy)
export CHAOS_KEY="your-key"
```

---

## Examples

### Full scan on a single target

```bash
echo "tesla.com" > targets.txt
./recon.sh -f targets.txt -o ./tesla_recon
```

### Multiple targets with conservative rate limiting

```bash
cat > targets.txt << EOF
target1.com
target2.org
target3.io
EOF

./recon.sh -f targets.txt -r 50 -t 25
```

### Only run subdomain enumeration

```bash
./recon.sh -f targets.txt --phase 1
```

### Run Phases 1-4 without nuclei (recon only)

```bash
./recon.sh -f targets.txt --skip-nuclei
```

### Scan top 1000 ports instead of default list

```bash
./recon.sh -f targets.txt --top-ports 1000
```

### Run only the SSL feedback loop

```bash
./recon.sh -f targets.txt --phase 4b
```

### Only critical and high severity nuclei scan

```bash
./recon.sh -f targets.txt --nuclei-severity critical,high
```

---

## SSL Organization Validation

Phase 4 performs a rigorous 4-layer verification to ensure every discovered host actually belongs to the target organization. This eliminates false positives from shared hosting, CDNs, and third-party services.

### Layer 1: Subject Organization Match

Compares the certificate's `Subject Organization` field against known organization names derived from WHOIS data and domain base names.

### Layer 2: Subject Common Name (CN) Match

Checks if the certificate's `Subject CN` contains any of the target root domains.

### Layer 3: Subject Alternative Names (SANs) Match

Verifies that at least one SAN entry matches a target root domain (e.g., `*.example.com` or `sub.example.com`).

### Layer 4: Reverse SAN Root Domain Derivation

Extracts individual SANs, derives their root domains, and checks if any root domain matches the target list. This catches cases where `app.example.com` appears as a SAN on a certificate for `cdn.example.com`.

### Validation Output

Each certificate gets one of two labels in `validation_report.txt`:

```
[VALID]    host:443 | CN=*.example.com | Org=Example Inc | Reason: Subject Org matches
[REJECTED] host:443 | CN=shared.cdn.net | Org=CloudFlare Inc | SANs: *.cdn.net
```

---

## Rate Limiting

Rate limiting is enforced at multiple levels to prevent overwhelming targets:

| Tool | Control | Default |
|------|---------|---------|
| nuclei | `-rl` flag (requests/sec) | 150 |
| naabu | `-rate` (packets/sec) | 1000 |
| httpx | `-threads` (concurrent) | 50 |
| dnsx | `-t` (concurrent) | 100 |
| BGP.he.net | `sleep 1` between queries | 1 req/s |
| crt.sh | Single request per domain | N/A |

**Important:** The nuclei `-rl` flag is always set. There is no way to run nuclei without rate limiting in this framework.

---

## Troubleshooting

### "Missing required tools"

Run the install commands shown in the error output. All Go tools require Go 1.21+.

```bash
# Verify Go is installed
go version

# Ensure GOPATH/bin is in PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

### "No subdomains found"

- Verify your target file has valid domains (not URLs)
- Check if subfinder's API sources are configured: `~/.config/subfinder/provider-config.yaml`
- Try running subfinder manually: `subfinder -d example.com -all`

### "No live hosts detected"

- The target may not have web services on standard ports
- Try expanding ports: `--top-ports 1000`
- Check DNS resolution: `dnsx -d example.com -a`

### nuclei scan takes too long

- Lower the rate limit: `-r 50`
- Focus on critical findings: `--nuclei-severity critical,high`
- Skip info-level templates which are numerous

### Permission errors with naabu

naabu may require root privileges for raw packet scanning:

```bash
sudo ./recon.sh -f targets.txt
# Or give naabu cap_net_raw:
sudo setcap cap_net_raw=ep $(which naabu)
```

---

## Legal Disclaimer

**This tool is intended for authorized security testing only.**

- Only use against targets you have explicit written permission to test
- Unauthorized scanning may violate computer fraud and abuse laws
- The authors are not responsible for misuse of this tool
- Always follow your organization's rules of engagement
- Respect rate limits and avoid denial-of-service conditions

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Credits

Built with the incredible open-source tools from:

- [Project Discovery](https://projectdiscovery.io/) — subfinder, dnsx, httpx, tlsx, naabu, nuclei, mapcidr, asnmap, chaos
- [Tom Hudson](https://github.com/tomnomnom) — assetfinder, anew
- [OWASP](https://owasp.org/) — amass
- [crt.sh](https://crt.sh/) — Certificate Transparency logs
- [BGP.he.net](https://bgp.he.net/) — ASN/BGP data
