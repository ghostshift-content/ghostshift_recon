# GhostShift Recon

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/bash-5.0+-green.svg" alt="Bash">
  <img src="https://img.shields.io/badge/license-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg" alt="Platform">
</p>

Comprehensive reconnaissance framework for authorized security testing and bug bounty workflows.

It combines ProjectDiscovery tooling with OSINT + archive URL intelligence and enforces certificate ownership checks to reduce false positives.

## Features

- Multi-source subdomain discovery (`subfinder`, `assetfinder`, `amass`, `crt.sh`, `chaos`)
- Parallel Phase 1 domain enumeration (`--enum-jobs`)
- Structured DNS outputs (A/AAAA/CNAME, subdomain-IP map, reverse IP map)
- ASN/CIDR expansion with ownership keyword filtering
- SSL/TLS ownership validation pipeline (CN/Org/SAN/root matching)
- SSL-validated ASN IP tracking to reduce noisy infrastructure findings
- URL intelligence collection for bounty coverage (`waybackurls`, `gau`, optional `katana`/`hakrawler`)
- Phase 4B feedback loop: SAN discoveries re-enter enum + resolve + probe
- Rate-limited nuclei scanning with configurable severity filter
- Consolidated final report and CSV/TXT export

## Architecture

```
Input roots -> Phase1 enum -> Phase2 DNS/httpx -> Phase3 ASN/CIDR/IP
         -> Phase4 SSL ownership validation -> Phase4B feedback re-scan
         -> Phase5 nuclei + URL intel -> consolidated report
```

## Requirements

### Required tools

- `subfinder`
- `dnsx`
- `httpx`
- `tlsx`
- `naabu`
- `nuclei`
- `mapcidr`
- `asnmap`
- `jq`
- `curl`
- `whois`

### Optional tools (recommended)

- `assetfinder`
- `amass`
- `chaos`
- `anew`
- `gau`
- `waybackurls`
- `katana`
- `hakrawler`

### Install (core)

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest

# Linux
sudo apt install -y jq curl whois

# macOS (Homebrew)
brew install jq curl whois
```

### Install (optional URL intel + extra enum)

```bash
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/hakluke/hakrawler@latest
```

### Optional API keys

```bash
export PDCP_API_KEY="your-key"
export CHAOS_KEY="your-key"
```

## Usage

### Basic

```bash
echo "example.com" > targets.txt
./recon.sh -f targets.txt
```

### Full options

```text
Usage: ./recon.sh [OPTIONS]

Required:
  -f, --file FILE          Input file with root domains (one per line)

Options:
  -o, --output DIR         Output directory (default: ./recon_results_TIMESTAMP)
  -r, --rate-limit N       Nuclei rate limit in req/s (default: 150)
  -t, --threads N          Default thread count (default: 50)
      --enum-jobs N        Parallel root-domain enum workers (default: 4)
      --crawl-depth N      URL crawl depth for katana/hakrawler (default: 2)
  -p, --ports PORTS        Comma-separated ports for naabu
      --top-ports N        Use naabu top-ports mode instead of port list
      --phase N            Run only specific phase (1-5, or 4b)
      --skip-nuclei        Skip Phase 5 nuclei scanning
      --nuclei-severity S  Nuclei severity list (default: info,low,medium,high,critical)
  -h, --help               Show help
```

### Examples

```bash
# Fast broad recon
./recon.sh -f targets.txt --enum-jobs 8 --threads 80

# Recon only (no nuclei)
./recon.sh -f targets.txt --skip-nuclei

# Conservative scan profile
./recon.sh -f targets.txt -r 50 --threads 25 --enum-jobs 3

# Deep URL intel crawl setup
./recon.sh -f targets.txt --crawl-depth 3

# Nuclei focused severities
./recon.sh -f targets.txt --nuclei-severity critical,high

# Single phase execution
./recon.sh -f targets.txt --phase 4
./recon.sh -f targets.txt --phase 4b
```

## Input format

`targets.txt` should contain root domains only:

```text
# comments are allowed
example.com
example.org
```

## Phase breakdown

### Phase 1: Subdomain enumeration

Sources: `subfinder`, `assetfinder`, `amass`, `crt.sh`, `chaos`.

Parallelized across target domains using `--enum-jobs`.

Output:
- `subdomains.txt`
- `phase1_subdomains/*.txt`

### Phase 2: DNS + live host probing

- Resolves A/AAAA/CNAME using `dnsx`
- Probes HTTP/HTTPS with `httpx`
- Builds normalized maps for domain-IP analysis

Output:
- `resolved_hosts.txt`
- `live_hosts.txt`
- `live_hosts_full.txt`
- `phase2_dns/dns_a_records.txt`
- `phase2_dns/dns_aaaa_records.txt`
- `phase2_dns/dns_cname_records.txt`
- `phase2_dns/subdomain_ip_map.txt`
- `phase2_dns/ip_subdomain_map.txt`
- `phase2_dns/resolved_ips.txt`

### Phase 3: ASN/CIDR/IP expansion

- Maps discovered infrastructure with `asnmap`
- Builds ownership keyword set from target/WHOIS org data
- Filters trusted ASN candidates
- Enriches prefixes via BGP.he.net
- Expands limited CIDRs with `mapcidr`

Output:
- `asn_cidrs.txt`
- `asn_ips.txt`
- `phase3_asn/asnmap_results_raw.txt`
- `phase3_asn/asnmap_json_raw.jsonl`
- `phase3_asn/unique_asns.txt`
- `phase3_asn/trusted_asns.txt`
- `phase3_asn/asn_info.txt`
- `phase3_asn/org_names.txt`
- `phase3_asn/org_keywords.txt`
- `phase3_asn/httpx_asn_ips.txt`

### Phase 4: SSL/TLS ownership validation

- Port discovery via `naabu`
- Cert extraction via `tlsx`
- Validates ownership using org/cn/san/root matching
- Produces validated IP sets used to reduce false positives

Output:
- `phase4_ssl/validated_hosts.txt`
- `phase4_ssl/unvalidated_hosts.txt`
- `phase4_ssl/validation_report.txt`
- `phase4_ssl/ssl_validated_ips.txt`
- `phase4_ssl/ssl_validated_ip_hosts.txt`
- `phase4_ssl/ssl_validated_ip_urls.txt`
- `ssl_validated_subdomains.txt`

### Phase 4B: SSL feedback loop

SAN-discovered subdomains are fed back into:
- re-enumeration
- DNS resolution
- HTTP probing

Then merged back into master lists.

### Phase 5: Nuclei + URL intelligence

Before nuclei run, script collects URL targets from:
- `waybackurls`
- `gau`
- optional active crawlers (`katana`, `hakrawler`)

URLs are scope-filtered, deduped, then merged into nuclei targets.

Output:
- `phase5_vulns/url_intel_raw.txt`
- `phase5_vulns/url_intel_scoped.txt`
- `phase5_vulns/url_intel_params.txt`
- `phase5_vulns/url_intel_js.txt`
- `phase5_vulns/nuclei_targets.txt`
- `phase5_vulns/nuclei_results.txt`
- `phase5_vulns/nuclei_results.jsonl`
- `phase5_vulns/nuclei_critical.txt`
- `phase5_vulns/nuclei_high.txt`
- `phase5_vulns/nuclei_medium.txt`
- `phase5_vulns/nuclei_low.txt`
- `phase5_vulns/nuclei_info.txt`

## Final outputs

Top-level key files:

- `RECON_REPORT.txt`
- `FINAL_CONSOLIDATED.txt`
- `FINAL_CONSOLIDATED.csv`
- `recon.log`

`FINAL_CONSOLIDATED` includes normalized subdomain/IP/CNAME/status/title plus SSL-validated ASN IP coverage.

## Troubleshooting

### awk syntax error in DNS parsing

If you saw errors like:

```text
awk: line 2: syntax error at or near =
```

This was caused by reserved-name conflicts in awk variable naming. Fixed in current code.

### Missing tools

Install required tools and ensure `$(go env GOPATH)/bin` is in `PATH`.

### No results from chaos

Set `PDCP_API_KEY` or `CHAOS_KEY`.

### naabu permission issues

```bash
sudo setcap cap_net_raw=ep $(which naabu)
# or run with sudo if your environment requires it
```

## Legal

Use only on assets you are explicitly authorized to test.

## License

MIT. See [LICENSE](LICENSE).

## Credits

- [ProjectDiscovery](https://projectdiscovery.io/)
- [tomnomnom](https://github.com/tomnomnom)
- [OWASP Amass](https://github.com/owasp-amass/amass)
- [crt.sh](https://crt.sh/)
- [BGP.he.net](https://bgp.he.net/)
