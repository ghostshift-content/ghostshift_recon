#!/usr/bin/env bash
# ============================================================================
# RECON.SH - Comprehensive Reconnaissance Tool
# ============================================================================
# Multi-phase reconnaissance framework using Project Discovery's suite
# and other reliable OSINT tools.
#
# Phases:
#   1. Subdomain Enumeration (subfinder, assetfinder, amass, crt.sh, chaos)
#   2. DNS Resolution & Live Host Detection (dnsx, httpx)
#   3. ASN Discovery & IP Enumeration (asnmap, mapcidr, BGP.he.net, whois)
#   4. SSL/TLS Certificate Validation with Org Verification (tlsx, naabu)
#   5. Vulnerability Scanning (nuclei - rate-limited)
#
# Usage: ./recon.sh -f targets.txt [-o output_dir] [-r rate_limit] [--phase N]
# ============================================================================

set -euo pipefail

# ============================================================================
# CONFIGURATION & DEFAULTS
# ============================================================================
VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# Default settings
DEFAULT_OUTPUT_DIR="./recon_results_${TIMESTAMP}"
DEFAULT_RATE_LIMIT=150          # nuclei requests per second
DEFAULT_THREADS=50              # default thread count for tools
DEFAULT_HTTPX_THREADS=50        # httpx concurrent threads
DEFAULT_NAABU_RATE=1000         # naabu packets per second
DEFAULT_DNSX_THREADS=100        # dnsx concurrent threads
DEFAULT_SUBFINDER_TIMEOUT=30    # subfinder timeout in minutes
DEFAULT_AMASS_TIMEOUT=30        # amass timeout in minutes
DEFAULT_NUCLEI_BULK_SIZE=25     # nuclei bulk size
DEFAULT_NUCLEI_CONCURRENCY=10   # nuclei template concurrency
DEFAULT_ENUM_JOBS=4             # parallel root-domain enumeration workers
DEFAULT_URL_CRAWL_DEPTH=2       # katana/hakrawler depth
DEFAULT_JS_MAX_FILES=300        # maximum JS files to fetch for secret checks
DEFAULT_CACHE_TEST_URLS=150     # maximum parameterized JS URLs for cache tests
DEFAULT_PORTS="80,443,8080,8443,8000,8888,9090,3000,5000,5443"
NAABU_TOP_PORTS=""              # if set, use top-ports instead of port list

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Symbols
CHECK="${GREEN}[✓]${NC}"
CROSS="${RED}[✗]${NC}"
INFO="${BLUE}[i]${NC}"
WARN="${YELLOW}[!]${NC}"
ARROW="${CYAN}[→]${NC}"
STAR="${MAGENTA}[★]${NC}"

# ============================================================================
# LOGGING SYSTEM
# ============================================================================
LOG_FILE=""

log_init() {
    LOG_FILE="${OUTPUT_DIR}/recon.log"
    echo "# Recon Log - Started $(date)" > "$LOG_FILE"
    echo "# Target file: ${TARGET_FILE}" >> "$LOG_FILE"
    echo "# Output dir: ${OUTPUT_DIR}" >> "$LOG_FILE"
    echo "---" >> "$LOG_FILE"
}

log() {
    local level="$1"
    shift
    local msg="$*"
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[${ts}] [${level}] ${msg}" >> "$LOG_FILE" 2>/dev/null || true
}

banner() {
    echo -e "${CYAN}"
    cat << 'BANNER'
    ____                                _____ __
   / __ \___  _________  ____          / ___// /_
  / /_/ / _ \/ ___/ __ \/ __ \         \__ \/ __ \
 / _, _/  __/ /__/ /_/ / / / /  _     ___/ / / / /
/_/ |_|\___/\___/\____/_/ /_/  (_)   /____/_/ /_/

    Comprehensive Reconnaissance Framework v${VERSION}
    Project Discovery Suite + Multi-Source OSINT
BANNER
    echo -e "${NC}"
}

phase_banner() {
    local phase_num="$1"
    local phase_name="$2"
    echo ""
    echo -e "${BOLD}${MAGENTA}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${MAGENTA}║  PHASE ${phase_num}: ${phase_name}$(printf '%*s' $((46 - ${#phase_name})) '')║${NC}"
    echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    log "INFO" "=== PHASE ${phase_num}: ${phase_name} ==="
}

print_status() {
    echo -e "${INFO} $*"
    log "INFO" "$*"
}

print_success() {
    echo -e "${CHECK} $*"
    log "SUCCESS" "$*"
}

print_error() {
    echo -e "${CROSS} $*"
    log "ERROR" "$*"
}

print_warning() {
    echo -e "${WARN} $*"
    log "WARN" "$*"
}

print_progress() {
    echo -e "${ARROW} $*"
    log "PROGRESS" "$*"
}

print_finding() {
    echo -e "${STAR} $*"
    log "FINDING" "$*"
}

count_lines() {
    local file="$1"
    if [[ -f "$file" ]]; then
        wc -l < "$file" | tr -d ' '
    else
        echo "0"
    fi
}

delete_empty_lines() {
    local file="$1"
    [[ ! -f "$file" ]] && return 0
    awk 'NF {print}' "$file" > "${file}.tmp.$$" 2>/dev/null || true
    mv "${file}.tmp.$$" "$file" 2>/dev/null || true
}

extract_ipv4s() {
    local input_file="$1"
    [[ ! -e "$input_file" ]] && return 0
    awk '
    {
        for (i = 1; i <= NF; i++) {
            token = $i
            gsub(/[^0-9.]/, "", token)
            if (token ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                print token
            }
        }
    }' "$input_file"
}

extract_cidrs() {
    local input_file="$1"
    [[ ! -e "$input_file" ]] && return 0
    awk '
    {
        for (i = 1; i <= NF; i++) {
            token = $i
            gsub(/[^0-9.\/]/, "", token)
            if (token ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$/) {
                print token
            }
        }
    }' "$input_file"
}

normalize_asn() {
    local input="$1"
    input=$(echo "$input" | tr -d '[:space:]')
    if [[ "$input" =~ ^AS[0-9]+$ ]]; then
        echo "$input"
    elif [[ "$input" =~ ^[0-9]+$ ]]; then
        echo "AS${input}"
    else
        echo ""
    fi
}

string_matches_keywords() {
    local value="$1"
    local keywords_file="$2"
    local val_lower
    val_lower=$(echo "$value" | tr '[:upper:]' '[:lower:]')

    if [[ -z "$val_lower" ]] || [[ ! -f "$keywords_file" ]]; then
        return 1
    fi

    while IFS= read -r kw || [[ -n "$kw" ]]; do
        kw=$(echo "$kw" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
        [[ -z "$kw" ]] && continue
        [[ ${#kw} -lt 3 ]] && continue
        if echo "$val_lower" | grep -Fqi "$kw" 2>/dev/null; then
            return 0
        fi
    done < "$keywords_file"
    return 1
}

ip_sort_unique() {
    local input_file="$1"
    local output_file="$2"
    if [[ -f "$input_file" ]]; then
        local tmp_file
        tmp_file="${output_file}.tmp.$$"
        sort -t. -k1,1n -k2,2n -k3,3n -k4,4n -u "$input_file" > "$tmp_file" 2>/dev/null || touch "$tmp_file"
        mv "$tmp_file" "$output_file" 2>/dev/null || true
    else
        touch "$output_file"
    fi
}

# ============================================================================
# TOOL VERIFICATION
# ============================================================================

REQUIRED_TOOLS=(
    "subfinder"
    "dnsx"
    "httpx"
    "tlsx"
    "naabu"
    "nuclei"
    "mapcidr"
    "asnmap"
    "jq"
    "curl"
    "whois"
)

OPTIONAL_TOOLS=(
    "assetfinder"
    "amass"
    "chaos"
    "anew"
    "gau"
    "waybackurls"
    "katana"
    "hakrawler"
    "subjs"
)

check_tools() {
    phase_banner "0" "TOOL VERIFICATION"

    local missing_required=()
    local missing_optional=()

    echo -e "${BOLD}Required Tools:${NC}"
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            local ver
            ver=$("$tool" -version 2>/dev/null | head -1 || echo "installed")
            echo -e "  ${CHECK} ${tool} ${CYAN}(${ver})${NC}"
        else
            echo -e "  ${CROSS} ${tool} ${RED}(NOT FOUND)${NC}"
            missing_required+=("$tool")
        fi
    done

    echo ""
    echo -e "${BOLD}Optional Tools:${NC}"
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            local ver
            ver=$("$tool" -version 2>/dev/null | head -1 || echo "installed")
            echo -e "  ${CHECK} ${tool} ${CYAN}(${ver})${NC}"
        else
            echo -e "  ${WARN} ${tool} ${YELLOW}(not found - will skip)${NC}"
            missing_optional+=("$tool")
        fi
    done

    echo ""

    if [[ ${#missing_required[@]} -gt 0 ]]; then
        print_error "Missing required tools: ${missing_required[*]}"
        echo ""
        echo -e "${BOLD}Install missing tools:${NC}"
        echo "  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        echo "  go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        echo "  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        echo "  go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
        echo "  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        echo "  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        echo "  go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
        echo "  go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
        echo "  go install -v github.com/tomnomnom/assetfinder@latest"
        echo "  sudo apt install -y jq curl whois"
        return 1
    fi

    print_success "All required tools verified"
    if ! httpx -h 2>&1 | grep -q -- "-status-code"; then
        print_error "Detected non-ProjectDiscovery httpx binary. Install PD httpx:"
        echo "  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        return 1
    fi
    print_status "Verified ProjectDiscovery httpx capabilities (-status-code supported)"

    if [[ ${#missing_optional[@]} -gt 0 ]]; then
        print_warning "Optional tools missing: ${missing_optional[*]} - coverage may be reduced"
    fi

    return 0
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

deduplicate() {
    local input_file="$1"
    local output_file="$2"
    if [[ -f "$input_file" ]]; then
        sort -u "$input_file" | grep -v '^$' > "$output_file" 2>/dev/null || true
        local count
        count=$(count_lines "$output_file")
        print_status "Deduplicated: $(count_lines "$input_file") → ${count} unique entries"
    else
        touch "$output_file"
        print_warning "Input file not found: $input_file"
    fi
}

merge_files() {
    local output="$1"
    shift
    local inputs=("$@")

    : > "$output"
    for f in "${inputs[@]}"; do
        if [[ -f "$f" ]]; then
            cat "$f" >> "$output"
        fi
    done
    sort -u -o "$output" "$output"
    # Remove empty lines
    delete_empty_lines "$output"
}

extract_domain_from_url() {
    echo "$1" | sed -e 's|https\?://||' -e 's|/.*||' -e 's|:.*||'
}

extract_root_domain() {
    # Extract root domain (e.g., example.com from sub.example.com)
    local domain="$1"
    echo "$domain" | awk -F. '{
        n = NF
        if (n >= 2) {
            printf "%s.%s\n", $(n-1), $n
        } else {
            print $0
        }
    }'
}

is_domain_in_scope() {
    local candidate="$1"
    candidate=$(echo "$candidate" | tr '[:upper:]' '[:lower:]')
    while IFS= read -r target_domain || [[ -n "$target_domain" ]]; do
        target_domain=$(echo "$target_domain" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
        [[ -z "$target_domain" || "$target_domain" == \#* ]] && continue
        if [[ "$candidate" == "$target_domain" ]] || [[ "$candidate" == *".${target_domain}" ]]; then
            return 0
        fi
    done < "$TARGET_FILE"
    return 1
}

scope_filter_urls_file() {
    local input_file="$1"
    local output_file="$2"
    : > "$output_file"
    [[ ! -f "$input_file" ]] && return 0
    while IFS= read -r url || [[ -n "$url" ]]; do
        [[ -z "$url" ]] && continue
        local host
        host=$(extract_domain_from_url "$url")
        [[ -z "$host" ]] && continue
        if is_domain_in_scope "$host"; then
            echo "$url" >> "$output_file"
        fi
    done < "$input_file"
    sort -u -o "$output_file" "$output_file" 2>/dev/null || true
    delete_empty_lines "$output_file"
}

is_useful_host() {
    local host="$1"
    [[ -z "$host" ]] && return 1

    if [[ -f "${OUTPUT_DIR}/resolved_hosts.txt" ]] && grep -qix "$host" "${OUTPUT_DIR}/resolved_hosts.txt" 2>/dev/null; then
        return 0
    fi
    if [[ -f "${OUTPUT_DIR}/subdomains.txt" ]] && grep -qix "$host" "${OUTPUT_DIR}/subdomains.txt" 2>/dev/null; then
        return 0
    fi
    if is_domain_in_scope "$host"; then
        return 0
    fi
    return 1
}

mask_secret_value() {
    local secret="$1"
    local len=${#secret}
    if [[ "$len" -le 10 ]]; then
        echo "$secret"
        return
    fi
    local start end
    start="${secret:0:4}"
    end="${secret: -4}"
    echo "${start}****${end}"
}

url_with_extra_param() {
    local url="$1"
    local param_name="$2"
    local param_value="$3"
    if [[ "$url" == *\?* ]]; then
        echo "${url}&${param_name}=${param_value}"
    else
        echo "${url}?${param_name}=${param_value}"
    fi
}

header_get_ci() {
    local header_file="$1"
    local header_name="$2"
    awk -v key="$(echo "$header_name" | tr '[:upper:]' '[:lower:]')" '
    BEGIN { FS=":" }
    {
      line_key=tolower($1)
      if (line_key==key) {
        sub(/^[^:]*:[[:space:]]*/, "", $0)
        print $0
        exit
      }
    }' "$header_file" 2>/dev/null
}

file_sha256() {
    local file="$1"
    if command -v sha256sum &>/dev/null; then
        sha256sum "$file" 2>/dev/null | awk '{print $1}'
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "$file" 2>/dev/null | awk '{print $1}'
    else
        wc -c < "$file" 2>/dev/null | tr -d ' '
    fi
}

is_ip() {
    local input="$1"
    if [[ "$input" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 0
    fi
    return 1
}

safe_timeout() {
    local timeout_val="$1"
    shift
    if command -v timeout &>/dev/null; then
        timeout "$timeout_val" "$@" 2>/dev/null || true
    else
        "$@" 2>/dev/null || true
    fi
}

# ============================================================================
# PHASE 1: SUBDOMAIN ENUMERATION
# ============================================================================

run_subfinder() {
    local domain="$1"
    local outfile="${SUBS_DIR}/subfinder_${domain}.txt"

    print_progress "Running subfinder on ${domain}..."
    subfinder -d "$domain" \
        -all \
        -silent \
        -t "$DEFAULT_THREADS" \
        -timeout "$DEFAULT_SUBFINDER_TIMEOUT" \
        -o "$outfile" 2>>"$LOG_FILE" || true

    local count
    count=$(count_lines "$outfile")
    print_status "subfinder found ${count} subdomains for ${domain}"
}

run_assetfinder() {
    local domain="$1"
    local outfile="${SUBS_DIR}/assetfinder_${domain}.txt"

    if ! command -v assetfinder &>/dev/null; then
        print_warning "assetfinder not installed, skipping..."
        return
    fi

    print_progress "Running assetfinder on ${domain}..."
    assetfinder --subs-only "$domain" > "$outfile" 2>>"$LOG_FILE" || true

    local count
    count=$(count_lines "$outfile")
    print_status "assetfinder found ${count} subdomains for ${domain}"
}

run_amass_passive() {
    local domain="$1"
    local outfile="${SUBS_DIR}/amass_${domain}.txt"

    if ! command -v amass &>/dev/null; then
        print_warning "amass not installed, skipping..."
        return
    fi

    print_progress "Running amass (passive) on ${domain}..."
    safe_timeout "${DEFAULT_AMASS_TIMEOUT}m" \
        amass enum -passive -d "$domain" -o "$outfile" 2>>"$LOG_FILE"

    local count
    count=$(count_lines "$outfile")
    print_status "amass found ${count} subdomains for ${domain}"
}

run_crtsh() {
    local domain="$1"
    local outfile="${SUBS_DIR}/crtsh_${domain}.txt"

    print_progress "Querying crt.sh for ${domain}..."

    local response
    response=$(curl -s "https://crt.sh/?q=%25.${domain}&output=json" \
        --connect-timeout 30 \
        --max-time 120 \
        -H "User-Agent: Mozilla/5.0 (compatible; ReconSh/1.0)" \
        2>>"$LOG_FILE" || echo "[]")

    if [[ -n "$response" && "$response" != "[]" && "$response" != "null" ]]; then
        echo "$response" | jq -r '.[].name_value' 2>/dev/null \
            | sed 's/\*\.//g' \
            | sort -u \
            | grep -i "\.${domain}$" \
            > "$outfile" 2>/dev/null || true
    else
        touch "$outfile"
    fi

    local count
    count=$(count_lines "$outfile")
    print_status "crt.sh found ${count} subdomains for ${domain}"
}

run_chaos() {
    local domain="$1"
    local outfile="${SUBS_DIR}/chaos_${domain}.txt"

    if ! command -v chaos &>/dev/null; then
        print_warning "chaos not installed, skipping..."
        return
    fi

    if [[ -z "${PDCP_API_KEY:-}" && -z "${CHAOS_KEY:-}" ]]; then
        print_warning "No PDCP_API_KEY or CHAOS_KEY set, skipping chaos..."
        return
    fi

    print_progress "Running chaos on ${domain}..."
    chaos -d "$domain" -silent -o "$outfile" 2>>"$LOG_FILE" || true

    local count
    count=$(count_lines "$outfile")
    print_status "chaos found ${count} subdomains for ${domain}"
}

phase1_subdomain_enumeration() {
    phase_banner "1" "SUBDOMAIN ENUMERATION"

    mkdir -p "$SUBS_DIR"

    local total_domains
    total_domains=$(count_lines "$TARGET_FILE")
    print_status "Enumerating subdomains for ${total_domains} root domain(s)..."

    while IFS= read -r domain || [[ -n "$domain" ]]; do
        domain=$(echo "$domain" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
        [[ -z "$domain" || "$domain" == \#* ]] && continue

        while [[ $(jobs -pr | wc -l | tr -d ' ') -ge "$ENUM_JOBS" ]]; do
            sleep 1
        done

        echo ""
        echo -e "${BOLD}${WHITE}── Target: ${domain} ──${NC}"

        (
            # Run all enumeration sources
            run_subfinder "$domain"
            run_assetfinder "$domain"
            run_amass_passive "$domain"
            run_crtsh "$domain"
            run_chaos "$domain"
        ) &

    done < "$TARGET_FILE"
    wait || true

    # Merge and deduplicate all results
    echo ""
    print_progress "Merging and deduplicating all subdomain results..."

    local all_sub_files=()
    while IFS= read -r -d '' f; do
        all_sub_files+=("$f")
    done < <(find "$SUBS_DIR" -name "*.txt" -print0 2>/dev/null)

    if [[ ${#all_sub_files[@]} -gt 0 ]]; then
        merge_files "${SUBS_DIR}/all_subdomains_raw.txt" "${all_sub_files[@]}"
    else
        touch "${SUBS_DIR}/all_subdomains_raw.txt"
    fi

    # Filter: only keep subdomains that belong to our target domains
    : > "${OUTPUT_DIR}/subdomains.txt"
    while IFS= read -r domain || [[ -n "$domain" ]]; do
        domain=$(echo "$domain" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
        [[ -z "$domain" || "$domain" == \#* ]] && continue
        grep -i "\.${domain}$\|^${domain}$" "${SUBS_DIR}/all_subdomains_raw.txt" \
            >> "${OUTPUT_DIR}/subdomains.txt" 2>/dev/null || true
    done < "$TARGET_FILE"

    sort -u -o "${OUTPUT_DIR}/subdomains.txt" "${OUTPUT_DIR}/subdomains.txt"
    delete_empty_lines "${OUTPUT_DIR}/subdomains.txt"

    local final_count
    final_count=$(count_lines "${OUTPUT_DIR}/subdomains.txt")

    echo ""
    print_success "Phase 1 Complete: ${final_count} unique subdomains discovered"
    print_finding "Results saved to: ${OUTPUT_DIR}/subdomains.txt"
}

# ============================================================================
# PHASE 2: DNS RESOLUTION
# ============================================================================

phase2_dns_and_livehost() {
    phase_banner "2" "DNS RESOLUTION"

    mkdir -p "$DNS_DIR"

    local sub_count
    sub_count=$(count_lines "${OUTPUT_DIR}/subdomains.txt")

    if [[ "$sub_count" -eq 0 ]]; then
        print_warning "No subdomains found in Phase 1. Skipping DNS resolution."
        touch "${OUTPUT_DIR}/resolved_hosts.txt"
        touch "${OUTPUT_DIR}/live_hosts.txt"
        touch "${OUTPUT_DIR}/live_hosts_full.txt"
        return
    fi

    # --- DNS Resolution with dnsx ---
    print_progress "Resolving DNS for ${sub_count} subdomains with dnsx..."

    dnsx -l "${OUTPUT_DIR}/subdomains.txt" \
        -a -aaaa -cname -resp \
        -t "$DEFAULT_DNSX_THREADS" \
        -silent \
        -o "${DNS_DIR}/dnsx_resolved.txt" \
        2>>"$LOG_FILE" || true

    # Extract and sort into separate categorized files
    if [[ -f "${DNS_DIR}/dnsx_resolved.txt" ]]; then

        # --- Unique subdomains (first column, deduplicated) ---
        awk '{print $1}' "${DNS_DIR}/dnsx_resolved.txt" \
            | sort -u > "${OUTPUT_DIR}/resolved_hosts.txt"

        # --- A records: subdomain → IP mapping (sorted by subdomain) ---
        grep '\[A\]' "${DNS_DIR}/dnsx_resolved.txt" 2>/dev/null \
            | sort -t' ' -k1,1 -u > "${DNS_DIR}/dns_a_records.txt" || touch "${DNS_DIR}/dns_a_records.txt"

        # --- AAAA records: subdomain → IPv6 mapping ---
        grep '\[AAAA\]' "${DNS_DIR}/dnsx_resolved.txt" 2>/dev/null \
            | sort -t' ' -k1,1 -u > "${DNS_DIR}/dns_aaaa_records.txt" || touch "${DNS_DIR}/dns_aaaa_records.txt"

        # --- CNAME records: subdomain → canonical name mapping ---
        grep '\[CNAME\]' "${DNS_DIR}/dnsx_resolved.txt" 2>/dev/null \
            | sort -t' ' -k1,1 -u > "${DNS_DIR}/dns_cname_records.txt" || touch "${DNS_DIR}/dns_cname_records.txt"

        # --- Subdomain-to-IP lookup table (clean TSV: subdomain<tab>ip) ---
        grep '\[A\]' "${DNS_DIR}/dnsx_resolved.txt" 2>/dev/null \
            | awk '{
                host = $1
                for (i=2; i<=NF; i++) {
                    if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                        printf "%s\t%s\n", host, $i
                    } else {
                        # strip brackets from [ip]
                        gsub(/[\[\]]/, "", $i)
                        if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                            printf "%s\t%s\n", host, $i
                        }
                    }
                }
            }' | sort -t$'\t' -k1,1 -u > "${DNS_DIR}/subdomain_ip_map.txt" || touch "${DNS_DIR}/subdomain_ip_map.txt"

        # --- IP-to-subdomain reverse lookup (sorted by IP) ---
        awk -F'\t' '{print $2 "\t" $1}' "${DNS_DIR}/subdomain_ip_map.txt" 2>/dev/null \
            | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n -u \
            > "${DNS_DIR}/ip_subdomain_map.txt" || touch "${DNS_DIR}/ip_subdomain_map.txt"

    else
        touch "${OUTPUT_DIR}/resolved_hosts.txt"
        touch "${DNS_DIR}/dns_a_records.txt"
        touch "${DNS_DIR}/dns_aaaa_records.txt"
        touch "${DNS_DIR}/dns_cname_records.txt"
        touch "${DNS_DIR}/subdomain_ip_map.txt"
        touch "${DNS_DIR}/ip_subdomain_map.txt"
    fi

    local resolved_count
    resolved_count=$(count_lines "${OUTPUT_DIR}/resolved_hosts.txt")
    local a_count cname_count
    a_count=$(count_lines "${DNS_DIR}/dns_a_records.txt")
    cname_count=$(count_lines "${DNS_DIR}/dns_cname_records.txt")
    print_status "DNS resolved: ${resolved_count} unique hosts"
    print_status "  A records:     ${a_count}"
    print_status "  CNAME records: ${cname_count}"

    # --- Extract unique IPs from DNS results ---
    print_progress "Extracting IP addresses from DNS results..."

    extract_ipv4s "${DNS_DIR}/dnsx_resolved.txt" \
        | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n -u \
        > "${DNS_DIR}/resolved_ips.txt" || touch "${DNS_DIR}/resolved_ips.txt"

    local ip_count
    ip_count=$(count_lines "${DNS_DIR}/resolved_ips.txt")
    print_status "Extracted ${ip_count} unique IP addresses (numerically sorted)"

    # httpx now runs later in dedicated Phase 4C after all target gathering
    touch "${OUTPUT_DIR}/live_hosts.txt"
    touch "${OUTPUT_DIR}/live_hosts_full.txt"

    echo ""
    print_success "Phase 2 Complete: ${resolved_count} resolved hosts, ${ip_count} unique IPs"
    print_status "HTTP probing deferred to Phase 4C (final consolidated httpx run)"
}

# ============================================================================
# PHASE 3: ASN DISCOVERY & IP ENUMERATION
# ============================================================================

query_bgp_he_net() {
    local asn="$1"
    local outfile="$2"

    # Query BGP.he.net for CIDR prefixes advertised by the ASN
    local response
    response=$(curl -s "https://bgp.he.net/${asn}#_prefixes" \
        --connect-timeout 15 \
        --max-time 30 \
        -H "User-Agent: Mozilla/5.0 (compatible; ReconSh/1.0)" \
        2>>"$LOG_FILE" || echo "")

    if [[ -n "$response" ]]; then
        echo "$response" \
            | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' \
            | sort -u >> "$outfile" 2>/dev/null || true
    fi
}

phase3_asn_discovery() {
    phase_banner "3" "ASN DISCOVERY & IP ENUMERATION"

    mkdir -p "$ASN_DIR"

    print_progress "Discovering ASN information for target domains..."

    local ip_file="${DNS_DIR}/resolved_ips.txt"
    if [[ ! -f "$ip_file" ]] || [[ $(count_lines "$ip_file") -eq 0 ]]; then
        print_warning "No resolved IPs available. Attempting IP extraction from subdomains..."

        # Quick DNS lookup just for IPs
        if [[ -f "${OUTPUT_DIR}/subdomains.txt" ]] && [[ $(count_lines "${OUTPUT_DIR}/subdomains.txt") -gt 0 ]]; then
            dnsx -l "${OUTPUT_DIR}/subdomains.txt" \
                -a -resp-only \
                -silent \
                -t "$DEFAULT_DNSX_THREADS" \
                2>>"$LOG_FILE" \
                | sort -u > "$ip_file" || touch "$ip_file"
        else
            touch "$ip_file"
        fi
    fi

    local ip_count
    ip_count=$(count_lines "$ip_file")

    if [[ "$ip_count" -eq 0 ]]; then
        print_warning "No IPs to perform ASN discovery. Skipping Phase 3."
        touch "${OUTPUT_DIR}/asn_cidrs.txt"
        touch "${OUTPUT_DIR}/asn_ips.txt"
        touch "${ASN_DIR}/asn_info.txt"
        return
    fi

    print_status "Processing ${ip_count} IPs for ASN mapping..."

    # --- ASN Mapping with asnmap ---
    print_progress "Running asnmap to discover ASN ownership..."

    asnmap -i "$ip_file" \
        -silent \
        2>>"$LOG_FILE" \
        | sort -u > "${ASN_DIR}/asnmap_results_raw.txt" || touch "${ASN_DIR}/asnmap_results_raw.txt"

    asnmap -i "$ip_file" \
        -json \
        -silent \
        2>>"$LOG_FILE" \
        > "${ASN_DIR}/asnmap_json_raw.jsonl" || touch "${ASN_DIR}/asnmap_json_raw.jsonl"

    # Also map root domains directly
    if [[ -f "$TARGET_FILE" ]]; then
        while IFS= read -r domain || [[ -n "$domain" ]]; do
            domain=$(echo "$domain" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
            [[ -z "$domain" || "$domain" == \#* ]] && continue
            asnmap -d "$domain" -silent 2>>"$LOG_FILE" >> "${ASN_DIR}/asnmap_results_raw.txt" || true
            asnmap -d "$domain" -json -silent 2>>"$LOG_FILE" >> "${ASN_DIR}/asnmap_json_raw.jsonl" || true
        done < "$TARGET_FILE"
    fi
    sort -u -o "${ASN_DIR}/asnmap_results_raw.txt" "${ASN_DIR}/asnmap_results_raw.txt"
    sort -u -o "${ASN_DIR}/asnmap_json_raw.jsonl" "${ASN_DIR}/asnmap_json_raw.jsonl"

    local asn_count
    asn_count=$(count_lines "${ASN_DIR}/asnmap_results_raw.txt")
    print_status "asnmap discovered ${asn_count} raw ownership records"

    # --- Extract organization names and keywords ---
    local org_names=()
    while IFS= read -r domain || [[ -n "$domain" ]]; do
        domain=$(echo "$domain" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
        [[ -z "$domain" || "$domain" == \#* ]] && continue

        # Try whois to get org name
        local org
        org=$(whois "$domain" 2>/dev/null \
            | grep -i "^org\|^registrant.*org\|^OrgName\|^Organization\|^owner\|^descr" \
            | head -1 \
            | sed 's/^[^:]*:\s*//' \
            | sed 's/[[:space:]]\+/ /g' \
            | sed 's/^ //; s/ $//' || echo "")

        if [[ -n "$org" ]]; then
            org_names+=("$org")
        fi

        # Use the domain's base name as fallback org identifier
        local base
        base=$(echo "$domain" | awk -F. '{print $(NF-1)}')
        org_names+=("$base")
    done < "$TARGET_FILE"

    # Save org names for later SSL validation
    printf '%s\n' "${org_names[@]}" | sort -u > "${ASN_DIR}/org_names.txt" 2>/dev/null || true

    # Create keyword set from org names and target roots
    : > "${ASN_DIR}/org_keywords.txt"
    while IFS= read -r value || [[ -n "$value" ]]; do
        [[ -z "$value" ]] && continue
        echo "$value" \
            | tr '[:upper:]' '[:lower:]' \
            | sed 's/[^a-z0-9]/ /g' \
            | tr ' ' '\n' \
            | awk 'length($0)>=3 {print}' >> "${ASN_DIR}/org_keywords.txt"
    done < "${ASN_DIR}/org_names.txt"
    sort -u -o "${ASN_DIR}/org_keywords.txt" "${ASN_DIR}/org_keywords.txt"

    # --- Extract trusted ASNs from asnmap json ---
    print_progress "Filtering ASN data by organization ownership keywords..."

    : > "${ASN_DIR}/unique_asns.txt"
    : > "${ASN_DIR}/trusted_asns.txt"
    : > "${ASN_DIR}/asn_info.txt"

    while IFS= read -r jline || [[ -n "$jline" ]]; do
        [[ -z "$jline" ]] && continue
        local asn_num asn_name first_ip last_ip country asn_norm
        asn_num=$(echo "$jline" | jq -r '.as_number // empty' 2>/dev/null || echo "")
        asn_name=$(echo "$jline" | jq -r '.as_name // .as_org // empty' 2>/dev/null || echo "")
        first_ip=$(echo "$jline" | jq -r '.first_ip // empty' 2>/dev/null || echo "")
        last_ip=$(echo "$jline" | jq -r '.last_ip // empty' 2>/dev/null || echo "")
        country=$(echo "$jline" | jq -r '.as_country // empty' 2>/dev/null || echo "")

        asn_norm=$(normalize_asn "$asn_num")
        [[ -z "$asn_norm" ]] && continue

        echo "$asn_norm" >> "${ASN_DIR}/unique_asns.txt"
        printf "%s\t%s\t%s\t%s-%s\n" "$asn_norm" "$asn_name" "$country" "$first_ip" "$last_ip" >> "${ASN_DIR}/asn_info.txt"

        if string_matches_keywords "$asn_name" "${ASN_DIR}/org_keywords.txt"; then
            echo "$asn_norm" >> "${ASN_DIR}/trusted_asns.txt"
        fi
    done < "${ASN_DIR}/asnmap_json_raw.jsonl"

    sort -u -o "${ASN_DIR}/unique_asns.txt" "${ASN_DIR}/unique_asns.txt"
    sort -u -o "${ASN_DIR}/trusted_asns.txt" "${ASN_DIR}/trusted_asns.txt"
    sort -u -o "${ASN_DIR}/asn_info.txt" "${ASN_DIR}/asn_info.txt"

    local trusted_asn_count
    trusted_asn_count=$(count_lines "${ASN_DIR}/trusted_asns.txt")
    if [[ "$trusted_asn_count" -eq 0 ]]; then
        print_warning "No ASN names matched org keywords. Falling back to all discovered ASNs."
        cp "${ASN_DIR}/unique_asns.txt" "${ASN_DIR}/trusted_asns.txt" 2>/dev/null || touch "${ASN_DIR}/trusted_asns.txt"
        trusted_asn_count=$(count_lines "${ASN_DIR}/trusted_asns.txt")
    fi
    print_status "Trusted ASN candidates: ${trusted_asn_count}"

    # Parse CIDRs from asnmap raw output and keep only trusted ASN lines where ASN exists
    : > "${ASN_DIR}/asnmap_cidrs.txt"
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" ]] && continue
        local line_asn include_line
        line_asn=$(echo "$line" | grep -Eo 'AS[0-9]+' | head -1 || true)
        include_line=true
        if [[ -n "$line_asn" ]] && [[ -f "${ASN_DIR}/trusted_asns.txt" ]]; then
            if ! grep -qx "$line_asn" "${ASN_DIR}/trusted_asns.txt" 2>/dev/null; then
                include_line=false
            fi
        fi
        if [[ "$include_line" == true ]]; then
            echo "$line" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' >> "${ASN_DIR}/asnmap_cidrs.txt" 2>/dev/null || true
        fi
    done < "${ASN_DIR}/asnmap_results_raw.txt"
    sort -u -o "${ASN_DIR}/asnmap_cidrs.txt" "${ASN_DIR}/asnmap_cidrs.txt"

    # --- BGP.he.net enrichment ---
    print_progress "Enriching ASN data from BGP.he.net..."

    : > "${ASN_DIR}/bgp_cidrs.txt"
    while IFS= read -r asn || [[ -n "$asn" ]]; do
        [[ -z "$asn" ]] && continue
        asn=$(normalize_asn "$asn")
        [[ -z "$asn" ]] && continue

        print_status "  Querying BGP.he.net for ${asn}..."
        query_bgp_he_net "$asn" "${ASN_DIR}/bgp_cidrs.txt"
        sleep 1  # Rate limiting for BGP.he.net
    done < "${ASN_DIR}/trusted_asns.txt"
    sort -u -o "${ASN_DIR}/bgp_cidrs.txt" "${ASN_DIR}/bgp_cidrs.txt"

    local bgp_count
    bgp_count=$(count_lines "${ASN_DIR}/bgp_cidrs.txt")
    print_status "BGP.he.net returned ${bgp_count} CIDR ranges"

    # --- Merge all CIDR ranges ---
    print_progress "Merging all discovered CIDR ranges..."

    merge_files "${OUTPUT_DIR}/asn_cidrs.txt" \
        "${ASN_DIR}/asnmap_cidrs.txt" \
        "${ASN_DIR}/bgp_cidrs.txt"
    delete_empty_lines "${OUTPUT_DIR}/asn_cidrs.txt"

    local total_cidrs
    total_cidrs=$(count_lines "${OUTPUT_DIR}/asn_cidrs.txt")
    print_status "Total unique CIDR ranges: ${total_cidrs}"

    # --- Expand CIDRs to IPs (for smaller ranges) ---
    print_progress "Expanding CIDR ranges with mapcidr..."

    if [[ "$total_cidrs" -gt 0 ]]; then
        # Only expand /24 and smaller to avoid massive IP lists
        grep -E '/2[4-9]|/3[0-2]' "${OUTPUT_DIR}/asn_cidrs.txt" \
            > "${ASN_DIR}/small_cidrs.txt" 2>/dev/null || touch "${ASN_DIR}/small_cidrs.txt"

        local small_cidr_count
        small_cidr_count=$(count_lines "${ASN_DIR}/small_cidrs.txt")

        if [[ "$small_cidr_count" -gt 0 ]]; then
            mapcidr -l "${ASN_DIR}/small_cidrs.txt" \
                -silent \
                2>>"$LOG_FILE" \
                | sort -u > "${ASN_DIR}/expanded_ips.txt" || touch "${ASN_DIR}/expanded_ips.txt"
        else
            touch "${ASN_DIR}/expanded_ips.txt"
        fi

        # Merge with directly resolved IPs
        merge_files "${OUTPUT_DIR}/asn_ips.txt" \
            "$ip_file" \
            "${ASN_DIR}/expanded_ips.txt"
        ip_sort_unique "${OUTPUT_DIR}/asn_ips.txt" "${OUTPUT_DIR}/asn_ips.txt"
    else
        cp "$ip_file" "${OUTPUT_DIR}/asn_ips.txt" 2>/dev/null || touch "${OUTPUT_DIR}/asn_ips.txt"
        ip_sort_unique "${OUTPUT_DIR}/asn_ips.txt" "${OUTPUT_DIR}/asn_ips.txt"
    fi

    local total_ips
    total_ips=$(count_lines "${OUTPUT_DIR}/asn_ips.txt")

    print_status "Total IPs from ASN expansion: ${total_ips}"

    # httpx now runs once in Phase 4C after all discovery is complete
    touch "${ASN_DIR}/httpx_asn_ips.txt"
    touch "${ASN_DIR}/asn_live_urls.txt"

    echo ""
    print_success "Phase 3 Complete: ${total_cidrs} CIDRs, ${total_ips} IPs enumerated"
    print_finding "CIDR ranges: ${OUTPUT_DIR}/asn_cidrs.txt"
    print_finding "IP addresses: ${OUTPUT_DIR}/asn_ips.txt"
    print_finding "Trusted ASNs: ${ASN_DIR}/trusted_asns.txt"
    print_status "HTTP probing deferred to Phase 4C (final consolidated httpx run)"
    print_finding "ASN info: ${ASN_DIR}/asn_info.txt"

    # Copy org names to output dir for Phase 4
    cp "${ASN_DIR}/org_names.txt" "${OUTPUT_DIR}/org_names.txt" 2>/dev/null || true
}

# ============================================================================
# PHASE 4: SSL/TLS CERTIFICATE VALIDATION WITH ORG VERIFICATION
# ============================================================================

validate_cert_org() {
    # Validates that a certificate's Subject or Issuer Organization matches
    # the target organization. Returns 0 if match found, 1 otherwise.
    local cert_json="$1"
    local org_file="$2"

    if [[ ! -f "$org_file" ]]; then
        return 1
    fi

    # Extract certificate organization fields
    local subject_org subject_cn issuer_org san_entries
    subject_org=$(echo "$cert_json" | jq -r '.subject_org // empty' 2>/dev/null || echo "")
    subject_cn=$(echo "$cert_json" | jq -r '.subject_cn // empty' 2>/dev/null || echo "")
    issuer_org=$(echo "$cert_json" | jq -r '.issuer_org // empty' 2>/dev/null || echo "")
    san_entries=$(echo "$cert_json" | jq -r '.subject_an[]? // empty' 2>/dev/null || echo "")

    # Check against each known organization name / domain
    while IFS= read -r org_name || [[ -n "$org_name" ]]; do
        [[ -z "$org_name" ]] && continue
        org_name_lower=$(echo "$org_name" | tr '[:upper:]' '[:lower:]')

        # Check subject org
        if [[ -n "$subject_org" ]] && echo "$subject_org" | tr '[:upper:]' '[:lower:]' | grep -qi "$org_name_lower" 2>/dev/null; then
            return 0
        fi

        # Check subject CN
        if [[ -n "$subject_cn" ]] && echo "$subject_cn" | tr '[:upper:]' '[:lower:]' | grep -qi "$org_name_lower" 2>/dev/null; then
            return 0
        fi

        # Check SANs against target root domains
        if [[ -n "$san_entries" ]]; then
            while IFS= read -r target_domain || [[ -n "$target_domain" ]]; do
                target_domain=$(echo "$target_domain" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
                [[ -z "$target_domain" || "$target_domain" == \#* ]] && continue

                if echo "$san_entries" | tr '[:upper:]' '[:lower:]' | grep -q "$target_domain" 2>/dev/null; then
                    return 0
                fi
            done < "$TARGET_FILE"
        fi

    done < "$org_file"

    return 1
}

phase4_ssl_validation() {
    phase_banner "4" "SSL/TLS CERTIFICATE VALIDATION"

    mkdir -p "$SSL_DIR"

    local org_file="${OUTPUT_DIR}/org_names.txt"
    [[ ! -f "$org_file" ]] && touch "$org_file"

    # Add root domains to org_names for SAN matching
    while IFS= read -r domain || [[ -n "$domain" ]]; do
        domain=$(echo "$domain" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
        [[ -z "$domain" || "$domain" == \#* ]] && continue
        echo "$domain" >> "$org_file"
    done < "$TARGET_FILE"
    sort -u -o "$org_file" "$org_file"

    print_status "Organization identifiers for validation:"
    while IFS= read -r org || [[ -n "$org" ]]; do
        echo -e "    ${CYAN}→${NC} ${org}"
    done < "$org_file"
    echo ""

    # ---- Port Scan with naabu ----
    local ip_file="${OUTPUT_DIR}/asn_ips.txt"
    if [[ ! -f "$ip_file" ]] || [[ $(count_lines "$ip_file") -eq 0 ]]; then
        ip_file="${DNS_DIR}/resolved_ips.txt"
    fi

    local ip_count
    ip_count=$(count_lines "$ip_file" 2>/dev/null || echo "0")

    if [[ "$ip_count" -gt 0 ]]; then
        print_progress "Running naabu port scan on ${ip_count} IPs..."

        local naabu_args="-list $ip_file -silent -rate $DEFAULT_NAABU_RATE"
        if [[ -n "$NAABU_TOP_PORTS" ]]; then
            naabu_args="$naabu_args -top-ports $NAABU_TOP_PORTS"
        else
            naabu_args="$naabu_args -p $DEFAULT_PORTS"
        fi

        eval naabu "$naabu_args" \
            -o "${SSL_DIR}/naabu_results.txt" \
            2>>"$LOG_FILE" || touch "${SSL_DIR}/naabu_results.txt"

        local port_count
        port_count=$(count_lines "${SSL_DIR}/naabu_results.txt")
        print_status "naabu found ${port_count} open port entries"
    else
        print_warning "No IPs available for port scanning"
        touch "${SSL_DIR}/naabu_results.txt"
    fi

    # ---- TLS Certificate Extraction with tlsx ----
    print_progress "Extracting TLS certificates with tlsx..."

    # Build target list: combine live hosts + naabu results
    : > "${SSL_DIR}/tlsx_targets.txt"

    # Add resolved hosts on SSL ports
    if [[ -f "${OUTPUT_DIR}/resolved_hosts.txt" ]]; then
        while IFS= read -r host || [[ -n "$host" ]]; do
            [[ -z "$host" ]] && continue
            echo "${host}:443" >> "${SSL_DIR}/tlsx_targets.txt"
        done < "${OUTPUT_DIR}/resolved_hosts.txt"
    fi

    # Add naabu results (already in host:port format)
    if [[ -f "${SSL_DIR}/naabu_results.txt" ]]; then
        cat "${SSL_DIR}/naabu_results.txt" >> "${SSL_DIR}/tlsx_targets.txt"
    fi

    sort -u -o "${SSL_DIR}/tlsx_targets.txt" "${SSL_DIR}/tlsx_targets.txt"
    delete_empty_lines "${SSL_DIR}/tlsx_targets.txt"

    local target_count
    target_count=$(count_lines "${SSL_DIR}/tlsx_targets.txt")

    if [[ "$target_count" -gt 0 ]]; then
        print_status "Probing ${target_count} targets for TLS certificates..."

        # JSON output for programmatic validation
        tlsx -l "${SSL_DIR}/tlsx_targets.txt" \
            -san -so -cn \
            -org \
            -json \
            -silent \
            -resp-only \
            -timeout 10 \
            2>>"$LOG_FILE" \
            > "${SSL_DIR}/tlsx_json_raw.jsonl" || touch "${SSL_DIR}/tlsx_json_raw.jsonl"

        # Also get human-readable output
        tlsx -l "${SSL_DIR}/tlsx_targets.txt" \
            -san -so -cn \
            -org \
            -silent \
            -resp-only \
            -timeout 10 \
            2>>"$LOG_FILE" \
            > "${SSL_DIR}/tlsx_readable.txt" || touch "${SSL_DIR}/tlsx_readable.txt"

        local cert_count
        cert_count=$(count_lines "${SSL_DIR}/tlsx_json_raw.jsonl")
        print_status "Retrieved ${cert_count} TLS certificate records"
    else
        print_warning "No targets available for TLS probing"
        touch "${SSL_DIR}/tlsx_json_raw.jsonl"
        touch "${SSL_DIR}/tlsx_readable.txt"
    fi

    # ---- Organization Validation ----
    print_progress "Validating certificate ownership against target organization..."

    : > "${SSL_DIR}/validated_hosts.txt"
    : > "${SSL_DIR}/unvalidated_hosts.txt"
    : > "${SSL_DIR}/validation_report.txt"
    : > "${OUTPUT_DIR}/ssl_validated_subdomains.txt"
    : > "${SSL_DIR}/ssl_validated_ips.txt"
    : > "${SSL_DIR}/ssl_validated_ip_hosts.txt"

    local validated=0
    local rejected=0
    local total_certs=0

    while IFS= read -r cert_line || [[ -n "$cert_line" ]]; do
        [[ -z "$cert_line" ]] && continue
        ((total_certs++)) || true

        local host
        host=$(echo "$cert_line" | jq -r '.host // empty' 2>/dev/null || echo "")
        local ip
        ip=$(echo "$cert_line" | jq -r '.ip // .host // empty' 2>/dev/null || echo "")
        local subject_cn
        subject_cn=$(echo "$cert_line" | jq -r '.subject_cn // empty' 2>/dev/null || echo "")
        local subject_org
        subject_org=$(echo "$cert_line" | jq -r '.subject_org // empty' 2>/dev/null || echo "")
        local san_list
        san_list=$(echo "$cert_line" | jq -r '.subject_an // [] | join(", ")' 2>/dev/null || echo "")

        # === MULTI-LAYER VALIDATION ===
        local is_valid=false
        local match_reason=""

        # Layer 1: Subject Organization match
        if [[ -n "$subject_org" ]]; then
            while IFS= read -r org_name || [[ -n "$org_name" ]]; do
                [[ -z "$org_name" ]] && continue
                if echo "$subject_org" | grep -qi "$org_name" 2>/dev/null; then
                    is_valid=true
                    match_reason="Subject Org matches: ${subject_org}"
                    break
                fi
            done < "$org_file"
        fi

        # Layer 2: Subject CN matches target domain
        if [[ "$is_valid" == false ]] && [[ -n "$subject_cn" ]]; then
            while IFS= read -r target_domain || [[ -n "$target_domain" ]]; do
                target_domain=$(echo "$target_domain" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
                [[ -z "$target_domain" || "$target_domain" == \#* ]] && continue

                if echo "$subject_cn" | tr '[:upper:]' '[:lower:]' | grep -q "${target_domain}" 2>/dev/null; then
                    is_valid=true
                    match_reason="Subject CN matches target: ${subject_cn}"
                    break
                fi
            done < "$TARGET_FILE"
        fi

        # Layer 3: SAN entries match target domains
        if [[ "$is_valid" == false ]] && [[ -n "$san_list" ]]; then
            while IFS= read -r target_domain || [[ -n "$target_domain" ]]; do
                target_domain=$(echo "$target_domain" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
                [[ -z "$target_domain" || "$target_domain" == \#* ]] && continue

                if echo "$san_list" | tr '[:upper:]' '[:lower:]' | grep -q "${target_domain}" 2>/dev/null; then
                    is_valid=true
                    match_reason="SAN contains target domain: ${target_domain}"
                    break
                fi
            done < "$TARGET_FILE"
        fi

        # Layer 4: Reverse — extract SANs and check if they match any root domain
        if [[ "$is_valid" == false ]] && [[ -n "$san_list" ]]; then
            local san_domains
            san_domains=$(echo "$san_list" | tr ',' '\n' | sed 's/^ *//' | sed 's/\*\.//')

            while IFS= read -r san_domain || [[ -n "$san_domain" ]]; do
                [[ -z "$san_domain" ]] && continue
                local san_root
                san_root=$(extract_root_domain "$san_domain")

                while IFS= read -r target_domain || [[ -n "$target_domain" ]]; do
                    target_domain=$(echo "$target_domain" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
                    [[ -z "$target_domain" || "$target_domain" == \#* ]] && continue

                    if [[ "$san_root" == "$target_domain" ]]; then
                        is_valid=true
                        match_reason="SAN root domain matches: ${san_domain} → ${san_root}"
                        break 2
                    fi
                done < "$TARGET_FILE"
            done <<< "$san_domains"
        fi

        # Record validation result
        if [[ "$is_valid" == true ]]; then
            ((validated++)) || true
            echo "$host" >> "${SSL_DIR}/validated_hosts.txt"
            echo "[VALID] ${host} | CN=${subject_cn} | Org=${subject_org} | Reason: ${match_reason}" \
                >> "${SSL_DIR}/validation_report.txt"

            local host_no_port ip_no_port
            host_no_port=$(echo "$host" | sed 's/:.*$//')
            ip_no_port=$(echo "$ip" | sed 's/:.*$//')
            if is_ip "$host_no_port"; then
                echo "$host_no_port" >> "${SSL_DIR}/ssl_validated_ips.txt"
                echo "$host" >> "${SSL_DIR}/ssl_validated_ip_hosts.txt"
            fi
            if is_ip "$ip_no_port"; then
                echo "$ip_no_port" >> "${SSL_DIR}/ssl_validated_ips.txt"
            fi

            # Extract additional subdomains from SANs of validated certs
            if [[ -n "$san_list" ]]; then
                echo "$san_list" | tr ',' '\n' | sed 's/^ *//' | sed 's/\*\.//' \
                    >> "${OUTPUT_DIR}/ssl_validated_subdomains.txt"
            fi
        else
            ((rejected++)) || true
            echo "$host" >> "${SSL_DIR}/unvalidated_hosts.txt"
            echo "[REJECTED] ${host} | CN=${subject_cn} | Org=${subject_org} | SANs: ${san_list}" \
                >> "${SSL_DIR}/validation_report.txt"
        fi

    done < "${SSL_DIR}/tlsx_json_raw.jsonl"

    # Deduplicate validated results
    sort -u -o "${SSL_DIR}/validated_hosts.txt" "${SSL_DIR}/validated_hosts.txt" 2>/dev/null || true
    sort -u -o "${SSL_DIR}/unvalidated_hosts.txt" "${SSL_DIR}/unvalidated_hosts.txt" 2>/dev/null || true
    ip_sort_unique "${SSL_DIR}/ssl_validated_ips.txt" "${SSL_DIR}/ssl_validated_ips.txt"
    sort -u -o "${SSL_DIR}/ssl_validated_ip_hosts.txt" "${SSL_DIR}/ssl_validated_ip_hosts.txt" 2>/dev/null || true

    # Deduplicate and filter SSL-discovered subdomains
    if [[ -f "${OUTPUT_DIR}/ssl_validated_subdomains.txt" ]]; then
        sort -u -o "${OUTPUT_DIR}/ssl_validated_subdomains.txt" "${OUTPUT_DIR}/ssl_validated_subdomains.txt"
        delete_empty_lines "${OUTPUT_DIR}/ssl_validated_subdomains.txt"

        # Filter to only include target-domain subdomains
        : > "${SSL_DIR}/ssl_new_subs.txt"
        while IFS= read -r target_domain || [[ -n "$target_domain" ]]; do
            target_domain=$(echo "$target_domain" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
            [[ -z "$target_domain" || "$target_domain" == \#* ]] && continue
            grep -i "\.${target_domain}$\|^${target_domain}$" "${OUTPUT_DIR}/ssl_validated_subdomains.txt" \
                >> "${SSL_DIR}/ssl_new_subs.txt" 2>/dev/null || true
        done < "$TARGET_FILE"

        # Find truly new subdomains from SSL SANs
        if [[ -f "${OUTPUT_DIR}/subdomains.txt" ]] && [[ -f "${SSL_DIR}/ssl_new_subs.txt" ]]; then
            local new_from_ssl
            new_from_ssl=$(comm -23 \
                <(sort -u "${SSL_DIR}/ssl_new_subs.txt") \
                <(sort -u "${OUTPUT_DIR}/subdomains.txt") \
                | wc -l | tr -d ' ')

            if [[ "$new_from_ssl" -gt 0 ]]; then
                print_finding "Discovered ${new_from_ssl} NEW subdomains from SSL SANs!"
                # Merge back into master subdomain list
                cat "${SSL_DIR}/ssl_new_subs.txt" >> "${OUTPUT_DIR}/subdomains.txt"
                sort -u -o "${OUTPUT_DIR}/subdomains.txt" "${OUTPUT_DIR}/subdomains.txt"
            fi
        fi
    fi

    : > "${SSL_DIR}/ssl_validated_ip_urls.txt"
    if [[ -f "${SSL_DIR}/validated_hosts.txt" ]]; then
        while IFS= read -r host || [[ -n "$host" ]]; do
            [[ -z "$host" ]] && continue
            local host_core url
            if [[ "$host" == http* ]]; then
                host_core=$(extract_domain_from_url "$host")
                url="$host"
            else
                host_core=$(echo "$host" | sed 's/:.*$//')
                url="https://${host}"
            fi

            if is_ip "$host_core"; then
                echo "$url" >> "${SSL_DIR}/ssl_validated_ip_urls.txt"
            fi
        done < "${SSL_DIR}/validated_hosts.txt"
        sort -u -o "${SSL_DIR}/ssl_validated_ip_urls.txt" "${SSL_DIR}/ssl_validated_ip_urls.txt"
    fi

    echo ""
    echo -e "${BOLD}${WHITE}── SSL Validation Summary ──${NC}"
    echo -e "  ${GREEN}Validated:${NC}  ${validated} certificates match target org"
    echo -e "  ${RED}Rejected:${NC}   ${rejected} certificates do NOT match"
    echo -e "  ${CYAN}Total:${NC}      ${total_certs} certificates analyzed"
    echo ""
    print_success "Phase 4 Complete: SSL certificate validation finished"
    print_finding "Validation report: ${SSL_DIR}/validation_report.txt"
    print_finding "Validated hosts: ${SSL_DIR}/validated_hosts.txt"
    print_finding "Validated IPs: ${SSL_DIR}/ssl_validated_ips.txt"
}

# ============================================================================
# PHASE 4B: RE-SCAN — FEED SSL-DISCOVERED SUBDOMAINS BACK INTO PHASE 1 + 2
# ============================================================================
# After Phase 4 discovers new subdomains via SSL SANs, we loop them back
# through subdomain enumeration (Phase 1 sources) and then DNS + httpx
# (Phase 2) so nothing is missed before nuclei runs.
# ============================================================================

phase4b_rescan_ssl_discoveries() {
    phase_banner "4B" "RE-SCAN SSL-DISCOVERED SUBDOMAINS"

    local ssl_new_subs="${SSL_DIR}/ssl_new_subs.txt"

    # Determine what's actually new (not already in the original Phase 1 output)
    if [[ ! -f "$ssl_new_subs" ]] || [[ $(count_lines "$ssl_new_subs") -eq 0 ]]; then
        print_status "No new subdomains discovered from SSL SANs. Skipping re-scan."
        return
    fi

    # Isolate subdomains that were NOT in the Phase 2 resolved set
    local new_unresolved="${SSL_DIR}/ssl_new_unresolved.txt"
    if [[ -f "${OUTPUT_DIR}/resolved_hosts.txt" ]]; then
        comm -23 \
            <(sort -u "$ssl_new_subs") \
            <(sort -u "${OUTPUT_DIR}/resolved_hosts.txt") \
            > "$new_unresolved" 2>/dev/null || cp "$ssl_new_subs" "$new_unresolved"
    else
        cp "$ssl_new_subs" "$new_unresolved"
    fi

    local new_count
    new_count=$(count_lines "$new_unresolved")

    if [[ "$new_count" -eq 0 ]]; then
        print_status "All SSL-discovered subdomains were already resolved. Nothing to re-scan."
        return
    fi

    print_finding "${new_count} new subdomains from SSL SANs need enumeration + scanning"
    echo ""

    # ─────────────────────────────────────────────────────────────────
    # STEP 1: Run Phase 1 sources on the ROOT DOMAINS of new subs
    #         to catch siblings we might have missed
    # ─────────────────────────────────────────────────────────────────
    echo -e "${BOLD}${WHITE}── Step 1: Additional subdomain enumeration on new roots ──${NC}"

    local rescan_subs_dir="${SSL_DIR}/rescan_subs"
    mkdir -p "$rescan_subs_dir"

    # Extract unique root domains from the new SSL subdomains
    : > "${rescan_subs_dir}/new_roots.txt"
    while IFS= read -r sub || [[ -n "$sub" ]]; do
        [[ -z "$sub" ]] && continue
        extract_root_domain "$sub" >> "${rescan_subs_dir}/new_roots.txt"
    done < "$new_unresolved"
    sort -u -o "${rescan_subs_dir}/new_roots.txt" "${rescan_subs_dir}/new_roots.txt"

    # Only enumerate roots that are in our target scope
    : > "${rescan_subs_dir}/roots_in_scope.txt"
    while IFS= read -r root || [[ -n "$root" ]]; do
        [[ -z "$root" ]] && continue
        if grep -qix "$root" "$TARGET_FILE" 2>/dev/null; then
            echo "$root" >> "${rescan_subs_dir}/roots_in_scope.txt"
        fi
    done < "${rescan_subs_dir}/new_roots.txt"

    local roots_in_scope
    roots_in_scope=$(count_lines "${rescan_subs_dir}/roots_in_scope.txt")

    if [[ "$roots_in_scope" -gt 0 ]]; then
        print_progress "Re-running subfinder on ${roots_in_scope} root domain(s) for deeper coverage..."

        while IFS= read -r root_domain || [[ -n "$root_domain" ]]; do
            [[ -z "$root_domain" ]] && continue

            # subfinder re-pass
            subfinder -d "$root_domain" \
                -all \
                -silent \
                -t "$DEFAULT_THREADS" \
                -timeout 10 \
                -o "${rescan_subs_dir}/subfinder_rescan_${root_domain}.txt" \
                2>>"$LOG_FILE" || true

            local sf_count
            sf_count=$(count_lines "${rescan_subs_dir}/subfinder_rescan_${root_domain}.txt")
            print_status "  subfinder re-scan: ${sf_count} subs for ${root_domain}"

            # crt.sh re-pass (quick)
            local crt_response
            crt_response=$(curl -s "https://crt.sh/?q=%25.${root_domain}&output=json" \
                --connect-timeout 15 \
                --max-time 60 \
                -H "User-Agent: Mozilla/5.0 (compatible; ReconSh/1.0)" \
                2>>"$LOG_FILE" || echo "[]")

            if [[ -n "$crt_response" && "$crt_response" != "[]" ]]; then
                echo "$crt_response" | jq -r '.[].name_value' 2>/dev/null \
                    | sed 's/\*\.//g' \
                    | sort -u \
                    | grep -i "\.${root_domain}$" \
                    > "${rescan_subs_dir}/crtsh_rescan_${root_domain}.txt" 2>/dev/null || true
            fi

            # assetfinder re-pass (if available)
            if command -v assetfinder &>/dev/null; then
                assetfinder --subs-only "$root_domain" \
                    > "${rescan_subs_dir}/assetfinder_rescan_${root_domain}.txt" \
                    2>>"$LOG_FILE" || true
            fi

        done < "${rescan_subs_dir}/roots_in_scope.txt"
    fi

    # Merge all re-scan discoveries + the original SSL new subs
    local all_rescan_files=()
    while IFS= read -r -d '' f; do
        all_rescan_files+=("$f")
    done < <(find "$rescan_subs_dir" -name "*.txt" ! -name "new_roots.txt" ! -name "roots_in_scope.txt" -print0 2>/dev/null)

    # Add the SSL new subs themselves
    all_rescan_files+=("$new_unresolved")

    : > "${SSL_DIR}/rescan_all_subs.txt"
    for f in "${all_rescan_files[@]}"; do
        if [[ -f "$f" ]]; then
            cat "$f" >> "${SSL_DIR}/rescan_all_subs.txt"
        fi
    done

    # Filter to target scope only
    : > "${SSL_DIR}/rescan_scoped_subs.txt"
    while IFS= read -r target_domain || [[ -n "$target_domain" ]]; do
        target_domain=$(echo "$target_domain" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
        [[ -z "$target_domain" || "$target_domain" == \#* ]] && continue
        grep -i "\.${target_domain}$\|^${target_domain}$" "${SSL_DIR}/rescan_all_subs.txt" \
            >> "${SSL_DIR}/rescan_scoped_subs.txt" 2>/dev/null || true
    done < "$TARGET_FILE"

    sort -u -o "${SSL_DIR}/rescan_scoped_subs.txt" "${SSL_DIR}/rescan_scoped_subs.txt"
    delete_empty_lines "${SSL_DIR}/rescan_scoped_subs.txt"

    # Find what's truly new vs what Phase 1 already had
    local truly_new="${SSL_DIR}/rescan_truly_new.txt"
    if [[ -f "${OUTPUT_DIR}/subdomains.txt" ]]; then
        comm -23 \
            <(sort -u "${SSL_DIR}/rescan_scoped_subs.txt") \
            <(sort -u "${OUTPUT_DIR}/subdomains.txt") \
            > "$truly_new" 2>/dev/null || touch "$truly_new"
    else
        cp "${SSL_DIR}/rescan_scoped_subs.txt" "$truly_new"
    fi

    local truly_new_count
    truly_new_count=$(count_lines "$truly_new")

    # Merge into master subdomain list (Phase 1 output)
    if [[ "$truly_new_count" -gt 0 ]]; then
        print_finding "Phase 1 enriched: +${truly_new_count} new subdomains merged into master list"
        cat "$truly_new" >> "${OUTPUT_DIR}/subdomains.txt"
        sort -u -o "${OUTPUT_DIR}/subdomains.txt" "${OUTPUT_DIR}/subdomains.txt"
    else
        print_status "No additional new subdomains beyond what Phase 1 already found"
    fi

    # ─────────────────────────────────────────────────────────────────
    # STEP 2: DNS resolution on all new subdomains (Phase 2 re-run)
    # ─────────────────────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}${WHITE}── Step 2: DNS resolution on new subdomains ──${NC}"

    # Resolve all subs that haven't been resolved yet
    local unresolved_subs="${SSL_DIR}/rescan_unresolved.txt"
    if [[ -f "${OUTPUT_DIR}/resolved_hosts.txt" ]]; then
        comm -23 \
            <(sort -u "${SSL_DIR}/rescan_scoped_subs.txt") \
            <(sort -u "${OUTPUT_DIR}/resolved_hosts.txt") \
            > "$unresolved_subs" 2>/dev/null || touch "$unresolved_subs"
    else
        cp "${SSL_DIR}/rescan_scoped_subs.txt" "$unresolved_subs"
    fi

    local unresolved_count
    unresolved_count=$(count_lines "$unresolved_subs")

    if [[ "$unresolved_count" -gt 0 ]]; then
        print_progress "Resolving ${unresolved_count} new subdomains with dnsx..."

        dnsx -l "$unresolved_subs" \
            -a -aaaa -cname -resp \
            -t "$DEFAULT_DNSX_THREADS" \
            -silent \
            -o "${SSL_DIR}/rescan_dnsx.txt" \
            2>>"$LOG_FILE" || touch "${SSL_DIR}/rescan_dnsx.txt"

        # Extract newly resolved hostnames
        if [[ -f "${SSL_DIR}/rescan_dnsx.txt" ]]; then
            awk '{print $1}' "${SSL_DIR}/rescan_dnsx.txt" \
                | sort -u > "${SSL_DIR}/rescan_resolved.txt"

            local rescan_resolved
            rescan_resolved=$(count_lines "${SSL_DIR}/rescan_resolved.txt")
            print_status "DNS resolved: ${rescan_resolved} new hosts"

            # Merge into master resolved list
            cat "${SSL_DIR}/rescan_resolved.txt" >> "${OUTPUT_DIR}/resolved_hosts.txt"
            sort -u -o "${OUTPUT_DIR}/resolved_hosts.txt" "${OUTPUT_DIR}/resolved_hosts.txt"

            # Extract new IPs and merge
            extract_ipv4s "${SSL_DIR}/rescan_dnsx.txt" \
                | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n -u > "${SSL_DIR}/rescan_ips.txt" || touch "${SSL_DIR}/rescan_ips.txt"

            if [[ -f "${DNS_DIR}/resolved_ips.txt" ]]; then
                cat "${SSL_DIR}/rescan_ips.txt" >> "${DNS_DIR}/resolved_ips.txt"
                sort -u -o "${DNS_DIR}/resolved_ips.txt" "${DNS_DIR}/resolved_ips.txt"
            fi

            # Merge into DNS full results
            if [[ -f "${DNS_DIR}/dnsx_resolved.txt" ]]; then
                cat "${SSL_DIR}/rescan_dnsx.txt" >> "${DNS_DIR}/dnsx_resolved.txt"
                sort -u -o "${DNS_DIR}/dnsx_resolved.txt" "${DNS_DIR}/dnsx_resolved.txt"
            fi
        fi
    else
        print_status "All new subdomains were already resolved. Skipping DNS."
    fi

    # ─────────────────────────────────────────────────────────────────
    # STEP 3: HTTP probing is deferred to dedicated final Phase 4C
    # ─────────────────────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}${WHITE}── Step 3: HTTP/HTTPS probing deferred ──${NC}"
    print_status "Phase 4C will run one consolidated httpx pass on final targets"

    # ─────────────────────────────────────────────────────────────────
    # Summary
    # ─────────────────────────────────────────────────────────────────
    echo ""
    local final_subs final_resolved final_live
    final_subs=$(count_lines "${OUTPUT_DIR}/subdomains.txt")
    final_resolved=$(count_lines "${OUTPUT_DIR}/resolved_hosts.txt")
    final_live=$(count_lines "${OUTPUT_DIR}/live_hosts.txt")

    echo -e "${BOLD}${WHITE}── Re-Scan Totals (after feedback loop) ──${NC}"
    echo -e "  ${CYAN}Total subdomains:${NC}     ${final_subs}"
    echo -e "  ${CYAN}Total resolved:${NC}       ${final_resolved}"
    echo -e "  ${CYAN}Total live hosts:${NC}     ${final_live}"
    echo ""
    print_success "Phase 4B Complete: SSL feedback loop finished — new subs resolved"
}

# ============================================================================
# PHASE 4C: FINAL CONSOLIDATED HTTPX PROBING
# ============================================================================

phase4c_final_httpx_probe() {
    phase_banner "4C" "FINAL CONSOLIDATED HTTPX PROBING"

    mkdir -p "$DNS_DIR" "$ASN_DIR"

    local targets_file="${DNS_DIR}/httpx_final_targets.txt"
    : > "$targets_file"

    # Final host/domain targets
    if [[ -f "${OUTPUT_DIR}/resolved_hosts.txt" ]]; then
        cat "${OUTPUT_DIR}/resolved_hosts.txt" >> "$targets_file"
    fi

    # Include ASN IP inventory discovered across phases
    if [[ -f "${OUTPUT_DIR}/asn_ips.txt" ]]; then
        cat "${OUTPUT_DIR}/asn_ips.txt" >> "$targets_file"
    fi

    # Include SSL validated host:port targets
    if [[ -f "${SSL_DIR}/validated_hosts.txt" ]]; then
        cat "${SSL_DIR}/validated_hosts.txt" >> "$targets_file"
    fi

    sort -u -o "$targets_file" "$targets_file"
    delete_empty_lines "$targets_file"

    local target_count
    target_count=$(count_lines "$targets_file")
    if [[ "$target_count" -eq 0 ]]; then
        print_warning "No final targets available for httpx probing."
        touch "${DNS_DIR}/httpx_results.txt"
        touch "${OUTPUT_DIR}/live_hosts.txt"
        touch "${OUTPUT_DIR}/live_hosts_full.txt"
        touch "${ASN_DIR}/httpx_asn_ips.txt"
        return
    fi

    print_progress "Running a single final httpx pass on ${target_count} targets..."
    httpx -l "$targets_file" \
        -silent \
        -threads "$DEFAULT_HTTPX_THREADS" \
        -status-code \
        -title \
        -tech-detect \
        -content-length \
        -follow-redirects \
        -timeout 10 \
        -retries 2 \
        -o "${DNS_DIR}/httpx_results.txt" \
        2>>"$LOG_FILE" || touch "${DNS_DIR}/httpx_results.txt"

    if [[ -f "${DNS_DIR}/httpx_results.txt" ]]; then
        awk '{print $1}' "${DNS_DIR}/httpx_results.txt" | sort -u > "${OUTPUT_DIR}/live_hosts.txt"
        cp "${DNS_DIR}/httpx_results.txt" "${OUTPUT_DIR}/live_hosts_full.txt"
    else
        touch "${OUTPUT_DIR}/live_hosts.txt"
        touch "${OUTPUT_DIR}/live_hosts_full.txt"
    fi

    # Keep ASN-IP-specific httpx slice for downstream compatibility/reporting
    : > "${ASN_DIR}/httpx_asn_ips.txt"
    if [[ -f "${OUTPUT_DIR}/asn_ips.txt" ]] && [[ -f "${DNS_DIR}/httpx_results.txt" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" ]] && continue
            local url host_part
            url=$(echo "$line" | awk '{print $1}')
            host_part=$(extract_domain_from_url "$url")
            if is_ip "$host_part" && grep -qx "$host_part" "${OUTPUT_DIR}/asn_ips.txt" 2>/dev/null; then
                echo "$line" >> "${ASN_DIR}/httpx_asn_ips.txt"
            fi
        done < "${DNS_DIR}/httpx_results.txt"
        sort -u -o "${ASN_DIR}/httpx_asn_ips.txt" "${ASN_DIR}/httpx_asn_ips.txt"
    fi

    print_success "Phase 4C Complete: final httpx probing finished"
    print_finding "Live hosts: ${OUTPUT_DIR}/live_hosts.txt"
    print_finding "Full httpx output: ${OUTPUT_DIR}/live_hosts_full.txt"
}

# ============================================================================
# PHASE 5: VULNERABILITY SCANNING
# ============================================================================

collect_url_intelligence() {
    local raw_urls="${VULN_DIR}/url_intel_raw.txt"
    local scoped_urls="${VULN_DIR}/url_intel_scoped.txt"
    local param_urls="${VULN_DIR}/url_intel_params.txt"
    local js_urls="${VULN_DIR}/url_intel_js.txt"

    : > "$raw_urls"
    : > "$scoped_urls"
    : > "$param_urls"
    : > "$js_urls"

    print_progress "Collecting URL intelligence (wayback/gau/crawler)..."

    # Historical URLs from root domains + discovered subdomains
    local archive_sources="${VULN_DIR}/url_sources.txt"
    : > "$archive_sources"
    if [[ -f "$TARGET_FILE" ]]; then
        cat "$TARGET_FILE" | grep -v '^\s*#' | grep -v '^\s*$' >> "$archive_sources" || true
    fi
    if [[ -f "${OUTPUT_DIR}/subdomains.txt" ]]; then
        cat "${OUTPUT_DIR}/subdomains.txt" >> "$archive_sources"
    fi
    sort -u -o "$archive_sources" "$archive_sources"
    delete_empty_lines "$archive_sources"

    if command -v waybackurls &>/dev/null; then
        waybackurls < "$archive_sources" >> "$raw_urls" 2>>"$LOG_FILE" || true
    fi

    if command -v gau &>/dev/null; then
        gau --subs --providers wayback,commoncrawl,otx,urlscan -threads "$DEFAULT_THREADS" \
            < "$archive_sources" >> "$raw_urls" 2>>"$LOG_FILE" || true
    fi

    # Optional active crawl from already-live hosts
    if [[ -f "${OUTPUT_DIR}/live_hosts.txt" ]] && [[ $(count_lines "${OUTPUT_DIR}/live_hosts.txt") -gt 0 ]]; then
        if command -v katana &>/dev/null; then
            katana -list "${OUTPUT_DIR}/live_hosts.txt" \
                -silent \
                -d "$DEFAULT_URL_CRAWL_DEPTH" \
                -jc \
                -timeout 10 \
                >> "$raw_urls" 2>>"$LOG_FILE" || true
        fi

        if command -v hakrawler &>/dev/null; then
            cat "${OUTPUT_DIR}/live_hosts.txt" \
                | hakrawler -depth "$DEFAULT_URL_CRAWL_DEPTH" -plain \
                >> "$raw_urls" 2>>"$LOG_FILE" || true
        fi
    fi

    sort -u -o "$raw_urls" "$raw_urls"
    delete_empty_lines "$raw_urls"

    # Keep only in-scope URLs
    scope_filter_urls_file "$raw_urls" "$scoped_urls"

    # Parameterized URLs are high-value for bug bounty testing
    if [[ -f "$scoped_urls" ]]; then
        grep '?' "$scoped_urls" | sort -u > "$param_urls" 2>/dev/null || touch "$param_urls"
        grep -Ei '\.js([?#].*)?$' "$scoped_urls" | sort -u > "$js_urls" 2>/dev/null || touch "$js_urls"
    fi

    print_status "URL intel total: $(count_lines "$scoped_urls")"
    print_status "URL intel with params: $(count_lines "$param_urls")"
    print_status "URL intel JS files: $(count_lines "$js_urls")"
}

phase5_vulnerability_scan() {
    phase_banner "5" "VULNERABILITY SCANNING (NUCLEI)"

    mkdir -p "$VULN_DIR"

    # Build comprehensive target list for nuclei
    : > "${VULN_DIR}/nuclei_targets.txt"

    # Add live hosts (URLs from httpx)
    if [[ -f "${OUTPUT_DIR}/live_hosts.txt" ]]; then
        cat "${OUTPUT_DIR}/live_hosts.txt" >> "${VULN_DIR}/nuclei_targets.txt"
    fi

    # Add validated SSL hosts as https URLs
    if [[ -f "${SSL_DIR}/validated_hosts.txt" ]]; then
        while IFS= read -r host || [[ -n "$host" ]]; do
            [[ -z "$host" ]] && continue
            # If it's already a URL, keep it; otherwise make it https
            if [[ "$host" != http* ]]; then
                echo "https://${host}" >> "${VULN_DIR}/nuclei_targets.txt"
            else
                echo "$host" >> "${VULN_DIR}/nuclei_targets.txt"
            fi
        done < "${SSL_DIR}/validated_hosts.txt"
    fi

    # Add only SSL-validated IP URLs (strict false-positive reduction for ASN IPs)
    if [[ -f "${SSL_DIR}/ssl_validated_ip_urls.txt" ]]; then
        cat "${SSL_DIR}/ssl_validated_ip_urls.txt" >> "${VULN_DIR}/nuclei_targets.txt"
    fi

    # Add URL intelligence targets for deeper bug bounty coverage
    collect_url_intelligence
    if [[ -f "${VULN_DIR}/url_intel_scoped.txt" ]]; then
        cat "${VULN_DIR}/url_intel_scoped.txt" >> "${VULN_DIR}/nuclei_targets.txt"
    fi

    sort -u -o "${VULN_DIR}/nuclei_targets.txt" "${VULN_DIR}/nuclei_targets.txt"
    delete_empty_lines "${VULN_DIR}/nuclei_targets.txt"

    local target_count
    target_count=$(count_lines "${VULN_DIR}/nuclei_targets.txt")

    if [[ "$target_count" -eq 0 ]]; then
        print_warning "No targets available for vulnerability scanning"
        return
    fi

    print_status "Scanning ${target_count} targets with nuclei..."
    print_status "Rate limit: ${RATE_LIMIT} requests/second"
    print_status "Severity filter: ${NUCLEI_SEVERITY}"
    print_status "Bulk size: ${DEFAULT_NUCLEI_BULK_SIZE}, Concurrency: ${DEFAULT_NUCLEI_CONCURRENCY}"

    # Update nuclei templates first
    print_progress "Updating nuclei templates..."
    nuclei -update-templates 2>>"$LOG_FILE" || true

    # ---- Run nuclei with rate limiting ----
    print_progress "Starting nuclei scan (this may take a while)..."

    nuclei -l "${VULN_DIR}/nuclei_targets.txt" \
        -rl "$RATE_LIMIT" \
        -bulk-size "$DEFAULT_NUCLEI_BULK_SIZE" \
        -c "$DEFAULT_NUCLEI_CONCURRENCY" \
        -severity "$NUCLEI_SEVERITY" \
        -silent \
        -stats \
        -stats-interval 30 \
        -timeout 10 \
        -retries 2 \
        -no-color \
        -o "${VULN_DIR}/nuclei_results.txt" \
        -jsonl \
        -je "${VULN_DIR}/nuclei_results.jsonl" \
        2>>"$LOG_FILE" || true

    # ---- Parse and organize results by severity ----
    print_progress "Organizing results by severity..."

    for severity in critical high medium low info; do
        if [[ -f "${VULN_DIR}/nuclei_results.jsonl" ]]; then
            jq -r "select(.info.severity == \"${severity}\") | [.host, .\"template-id\", .info.name, .\"matched-at\" // .host] | @tsv" \
                "${VULN_DIR}/nuclei_results.jsonl" \
                > "${VULN_DIR}/nuclei_${severity}.txt" 2>/dev/null || touch "${VULN_DIR}/nuclei_${severity}.txt"
        else
            touch "${VULN_DIR}/nuclei_${severity}.txt"
        fi

        local sev_count
        sev_count=$(count_lines "${VULN_DIR}/nuclei_${severity}.txt")

        case "$severity" in
            critical) echo -e "  ${RED}${BOLD}CRITICAL:${NC} ${sev_count} findings" ;;
            high)     echo -e "  ${RED}HIGH:${NC}     ${sev_count} findings" ;;
            medium)   echo -e "  ${YELLOW}MEDIUM:${NC}   ${sev_count} findings" ;;
            low)      echo -e "  ${BLUE}LOW:${NC}      ${sev_count} findings" ;;
            info)     echo -e "  ${CYAN}INFO:${NC}     ${sev_count} findings" ;;
        esac
    done

    local total_findings
    total_findings=$(count_lines "${VULN_DIR}/nuclei_results.txt" 2>/dev/null || echo "0")

    echo ""
    print_success "Phase 5 Complete: ${total_findings} total findings"
    print_finding "Full results: ${VULN_DIR}/nuclei_results.txt"
    print_finding "JSON results: ${VULN_DIR}/nuclei_results.jsonl"
}

# ============================================================================
# PHASE 6: JAVASCRIPT URL DISCOVERY
# ============================================================================

phase6_js_discovery() {
    phase_banner "6" "JAVASCRIPT URL DISCOVERY"

    mkdir -p "$JS_DIR" "$VULN_DIR"

    local js_raw="${JS_DIR}/js_urls_raw.txt"
    local js_useful="${JS_DIR}/js_urls_useful.txt"
    local js_params="${JS_DIR}/js_urls_params.txt"
    local js_sources="${JS_DIR}/js_sources.txt"

    : > "$js_raw"
    : > "$js_useful"
    : > "$js_params"
    : > "$js_sources"

    # Build URL intel corpus first (archive + optional crawlers)
    collect_url_intelligence

    # Source hosts from root + discovered subdomains
    if [[ -f "$TARGET_FILE" ]]; then
        grep -v '^\s*#' "$TARGET_FILE" | grep -v '^\s*$' >> "$js_sources" 2>/dev/null || true
    fi
    if [[ -f "${OUTPUT_DIR}/subdomains.txt" ]]; then
        cat "${OUTPUT_DIR}/subdomains.txt" >> "$js_sources"
    fi
    sort -u -o "$js_sources" "$js_sources"
    delete_empty_lines "$js_sources"

    # Harvest JS from URL intel
    if [[ -f "${VULN_DIR}/url_intel_scoped.txt" ]]; then
        grep -Ei '\.m?js([?#].*)?$' "${VULN_DIR}/url_intel_scoped.txt" >> "$js_raw" 2>/dev/null || true
    fi

    # Additional JS discovery from subjs (if available)
    if command -v subjs &>/dev/null && [[ -f "$js_sources" ]]; then
        subjs -i "$js_sources" >> "$js_raw" 2>>"$LOG_FILE" || true
    fi

    # Extra quick pass from gau/wayback directly on discovered hosts
    if command -v waybackurls &>/dev/null && [[ -f "$js_sources" ]]; then
        waybackurls < "$js_sources" | grep -Ei '\.m?js([?#].*)?$' >> "$js_raw" 2>>"$LOG_FILE" || true
    fi
    if command -v gau &>/dev/null && [[ -f "$js_sources" ]]; then
        gau --subs --providers wayback,commoncrawl,otx,urlscan -threads "$DEFAULT_THREADS" \
            < "$js_sources" \
            | grep -Ei '\.m?js([?#].*)?$' >> "$js_raw" 2>>"$LOG_FILE" || true
    fi

    sort -u -o "$js_raw" "$js_raw" 2>/dev/null || true
    delete_empty_lines "$js_raw"

    # Filter to useful hosts only
    while IFS= read -r url || [[ -n "$url" ]]; do
        [[ -z "$url" ]] && continue
        local host
        host=$(extract_domain_from_url "$url")
        if is_useful_host "$host"; then
            echo "$url" >> "$js_useful"
        fi
    done < "$js_raw"
    sort -u -o "$js_useful" "$js_useful"
    delete_empty_lines "$js_useful"

    grep '?' "$js_useful" | sort -u > "$js_params" 2>/dev/null || touch "$js_params"

    print_status "Raw JS URLs: $(count_lines "$js_raw")"
    print_status "Useful scoped JS URLs: $(count_lines "$js_useful")"
    print_status "Parameterized JS URLs: $(count_lines "$js_params")"
    print_finding "JS URL list: ${js_useful}"
}

# ============================================================================
# PHASE 7: JS HARDCODED CREDENTIALS + S3 TAKEOVER SIGNALS
# ============================================================================

phase7_js_security_scan() {
    phase_banner "7" "JS HARDCODED CREDS + S3 ANALYSIS"

    mkdir -p "$JS_DIR"

    local js_useful="${JS_DIR}/js_urls_useful.txt"
    if [[ ! -f "$js_useful" ]] || [[ $(count_lines "$js_useful") -eq 0 ]]; then
        print_warning "No JS URL inventory found. Running Phase 6 first..."
        phase6_js_discovery
    fi

    if [[ ! -f "$js_useful" ]] || [[ $(count_lines "$js_useful") -eq 0 ]]; then
        print_warning "No JS URLs available after discovery. Skipping Phase 7."
        touch "${JS_DIR}/js_secret_findings.txt"
        touch "${JS_DIR}/js_s3_claimable_candidates.txt"
        touch "${JS_DIR}/js_s3_in_use.txt"
        return
    fi

    local findings="${JS_DIR}/js_secret_findings.txt"
    local s3_refs="${JS_DIR}/js_s3_endpoints_raw.txt"
    local s3_claimable="${JS_DIR}/js_s3_claimable_candidates.txt"
    local s3_in_use="${JS_DIR}/js_s3_in_use.txt"
    local fetch_errors="${JS_DIR}/js_fetch_errors.txt"
    local tmp_dir="${JS_DIR}/tmp_js_fetch"
    local origin_urls="${JS_DIR}/origin_urls_to_scan.txt"

    : > "$findings"
    : > "$s3_refs"
    : > "$s3_claimable"
    : > "$s3_in_use"
    : > "$fetch_errors"
    : > "$origin_urls"
    mkdir -p "$tmp_dir"

    local processed=0
    while IFS= read -r js_url || [[ -n "$js_url" ]]; do
        [[ -z "$js_url" ]] && continue
        ((processed++))
        if [[ "$processed" -gt "$DEFAULT_JS_MAX_FILES" ]]; then
            break
        fi

        local js_file
        js_file="${tmp_dir}/js_${processed}.txt"

        if ! curl -sS -L --max-time 20 --connect-timeout 8 "$js_url" -o "$js_file" 2>>"$LOG_FILE"; then
            echo "$js_url" >> "$fetch_errors"
            continue
        fi

        # High-confidence token patterns
        grep -Eo 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z-]{10,80}' "$js_file" 2>/dev/null \
            | sort -u \
            | while IFS= read -r token || [[ -n "$token" ]]; do
                [[ -z "$token" ]] && continue
                echo "[HIGH] ${js_url} | token=$(mask_secret_value "$token")" >> "$findings"
            done

        # Suspicious hardcoded key-value assignments (reduced-noise)
        grep -Ein '(api[_-]?key|access[_-]?key|secret|token|password|passwd|client[_-]?secret)[[:space:]]*[:=][[:space:]]*["'"'"'][A-Za-z0-9_./+=:-]{12,120}["'"'"']' "$js_file" 2>/dev/null \
            | grep -Eiv 'example|sample|dummy|test|changeme|placeholder|your[_-]?key' \
            | head -n 20 \
            | while IFS= read -r match_line || [[ -n "$match_line" ]]; do
                [[ -z "$match_line" ]] && continue
                echo "[MEDIUM] ${js_url} | ${match_line}" >> "$findings"
            done

        # S3 endpoint extraction (for takeover/in-use triage)
        grep -Eoi '([a-z0-9.-]+\.s3[.-][a-z0-9-]+\.amazonaws\.com|[a-z0-9.-]+\.s3\.amazonaws\.com|s3\.amazonaws\.com/[a-z0-9.-]+|[a-z0-9.-]+\.s3-website[.-][a-z0-9-]+\.amazonaws\.com)' "$js_file" 2>/dev/null \
            | sort -u \
            | while IFS= read -r s3_ep || [[ -n "$s3_ep" ]]; do
                [[ -z "$s3_ep" ]] && continue
                echo -e "${s3_ep}\t${js_url}" >> "$s3_refs"
            done
    done < "$js_useful"

    # Also scan original target URLs (homepage/source) for inline hardcoded creds/S3 refs
    while IFS= read -r domain || [[ -n "$domain" ]]; do
        domain=$(echo "$domain" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
        [[ -z "$domain" || "$domain" == \#* ]] && continue
        echo "https://${domain}" >> "$origin_urls"
        echo "https://www.${domain}" >> "$origin_urls"
        echo "http://${domain}" >> "$origin_urls"
    done < "$TARGET_FILE"
    sort -u -o "$origin_urls" "$origin_urls"

    local origin_processed=0
    while IFS= read -r origin_url || [[ -n "$origin_url" ]]; do
        [[ -z "$origin_url" ]] && continue
        ((origin_processed++))

        local origin_file
        origin_file="${tmp_dir}/origin_${origin_processed}.txt"
        if ! curl -sS -L --max-time 20 --connect-timeout 8 "$origin_url" -o "$origin_file" 2>>"$LOG_FILE"; then
            echo "$origin_url" >> "$fetch_errors"
            continue
        fi

        # High-confidence token patterns
        grep -Eo 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z-]{10,80}' "$origin_file" 2>/dev/null \
            | sort -u \
            | while IFS= read -r token || [[ -n "$token" ]]; do
                [[ -z "$token" ]] && continue
                echo "[HIGH][ORIGIN] ${origin_url} | token=$(mask_secret_value "$token")" >> "$findings"
            done

        # Suspicious hardcoded key-value assignments (reduced-noise)
        grep -Ein '(api[_-]?key|access[_-]?key|secret|token|password|passwd|client[_-]?secret)[[:space:]]*[:=][[:space:]]*["'"'"'][A-Za-z0-9_./+=:-]{12,120}["'"'"']' "$origin_file" 2>/dev/null \
            | grep -Eiv 'example|sample|dummy|test|changeme|placeholder|your[_-]?key' \
            | head -n 20 \
            | while IFS= read -r match_line || [[ -n "$match_line" ]]; do
                [[ -z "$match_line" ]] && continue
                echo "[MEDIUM][ORIGIN] ${origin_url} | ${match_line}" >> "$findings"
            done

        # S3 endpoint extraction
        grep -Eoi '([a-z0-9.-]+\.s3[.-][a-z0-9-]+\.amazonaws\.com|[a-z0-9.-]+\.s3\.amazonaws\.com|s3\.amazonaws\.com/[a-z0-9.-]+|[a-z0-9.-]+\.s3-website[.-][a-z0-9-]+\.amazonaws\.com)' "$origin_file" 2>/dev/null \
            | sort -u \
            | while IFS= read -r s3_ep || [[ -n "$s3_ep" ]]; do
                [[ -z "$s3_ep" ]] && continue
                echo -e "${s3_ep}\t${origin_url}" >> "$s3_refs"
            done
    done < "$origin_urls"

    sort -u -o "$findings" "$findings" 2>/dev/null || true
    sort -u -o "$s3_refs" "$s3_refs" 2>/dev/null || true

    # Classify S3 endpoints by safe HTTP signals
    if [[ -f "$s3_refs" ]] && [[ $(count_lines "$s3_refs") -gt 0 ]]; then
        cut -f1 "$s3_refs" | sort -u | while IFS= read -r s3_ep || [[ -n "$s3_ep" ]]; do
            [[ -z "$s3_ep" ]] && continue

            local s3_url body tmp_code
            if [[ "$s3_ep" == http* ]]; then
                s3_url="$s3_ep"
            else
                s3_url="https://${s3_ep}"
            fi

            body=$(curl -sS -L --max-time 15 --connect-timeout 6 "$s3_url" 2>>"$LOG_FILE" || true)
            tmp_code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 --connect-timeout 6 "$s3_url" 2>>"$LOG_FILE" || echo "000")

            if echo "$body" | grep -qi 'NoSuchBucket'; then
                echo "${s3_ep} | status=${tmp_code} | signal=NoSuchBucket" >> "$s3_claimable"
            elif echo "$body" | grep -Eqi 'AccessDenied|ListBucketResult|PermanentRedirect|x-amz-bucket-region'; then
                echo "${s3_ep} | status=${tmp_code} | signal=InUse" >> "$s3_in_use"
            elif [[ "$tmp_code" == "200" ]] || [[ "$tmp_code" == "403" ]] || [[ "$tmp_code" == "301" ]] || [[ "$tmp_code" == "302" ]]; then
                echo "${s3_ep} | status=${tmp_code} | signal=LikelyInUse" >> "$s3_in_use"
            fi
        done
    fi

    sort -u -o "$s3_claimable" "$s3_claimable" 2>/dev/null || true
    sort -u -o "$s3_in_use" "$s3_in_use" 2>/dev/null || true

    print_status "JS files fetched: $((processed < DEFAULT_JS_MAX_FILES ? processed : DEFAULT_JS_MAX_FILES))"
    print_status "Origin URLs scanned: ${origin_processed}"
    print_status "Secret findings: $(count_lines "$findings")"
    print_status "S3 claimable candidates: $(count_lines "$s3_claimable")"
    print_status "S3 in-use endpoints: $(count_lines "$s3_in_use")"
    print_finding "Secret report: ${findings}"
}

# ============================================================================
# PHASE 8: SAFE CACHE-POISONING SIGNAL CHECKS (PARAMETERIZED JS URLs)
# ============================================================================

phase8_cache_poisoning_safe() {
    phase_banner "8" "SAFE CACHE-POISONING CHECKS (.JS WITH PARAMS)"

    mkdir -p "$JS_DIR"

    local js_params="${JS_DIR}/js_urls_params.txt"
    if [[ ! -f "$js_params" ]] || [[ $(count_lines "$js_params") -eq 0 ]]; then
        print_warning "No parameterized JS URL inventory found. Running Phase 6 first..."
        phase6_js_discovery
    fi

    if [[ ! -f "$js_params" ]] || [[ $(count_lines "$js_params") -eq 0 ]]; then
        print_warning "No parameterized JS URLs available. Skipping Phase 8."
        touch "${JS_DIR}/js_cache_poisoning_safe_report.txt"
        return
    fi

    local report="${JS_DIR}/js_cache_poisoning_safe_report.txt"
    local tested_file="${JS_DIR}/js_cache_poisoning_tested.txt"
    : > "$report"
    : > "$tested_file"

    local tested=0
    while IFS= read -r url || [[ -n "$url" ]]; do
        [[ -z "$url" ]] && continue
        ((tested++))
        if [[ "$tested" -gt "$DEFAULT_CACHE_TEST_URLS" ]]; then
            break
        fi

        local marker hdr1 hdr2 body1 body2 probe_url cache_control age xcache cf_cache_status hash1 hash2
        marker="cacheprobe$RANDOM$RANDOM"
        hdr1="${JS_DIR}/.hdr1_${tested}.tmp"
        hdr2="${JS_DIR}/.hdr2_${tested}.tmp"
        body1="${JS_DIR}/.body1_${tested}.tmp"
        body2="${JS_DIR}/.body2_${tested}.tmp"
        probe_url=$(url_with_extra_param "$url" "__cacheprobe" "$marker")

        curl -sS -L -D "$hdr1" -o "$body1" --max-time 20 --connect-timeout 8 "$url" 2>>"$LOG_FILE" || true
        curl -sS -L -D "$hdr2" -o "$body2" --max-time 20 --connect-timeout 8 \
            -H "X-Forwarded-Host: ${marker}.invalid" \
            "$probe_url" 2>>"$LOG_FILE" || true

        hash1=$(file_sha256 "$body1")
        hash2=$(file_sha256 "$body2")

        cache_control=$(header_get_ci "$hdr1" "Cache-Control")
        age=$(header_get_ci "$hdr1" "Age")
        xcache=$(header_get_ci "$hdr1" "X-Cache")
        cf_cache_status=$(header_get_ci "$hdr1" "CF-Cache-Status")

        local cache_signal reflected_marker verdict
        cache_signal="no"
        reflected_marker="no"
        verdict="low-signal"

        if echo "${cache_control} ${age} ${xcache} ${cf_cache_status}" | grep -Eqi 'public|max-age|s-maxage|hit|miss|cache'; then
            cache_signal="yes"
        fi

        if grep -qi "$marker" "$body2" 2>/dev/null || grep -qi "$marker" "$hdr2" 2>/dev/null; then
            reflected_marker="yes"
        fi

        if [[ "$cache_signal" == "yes" && "$reflected_marker" == "yes" ]]; then
            verdict="potential-unkeyed-input-cache-risk"
            echo "[POTENTIAL] ${url} | probe=${probe_url} | cache=${cache_control:-none} | x-cache=${xcache:-none} | cf-cache=${cf_cache_status:-none} | body-hash-changed=$([[ "$hash1" == "$hash2" ]] && echo "no" || echo "yes")" >> "$report"
        fi

        echo "${url} | cache_signal=${cache_signal} | reflected_marker=${reflected_marker} | verdict=${verdict}" >> "$tested_file"

        rm -f "$hdr1" "$hdr2" "$body1" "$body2" 2>/dev/null || true
    done < "$js_params"

    sort -u -o "$report" "$report" 2>/dev/null || true
    sort -u -o "$tested_file" "$tested_file" 2>/dev/null || true

    print_status "Cache-safety test URLs processed: $((tested < DEFAULT_CACHE_TEST_URLS ? tested : DEFAULT_CACHE_TEST_URLS))"
    print_status "Potential cache-risk signals: $(count_lines "$report")"
    print_finding "Safe cache check report: ${report}"
}

# ============================================================================
# FINAL REPORT GENERATION
# ============================================================================

generate_consolidated_file() {
    # ================================================================
    # FINAL CONSOLIDATED FILE
    # Master file with every subdomain, its IPs, CNAMEs, and HTTP status
    # Format: SUBDOMAIN | IPS | CNAME | HTTP_STATUS | TITLE
    # ================================================================

    print_progress "Generating consolidated master file..."

    local master_file="${OUTPUT_DIR}/FINAL_CONSOLIDATED.txt"
    local master_csv="${OUTPUT_DIR}/FINAL_CONSOLIDATED.csv"

    # Header
    printf "%-60s | %-18s | %-50s | %-6s | %s\n" \
        "SUBDOMAIN" "IP(s)" "CNAME" "STATUS" "TITLE" > "$master_file"
    printf "%s\n" "$(printf '─%.0s' {1..160})" >> "$master_file"

    echo "subdomain,ip,cname,http_status,title,technologies" > "$master_csv"

    # Build lookup tables in memory using temp files
    local tmp_ip_map="/tmp/recon_ip_map_$$.txt"
    local tmp_cname_map="/tmp/recon_cname_map_$$.txt"
    local tmp_httpx_map="/tmp/recon_httpx_map_$$.txt"

    # IP map: subdomain → IPs (comma-separated if multiple)
    if [[ -f "${DNS_DIR}/dns_a_records.txt" ]]; then
        awk '{
            host = $1
            for (i=2; i<=NF; i++) {
                gsub(/[\[\]]/, "", $i)
                if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                    if (host in ips) ips[host] = ips[host] "," $i
                    else ips[host] = $i
                }
            }
        } END {
            for (s in ips) print s "\t" ips[s]
        }' "${DNS_DIR}/dns_a_records.txt" | sort > "$tmp_ip_map" 2>/dev/null || touch "$tmp_ip_map"
    else
        touch "$tmp_ip_map"
    fi

    # CNAME map: subdomain → cname target
    if [[ -f "${DNS_DIR}/dns_cname_records.txt" ]]; then
        awk '{
            host = $1
            for (i=2; i<=NF; i++) {
                gsub(/[\[\]]/, "", $i)
                if ($i != "[CNAME]" && $i != "CNAME" && $i ~ /\./) {
                    print host "\t" $i
                    break
                }
            }
        }' "${DNS_DIR}/dns_cname_records.txt" | sort -u > "$tmp_cname_map" 2>/dev/null || touch "$tmp_cname_map"
    else
        touch "$tmp_cname_map"
    fi

    # httpx map: hostname → status,title,tech
    if [[ -f "${OUTPUT_DIR}/live_hosts_full.txt" ]]; then
        cp "${OUTPUT_DIR}/live_hosts_full.txt" "${ASN_DIR}/consolidated_httpx_input.txt" 2>/dev/null || true
        if [[ -f "${ASN_DIR}/httpx_asn_ips.txt" ]]; then
            cat "${ASN_DIR}/httpx_asn_ips.txt" >> "${ASN_DIR}/consolidated_httpx_input.txt"
        fi
        awk '{
            url = $1
            # Extract hostname from URL
            gsub(/https?:\/\//, "", url)
            gsub(/\/.*/, "", url)
            gsub(/:.*/, "", url)

            status = ""
            title = ""
            tech = ""
            for (i=2; i<=NF; i++) {
                if ($i ~ /^\[[0-9]+\]$/) {
                    gsub(/[\[\]]/, "", $i)
                    status = $i
                } else if (status != "" && title == "") {
                    gsub(/[\[\]]/, "", $i)
                    title = $i
                }
            }
            if (!(url in seen)) {
                print url "\t" status "\t" title
                seen[url] = 1
            }
        }' "${ASN_DIR}/consolidated_httpx_input.txt" | sort -u > "$tmp_httpx_map" 2>/dev/null || touch "$tmp_httpx_map"
    else
        touch "$tmp_httpx_map"
    fi

    # Iterate all subdomains and build the consolidated file
    local count=0
    while IFS= read -r subdomain || [[ -n "$subdomain" ]]; do
        [[ -z "$subdomain" ]] && continue
        ((count++)) || true

        # Lookup IP
        local ips
        ips=$(grep -m1 "^${subdomain}	" "$tmp_ip_map" 2>/dev/null | cut -f2 || echo "-")
        [[ -z "$ips" ]] && ips="-"

        # Lookup CNAME
        local cname
        cname=$(grep -m1 "^${subdomain}	" "$tmp_cname_map" 2>/dev/null | cut -f2 || echo "-")
        [[ -z "$cname" ]] && cname="-"

        # Lookup HTTP status
        local http_status http_title
        local httpx_line
        httpx_line=$(grep -m1 "^${subdomain}	" "$tmp_httpx_map" 2>/dev/null || echo "")
        if [[ -n "$httpx_line" ]]; then
            http_status=$(echo "$httpx_line" | cut -f2)
            http_title=$(echo "$httpx_line" | cut -f3)
        else
            http_status="-"
            http_title="-"
        fi
        [[ -z "$http_status" ]] && http_status="-"
        [[ -z "$http_title" ]] && http_title="-"

        # Write to text file
        printf "%-60s | %-18s | %-50s | %-6s | %s\n" \
            "$subdomain" "$ips" "$cname" "$http_status" "$http_title" >> "$master_file"

        # Write to CSV (escape commas in fields)
        local csv_title="${http_title//,/;}"
        echo "${subdomain},${ips},${cname},${http_status},${csv_title}" >> "$master_csv"

    done < "${OUTPUT_DIR}/subdomains.txt"

    # Also add ASN-discovered IPs that passed SSL ownership validation
    if [[ -f "${SSL_DIR}/ssl_validated_ips.txt" ]]; then
        echo "" >> "$master_file"
        printf "%s\n" "$(printf '─%.0s' {1..160})" >> "$master_file"
        printf "%-60s\n" "SSL-VALIDATED ASN IPs (owned by target org)" >> "$master_file"
        printf "%s\n" "$(printf '─%.0s' {1..160})" >> "$master_file"

        while IFS= read -r ip || [[ -n "$ip" ]]; do
            [[ -z "$ip" ]] && continue

            # Check if this IP is already in our subdomain map
            if ! grep -q "$ip" "$tmp_ip_map" 2>/dev/null; then
                local ip_http_status ip_http_title
                local ip_httpx_line
                ip_httpx_line=$(grep -m1 "^${ip}	" "$tmp_httpx_map" 2>/dev/null || echo "")
                if [[ -n "$ip_httpx_line" ]]; then
                    ip_http_status=$(echo "$ip_httpx_line" | cut -f2)
                    ip_http_title=$(echo "$ip_httpx_line" | cut -f3)
                else
                    ip_http_status="-"
                    ip_http_title="-"
                fi
                [[ -z "$ip_http_status" ]] && ip_http_status="-"
                [[ -z "$ip_http_title" ]] && ip_http_title="-"

                printf "%-60s | %-18s | %-50s | %-6s | %s\n" \
                    "$ip" "$ip" "-" "$ip_http_status" "$ip_http_title" >> "$master_file"

                echo "${ip},${ip},-,${ip_http_status},${ip_http_title}" >> "$master_csv"
            fi
        done < "${SSL_DIR}/ssl_validated_ips.txt"
    fi

    # Clean up temp files
    rm -f "$tmp_ip_map" "$tmp_cname_map" "$tmp_httpx_map" "${ASN_DIR}/consolidated_httpx_input.txt" 2>/dev/null || true

    print_success "Consolidated file: ${count} subdomains + ASN IPs"
    print_finding "Master TXT: ${master_file}"
    print_finding "Master CSV: ${master_csv}"
}

generate_report() {
    phase_banner "9" "REPORT GENERATION"

    # Generate consolidated master file first
    generate_consolidated_file

    local report_file="${OUTPUT_DIR}/RECON_REPORT.txt"

    {
        echo "============================================================================"
        echo "  RECONNAISSANCE REPORT"
        echo "  Generated: $(date)"
        echo "  Target file: ${TARGET_FILE}"
        echo "============================================================================"
        echo ""
        echo "TARGET DOMAINS:"
        echo "─────────────────────────────────────"
        cat "$TARGET_FILE" 2>/dev/null | grep -v '^#' | grep -v '^$'
        echo ""

        echo "============================================================================"
        echo "  SUMMARY"
        echo "============================================================================"
        echo ""
        echo "  Subdomains discovered:     $(count_lines "${OUTPUT_DIR}/subdomains.txt" 2>/dev/null || echo 0)"
        echo "  DNS resolved hosts:        $(count_lines "${OUTPUT_DIR}/resolved_hosts.txt" 2>/dev/null || echo 0)"
        echo "    ├─ A records:            $(count_lines "${DNS_DIR}/dns_a_records.txt" 2>/dev/null || echo 0)"
        echo "    ├─ AAAA records:         $(count_lines "${DNS_DIR}/dns_aaaa_records.txt" 2>/dev/null || echo 0)"
        echo "    └─ CNAME records:        $(count_lines "${DNS_DIR}/dns_cname_records.txt" 2>/dev/null || echo 0)"
        echo "  Unique IPs from DNS:       $(count_lines "${DNS_DIR}/resolved_ips.txt" 2>/dev/null || echo 0)"
        echo "  Live HTTP hosts:           $(count_lines "${OUTPUT_DIR}/live_hosts.txt" 2>/dev/null || echo 0)"
        echo "  ASN CIDR ranges:           $(count_lines "${OUTPUT_DIR}/asn_cidrs.txt" 2>/dev/null || echo 0)"
        echo "  Enumerated IPs:            $(count_lines "${OUTPUT_DIR}/asn_ips.txt" 2>/dev/null || echo 0)"
        echo "  SSL validated hosts:       $(count_lines "${SSL_DIR}/validated_hosts.txt" 2>/dev/null || echo 0)"
        echo "  SSL validated IPs:         $(count_lines "${SSL_DIR}/ssl_validated_ips.txt" 2>/dev/null || echo 0)"
        echo "  SSL rejected hosts:        $(count_lines "${SSL_DIR}/unvalidated_hosts.txt" 2>/dev/null || echo 0)"
        echo "  SSL-discovered subdomains: $(count_lines "${OUTPUT_DIR}/ssl_validated_subdomains.txt" 2>/dev/null || echo 0)"
        echo "  URL intel endpoints:       $(count_lines "${VULN_DIR}/url_intel_scoped.txt" 2>/dev/null || echo 0)"
        echo "    ├─ Parameterized URLs:   $(count_lines "${VULN_DIR}/url_intel_params.txt" 2>/dev/null || echo 0)"
        echo "    └─ JavaScript URLs:      $(count_lines "${VULN_DIR}/url_intel_js.txt" 2>/dev/null || echo 0)"
        echo "  Useful JS URLs:            $(count_lines "${JS_DIR}/js_urls_useful.txt" 2>/dev/null || echo 0)"
        echo "  JS secret findings:        $(count_lines "${JS_DIR}/js_secret_findings.txt" 2>/dev/null || echo 0)"
        echo "  S3 claimable candidates:   $(count_lines "${JS_DIR}/js_s3_claimable_candidates.txt" 2>/dev/null || echo 0)"
        echo "  JS cache-risk signals:     $(count_lines "${JS_DIR}/js_cache_poisoning_safe_report.txt" 2>/dev/null || echo 0)"
        echo ""

        if [[ -f "${VULN_DIR}/nuclei_results.jsonl" ]]; then
            echo "  VULNERABILITY FINDINGS:"
            echo "  ─────────────────────────────────────"
            echo "    Critical: $(count_lines "${VULN_DIR}/nuclei_critical.txt" 2>/dev/null || echo 0)"
            echo "    High:     $(count_lines "${VULN_DIR}/nuclei_high.txt" 2>/dev/null || echo 0)"
            echo "    Medium:   $(count_lines "${VULN_DIR}/nuclei_medium.txt" 2>/dev/null || echo 0)"
            echo "    Low:      $(count_lines "${VULN_DIR}/nuclei_low.txt" 2>/dev/null || echo 0)"
            echo "    Info:     $(count_lines "${VULN_DIR}/nuclei_info.txt" 2>/dev/null || echo 0)"
            echo ""
        fi

        echo "============================================================================"
        echo "  CONSOLIDATED MASTER LIST (Subdomain | IP | CNAME | HTTP Status)"
        echo "============================================================================"
        echo ""
        if [[ -f "${OUTPUT_DIR}/FINAL_CONSOLIDATED.txt" ]]; then
            cat "${OUTPUT_DIR}/FINAL_CONSOLIDATED.txt"
        else
            echo "  Consolidated file not generated."
        fi
        echo ""

        echo "============================================================================"
        echo "  CRITICAL & HIGH FINDINGS (DETAILS)"
        echo "============================================================================"
        echo ""

        for severity in critical high; do
            local sev_file="${VULN_DIR}/nuclei_${severity}.txt"
            if [[ -f "$sev_file" ]] && [[ $(count_lines "$sev_file") -gt 0 ]]; then
                echo "[${severity^^}]"
                echo "─────────────────────────────────────"
                cat "$sev_file"
                echo ""
            fi
        done

        echo "============================================================================"
        echo "  SSL VALIDATION REPORT"
        echo "============================================================================"
        echo ""
        if [[ -f "${SSL_DIR}/validation_report.txt" ]]; then
            cat "${SSL_DIR}/validation_report.txt"
        else
            echo "  No SSL validation data available."
        fi
        echo ""

        echo "============================================================================"
        echo "  LIVE HOSTS (HTTPX)"
        echo "============================================================================"
        echo ""
        if [[ -f "${OUTPUT_DIR}/live_hosts_full.txt" ]]; then
            cat "${OUTPUT_DIR}/live_hosts_full.txt"
        else
            echo "  No live hosts detected."
        fi
        echo ""

        echo "============================================================================"
        echo "  DNS RECORDS BREAKDOWN"
        echo "============================================================================"
        echo ""
        echo "── A Records (Subdomain → IP) ──"
        if [[ -f "${DNS_DIR}/dns_a_records.txt" ]] && [[ $(count_lines "${DNS_DIR}/dns_a_records.txt") -gt 0 ]]; then
            cat "${DNS_DIR}/dns_a_records.txt"
        else
            echo "  No A records."
        fi
        echo ""
        echo "── CNAME Records (Subdomain → Canonical Name) ──"
        if [[ -f "${DNS_DIR}/dns_cname_records.txt" ]] && [[ $(count_lines "${DNS_DIR}/dns_cname_records.txt") -gt 0 ]]; then
            cat "${DNS_DIR}/dns_cname_records.txt"
        else
            echo "  No CNAME records."
        fi
        echo ""
        echo "── Subdomain → IP Mapping ──"
        if [[ -f "${DNS_DIR}/subdomain_ip_map.txt" ]] && [[ $(count_lines "${DNS_DIR}/subdomain_ip_map.txt") -gt 0 ]]; then
            echo "SUBDOMAIN	IP_ADDRESS"
            cat "${DNS_DIR}/subdomain_ip_map.txt"
        else
            echo "  No mapping data."
        fi
        echo ""
        echo "── IP → Subdomain Reverse Mapping ──"
        if [[ -f "${DNS_DIR}/ip_subdomain_map.txt" ]] && [[ $(count_lines "${DNS_DIR}/ip_subdomain_map.txt") -gt 0 ]]; then
            echo "IP_ADDRESS	SUBDOMAIN"
            cat "${DNS_DIR}/ip_subdomain_map.txt"
        else
            echo "  No reverse mapping data."
        fi
        echo ""

        echo "============================================================================"
        echo "  ASN INFORMATION"
        echo "============================================================================"
        echo ""
        if [[ -f "${ASN_DIR}/asn_info.txt" ]] && [[ $(count_lines "${ASN_DIR}/asn_info.txt") -gt 0 ]]; then
            echo "ASN_NUMBER	ASN_NAME	COUNTRY	IP_RANGE"
            cat "${ASN_DIR}/asn_info.txt"
        else
            echo "  No ASN data available."
        fi
        echo ""

        echo "============================================================================"
        echo "  JAVASCRIPT SECURITY ANALYSIS"
        echo "============================================================================"
        echo ""
        echo "── Secret Findings (high-signal) ──"
        if [[ -f "${JS_DIR}/js_secret_findings.txt" ]] && [[ $(count_lines "${JS_DIR}/js_secret_findings.txt") -gt 0 ]]; then
            cat "${JS_DIR}/js_secret_findings.txt"
        else
            echo "  No JS secret findings."
        fi
        echo ""
        echo "── S3 Claimable Candidates ──"
        if [[ -f "${JS_DIR}/js_s3_claimable_candidates.txt" ]] && [[ $(count_lines "${JS_DIR}/js_s3_claimable_candidates.txt") -gt 0 ]]; then
            cat "${JS_DIR}/js_s3_claimable_candidates.txt"
        else
            echo "  No claimable S3 candidates detected."
        fi
        echo ""
        echo "── Safe Cache-Poisoning Risk Signals ──"
        if [[ -f "${JS_DIR}/js_cache_poisoning_safe_report.txt" ]] && [[ $(count_lines "${JS_DIR}/js_cache_poisoning_safe_report.txt") -gt 0 ]]; then
            cat "${JS_DIR}/js_cache_poisoning_safe_report.txt"
        else
            echo "  No cache-risk signals detected in safe checks."
        fi
        echo ""

        echo "============================================================================"
        echo "  OUTPUT FILES"
        echo "============================================================================"
        echo ""
        echo "  ${OUTPUT_DIR}/"
        find "$OUTPUT_DIR" -type f -name "*.txt" -o -name "*.jsonl" -o -name "*.log" \
            | sort | sed "s|${OUTPUT_DIR}/|    |"
        echo ""
        echo "============================================================================"
        echo "  END OF REPORT"
        echo "============================================================================"

    } > "$report_file"

    print_success "Report generated: ${report_file}"
}

# ============================================================================
# USAGE & ARGUMENT PARSING
# ============================================================================

usage() {
    echo -e "${BOLD}Usage:${NC} $0 [OPTIONS]"
    echo ""
    echo -e "${BOLD}Required:${NC}"
    echo "  -f, --file FILE          Input file with root domains (one per line)"
    echo ""
    echo -e "${BOLD}Options:${NC}"
    echo "  -o, --output DIR         Output directory (default: ./recon_results_TIMESTAMP)"
    echo "  -r, --rate-limit N       Nuclei rate limit in req/s (default: ${DEFAULT_RATE_LIMIT})"
    echo "  -t, --threads N          Default thread count (default: ${DEFAULT_THREADS})"
    echo "      --enum-jobs N        Parallel root-domain enum workers (default: ${DEFAULT_ENUM_JOBS})"
    echo "      --crawl-depth N      URL crawl depth for katana/hakrawler (default: ${DEFAULT_URL_CRAWL_DEPTH})"
    echo "  -p, --ports PORTS        Comma-separated ports for naabu (default: ${DEFAULT_PORTS})"
    echo "      --top-ports N        Use naabu top-ports mode instead of port list"
    echo "      --phase N            Run only specific phase (1-8, or 4b/4c)"
    echo "      --skip-nuclei        Skip vulnerability scanning (Phase 5)"
    echo "      --nuclei-severity S  Nuclei severity filter (default: info,low,medium,high,critical)"
    echo "  -h, --help               Show this help message"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  $0 -f targets.txt"
    echo "  $0 -f targets.txt -o ./results -r 100"
    echo "  $0 -f targets.txt --phase 1"
    echo "  $0 -f targets.txt --phase 6"
    echo "  $0 -f targets.txt --phase 4c"
    echo "  $0 -f targets.txt --enum-jobs 8 --crawl-depth 3"
    echo "  $0 -f targets.txt --skip-nuclei"
    echo "  $0 -f targets.txt --top-ports 1000"
    echo ""
    echo -e "${BOLD}Input File Format:${NC}"
    echo "  One root domain per line. Lines starting with # are comments."
    echo "  Example:"
    echo "    example.com"
    echo "    target.org"
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    banner

    # Parse arguments
    TARGET_FILE=""
    OUTPUT_DIR=""
    RATE_LIMIT="$DEFAULT_RATE_LIMIT"
    THREADS="$DEFAULT_THREADS"
    ENUM_JOBS="$DEFAULT_ENUM_JOBS"
    URL_CRAWL_DEPTH="$DEFAULT_URL_CRAWL_DEPTH"
    SPECIFIC_PHASE=""
    SKIP_NUCLEI=false
    NUCLEI_SEVERITY="info,low,medium,high,critical"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -f|--file)
                TARGET_FILE="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -r|--rate-limit)
                RATE_LIMIT="$2"
                shift 2
                ;;
            -t|--threads)
                THREADS="$2"
                DEFAULT_THREADS="$2"
                DEFAULT_HTTPX_THREADS="$2"
                DEFAULT_DNSX_THREADS="$2"
                shift 2
                ;;
            --enum-jobs)
                ENUM_JOBS="$2"
                shift 2
                ;;
            --crawl-depth)
                URL_CRAWL_DEPTH="$2"
                DEFAULT_URL_CRAWL_DEPTH="$2"
                shift 2
                ;;
            -p|--ports)
                DEFAULT_PORTS="$2"
                shift 2
                ;;
            --top-ports)
                NAABU_TOP_PORTS="$2"
                shift 2
                ;;
            --phase)
                SPECIFIC_PHASE="$2"
                shift 2
                ;;
            --skip-nuclei)
                SKIP_NUCLEI=true
                shift
                ;;
            --nuclei-severity)
                NUCLEI_SEVERITY="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo -e "${CROSS} Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Validate input
    if [[ -z "$TARGET_FILE" ]]; then
        echo -e "${CROSS} Error: Target file is required (-f flag)"
        echo ""
        usage
        exit 1
    fi

    if [[ ! -f "$TARGET_FILE" ]]; then
        echo -e "${CROSS} Error: Target file not found: ${TARGET_FILE}"
        exit 1
    fi

    # Resolve to absolute path
    TARGET_FILE="$(cd "$(dirname "$TARGET_FILE")" && pwd)/$(basename "$TARGET_FILE")"

    local domain_count
    domain_count=$(grep -cve '^\s*$' -e '^\s*#' "$TARGET_FILE" || echo "0")
    if [[ "$domain_count" -eq 0 ]]; then
        echo -e "${CROSS} Error: No valid domains found in ${TARGET_FILE}"
        exit 1
    fi

    if ! [[ "$ENUM_JOBS" =~ ^[0-9]+$ ]] || [[ "$ENUM_JOBS" -lt 1 ]]; then
        echo -e "${CROSS} Error: --enum-jobs must be a positive integer"
        exit 1
    fi

    if ! [[ "$URL_CRAWL_DEPTH" =~ ^[0-9]+$ ]] || [[ "$URL_CRAWL_DEPTH" -lt 1 ]]; then
        echo -e "${CROSS} Error: --crawl-depth must be a positive integer"
        exit 1
    fi

    # Set output directory
    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="$DEFAULT_OUTPUT_DIR"
    fi

    # Create directory structure
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

    SUBS_DIR="${OUTPUT_DIR}/phase1_subdomains"
    DNS_DIR="${OUTPUT_DIR}/phase2_dns"
    ASN_DIR="${OUTPUT_DIR}/phase3_asn"
    SSL_DIR="${OUTPUT_DIR}/phase4_ssl"
    VULN_DIR="${OUTPUT_DIR}/phase5_vulns"
    JS_DIR="${OUTPUT_DIR}/phase6_js"

    mkdir -p "$SUBS_DIR" "$DNS_DIR" "$ASN_DIR" "$SSL_DIR" "$VULN_DIR" "$JS_DIR"

    # Initialize logging
    log_init

    # Print scan config
    echo -e "${BOLD}${WHITE}Scan Configuration:${NC}"
    echo -e "  Target file:    ${TARGET_FILE}"
    echo -e "  Domains:        ${domain_count}"
    echo -e "  Output:         ${OUTPUT_DIR}"
    echo -e "  Rate limit:     ${RATE_LIMIT} req/s"
    echo -e "  Threads:        ${THREADS}"
    echo -e "  Enum jobs:      ${ENUM_JOBS}"
    echo -e "  Crawl depth:    ${URL_CRAWL_DEPTH}"
    echo -e "  Ports:          ${NAABU_TOP_PORTS:+top-${NAABU_TOP_PORTS}}${NAABU_TOP_PORTS:-${DEFAULT_PORTS}}"
    echo -e "  Skip nuclei:    ${SKIP_NUCLEI}"
    echo ""

    log "INFO" "Scan started with config: domains=${domain_count}, rate_limit=${RATE_LIMIT}, threads=${THREADS}"

    local start_time
    start_time=$(date +%s)

    # Tool verification
    if ! check_tools; then
        echo -e "${CROSS} Cannot proceed without required tools. Please install them first."
        exit 1
    fi

    # Run phases
    if [[ -n "$SPECIFIC_PHASE" ]]; then
        case "$SPECIFIC_PHASE" in
            1)  phase1_subdomain_enumeration ;;
            2)  phase2_dns_and_livehost ;;
            3)  phase3_asn_discovery ;;
            4)  phase4_ssl_validation ;;
            4b|4B) phase4b_rescan_ssl_discoveries ;;
            4c|4C) phase4c_final_httpx_probe ;;
            5)  phase5_vulnerability_scan ;;
            6)  phase6_js_discovery ;;
            7)  phase7_js_security_scan ;;
            8)  phase8_cache_poisoning_safe ;;
            *)
                echo -e "${CROSS} Invalid phase: ${SPECIFIC_PHASE}. Use 1-8 or 4b/4c."
                exit 1
                ;;
        esac
    else
        phase1_subdomain_enumeration
        phase2_dns_and_livehost
        phase3_asn_discovery
        phase4_ssl_validation
        phase4b_rescan_ssl_discoveries
        phase4c_final_httpx_probe

        if [[ "$SKIP_NUCLEI" == false ]]; then
            phase5_vulnerability_scan
        else
            print_warning "Skipping nuclei vulnerability scan (--skip-nuclei flag)"
        fi
        phase6_js_discovery
        phase7_js_security_scan
        phase8_cache_poisoning_safe
    fi

    # Generate report
    generate_report

    # Final summary
    local end_time
    end_time=$(date +%s)
    local duration=$(( end_time - start_time ))
    local minutes=$(( duration / 60 ))
    local seconds=$(( duration % 60 ))

    echo ""
    echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${GREEN}║  RECONNAISSANCE COMPLETE                                     ║${NC}"
    echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${CYAN}Duration:${NC}  ${minutes}m ${seconds}s"
    echo -e "  ${CYAN}Results:${NC}   ${OUTPUT_DIR}"
    echo -e "  ${CYAN}Report:${NC}    ${OUTPUT_DIR}/RECON_REPORT.txt"
    echo -e "  ${CYAN}Log:${NC}       ${OUTPUT_DIR}/recon.log"
    echo ""

    log "INFO" "Scan completed in ${minutes}m ${seconds}s"
}

main "$@"
