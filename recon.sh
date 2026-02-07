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
    sed -i '/^$/d' "$output" 2>/dev/null || true
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

        echo ""
        echo -e "${BOLD}${WHITE}── Target: ${domain} ──${NC}"

        # Run all enumeration sources
        run_subfinder "$domain"
        run_assetfinder "$domain"
        run_amass_passive "$domain"
        run_crtsh "$domain"
        run_chaos "$domain"

    done < "$TARGET_FILE"

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
    sed -i '/^$/d' "${OUTPUT_DIR}/subdomains.txt" 2>/dev/null || true

    local final_count
    final_count=$(count_lines "${OUTPUT_DIR}/subdomains.txt")

    echo ""
    print_success "Phase 1 Complete: ${final_count} unique subdomains discovered"
    print_finding "Results saved to: ${OUTPUT_DIR}/subdomains.txt"
}

# ============================================================================
# PHASE 2: DNS RESOLUTION & LIVE HOST DETECTION
# ============================================================================

phase2_dns_and_livehost() {
    phase_banner "2" "DNS RESOLUTION & LIVE HOST DETECTION"

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

    # Extract just the hostnames that resolved
    if [[ -f "${DNS_DIR}/dnsx_resolved.txt" ]]; then
        awk '{print $1}' "${DNS_DIR}/dnsx_resolved.txt" \
            | sort -u > "${OUTPUT_DIR}/resolved_hosts.txt"
    else
        touch "${OUTPUT_DIR}/resolved_hosts.txt"
    fi

    local resolved_count
    resolved_count=$(count_lines "${OUTPUT_DIR}/resolved_hosts.txt")
    print_status "DNS resolved: ${resolved_count} hosts have valid DNS records"

    # --- Extract IPs from DNS results ---
    print_progress "Extracting IP addresses from DNS results..."

    grep -oP '\d+\.\d+\.\d+\.\d+' "${DNS_DIR}/dnsx_resolved.txt" 2>/dev/null \
        | sort -u > "${DNS_DIR}/resolved_ips.txt" || touch "${DNS_DIR}/resolved_ips.txt"

    local ip_count
    ip_count=$(count_lines "${DNS_DIR}/resolved_ips.txt")
    print_status "Extracted ${ip_count} unique IP addresses from DNS"

    # --- Live Host Detection with httpx ---
    print_progress "Probing for live HTTP/HTTPS services with httpx..."

    httpx -l "${OUTPUT_DIR}/resolved_hosts.txt" \
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
        2>>"$LOG_FILE" || true

    # Extract live host URLs
    if [[ -f "${DNS_DIR}/httpx_results.txt" ]]; then
        awk '{print $1}' "${DNS_DIR}/httpx_results.txt" \
            | sort -u > "${OUTPUT_DIR}/live_hosts.txt"
        cp "${DNS_DIR}/httpx_results.txt" "${OUTPUT_DIR}/live_hosts_full.txt"
    else
        touch "${OUTPUT_DIR}/live_hosts.txt"
        touch "${OUTPUT_DIR}/live_hosts_full.txt"
    fi

    local live_count
    live_count=$(count_lines "${OUTPUT_DIR}/live_hosts.txt")

    echo ""
    print_success "Phase 2 Complete: ${resolved_count} resolved, ${live_count} live hosts"
    print_finding "Live hosts: ${OUTPUT_DIR}/live_hosts.txt"
    print_finding "Full httpx output: ${OUTPUT_DIR}/live_hosts_full.txt"
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
            | grep -oP '\d+\.\d+\.\d+\.\d+/\d+' \
            | sort -u >> "$outfile" 2>/dev/null || true
    fi
}

validate_asn_ownership() {
    local asn="$1"
    local target_org="$2"

    # Validate the ASN actually belongs to the target org via whois
    local whois_data
    whois_data=$(whois "$asn" 2>/dev/null | head -50 || echo "")

    if echo "$whois_data" | grep -qi "$target_org" 2>/dev/null; then
        return 0  # Matches
    fi
    return 1  # Does not match
}

phase3_asn_discovery() {
    phase_banner "3" "ASN DISCOVERY & IP ENUMERATION"

    mkdir -p "$ASN_DIR"

    # --- Derive organization name from target domains ---
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
        | sort -u > "${ASN_DIR}/asnmap_results.txt" || touch "${ASN_DIR}/asnmap_results.txt"

    # Also map domains directly
    if [[ -f "$TARGET_FILE" ]]; then
        asnmap -d "$(paste -sd, "$TARGET_FILE")" \
            -silent \
            2>>"$LOG_FILE" \
            | sort -u >> "${ASN_DIR}/asnmap_results.txt" || true
        sort -u -o "${ASN_DIR}/asnmap_results.txt" "${ASN_DIR}/asnmap_results.txt"
    fi

    local asn_count
    asn_count=$(count_lines "${ASN_DIR}/asnmap_results.txt")
    print_status "asnmap discovered ${asn_count} CIDR ranges"

    # --- Extract unique ASNs ---
    print_progress "Extracting unique ASN numbers..."

    # Try to get ASN numbers from asnmap's JSON mode
    asnmap -i "$ip_file" \
        -json \
        -silent \
        2>>"$LOG_FILE" \
        | jq -r '.as_number // empty' 2>/dev/null \
        | sort -u > "${ASN_DIR}/unique_asns.txt" || touch "${ASN_DIR}/unique_asns.txt"

    # Also extract ASN info for reporting
    asnmap -i "$ip_file" \
        -json \
        -silent \
        2>>"$LOG_FILE" \
        | jq -r '[.as_number, .as_name, .as_country, .first_ip + "-" + .last_ip] | @tsv' 2>/dev/null \
        | sort -u > "${ASN_DIR}/asn_info.txt" || touch "${ASN_DIR}/asn_info.txt"

    # --- Extract organization names for validation ---
    local org_names=()
    while IFS= read -r domain || [[ -n "$domain" ]]; do
        domain=$(echo "$domain" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
        [[ -z "$domain" || "$domain" == \#* ]] && continue

        # Try whois to get org name
        local org
        org=$(whois "$domain" 2>/dev/null \
            | grep -i "^org\|^registrant.*org\|^OrgName" \
            | head -1 \
            | sed 's/^[^:]*:\s*//' \
            | tr -d '[:space:]' || echo "")

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

    # --- BGP.he.net enrichment ---
    print_progress "Enriching ASN data from BGP.he.net..."

    : > "${ASN_DIR}/bgp_cidrs.txt"
    while IFS= read -r asn || [[ -n "$asn" ]]; do
        [[ -z "$asn" ]] && continue
        asn=$(echo "$asn" | grep -oP 'AS\d+' || echo "$asn")
        [[ -z "$asn" ]] && continue

        print_status "  Querying BGP.he.net for ${asn}..."
        query_bgp_he_net "$asn" "${ASN_DIR}/bgp_cidrs.txt"
        sleep 1  # Rate limiting for BGP.he.net
    done < "${ASN_DIR}/unique_asns.txt"

    local bgp_count
    bgp_count=$(count_lines "${ASN_DIR}/bgp_cidrs.txt")
    print_status "BGP.he.net returned ${bgp_count} CIDR ranges"

    # --- Merge all CIDR ranges ---
    print_progress "Merging all discovered CIDR ranges..."

    merge_files "${OUTPUT_DIR}/asn_cidrs.txt" \
        "${ASN_DIR}/asnmap_results.txt" \
        "${ASN_DIR}/bgp_cidrs.txt"

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
    else
        cp "$ip_file" "${OUTPUT_DIR}/asn_ips.txt" 2>/dev/null || touch "${OUTPUT_DIR}/asn_ips.txt"
    fi

    local total_ips
    total_ips=$(count_lines "${OUTPUT_DIR}/asn_ips.txt")

    echo ""
    print_success "Phase 3 Complete: ${total_cidrs} CIDRs, ${total_ips} IPs enumerated"
    print_finding "CIDR ranges: ${OUTPUT_DIR}/asn_cidrs.txt"
    print_finding "IP addresses: ${OUTPUT_DIR}/asn_ips.txt"
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
    sed -i '/^$/d' "${SSL_DIR}/tlsx_targets.txt" 2>/dev/null || true

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

    # Deduplicate and filter SSL-discovered subdomains
    if [[ -f "${OUTPUT_DIR}/ssl_validated_subdomains.txt" ]]; then
        sort -u -o "${OUTPUT_DIR}/ssl_validated_subdomains.txt" "${OUTPUT_DIR}/ssl_validated_subdomains.txt"
        sed -i '/^$/d' "${OUTPUT_DIR}/ssl_validated_subdomains.txt" 2>/dev/null || true

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

    echo ""
    echo -e "${BOLD}${WHITE}── SSL Validation Summary ──${NC}"
    echo -e "  ${GREEN}Validated:${NC}  ${validated} certificates match target org"
    echo -e "  ${RED}Rejected:${NC}   ${rejected} certificates do NOT match"
    echo -e "  ${CYAN}Total:${NC}      ${total_certs} certificates analyzed"
    echo ""
    print_success "Phase 4 Complete: SSL certificate validation finished"
    print_finding "Validation report: ${SSL_DIR}/validation_report.txt"
    print_finding "Validated hosts: ${SSL_DIR}/validated_hosts.txt"
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
    sed -i '/^$/d' "${SSL_DIR}/rescan_scoped_subs.txt" 2>/dev/null || true

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
            grep -oP '\d+\.\d+\.\d+\.\d+' "${SSL_DIR}/rescan_dnsx.txt" 2>/dev/null \
                | sort -u > "${SSL_DIR}/rescan_ips.txt" || touch "${SSL_DIR}/rescan_ips.txt"

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
    # STEP 3: HTTP probing on new resolved hosts (Phase 2 re-run)
    # ─────────────────────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}${WHITE}── Step 3: HTTP/HTTPS probing on new hosts ──${NC}"

    # Only probe hosts not already in live_hosts
    local unprobed="${SSL_DIR}/rescan_unprobed.txt"
    if [[ -f "${SSL_DIR}/rescan_resolved.txt" ]]; then
        if [[ -f "${OUTPUT_DIR}/live_hosts.txt" ]]; then
            # Extract hostnames from live_hosts URLs for comparison
            local existing_live_domains="${SSL_DIR}/existing_live_domains.txt"
            sed -e 's|https\?://||' -e 's|/.*||' -e 's|:.*||' \
                "${OUTPUT_DIR}/live_hosts.txt" \
                | sort -u > "$existing_live_domains" 2>/dev/null || touch "$existing_live_domains"

            comm -23 \
                <(sort -u "${SSL_DIR}/rescan_resolved.txt") \
                <(sort -u "$existing_live_domains") \
                > "$unprobed" 2>/dev/null || touch "$unprobed"
        else
            cp "${SSL_DIR}/rescan_resolved.txt" "$unprobed"
        fi
    else
        touch "$unprobed"
    fi

    local unprobed_count
    unprobed_count=$(count_lines "$unprobed")

    if [[ "$unprobed_count" -gt 0 ]]; then
        print_progress "Probing ${unprobed_count} new hosts with httpx..."

        httpx -l "$unprobed" \
            -silent \
            -threads "$DEFAULT_HTTPX_THREADS" \
            -status-code \
            -title \
            -tech-detect \
            -content-length \
            -follow-redirects \
            -timeout 10 \
            -retries 2 \
            -o "${SSL_DIR}/rescan_httpx.txt" \
            2>>"$LOG_FILE" || touch "${SSL_DIR}/rescan_httpx.txt"

        if [[ -f "${SSL_DIR}/rescan_httpx.txt" ]]; then
            local new_live
            new_live=$(count_lines "${SSL_DIR}/rescan_httpx.txt")
            print_status "httpx found ${new_live} new live hosts"

            # Extract URLs and merge into master live_hosts
            awk '{print $1}' "${SSL_DIR}/rescan_httpx.txt" \
                | sort -u >> "${OUTPUT_DIR}/live_hosts.txt"
            sort -u -o "${OUTPUT_DIR}/live_hosts.txt" "${OUTPUT_DIR}/live_hosts.txt"

            # Merge full httpx output
            cat "${SSL_DIR}/rescan_httpx.txt" >> "${OUTPUT_DIR}/live_hosts_full.txt"
            sort -u -o "${OUTPUT_DIR}/live_hosts_full.txt" "${OUTPUT_DIR}/live_hosts_full.txt"
        fi
    else
        print_status "All new hosts were already probed. Skipping httpx."
    fi

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
    print_success "Phase 4B Complete: SSL feedback loop finished — all new subs resolved & probed"
}

# ============================================================================
# PHASE 5: VULNERABILITY SCANNING
# ============================================================================

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

    sort -u -o "${VULN_DIR}/nuclei_targets.txt" "${VULN_DIR}/nuclei_targets.txt"
    sed -i '/^$/d' "${VULN_DIR}/nuclei_targets.txt" 2>/dev/null || true

    local target_count
    target_count=$(count_lines "${VULN_DIR}/nuclei_targets.txt")

    if [[ "$target_count" -eq 0 ]]; then
        print_warning "No targets available for vulnerability scanning"
        return
    fi

    print_status "Scanning ${target_count} targets with nuclei..."
    print_status "Rate limit: ${RATE_LIMIT} requests/second"
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
        -severity info,low,medium,high,critical \
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
# FINAL REPORT GENERATION
# ============================================================================

generate_report() {
    phase_banner "6" "REPORT GENERATION"

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
        echo "  Live HTTP hosts:           $(count_lines "${OUTPUT_DIR}/live_hosts.txt" 2>/dev/null || echo 0)"
        echo "  ASN CIDR ranges:           $(count_lines "${OUTPUT_DIR}/asn_cidrs.txt" 2>/dev/null || echo 0)"
        echo "  Enumerated IPs:            $(count_lines "${OUTPUT_DIR}/asn_ips.txt" 2>/dev/null || echo 0)"
        echo "  SSL validated hosts:       $(count_lines "${SSL_DIR}/validated_hosts.txt" 2>/dev/null || echo 0)"
        echo "  SSL rejected hosts:        $(count_lines "${SSL_DIR}/unvalidated_hosts.txt" 2>/dev/null || echo 0)"
        echo "  SSL-discovered subdomains: $(count_lines "${OUTPUT_DIR}/ssl_validated_subdomains.txt" 2>/dev/null || echo 0)"
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
    echo "  -p, --ports PORTS        Comma-separated ports for naabu (default: ${DEFAULT_PORTS})"
    echo "      --top-ports N        Use naabu top-ports mode instead of port list"
    echo "      --phase N            Run only specific phase (1-5, or 4b for SSL re-scan)"
    echo "      --skip-nuclei        Skip vulnerability scanning (Phase 5)"
    echo "      --nuclei-severity S  Nuclei severity filter (default: info,low,medium,high,critical)"
    echo "  -h, --help               Show this help message"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  $0 -f targets.txt"
    echo "  $0 -f targets.txt -o ./results -r 100"
    echo "  $0 -f targets.txt --phase 1"
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

    mkdir -p "$SUBS_DIR" "$DNS_DIR" "$ASN_DIR" "$SSL_DIR" "$VULN_DIR"

    # Initialize logging
    log_init

    # Print scan config
    echo -e "${BOLD}${WHITE}Scan Configuration:${NC}"
    echo -e "  Target file:    ${TARGET_FILE}"
    echo -e "  Domains:        ${domain_count}"
    echo -e "  Output:         ${OUTPUT_DIR}"
    echo -e "  Rate limit:     ${RATE_LIMIT} req/s"
    echo -e "  Threads:        ${THREADS}"
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
            5)  phase5_vulnerability_scan ;;
            *)
                echo -e "${CROSS} Invalid phase: ${SPECIFIC_PHASE}. Use 1-5 or 4b."
                exit 1
                ;;
        esac
    else
        phase1_subdomain_enumeration
        phase2_dns_and_livehost
        phase3_asn_discovery
        phase4_ssl_validation
        phase4b_rescan_ssl_discoveries

        if [[ "$SKIP_NUCLEI" == false ]]; then
            phase5_vulnerability_scan
        else
            print_warning "Skipping nuclei vulnerability scan (--skip-nuclei flag)"
        fi
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
