#!/usr/bin/env bash
# ============================================================================
# GhostShift Recon - Tool Installer
# ============================================================================
# Installs all required and optional tools for recon.sh
# Requires: Go 1.21+, sudo access for system packages
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════════╗"
echo "║  GhostShift Recon - Tool Installer           ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# Check Go
if ! command -v go &>/dev/null; then
    echo -e "${RED}[✗] Go is not installed. Please install Go 1.21+ first:${NC}"
    echo "    https://go.dev/dl/"
    exit 1
fi

GO_VERSION=$(go version | grep -oP '\d+\.\d+' | head -1)
echo -e "${GREEN}[✓]${NC} Go ${GO_VERSION} detected"
echo ""

# Ensure GOPATH/bin is in PATH
export PATH=$PATH:$(go env GOPATH)/bin

install_go_tool() {
    local name="$1"
    local pkg="$2"
    local required="${3:-required}"

    if command -v "$name" &>/dev/null; then
        echo -e "${GREEN}[✓]${NC} ${name} already installed"
        return
    fi

    echo -e "${CYAN}[→]${NC} Installing ${name}..."
    if go install -v "$pkg" 2>/dev/null; then
        echo -e "${GREEN}[✓]${NC} ${name} installed successfully"
    else
        if [[ "$required" == "optional" ]]; then
            echo -e "${YELLOW}[!]${NC} ${name} failed to install (optional, skipping)"
        else
            echo -e "${RED}[✗]${NC} ${name} failed to install"
        fi
    fi
}

echo -e "${BOLD}── Installing Required Tools ──${NC}"
echo ""

install_go_tool "subfinder"  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "dnsx"       "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
install_go_tool "httpx"      "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "tlsx"       "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
install_go_tool "naabu"      "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
install_go_tool "nuclei"     "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_tool "mapcidr"    "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
install_go_tool "asnmap"     "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"

echo ""
echo -e "${BOLD}── Installing Optional Tools ──${NC}"
echo ""

install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest" "optional"
install_go_tool "anew"        "github.com/tomnomnom/anew@latest" "optional"

echo ""
echo -e "${BOLD}── Installing System Dependencies ──${NC}"
echo ""

for pkg in jq curl whois; do
    if command -v "$pkg" &>/dev/null; then
        echo -e "${GREEN}[✓]${NC} ${pkg} already installed"
    else
        echo -e "${CYAN}[→]${NC} Installing ${pkg}..."
        if sudo apt install -y "$pkg" 2>/dev/null; then
            echo -e "${GREEN}[✓]${NC} ${pkg} installed"
        elif sudo yum install -y "$pkg" 2>/dev/null; then
            echo -e "${GREEN}[✓]${NC} ${pkg} installed"
        elif brew install "$pkg" 2>/dev/null; then
            echo -e "${GREEN}[✓]${NC} ${pkg} installed"
        else
            echo -e "${RED}[✗]${NC} Failed to install ${pkg}. Please install manually."
        fi
    fi
done

echo ""
echo -e "${BOLD}── Updating Nuclei Templates ──${NC}"
echo ""

if command -v nuclei &>/dev/null; then
    nuclei -update-templates 2>/dev/null || echo -e "${YELLOW}[!]${NC} Template update failed (run manually: nuclei -update-templates)"
fi

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║  Installation Complete!                      ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Run ${CYAN}./recon.sh -f targets.txt${NC} to start scanning."
echo ""
echo -e "${YELLOW}Note:${NC} Ensure \$(go env GOPATH)/bin is in your PATH:"
echo "  export PATH=\$PATH:\$(go env GOPATH)/bin"
