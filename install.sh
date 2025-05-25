#!/bin/bash

set -e

GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m' 
SHELL_NAME=$(basename "$SHELL")
CONFIG_FILE="$HOME/.${SHELL_NAME}rc"

echo -e "${BLUE}[i] Detected shell: ${YELLOW}$SHELL_NAME${NC}"
echo -e "${BLUE}[i] Using config file: ${YELLOW}$CONFIG_FILE${NC}"

echo -e "${YELLOW}[+] Installing packer...${NC}"
sudo apt update -y
sudo apt install -y upx-ucl
chmod +x src/garble/garble

# Install Python and pip
echo -e "${YELLOW}[+] Installing Python and pip...${NC}"
sudo apt install -y python3 python3-pip
pip3 install --user filetype

INSTALL_GO=false
REQUIRED_GO_VERSION="1.24.0"

if command -v go &>/dev/null; then
    CURRENT_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    echo -e "${BLUE}[i] Found Go version: ${YELLOW}$CURRENT_GO_VERSION${NC}"

    if [ "$(printf '%s\n' "$REQUIRED_GO_VERSION" "$CURRENT_GO_VERSION" | sort -V | head -n1)" != "$REQUIRED_GO_VERSION" ]; then
        echo -e "${BLUE}[i] Go version is sufficient (>= $REQUIRED_GO_VERSION), skipping installation.${NC}"
    else
        INSTALL_GO=true
    fi
else
    echo -e "${YELLOW}[!] Go not found. Will install Go $REQUIRED_GO_VERSION...${NC}"
    INSTALL_GO=true
fi

if [ "$INSTALL_GO" = true ]; then
    cdirect=$(pwd)
    GO_VERSION="1.24.2"
    GO_ARCHIVE="go${GO_VERSION}.linux-amd64.tar.gz"
    GO_URL="https://go.dev/dl/${GO_ARCHIVE}"

    echo -e "${YELLOW}[+] Installing Go ${GO_VERSION}...${NC}"
    sudo rm $(which go)
    cd /tmp
    wget -q --show-progress ${GO_URL}
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf ${GO_ARCHIVE}

    # Add Go to PATH if not already present
    if ! grep -q '/usr/local/go/bin' "$CONFIG_FILE"; then
        echo -e "${BLUE}[i] Adding Go to PATH in ${CONFIG_FILE}...${NC}"
        echo 'export PATH=$PATH:/usr/local/go/bin' >> "$CONFIG_FILE"
    fi
    export PATH=$PATH:/usr/local/go/bin
    if [[ "$SHELL" == *"bash" ]]; then
        source ~/.bashrc
    elif [[ "$SHELL" == *"zsh" ]]; then
        source ~/.zshrc
    fi

    cd "$cdirect"
fi

# Verify Go installation
echo -e "${BLUE}[i] Verifying Go installation...${NC}"
go version
echo -e "${BLUE}[i] Romoving Go old Version...${NC}"

if [ -f "go.mod" ]; then
    echo -e "${YELLOW}[+] Tidying Go modules...${NC}"
    go mod tidy
else
    echo -e "${YELLOW}[!] Skipping 'go mod tidy': no go.mod found in current directory.${NC}"
fi

echo -e "${GREEN}[✓] Setup completed successfully.${NC}"
echo -e "${BLUE}[i] You can now run the teamserver using:${NC} ${YELLOW}sudo ./mbeubeu-teamserver -h${NC}"
