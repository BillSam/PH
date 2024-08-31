#!/bin/bash

# Piga Hacks - Tool Installation Script

# Function to check if a command exists
function command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install a tool if it doesn't exist
function install_tool() {
    local tool_name=$1
    local install_command=$2

    if command_exists $tool_name; then
        echo "[+] $tool_name is already installed."
    else
        echo "[+] Installing $tool_name..."
        eval $install_command
    fi
}

# Update and upgrade system packages
sudo apt-get update -y && sudo apt-get upgrade -y

# Install dependencies
sudo apt-get install -y git curl python3-pip nmap masscan gnome-terminal

# Install subfinder
install_tool "subfinder" "GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && sudo cp ~/go/bin/subfinder /usr/local/bin/"

# Install assetfinder
install_tool "assetfinder" "GO111MODULE=on go install -v github.com/tomnomnom/assetfinder@latest && sudo cp ~/go/bin/assetfinder /usr/local/bin/"

# Install amass
install_tool "amass" "sudo apt-get install -y amass"

# Install github-subdomains
install_tool "github-subdomains" "pip3 install github-subdomains"

# Install chaos
install_tool "chaos" "GO111MODULE=on go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest && sudo cp ~/go/bin/chaos /usr/local/bin/"

# Install dnsenum
install_tool "dnsenum" "sudo apt-get install -y dnsenum"

# Install dnsrecon
install_tool "dnsrecon" "sudo apt-get install -y dnsrecon"

# Install dnsx
install_tool "dnsx" "GO111MODULE=on go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && sudo cp ~/go/bin/dnsx /usr/local/bin/"

# Install host (part of dnsutils)
install_tool "host" "sudo apt-get install -y dnsutils"

# Install nmap
install_tool "nmap" "sudo apt-get install -y nmap"

# Install masscan
install_tool "masscan" "sudo apt-get install -y masscan"

# Install rustscan
install_tool "rustscan" "curl https://sh.rustup.rs -sSf | sh && sudo apt-get install -y rustscan"

# Install httpx
install_tool "httpx" "GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && sudo cp ~/go/bin/httpx /usr/local/bin/"

# Install wafw00f
install_tool "wafw00f" "pip3 install wafw00f"

# Install gowitness
install_tool "gowitness" "GO111MODULE=on go install -v github.com/sensepost/gowitness@latest && sudo cp ~/go/bin/gowitness /usr/local/bin/"

# Install nuclei
install_tool "nuclei" "GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && sudo cp ~/go/bin/nuclei /usr/local/bin/"

# Install nikto
install_tool "nikto" "sudo apt-get install -y nikto"

# Install s3scanner
install_tool "s3scanner" "pip3 install s3scanner"

# Install getJS
install_tool "getJS" "GO111MODULE=on go install -v github.com/003random/getJS@latest && sudo cp ~/go/bin/getJS /usr/local/bin/"

# Print completion message
echo "[+] All tools have been installed and added to the PATH."
