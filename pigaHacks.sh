#!/bin/bash

# Piga Hacks - Bug Bounty Automation Tool

# Global variables
DOMAIN=""
OUTPUT_DIR=""

# Function to display the main menu
function show_menu() {
    clear
    cat << EOF
#######################################################################
#                                                                     #
#  ██████╗ ██╗ ██████╗  █████╗     ██╗  ██╗ █████╗  ██████╗██╗  ██╗    #
#  ██╔══██╗██║██╔════╝ ██╔══██╗    ██║ ██╔╝██╔══██╗██╔════╝██║  ██║    #
#  ██████╔╝██║██║  ███╗███████║    █████╔╝ ███████║██║     ███████║    #
#  ██╔══██╗██║██║   ██║██╔══██║    ██╔═██╗ ██╔══██║██║     ██╔══██║    #
#  ██║  ██║██║╚██████╔╝██║  ██║    ██║  ██╗██║  ██║╚██████╗██║  ██║    #
#  ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝    #
#                                                                     #
#  A powerful tool for bug bounty hunting and cybersecurity workflows  #
#                                                                     #
#######################################################################
                              PIGA HACK                               
#######################################################################
Current Domain: ${DOMAIN:-Not set}
Output Directory: ${OUTPUT_DIR:-Not set}
---------------------------------------------------------------------
1) Set Target Domain
2) Comprehensive Reconnaissance and Vulnerability Scanning
3) Subdomain Enumeration
4) DNS Enumeration
5) IP Resolution and Port Scanning
6) Web Server Probing and WAF Detection
7) Vulnerability Scanning
8) Git Exposure Check
9) S3 Bucket Enumeration
10) JavaScript Analysis
11) SSL/TLS Analysis
12) CORS Misconfiguration Check
13) Technology Stack Identification
14) Email Harvesting
15) Subdomain Takeover Check
16) DNS Zone Transfer
17) Certificate Transparency Logs
18) Fuzzing for Virtual Hosts
19) API Endpoint Discovery
20) Wayback Machine Crawling
21) SQL Injection Scanning
22) XSS Vulnerability Scanning
23) Open Redirect Scanning
24) SSRF Vulnerability Scanning
25) GraphQL Introspection
26) CRLF Injection
27) XML External Entity (XXE) Injection
28) Server-Side Template Injection (SSTI)
29) WebSocket Security Analysis
30) HTTP Request Smuggling
31) Web Cache Poisoning
32) Client-Side Template Injection (CSTI)
33) Exit
=====================================================
Choose an option (1-33): 
EOF
}

# Function to set the target domain
function set_target_domain() {
    read -p "Enter target domain: " DOMAIN
    OUTPUT_DIR="recon_${DOMAIN}"
    mkdir -p "$OUTPUT_DIR"/{subdomains,ip_addresses,ports,screenshots,content,vulnerabilities,emails,technologies,dns,certificates,scans}
    echo "Target domain set to $DOMAIN. Output directory: $OUTPUT_DIR"
    read -p "Press Enter to continue"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to run a command in a new terminal
run_in_new_terminal() {
    local title="$1"
    shift
    if command_exists gnome-terminal; then
        gnome-terminal --title="$title" -- bash -c "$*; echo 'Press Enter to close this window'; read"
    elif command_exists xterm; then
        xterm -T "$title" -e bash -c "$*; echo 'Press Enter to close this window'; read"
    else
        echo "Error: Neither gnome-terminal nor xterm found. Unable to open new terminal window."
        echo "Running command in current terminal:"
        bash -c "$*"
    fi
}

# Comprehensive Reconnaissance and Vulnerability Scanning
function run_full_recon() {
    if [ -z "$DOMAIN" ]; then
        echo "Error: Target domain not set. Please set the target domain first."
        read -p "Press Enter to continue"
        return
    fi

    echo "[+] Starting comprehensive reconnaissance and vulnerability scanning for $DOMAIN"

    run_in_new_terminal "Full Recon" "
        ./$(basename "$0") run_subdomain_enum;
        ./$(basename "$0") run_dns_enum;
        ./$(basename "$0") run_ip_resolution;
        ./$(basename "$0") run_web_probe;
        ./$(basename "$0") run_vuln_scan;
        ./$(basename "$0") run_git_exposure_check;
        ./$(basename "$0") run_s3_enum;
        ./$(basename "$0") run_js_analysis;
        ./$(basename "$0") run_ssl_tls_analysis;
        ./$(basename "$0") run_cors_check;
        ./$(basename "$0") run_tech_stack_identification;
        ./$(basename "$0") run_email_harvesting;
        ./$(basename "$0") run_subdomain_takeover_check;
        ./$(basename "$0") run_dns_zone_transfer;
        ./$(basename "$0") run_ct_logs;
        ./$(basename "$0") run_vhost_fuzzing;
        ./$(basename "$0") run_api_discovery;
        ./$(basename "$0") run_wayback_crawl;
        ./$(basename "$0") run_sqli_scan;
        ./$(basename "$0") run_xss_scan;
        ./$(basename "$0") run_open_redirect_check;
        ./$(basename "$0") run_ssrf_scan;
        ./$(basename "$0") run_graphql_introspection;
        ./$(basename "$0") run_crlf_injection;
        ./$(basename "$0") run_xxe_scan;
        ./$(basename "$0") run_ssti_check;
        ./$(basename "$0") run_websocket_analysis;
        ./$(basename "$0") run_http_smuggling;
        ./$(basename "$0") run_cache_poisoning;
        ./$(basename "$0") run_csti_check;
    "

    echo "[+] Comprehensive reconnaissance and vulnerability scanning started in a new terminal window."
    read -p "Press Enter to continue"
}

# Subdomain Enumeration
function run_subdomain_enum() {
    local output_dir="$OUTPUT_DIR/subdomains"
    echo "[+] Enumerating subdomains for $DOMAIN..."
    run_command subfinder -d "$DOMAIN" -o "$output_dir/subfinder.txt"
    run_command assetfinder --subs-only "$DOMAIN" > "$output_dir/assetfinder.txt"
    run_command amass enum -d "$DOMAIN" -o "$output_dir/amass.txt"
    # Note: github-subdomains requires a GitHub token, so we'll skip it for now
    run_command chaos -d "$DOMAIN" -o "$output_dir/chaos.txt"
    sort -u "$output_dir"/*.txt > "$output_dir/all_subdomains.txt"
    echo "Subdomain enumeration completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# Add similar improvements for other functions...
# DNS Enumeration
function run_dns_enum() {
    local output_dir="$OUTPUT_DIR/dns"
    echo "[+] Performing DNS enumeration for $DOMAIN..."
    run_command dnsenum "$DOMAIN" --noreverse -o "$output_dir/dns_enum.txt"
    run_command dnsrecon -d "$DOMAIN" -t std,brt -c "$output_dir/dnsrecon.csv"
    echo "DNS enumeration completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# IP Resolution and Reverse DNS Lookup
function run_ip_resolution() {
    local output_dir="$OUTPUT_DIR/ip_addresses"
    echo "[+] Resolving IP addresses for $DOMAIN..."
    if [[ -f "$OUTPUT_DIR/subdomains/all_subdomains.txt" ]]; then
        run_command dnsx -l "$OUTPUT_DIR/subdomains/all_subdomains.txt" -a -resp-only -o "$output_dir/resolved_ips.txt"
    else
        echo "Error: Subdomain list not found. Please run subdomain enumeration first."
        read -p "Press Enter to continue"
        return
    fi

    echo "[+] Performing reverse DNS lookup for $DOMAIN..."
    while IFS= read -r ip; do
        host "$ip" | awk '{print $5}' >> "$output_dir/reverse_dns.txt"
    done < "$output_dir/resolved_ips.txt"
    echo "IP resolution and reverse DNS lookup completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# Web Probing and WAF Detection
function run_web_probe() {
    local output_dir="$OUTPUT_DIR/content"
    echo "[+] Probing for web servers on $DOMAIN..."
    if [[ -f "$OUTPUT_DIR/subdomains/all_subdomains.txt" ]]; then
        run_command httpx -l "$OUTPUT_DIR/subdomains/all_subdomains.txt" -o "$output_dir/live_subdomains.txt"
    else
        echo "Error: Subdomain list not found. Please run subdomain enumeration first."
        read -p "Press Enter to continue"
        return
    fi

    echo "[+] Detecting WAF on $DOMAIN..."
    run_command wafw00f -i "$output_dir/live_subdomains.txt" -o "$output_dir/waf_detection.txt"

    echo "[+] Taking screenshots for $DOMAIN..."
    run_command gowitness file -f "$output_dir/live_subdomains.txt" -P "$OUTPUT_DIR/screenshots/"
    echo "Web probing and WAF detection completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# Vulnerability Scanning
function run_vuln_scan() {
    local output_dir="$OUTPUT_DIR/vulnerabilities"
    echo "[+] Scanning for vulnerabilities on $DOMAIN..."
    if [[ -f "$OUTPUT_DIR/content/live_subdomains.txt" ]]; then
        run_command nuclei -l "$OUTPUT_DIR/content/live_subdomains.txt" -o "$output_dir/nuclei_results.txt"
        run_command nikto -h "$OUTPUT_DIR/content/live_subdomains.txt" -output "$output_dir/nikto_results.txt"
    else
        echo "Error: Live subdomains list not found. Please run web probing first."
        read -p "Press Enter to continue"
        return
    fi
    echo "Vulnerability scanning completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# Git Exposure Check
function run_git_exposure_check() {
    local output_dir="$OUTPUT_DIR/vulnerabilities"
    echo "[+] Checking for exposed .git directories on $DOMAIN..."
    if [[ -f "$OUTPUT_DIR/content/live_subdomains.txt" ]]; then
        while IFS= read -r subdomain; do
            if curl -s "https://$subdomain/.git/HEAD" | grep -q "ref:"; then
                echo "https://$subdomain/.git" >> "$output_dir/exposed_git.txt"
            fi
        done < "$OUTPUT_DIR/content/live_subdomains.txt"
    else
        echo "Error: Live subdomains list not found. Please run web probing first."
        read -p "Press Enter to continue"
        return
    fi
    echo "Git exposure check completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# S3 Bucket Enumeration
function run_s3_enum() {
    local output_dir="$OUTPUT_DIR/vulnerabilities"
    echo "[+] Enumerating S3 buckets for $DOMAIN..."
    if [[ -f "$OUTPUT_DIR/subdomains/all_subdomains.txt" ]]; then
        while IFS= read -r subdomain; do
            run_command s3scanner scan --bucket-name "$subdomain" >> "$output_dir/s3_buckets.txt"
        done < "$OUTPUT_DIR/subdomains/all_subdomains.txt"
    else
        echo "Error: Subdomain list not found. Please run subdomain enumeration first."
        read -p "Press Enter to continue"
        return
    fi
    echo "S3 bucket enumeration completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# JavaScript Analysis
function run_js_analysis() {
    local output_dir="$OUTPUT_DIR/content"
    echo "[+] Analyzing JavaScript files for $DOMAIN..."
    if [[ -f "$output_dir/live_subdomains.txt" ]]; then
        while IFS= read -r subdomain; do
            run_command getJS --url "https://$subdomain" --output "$output_dir/js_files_${subdomain}.txt"
            grep -Ei "api\.|token|key|secret|password|aws|azure|gcp" "$output_dir/js_files_${subdomain}.txt" >> "$OUTPUT_DIR/vulnerabilities/js_secrets_${subdomain}.txt"
            run_command linkfinder -i "https://$subdomain" -o "$output_dir/linkfinder_${subdomain}.txt"
        done < "$output_dir/live_subdomains.txt"
    else
        echo "Error: Live subdomains list not found. Please run web probing first."
        read -p "Press Enter to continue"
        return
    fi
    echo "JavaScript analysis completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# SSL/TLS Analysis
function run_ssl_tls_analysis() {
    local output_dir="$OUTPUT_DIR/vulnerabilities"
    echo "[+] Analyzing SSL/TLS for $DOMAIN..."
    if [[ -f "$OUTPUT_DIR/content/live_subdomains.txt" ]]; then
        while IFS= read -r subdomain; do
            run_command sslyze --regular "$subdomain" >> "$output_dir/sslyze_results.txt"
            run_command testssl.sh "$subdomain" >> "$output_dir/testssl_results.txt"
        done < "$OUTPUT_DIR/content/live_subdomains.txt"
    else
        echo "Error: Live subdomains list not found. Please run web probing first."
        read -p "Press Enter to continue"
        return
    fi
    echo "SSL/TLS analysis completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# CORS Misconfiguration Check
function run_cors_check() {
    local output_dir="$OUTPUT_DIR/vulnerabilities"
    echo "[+] Checking for CORS misconfigurations on $DOMAIN..."
    if [[ -f "$OUTPUT_DIR/content/live_subdomains.txt" ]]; then
        while IFS= read -r subdomain; do
            run_command corstest -u "https://$subdomain" >> "$output_dir/cors_misconfig.txt"
        done < "$OUTPUT_DIR/content/live_subdomains.txt"
    else
        echo "Error: Live subdomains list not found. Please run web probing first."
        read -p "Press Enter to continue"
        return
    fi
    echo "CORS misconfiguration check completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# Technology Stack Identification
function run_tech_stack_identification() {
    local output_dir="$OUTPUT_DIR/technologies"
    echo "[+] Identifying technology stack for $DOMAIN..."
    if [[ -f "$OUTPUT_DIR/content/live_subdomains.txt" ]]; then
        while IFS= read -r subdomain; do
            run_command whatweb "https://$subdomain" >> "$output_dir/whatweb_results.txt"
            run_command wappalyzer "https://$subdomain" --pretty >> "$output_dir/wappalyzer_results.json"
        done < "$OUTPUT_DIR/content/live_subdomains.txt"
    else
        echo "Error: Live subdomains list not found. Please run web probing first."
        read -p "Press Enter to continue"
        return
    fi
    echo "Technology stack identification completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# Email Harvesting
function run_email_harvesting() {
    local output_dir="$OUTPUT_DIR/emails"
    echo "[+] Harvesting email addresses from $DOMAIN..."
    run_command theHarvester -d "$DOMAIN" -b all -f "$output_dir/theharvester_results.txt"
    echo "Email harvesting completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# Subdomain Takeover Check
function run_subdomain_takeover_check() {
    local output_dir="$OUTPUT_DIR/vulnerabilities"
    echo "[+] Checking for subdomain takeover vulnerabilities on $DOMAIN..."
    if [[ -f "$OUTPUT_DIR/subdomains/all_subdomains.txt" ]]; then
        run_command subjack -w "$OUTPUT_DIR/subdomains/all_subdomains.txt" -t 100 -timeout 30 -o "$output_dir/subjack_results.txt" -ssl
    else
        echo "Error: Subdomain list not found. Please run subdomain enumeration first."
        read -p "Press Enter to continue"
        return
    fi
    echo "Subdomain takeover check completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# DNS Zone Transfer
function run_dns_zone_transfer() {
    local output_dir="$OUTPUT_DIR/dns"
    echo "[+] Attempting DNS zone transfer for $DOMAIN..."
    for ns in $(dig +short NS "$DOMAIN"); do
        dig @"$ns" "$DOMAIN" AXFR > "$output_dir/zone_transfer_${ns}.txt"
    done
    echo "DNS zone transfer attempt completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# Certificate Transparency Logs
function run_ct_logs() {
    local output_dir="$OUTPUT_DIR/certificates"
    echo "[+] Checking Certificate Transparency logs for $DOMAIN..."
    run_command ct_logs=$(curl -s "https://crt.sh/?q=%.$DOMAIN&output=json" | jq -r '.[].name_value' | sort -u)
    echo "$ct_logs" > "$output_dir/ct_logs.txt"
    echo "Certificate Transparency log check completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# Fuzzing for Virtual Hosts
function run_vhost_fuzzing() {
    local output_dir="$OUTPUT_DIR/content"
    echo "[+] Fuzzing for virtual hosts on $DOMAIN..."
    if [[ -f "$OUTPUT_DIR/ip_addresses/resolved_ips.txt" ]]; then
        while IFS= read -r ip; do
            run_command ffuf -w "$OUTPUT_DIR/subdomains/all_subdomains.txt" -u "http://$ip" -H "Host: FUZZ" -fc 404 -o "$output_dir/vhost_fuzzing_${ip}.json"
        done < "$OUTPUT_DIR/ip_addresses/resolved_ips.txt"
    else
        echo "Error: Resolved IPs list not found. Please run IP resolution first."
        read -p "Press Enter to continue"
        return
    fi
    echo "Virtual host fuzzing completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# API Endpoint Discovery
function run_api_discovery() {
    local output_dir="$OUTPUT_DIR/content"
    echo "[+] Discovering API endpoints for $DOMAIN..."
    if [[ -f "$OUTPUT_DIR/content/live_subdomains.txt" ]]; then
        while IFS= read -r subdomain; do
            run_command ffuf -w /path/to/api_wordlist.txt -u "https://$subdomain/FUZZ" -mc 200,201,204,301,302,307,401,403 -o "$output_dir/api_discovery_${subdomain}.json"
        done < "$OUTPUT_DIR/content/live_subdomains.txt"
    else
        echo "Error: Live subdomains list not found. Please run web probing first."
        read -p "Press Enter to continue"
        return
    fi
    echo "API endpoint discovery completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# Wayback Machine Crawling
function run_wayback_crawl() {
    local output_dir="$OUTPUT_DIR/content"
    echo "[+] Crawling Wayback Machine for $DOMAIN..."
    run_command waybackurls "$DOMAIN" | sort -u > "$output_dir/wayback_urls.txt"
    echo "Wayback Machine crawling completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# SQL Injection Scanning
function run_sqli_scan() {
    local output_dir="$OUTPUT_DIR/vulnerabilities"
    echo "[+] Scanning for SQL injection vulnerabilities on $DOMAIN..."
    if [[ -f "$OUTPUT_DIR/content/wayback_urls.txt" ]]; then
        run_command sqlmap -m "$OUTPUT_DIR/content/wayback_urls.txt" --batch --random-agent --level 1 --risk 1 -o --report-file "$output_dir/sqlmap_results.txt"
    else
        echo "Error: Wayback URLs list not found. Please run Wayback Machine crawling first."
        read -p "Press Enter to continue"
        return
    fi
    echo "SQL injection scanning completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# XSS Scanning
function run_xss_scan() {
    local output_dir="$OUTPUT_DIR/vulnerabilities"
    echo "[+] Scanning for XSS vulnerabilities on $DOMAIN..."
    run_command xsser --url "https://$DOMAIN" --auto --Cw 3 --Cl 5 --Cs 5 --Cp 5 --CT 5 --threads 10 --output "$output_dir/xsser_results.xml"
    echo "XSS scanning completed. Results saved in $output_dir"
    read -p "Press Enter to continue"
}

# Wrapper function to loop the menu until exit
function menu_loop() {
    while true; do
        show_menu
        read -r option
        case $option in
            1) set_target_domain ;;
            2) run_full_recon ;;
            3) run_in_new_terminal "Subdomain Enumeration" "./$(basename "$0") run_subdomain_enum" ;;
            4) run_in_new_terminal "DNS Enumeration" "./$(basename "$0") run_dns_enum" ;;
            5) run_in_new_terminal "IP Resolution" "./$(basename "$0") run_ip_resolution" ;;
            6) run_in_new_terminal "Web Probe" "./$(basename "$0") run_web_probe" ;;
            7) run_in_new_terminal "Vulnerability Scan" "./$(basename "$0") run_vuln_scan" ;;
            8) run_in_new_terminal "Git Exposure Check" "./$(basename "$0") run_git_exposure_check" ;;
            9) run_in_new_terminal "S3 Bucket Enumeration" "./$(basename "$0") run_s3_enum" ;;
            10) run_in_new_terminal "JavaScript Analysis" "./$(basename "$0") run_js_analysis" ;;
            11) run_in_new_terminal "SSL/TLS Analysis" "./$(basename "$0") run_ssl_tls_analysis" ;;
            12) run_in_new_terminal "CORS Check" "./$(basename "$0") run_cors_check" ;;
            13) run_in_new_terminal "Tech Stack Identification" "./$(basename "$0") run_tech_stack_identification" ;;
            14) run_in_new_terminal "Email Harvesting" "./$(basename "$0") run_email_harvesting" ;;
            15) run_in_new_terminal "Subdomain Takeover Check" "./$(basename "$0") run_subdomain_takeover_check" ;;
            16) run_in_new_terminal "DNS Zone Transfer" "./$(basename "$0") run_dns_zone_transfer" ;;
            17) run_in_new_terminal "CT Logs" "./$(basename "$0") run_ct_logs" ;;
            18) run_in_new_terminal "VHost Fuzzing" "./$(basename "$0") run_vhost_fuzzing" ;;
            19) run_in_new_terminal "API Discovery" "./$(basename "$0") run_api_discovery" ;;
            20) run_in_new_terminal "Wayback Crawl" "./$(basename "$0") run_wayback_crawl" ;;
            21) run_in_new_terminal "SQLi Scan" "./$(basename "$0") run_sqli_scan" ;;
            22) run_in_new_terminal "XSS Scan" "./$(basename "$0") run_xss_scan" ;;
            23) run_in_new_terminal "Open Redirect Check" "./$(basename "$0") run_open_redirect_check" ;;
            24) run_in_new_terminal "SSRF Scan" "./$(basename "$0") run_ssrf_scan" ;;
            25) run_in_new_terminal "GraphQL Introspection" "./$(basename "$0") run_graphql_introspection" ;;
            26) run_in_new_terminal "CRLF Injection" "./$(basename "$0") run_crlf_injection" ;;
            27) run_in_new_terminal "XXE Scan" "./$(basename "$0") run_xxe_scan" ;;
            28) run_in_new_terminal "SSTI Check" "./$(basename "$0") run_ssti_check" ;;
            29) run_in_new_terminal "WebSocket Analysis" "./$(basename "$0") run_websocket_analysis" ;;
            30) run_in_new_terminal "HTTP Smuggling" "./$(basename "$0") run_http_smuggling" ;;
            31) run_in_new_terminal "Cache Poisoning" "./$(basename "$0") run_cache_poisoning" ;;
            32) run_in_new_terminal "CSTI Check" "./$(basename "$0") run_csti_check" ;;
            33) echo "Exiting..."; exit 0 ;;
            *) echo "Invalid option. Press Enter to continue."; read -r ;;
        esac
    done
}

# Check if a function name is passed as an argument
if [[ "$1" == run_* ]] && [[ $(type -t "$1") == function ]]; then
    if [ -z "$DOMAIN" ]; then
        echo "Error: Target domain not set. Please run the script without arguments first."
        exit 1
    fi
    $1
    exit 0
fi

# Start the menu loop
menu_loop