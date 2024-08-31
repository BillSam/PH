#!/bin/bash

# Port Scan
run_port_scan() {
    local domain=$1
    local output_dir="recon_${domain}/port_scan"
    echo "[+] Running port scan on $domain..."
    masscan "$domain" -p1-65535 --rate=10000 -oX "$output_dir/masscan.xml"
}

# Web Server Probing and WAF Detection
run_web_probe() {
    local domain=$1
    local output_dir="recon_${domain}/web_servers"
    echo "[+] Probing web servers and detecting WAFs for $domain..."
    gau "$domain" -o "$output_dir/gau.txt"
    wfuzz -c -z file,"/path/to/wordlist.txt" -u "http://$domain/FUZZ" -o "$output_dir/wfuzz.txt"
    whatweb "$domain" -v -o "$output_dir/whatweb.txt"
}

# Vulnerability Scanning
run_vuln_scan() {
    local domain=$1
    local output_dir="recon_${domain}/vulnerabilities"
    echo "[+] Scanning for vulnerabilities on $domain..."
    nikto -h "$domain" -o "$output_dir/nikto_scan.txt"
    gobuster dir -u "http://$domain" -w /path/to/wordlist.txt -o "$output_dir/gobuster.txt"
    dirb "http://$domain" /path/to/wordlist.txt -o "$output_dir/dirb.txt"
}

# Git Exposure Check
run_git_exposure_check() {
    local domain=$1
    local output_dir="recon_${domain}/git_exposure"
    echo "[+] Checking for Git exposure on $domain..."
    git-dumper "http://$domain/.git" "$output_dir/git_dumper"
}

# S3 Bucket Enumeration
run_s3_enum() {
    local domain=$1
    local output_dir="recon_${domain}/s3_buckets"
    echo "[+] Enumerating S3 buckets for $domain..."
    s3scanner -d "$domain" -o "$output_dir/s3_buckets.txt"
}

# JavaScript Analysis
run_js_analysis() {
    local domain=$1
    local output_dir="recon_${domain}/js_analysis"
    echo "[+] Analyzing JavaScript files for $domain..."
    jsfucker "$domain" -o "$output_dir/jsfucker.txt"
}

# SSL/TLS Analysis
run_ssl_tls_analysis() {
    local domain=$1
    local output_dir="recon_${domain}/ssl_tls"
    echo "[+] Performing SSL/TLS analysis for $domain..."
    sslyze --regular "$domain" -o "$output_dir/sslyze.txt"
}

# CORS Misconfiguration Check
run_cors_check() {
    local domain=$1
    local output_dir="recon_${domain}/cors_check"
    echo "[+] Checking for CORS misconfigurations on $domain..."
    corsy -u "$domain" -o "$output_dir/corsy.txt"
}

# Technology Stack Identification
run_tech_stack_identification() {
    local domain=$1
    local output_dir="recon_${domain}/tech_stack"
    echo "[+] Identifying technology stack for $domain..."
    builtwith -u "$domain" -o "$output_dir/builtwith.txt"
}

# Email Harvesting
run_email_harvesting() {
    local domain=$1
    local output_dir="recon_${domain}/emails"
    echo "[+] Harvesting emails from $domain..."
    theharvester -d "$domain" -b google -l 500 -o "$output_dir/theharvester.txt"
}

# Subdomain Takeover Check
run_subdomain_takeover_check() {
    local domain=$1
    local output_dir="recon_${domain}/subdomain_takeover"
    echo "[+] Checking for subdomain takeover vulnerabilities on $domain..."
    subjack -w "recon_${domain}/subdomains/all_subdomains.txt" -t 100 -timeout 30 -o "$output_dir/subjack.txt"
}

# DNS Zone Transfer
run_dns_zone_transfer() {
    local domain=$1
    local output_dir="recon_${domain}/dns_zone_transfer"
    echo "[+] Attempting DNS zone transfer for $domain..."
    dnsrecon -d "$domain" -t axfr -o "$output_dir/dns_zone_transfer.txt"
}

# Certificate Transparency Logs
run_ct_logs() {
    local domain=$1
    local output_dir="recon_${domain}/ct_logs"
    echo "[+] Checking Certificate Transparency logs for $domain..."
    crtsh -d "$domain" -o "$output_dir/crtsh.txt"
}

# Fuzzing for Virtual Hosts
run_vhost_fuzzing() {
    local domain=$1
    local output_dir="recon_${domain}/vhost_fuzzing"
    echo "[+] Fuzzing for virtual hosts on $domain..."
    ffuf -w /path/to/vhost_wordlist.txt -u "http://$domain/FUZZ" -o "$output_dir/vhost_fuzzing.txt"
}

# API Endpoint Discovery
run_api_discovery() {
    local domain=$1
    local output_dir="recon_${domain}/api_discovery"
    echo "[+] Discovering API endpoints for $domain..."
    apiscan -u "$domain" -o "$output_dir/api_discovery.txt"
}

# Wayback Machine Crawling
run_wayback_crawl() {
    local domain=$1
    local output_dir="recon_${domain}/wayback_crawl"
    echo "[+] Crawling Wayback Machine for $domain..."
    waybackurls "$domain" -o "$output_dir/waybackurls.txt"
}

# SQL Injection Scanning
run_sqli_scan() {
    local domain=$1
    local output_dir="recon_${domain}/sqli_scan"
    echo "[+] Scanning for SQL injection vulnerabilities on $domain..."
    sqlmap -u "http://$domain" --batch -o "$output_dir/sqlmap.txt"
}

# XSS Vulnerability Scanning
run_xss_scan() {
    local domain=$1
    local output_dir="recon_${domain}/xss_scan"
    echo "[+] Scanning for XSS vulnerabilities on $domain..."
    xsser -u "http://$domain" -o "$output_dir/xsser.txt"
}

# Open Redirect Scanning
run_open_redirect_check() {
    local domain=$1
    local output_dir="recon_${domain}/open_redirect"
    echo "[+] Checking for open redirects on $domain..."
    redirector -u "http://$domain" -o "$output_dir/redirector.txt"
}

# SSRF Vulnerability Scanning
run_ssrf_scan() {
    local domain=$1
    local output_dir="recon_${domain}/ssrf_scan"
    echo "[+] Scanning for SSRF vulnerabilities on $domain..."
    ssrfmap -u "http://$domain" -o "$output_dir/ssrfmap.txt"
}

# GraphQL Introspection
run_graphql_introspection() {
    local domain=$1
    local output_dir="recon_${domain}/graphql_introspection"
    echo "[+] Performing GraphQL introspection on $domain..."
    graphql-introspection -u "http://$domain/graphql" -o "$output_dir/graphql_introspection.txt"
}

# CRLF Injection
run_crlf_injection() {
    local domain=$1
    local output_dir="recon_${domain}/crlf_injection"
    echo "[+] Checking for CRLF injection vulnerabilities on $domain..."
    crlfuzz -u "http://$domain" -o "$output_dir/crlfuzz.txt"
}

# XXE Injection
run_xxe_scan() {
    local domain=$1
    local output_dir="recon_${domain}/xxe_scan"
    echo "[+] Scanning for XXE vulnerabilities on $domain..."
    xxe -u "http://$domain" -o "$output_dir/xxe.txt"
}

# Server-Side Template Injection (SSTI)
run_ssti_check() {
    local domain=$1
    local output_dir="recon_${domain}/ssti_check"
    echo "[+] Checking for SSTI vulnerabilities on $domain..."
    ssti-scan -u "http://$domain" -o "$output_dir/ssti_scan.txt"
}

# WebSocket Security Analysis
run_websocket_analysis() {
    local domain=$1
    local output_dir="recon_${domain}/websocket_analysis"
    echo "[+] Analyzing WebSocket security on $domain..."
    websocket_scan -u "ws://$domain" -o "$output_dir/websocket_scan.txt"
}

# HTTP Request Smuggling
run_http_smuggling() {
    local domain=$1
    local output_dir="recon_${domain}/http_smuggling"
    echo "[+] Scanning for HTTP request smuggling on $domain..."
    smuggler -u "http://$domain" -o "$output_dir/smuggler.txt"
}

# Web Cache Poisoning
run_cache_poisoning() {
    local domain=$1
    local output_dir="recon_${domain}/cache_poisoning"
    echo "[+] Checking for web cache poisoning on $domain..."
    cachepoison -u "http://$domain" -o "$output_dir/cachepoison.txt"
}

# Client-Side Template Injection (CSTI)
run_csti_check() {
    local domain=$1
    local output_dir="recon_${domain}/csti_check"
    echo "[+] Checking for CSTI vulnerabilities on $domain..."
    csti -u "http://$domain" -o "$output_dir/csti.txt"
}
