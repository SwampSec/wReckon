#!/bin/bash
# Written by MaliceInChains - maliceinchains106@gmail.com 
# -----------------------------------------------------------------
# Reckon performs common active reconnaissance tasks in order speed 
# up scanning and enumeration processes during penetration testing.
# Enhanced with comprehensive vulnerability scanning & discovery tools
# -----------------------------------------------------------------

# === SCAN CONFIGURATION ===
# NMAP --top-ports
tports=100
# NMAP UDP Scans
udp=False
# NMAP TCP Scans
tcp=True

# === SCANNING FEATURES ===
# Enable DNS enumeration and subdomain discovery
dns_enum=True
# Enable SSL/TLS vulnerability scanning (testssl)
ssl_scan=True
# Enable OWASP scanning (if tools available)
owasp_scan=True
# Enable web app vulnerability scanning (ZAP, sqlmap)
web_vuln_scan=True
# Enable password policy testing (hydra)
password_test=False
# Enable service vulnerability assessment
service_vuln_scan=True

# === MODULE TOGGLES (Future Expansion) ===
# Enable API testing module (REST/GraphQL/SOAP)
api_testing=False
# Enable cloud platform testing (AWS/Azure/GCP)
cloud_testing=False
# Enable container security scanning (Docker/K8s)
container_testing=False
# Enable Infrastructure as Code scanning (Terraform/CloudFormation)
iac_testing=False

# === NETWORK MONITORING ===
# Enable tcpdump packet capture monitoring
network_monitor=False
# Default network interface (eth0, en0, tun0, etc)
monitor_interface="eth0"
# Packet capture filter (empty = all traffic)
pcap_filter=""
# Output directory for pcap files
pcap_output_dir="pcap_captures"

# Color Variables
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# For calculating run time
SECONDS=0

# === INTERACTIVE CONFIGURATION (Metasploit-style) ===
show_options() {
	echo -e "${BLUE}======= wReckon Configuration Options =======${NC}"
	echo ""
	echo -e "${GREEN}SCANNING OPTIONS:${NC}"
	echo -e "  tports              => $tports               (Top N ports to scan)"
	echo -e "  tcp                 => $tcp                 (Enable TCP scanning)"
	echo -e "  udp                 => $udp                 (Enable UDP scanning)"
	echo ""
	echo -e "${GREEN}VULNERABILITY SCANNING:${NC}"
	echo -e "  dns_enum            => $dns_enum             (DNS enumeration)"
	echo -e "  ssl_scan            => $ssl_scan             (SSL/TLS scanning)"
	echo -e "  owasp_scan          => $owasp_scan           (OWASP Top 10 scanning)"
	echo -e "  web_vuln_scan       => $web_vuln_scan        (Web app vulnerability scanning)"
	echo -e "  service_vuln_scan   => $service_vuln_scan    (Service vulnerability assessment)"
	echo -e "  password_test       => $password_test        (Password policy testing)"
	echo ""
	echo -e "${GREEN}MODULE TOGGLES:${NC}"
	echo -e "  api_testing         => $api_testing          (API testing module)"
	echo -e "  cloud_testing       => $cloud_testing        (Cloud platform testing)"
	echo -e "  container_testing   => $container_testing    (Container security scanning)"
	echo -e "  iac_testing         => $iac_testing          (Infrastructure as Code scanning)"
	echo ""
	echo -e "${GREEN}NETWORK MONITORING:${NC}"
	echo -e "  network_monitor     => $network_monitor      (Network packet capture)"
	echo -e "  monitor_interface   => $monitor_interface    (Network interface to monitor)"
	echo -e "  pcap_filter         => ${pcap_filter:-'(all traffic)'} (Capture filter)"
	echo ""
}

interactive_config() {
	while true; do
		show_options
		echo ""
		read -p "SET option=value (or 'help', 'done'): " user_input
		
		if [[ "$user_input" == "help" ]]; then
			echo ""
			echo "SET command syntax:"
			echo "  SET tports 500          - Change top ports to scan"
			echo "  SET tcp True            - Enable TCP scanning"
			echo "  SET api_testing True    - Enable API testing module"
			echo "  SET network_monitor True - Enable network monitoring"
			echo "  SET dns_enum False      - Disable DNS enumeration"
			echo ""
			continue
		elif [[ "$user_input" == "done" ]]; then
			break
		fi
		
		# Parse SET command
		if [[ "$user_input" =~ ^SET[[:space:]]+ ]] || [[ "$user_input" =~ ^set[[:space:]]+ ]]; then
			user_input="${user_input#*[[:space:]]}"
		fi
		
		if [[ -z "$user_input" ]]; then
			continue
		fi
		
		# Split on = or whitespace
		IFS='=' read -r option value <<< "$user_input"
		option=$(echo "$option" | xargs)  # Trim whitespace
		value=$(echo "$value" | xargs)    # Trim whitespace
		
		# If no equals sign, try space-separated
		if [[ -z "$value" ]]; then
			IFS=' ' read -r option value <<< "$user_input"
			option=$(echo "$option" | xargs)
			value=$(echo "$value" | xargs)
		fi
		
		if [[ -z "$option" ]] || [[ -z "$value" ]]; then
			echo -e "${RED}[!] Invalid syntax${NC}"
			continue
		fi
		
		# Update configuration
		case "$option" in
			tports)
				if [[ "$value" =~ ^[0-9]+$ ]]; then
					tports=$value
					echo -e "${GREEN}[✓]${NC} tports set to $tports"
				else
					echo -e "${RED}[!] Invalid value (must be number)${NC}"
				fi
				;;
			tcp|udp|dns_enum|ssl_scan|owasp_scan|web_vuln_scan|password_test|service_vuln_scan|api_testing|cloud_testing|container_testing|iac_testing|network_monitor)
				if [[ "$value" =~ ^(True|true|False|false|1|0)$ ]]; then
					# Normalize to True/False
					[[ "$value" =~ ^(True|true|1)$ ]] && value="True" || value="False"
					eval "${option}=${value}"
					echo -e "${GREEN}[✓]${NC} $option set to $value"
				else
					echo -e "${RED}[!] Invalid value (use True or False)${NC}"
				fi
				;;
			monitor_interface)
				monitor_interface=$value
				echo -e "${GREEN}[✓]${NC} monitor_interface set to $monitor_interface"
				;;
			pcap_filter)
				pcap_filter=$value
				echo -e "${GREEN}[✓]${NC} pcap_filter set to '$pcap_filter'"
				;;
			*)
				echo -e "${RED}[!] Unknown option: $option${NC}"
				;;
		esac
	done
}

# === TOOL AVAILABILITY CHECK ===
declare -A tool_available
check_tools_availability() {
	local tools=("nmap" "nikto" "dirb" "enum4linux" "curl" "dig" "whois" "wget")
	
	for tool in "${tools[@]}"; do
		if command -v "$tool" &> /dev/null; then
			tool_available[$tool]=true
		else
			tool_available[$tool]=false
		fi
	done
	
	# Optional tools for enhanced scanning
	command -v "testssl.sh" &> /dev/null && tool_available["testssl"]=true || tool_available["testssl"]=false
	command -v "sqlmap" &> /dev/null && tool_available["sqlmap"]=true || tool_available["sqlmap"]=false
	command -v "zaproxy" &> /dev/null && tool_available["zaproxy"]=true || tool_available["zaproxy"]=false
	command -v "nuclei" &> /dev/null && tool_available["nuclei"]=true || tool_available["nuclei"]=false
	command -v "ffuf" &> /dev/null && tool_available["ffuf"]=true || tool_available["ffuf"]=false
}

# === DNS & DISCOVERY FUNCTIONS ===
dns_recon() {
	if [[ "${tool_available[dig]}" == false ]]; then
		return
	fi
	
	echo -e "${GREEN}[!]${NC} Performing DNS Reconnaissance on $target" |tee -a reckon
	
	# Forward DNS lookup
	dig $target +short > dns-forward-lookup 2>/dev/null
	dig $target ANY +short > dns-any-lookup 2>/dev/null
	
	# Reverse DNS lookup
	dig -x $target +short > dns-reverse-lookup 2>/dev/null
	
	# Zone transfer attempt
	dig @$target axfr $target > dns-axfr 2>/dev/null
	
	# Extract results
	IFS=$'\n'
	forward_results=$(grep -v "^$" dns-forward-lookup | wc -l)
	if [[ "$forward_results" -gt "0" ]]; then
		echo -e "[-]      DNS A/AAAA Records:" |tee -a reckon
		for record in $(cat dns-forward-lookup); do
			echo "[-]        $record" |tee -a reckon
		done
	fi
	
	any_results=$(grep -v "^$" dns-any-lookup | wc -l)
	if [[ "$any_results" -gt "0" ]]; then
		echo -e "[-]      DNS ANY Records:" |tee -a reckon
		for record in $(cat dns-any-lookup | head -10); do
			echo "[-]        $record" |tee -a reckon
		done
	fi
	
	axfr_success=$(grep -i "Transfer failed" dns-axfr | wc -l)
	if [[ "$axfr_success" == "0" ]] && [[ $(wc -l < dns-axfr) -gt 5 ]]; then
		echo -e "${RED}[-]      Zone Transfer SUCCESSFUL (DNS misconfiguration)${NC}" |tee -a reckon
		head -10 dns-axfr |tee -a reckon
	fi
	unset IFS
}

whois_lookup() {
	if [[ "${tool_available[whois]}" == false ]]; then
		return
	fi
	
	echo -e "${GREEN}[!]${NC} Performing WHOIS Lookup" |tee -a reckon
	whois $target > whois-lookup 2>/dev/null
	
	# Extract useful info
	IFS=$'\n'
	for info in $(cat whois-lookup | grep -i -E "(Registrant|Admin|Tech|Name Server|Organization)" | head -10); do
		echo "[-]      $info" |tee -a reckon
	done
	unset IFS
}

topscan(){ # Conducts a quick scan of top ___ TCP ports, change tports for top 10
	if [[ $tcp == "True" ]]; then
		nmap -Pn -sT $target -oN quickscan --top-ports $tports --open >/dev/null 2>&1;
		cat quickscan |grep open |grep -v nmap > .openports
		echo -e "${GREEN}[!]${NC}   Nmap identified $(cat quickscan |grep open |grep -v nmap |wc -l) open TCP ports on $target" "\a"  |tee -a reckon
	
		for nports in $(cat quickscan |grep open |grep -v nmap |awk '{print$1}'); do 
			echo "[-]      $nports" |tee -a reckon
		done
	fi
	# Conducts a quick scan of top 100 UDP ports.

	if [[ $udp == "True" ]]; then
		nmap -Pn -sU $target -oN quickudpscan --top-ports $tports --open >/dev/null 2>&1;
		cat quickudpscan |grep open |grep -v filtered |grep -v nmap > .openudpports
		echo -e "${GREEN}[!]${NC}   Nmap identified $(cat quickudpscan |grep open |grep -v filtered |grep -v nmap |wc -l) open UDP ports on $target" "\a"  |tee -a reckon
	
		for nports in $(cat quickudpscan |grep open |grep -v filtered |grep -v nmap |awk '{print$1}'); do 
			echo "[-]      $nports" |tee -a reckon
		done
	fi
}

versionscantcp(){ # Conduct -sV scan on previously identified TCP ports

	for oports in $(cat .openports |grep open |grep -v "\-\-top\-ports" |awk '{print$1}' |awk -F "/" '{print$1}'); do
		nmap -Pn -sT -sV $target -p $oports -oN $oports-version 2> /dev/null 1> /dev/null
		trn=$(cat $oports-version |grep open |awk -F "$(cat $oports-version |grep open |cut -d " " -f1,2,3,4)" '{print$2}' |sed 's/  //g')
		vrn=$(echo $trn |sed 's/  / /g')
		srv=$(cat $oports-version |grep open |awk '{print$3}')

		if [[ -z "$vrn" ]] | [[ "$vrn" == "?" ]]; then
			vrn="- Nmap was unable to identify the service or version"
			echo -e "[-]      $oports/TCP may be running $srv $vrn"  |tee -a reckon
		else
			echo -e "[-]      $oports/TCP is running $srv service via $vrn"  |tee -a reckon
		fi	
	done
	cat *-version |grep "tcp open" |grep -v nmap 2> /dev/null 1> .openports
}

versionscanudp(){ # Conduct -sV scan on previously identified UDP ports

	for oports in $(cat .openudpports |grep open |grep -v filtered |awk '{print$1}' |awk -F "/" '{print$1}' 2> /dev/null); do
		nmap -Pn -sU -sV $target -p $oports -oN $oports-udp-version 2> /dev/null 1> /dev/null
		trn=$(cat $oports-udp-version |grep open |awk -F "$(cat $oports-udp-version |grep open |cut -d " " -f1,2,3,4)" '{print$2}' |sed 's/  //g')
		vrn=$(echo $trn |sed 's/  / /g')
		srv=$(cat $oports-udp-version |grep open |awk '{print$3}')

		if [[ -z "$vrn" ]] | [[ "$vrn" == "?" ]]; then
			vrn="- Nmap was unable to identify the service or version"
			echo -e "[-]      $oports/UDP may be running $srv $vrn"  |tee -a reckon
		else
			echo -e "[-]      $oports/UDP is running $srv service via $vrn"  |tee -a reckon
		fi	
	done
	cat *-version |grep "udp open" |grep -v nmap 2> /dev/null 1> .openudpports
}

ssl_tls_scan() { # Test SSL/TLS vulnerabilities (Heartbleed, etc)
	if [[ "${tool_available[testssl]}" == false ]]; then
		echo -e "${YELLOW}[-]${NC}   testssl.sh not found - skipping SSL/TLS scanning" |tee -a reckon
		return
	fi
	
	for sslport in $(cat .openports |grep -E '(443|8443|465|993|995|3389)' |awk '{print$1}' |awk -F "/" '{print$1}' |sort -g); do
		echo -e "${GREEN}[!]${NC} Running SSL/TLS Scan on port $sslport" |tee -a reckon
		testssl.sh --full $target:$sslport > $sslport-ssl-test 2>/dev/null
		
		# Extract findings
		IFS=$'\n'
		for finding in $(grep -E "(VULNERABLE|WARN|INFO)" $sslport-ssl-test | grep -v "^$" | head -10); do
			echo "[-]      $finding" |tee -a reckon
		done
		unset IFS
	done
}

sqlmap_scan() { # Test for SQL injection vulnerabilities
	if [[ "${tool_available[sqlmap]}" == false ]]; then
		return
	fi
	
	for wport in $(cat .openports |grep http |awk '{print$1}' |awk -F "/" '{print$1}'); do
		if [[ "$wport" == "443" ]]; then
			web_url="https://$target"
		else
			web_url="http://$target:$wport"
		fi
		
		echo -e "${GREEN}[!]${NC} Running SQLmap on $web_url" |tee -a reckon
		sqlmap -u "$web_url" --batch --forms -q > $wport-sqlmap 2>/dev/null
		
		findings=$(grep -i "vulnerable" $wport-sqlmap | wc -l)
		if [[ "$findings" -gt "0" ]]; then
			echo -e "${RED}[!] SQL Injection vulnerabilities found!${NC}" |tee -a reckon
			grep -i "vulnerable" $wport-sqlmap |tee -a reckon
		fi
	done
}

nuclei_scan() { # Template-based vulnerability scanning
	if [[ "${tool_available[nuclei]}" == false ]]; then
		return
	fi
	
	for wport in $(cat .openports |grep http |awk '{print$1}' |awk -F "/" '{print$1}'); do
		if [[ "$wport" == "443" ]]; then
			web_url="https://$target"
		else
			web_url="http://$target:$wport"
		fi
		
		echo -e "${GREEN}[!]${NC} Running Nuclei Template Scanning on $web_url" |tee -a reckon
		nuclei -u "$web_url" -o $wport-nuclei 2>/dev/null
		
		if [[ -f "$wport-nuclei" ]] && [[ -s "$wport-nuclei" ]]; then
			echo "[-]      Template-based vulnerabilities found:" |tee -a reckon
			cat $wport-nuclei |tee -a reckon
		fi
	done
}

cve_check_services() { # Check identified services against known CVEs
	echo -e "${GREEN}[!]${NC} Checking identified services for known CVEs" |tee -a reckon
	
	# Extract service versions from nmap scans
	IFS=$'\n'
	for service_info in $(cat *-version 2>/dev/null | grep "open" | grep -v nmap); do
		port=$(echo "$service_info" | awk '{print$1}')
		service=$(echo "$service_info" | awk '{print$3}')
		version=$(echo "$service_info" | awk '{$1=$2=$3=$4=$5=""; print $0}' | xargs)
		
		echo "[-]      Checking $service $version for CVEs" |tee -a reckon
		# Could integrate with external CVE APIs here (NVD, etc)
	done
	unset IFS
}

service_vuln_check() { # Enhanced service vulnerability detection via NSE
	echo -e "${GREEN}[!]${NC} Running enhanced service vulnerability checks" |tee -a reckon
	
	# FTP vulnerabilities
	ftp_ports=$(cat .openports 2>/dev/null |grep ftp |wc -l)
	if [[ "$ftp_ports" -gt "0" ]]; then
		for ftpport in $(cat .openports |grep ftp |awk '{print$1}' |awk -F "/" '{print$1}'); do
			nmap -Pn -sV --script ftp-* $target -p $ftpport -oN $ftpport-ftp-vuln 2>/dev/null 1>/dev/null
			findings=$(cat $ftpport-ftp-vuln |grep "|" |wc -l)
			if [[ "$findings" -gt "0" ]]; then
				echo "[-]      FTP Vulnerabilities on port $ftpport:" |tee -a reckon
				cat $ftpport-ftp-vuln |grep "|" |cut -c 3- |tee -a reckon
			fi
		done
	fi
	
	# SMTP vulnerabilities
	smtp_ports=$(cat .openports 2>/dev/null |grep smtp |wc -l)
	if [[ "$smtp_ports" -gt "0" ]]; then
		for smtpport in $(cat .openports |grep smtp |awk '{print$1}' |awk -F "/" '{print$1}'); do
			nmap -Pn -sV --script smtp-* $target -p $smtpport -oN $smtpport-smtp-vuln 2>/dev/null 1>/dev/null
			findings=$(cat $smtpport-smtp-vuln |grep "|" |wc -l)
			if [[ "$findings" -gt "0" ]]; then
				echo "[-]      SMTP Vulnerabilities on port $smtpport:" |tee -a reckon
				cat $smtpport-smtp-vuln |grep "|" |cut -c 3- |tee -a reckon
			fi
		done
	fi
}

wafscan() { # Detect WAF/IPS/IDS
	echo -e "${GREEN}[!]${NC} Performing WAF Detection" |tee -a reckon
	for wport in $(cat .openports |grep http |awk '{print$1}' |awk -F "/" '{print$1}' |sort -g); do
		if [[ "$wport" == "443" ]]; then
			nmap --script http-waf-detection,http-waf-fingerprint -p $wport $target -oN $wport-waf 2>/dev/null 1>/dev/null
		else
			nmap --script http-waf-detection,http-waf-fingerprint -p $wport $target -oN $wport-waf 2>/dev/null 1>/dev/null
		fi
		
		waf_found=$(cat $wport-waf |grep -i "WAF\|detected" |wc -l)
		if [[ "$waf_found" -gt "0" ]]; then
			echo "[-]      WAF detected on port $wport:" |tee -a reckon
			cat $wport-waf |grep "|" |cut -c 3- |tee -a reckon
		fi
	done
}

web_app_vuln_scan() { # Comprehensive web application vulnerability scanning
	echo -e "${GREEN}[!]${NC} Running Web Application Vulnerability Scan" |tee -a reckon
	
	for wport in $(cat .openports |grep http |awk '{print$1}' |awk -F "/" '{print$1}' |sort -g); do
		if [[ "$wport" == "443" ]]; then
			web_url="https://$target"
		else
			web_url="http://$target:$wport"
		fi
		
		# OWASP Top 10 checks via NSE
		echo "[-]      Running OWASP Top 10 checks on $web_url" |tee -a reckon
		nmap --script http-vuln*,http-csrf*,http-slowloris* -p $wport $target -oN $wport-owasp 2>/dev/null 1>/dev/null
		
		findings=$(cat $wport-owasp |grep "|" |wc -l)
		if [[ "$findings" -gt "0" ]]; then
			IFS=$'\n'
			for vuln in $(cat $wport-owasp |grep "|" |cut -c 3-); do
				echo "[-]        $vuln" |tee -a reckon
			done
			unset IFS
		fi
		
		# Additional checks
		echo "[-]      Checking for common vulnerabilities:" |tee -a reckon
		nmap --script http-open-proxy,http-trace,http-auth-finder,http-sitemap-generator -p $wport $target -oN $wport-common-vuln 2>/dev/null 1>/dev/null
		
		findings=$(cat $wport-common-vuln |grep "|" |wc -l)
		if [[ "$findings" -gt "0" ]]; then
			IFS=$'\n'
			for vuln in $(cat $wport-common-vuln |grep "|" |cut -c 3-); do
				echo "[-]        $vuln" |tee -a reckon
			done
			unset IFS
		fi
	done
}

pathtraversal_scan() { # Test for path traversal vulnerabilities
	echo -e "${GREEN}[!]${NC} Testing for Path Traversal Vulnerabilities" |tee -a reckon
	
	for wport in $(cat .openports |grep http |awk '{print$1}' |awk -F "/" '{print$1}' |sort -g); do
		if [[ "$wport" == "443" ]]; then
			web_url="https://$target"
		else
			web_url="http://$target:$wport"
		fi
		
		# Simple path traversal tests
		for path in "etc/passwd" "..%2fwindows%2fsystem32" "....//....//....//etc/passwd"; do
			response=$(curl -s "$web_url/$path" 2>/dev/null | head -c 200)
			if [[ ! -z "$response" ]] && [[ "$response" != *"404"* ]] && [[ "$response" != *"not found"* ]]; then
				echo -e "${RED}[!] Path Traversal possible: $path${NC}" |tee -a reckon
			fi
		done
	done
}

information_disclosure_scan() { # Check for information disclosure
	echo -e "${GREEN}[!]${NC} Scanning for Information Disclosure" |tee -a reckon
	
	for wport in $(cat .openports |grep http |awk '{print$1}' |awk -F "/" '{print$1}' |sort -g); do
		if [[ "$wport" == "443" ]]; then
			web_url="https://$target"
		else
			web_url="http://$target:$wport"
		fi
		
		nmap --script http-methods,http-server-header,http-xssed,http-git,http-svn-enum -p $wport $target -oN $wport-info-disclosure 2>/dev/null 1>/dev/null
		
		findings=$(cat $wport-info-disclosure |grep "|" |wc -l)
		if [[ "$findings" -gt "0" ]]; then
			echo "[-]      Information Disclosure findings:" |tee -a reckon
			IFS=$'\n'
			for info in $(cat $wport-info-disclosure |grep "|" |cut -c 3-); do
				echo "[-]        $info" |tee -a reckon
			done
			unset IFS
		fi
	done
}

httpenum(){ # Runs various scanners against http and https ports - ENHANCED
	
	for wports in $(cat .openports |grep http |grep -v "Microsoft Windows RPC over HTTP" |awk '{print$1}' |awk -F "/" '{print$1}' |sort -g); do
		pullheaders
		nsedefhttp
		wafscan
		web_app_vuln_scan
		information_disclosure_scan
		pathtraversal_scan
		
		if [[ "${tool_available[testssl]}" == true ]]; then
			ssl_tls_scan
		fi
		
		if [[ "${tool_available[nuclei]}" == true ]]; then
			nuclei_scan
		fi
	done
	
	niktohttp&
	dirbhttp&
	
	# Run in background if tools available
	if [[ "${tool_available[sqlmap]}" == true ]] && [[ "$web_vuln_scan" == "True" ]]; then
		sqlmap_scan&
	fi
}

pullheaders(){ # Grabs HTTP headers from http://target/
	IFS=$'\n';
	if [[ $wports == "443" ]]; then
		curl -I -k https://$target -D $wports-header 2> /dev/null 1> /dev/null
	else
		curl -I http://$target:$wports -D $wports-header 2> /dev/null 1> /dev/null
	fi
	
	hcheck=$(cat $wports-header |grep :)
	if [[ -z "$hcheck" ]]; then
		echo -e "${GREEN}[!]${NC} Unable to pull HTTP headers for port $wports." |tee -a reckon
	else
		echo -e "${GREEN}[!]${NC}    Pulling HTTP headers for port $wports." |tee -a reckon
			for info in $(cat $wports-header |grep ":" |egrep -v "Date:"); do
				echo "[-]      $info" |tee -a reckon
			done
	fi
	unset IFS
}

niktohttp(){ # Runs default Nikto scan
	wports=$(cat .openports |grep -i http |grep -v "Microsoft Windows RPC over HTTP" |wc -l)
	if [[ "$wports" -gt "0" ]];then
		echo -e "${GREEN}[!]${NC}    Nikto queued for http ports." |tee -a reckon
		for nikports in $(cat .openports |grep -i http |grep -v "Microsoft Windows RPC over HTTP" |awk '{print$1}' |awk -F "/" '{print$1}' |sort -g); do
		
			if [[ "$wports" == "443" ]]; then
				nikto -h https://$target  2> /dev/null 1> $nikports-nikto
				echo -e "${GREEN}[!]${NC} The Nikto scan for https://$target has completed." "\a" |tee -a reckon
			else
				nikto -h http://$target:$nikports 2> /dev/null 1> $nikports-nikto
				echo -e "${GREEN}[!]${NC} The Nikto scan for http://$target:$nikports has completed." "\a" |tee -a reckon
			fi

			IFS=$'\n';
			for info in $(cat $nikports-nikto |grep + |egrep -v '(Target IP:|Target Hostname:|Target Port:|Start Time:|End Time:|host\(s\) tested|reported on remote host)' |sed 's/+ //g'); do
			echo "[-]      $info" |tee -a reckon
			done
			unset IFS
		done
	fi
}

dirbhttp(){  #Runs dirb against / of web services
	wports=$(cat .openports |grep -i http |grep -v "Microsoft Windows RPC over HTTP" |wc -l)
	if [[ "$wports" -gt "0" ]];then
		echo -e "${GREEN}[!]${NC}    Dirb queued for http ports." |tee -a reckon
		for dirbports in $(cat .openports |grep http |grep -v "Microsoft Windows RPC over HTTP" |awk '{print$1}' |awk -F "/" '{print$1}' |sort -g); do
		
			if [[ "$wports" == "443" ]]; then
				dirb https://$target/ /usr/share/wordlists/dirb/big.txt -S -r -w  2> /dev/null 1> $dirbports-dirb
				echo -e "${GREEN}[!]${NC} The Dirb scan for https://$target/ has completed." "\a" |tee -a reckon
			else
				dirb http://$target:$dirbports/ /usr/share/wordlists/dirb/big.txt -S -r -w 2> /dev/null 1> $dirbports-dirb
				echo -e "${GREEN}[!]${NC} The Dirb scan for http://$target:$dirbports/ has completed." "\a" |tee -a reckon
			fi

			dirbcheck=$(cat $dirbports-dirb |tr "\015" "\n" |egrep '(==>|\+)' |sed 's/+ http/http/g' |sed 's/==> //g' |grep -v Testing:|wc -l)
			if [[ "$dirbcheck" -gt "0" ]]; then
				IFS=$'\n';
					for info in $(cat $dirbports-dirb |tr "\015" "\n" |egrep '(==>|\+)' |sed 's/+ http/http/g' |sed 's/==> //g' |grep -v Testing:); do
					echo "[-]      $info" |tee -a reckon
					done
				unset IFS
			else
				if [[ "$wports" == "443" ]]; then
					echo -e "${GREEN}[!]${NC} Dirb found no file or directories in https://$target/ " "\a" |tee -a reckon
				else
					echo -e "${GREEN}[!]${NC} Dirb found no file or directories in http://$target:$dirbports/ " "\a" |tee -a reckon
				fi
			fi
		done
	fi
}

nsedefhttp(){ # Runs Default HTTP NSE scripts
	echo -e "${GREEN}[!]${NC} Running NSE Default Scripts against HTTP on port $wports" |tee -a reckon
	nmap -Pn -sT -sV -sC $target -p $wports -oN $wports-nse 2> /dev/null 1> /dev/null
	results=$(cat $wports-nse |grep "|" |wc -l)

	if [[ "$results" -gt "0" ]]; then
		IFS=$'\n';
		for nsescript in $(cat $wports-nse |grep "|" |cut -c 3-); do
			echo "[-]      $nsescript" |tee -a reckon
		done
		unset IFS
	else
		echo "[-]      No results from NSE Default Scripts" |tee -a reckon
	fi

	if [[ "results" == "0" ]]; then
		echo "[-]      No Results" |tee -a reckon
	fi
}

nsedefother(){ # Runs Default NSE scripts
	
	openudpports=$(cat .openudpports |grep open |egrep -vi '(microsoft-ds|netbios-ssn|samba|http)' |grep -v filtered |wc -l 2> /dev/null)
	opentcpports=$(cat .openports |egrep -vi '(microsoft-ds|netbios-ssn|samba|smb|http)' |grep open |wc -l)
	
	# NSE Default scripts for open TCP ports
	if [[ "$opentcpports" -gt "0" ]]; then
		for otherports in $(cat .openports |egrep -vi '(microsoft-ds|netbios-ssn|samba|smb|http)' |grep open |awk -F "/" '{print$1}'); do
			echo -e "${GREEN}[!]${NC} Running NSE Default Scripts against TCP port $otherports" |tee -a reckon
			nmap -Pn -sT -sV -sC $target -p $otherports --open -oN $otherports-tcp-nse 2> /dev/null 1> /dev/null
			results=$(cat $otherports-tcp-nse |grep "|" |wc -l)

			if [[ "$results" -gt "0" ]]; then
				IFS=$'\n';
				for nsescript in $(cat $otherports-tcp-nse |grep "|" |cut -c 3-); do
					echo "[-]      $nsescript" |tee -a reckon
				done
				unset IFS
			fi

			if [[ "results" == "0" ]]; then
				echo "[-]      No Results" |tee -a reckon
			fi

		done
	fi
	echo "" > .openports

	# NSE Default scripts for open UDP ports
	if [[ "$openudpports" -gt "0" ]]; then
		for otherports in $(cat .openudpports |egrep -vi '(microsoft-ds|netbios-ssn|samba|http)' |grep open |awk -F "/" '{print$1}' 2> /dev/null); do
			echo -e "${GREEN}[!]${NC} Running NSE Default Scripts against UDP port $otherports" |tee -a reckon
			nmap -Pn -sU -sV -sC $target -p $otherports --open -oN $otherports-udp-nse 2> /dev/null 1> /dev/null
			results=$(cat $otherports-udp-nse |grep "|" |wc -l)

			if [[ "$results" -gt "0" ]]; then
				IFS=$'\n';
				for nsescript in $(cat $otherports-udp-nse |grep "|" |cut -c 3-); do
					echo "[-]      $nsescript" |tee -a reckon
				done
				unset IFS
			fi

			if [[ "results" == "0" ]]; then
				echo "[-]      No Results" |tee -a reckon
			fi
			
		done
	fi	
	echo "" > .openudpports
}

enumflnx(){ # Runs enum4linux
	enumdir=$(pwd)
	echo -e "${GREEN}[!]${NC} Running Enum4Linux on $target" |tee -a reckon
	enum4linux $target 1> smb-enum4linux 2> /dev/null
	smblines=$(cat $enumdir/smb-enum4linux |wc -l)
	echo -e "${GREEN}[!]${NC} Enum4Linux Report contains $smblines lines! "  |tee -a reckon
	echo -e "${GREEN}[!]${NC} Review: $enumdir/smb-enum4linux" |tee -a reckon

	IFS=$'\n'
	for eflrep in $(cat smb-enum4linux |egrep '(allows sessions|\/\/)' |sed 's/\[+] //g' |grep -v "enum4linux v"); do
	echo "[-]      $eflrep" |tee -a reckon
	done
	unset IFS
}

smbnsedefault(){ # Runs Def NSE SMB scripts
	echo -e "${GREEN}[!]${NC} Running NSE Default Scripts for SMB ports" |tee -a reckon
	for smbports in $(cat .open* |grep open |egrep -i '(microsoft-ds|netbios-ssn|samba|smb)'|awk -F "/" '{print$1}' |sort -g);do
		nmap -Pn -sV -sC -sT -sU $target -p $smbports --open -oN $smbports-smb-nsedef 2> /dev/null 1> /dev/null
		IFS=$'\n'
			for smbenumdef in $(cat $smbports-smb-nsedef |grep "|" |cut -c 3-); do
				echo "[-]      $smbenumdef" |tee -a reckon
			done
			unset IFS
	done
}

smbnsevulns(){ # Runs all smb-vuln NSE scripts. DANGER: This could crash the target
	echo -e "${GREEN}[!]${NC} Running NSE Vuln Scripts for SMB" |tee -a reckon
	nmap -sT -sU -sV -p 137,138,139,445 $target --script smb-vuln* -oN smb-nsevulns 2> /dev/null 1> /dev/null
	
	smbresults=$(cat smb-nsevulns |grep "|" |wc -l)
	
	if [[ "$smbresults" -gt "0" ]]; then
		IFS=$'\n';
		for smbscan in $(cat smb-nsevulns |grep "|" |cut -c 3-); do
			echo "[-]      $smbscan" |tee -a reckon
		done
		unset IFS
	else 
	echo -e "${GREEN}[!]${NC} NSE Vuln Scripts for SMB - No Results" |tee -a reckon
	fi
}

enumscans(){ # Creates a priority of services to enumerate first
	wports=$(cat *-version |grep open |grep -i http |wc -l)
		if [[ "$wports" -gt "0" ]]; then
			httpenum
		fi

	smbports=$(cat *-version |grep open |egrep -i '(microsoft-ds|netbios-ssn|samba|smb)'|wc -l)
		if [[ "$smbports" -gt "0" ]]; then
			enumflnx
			smbnsedefault
			smbnsevulns
		fi

	otherports=$(cat *-version |grep open |egrep -vi '(microsoft-ds|netbios-ssn|samba|smb|http)' |wc -l)
		if [[ "$otherports" -gt "0" ]]; then
				nsedefother
		fi
}

alltcpscan(){ # Scans for all TCP ports but excludes previously discovered ports in output
	nmap -Pn -sT $target -oN fullscan -p- --open >/dev/null 2>&1;
	cat fullscan |grep open |grep -v nmap > .fsopen

	for qsopen in $(cat quickscan |grep open |grep -v nmap |awk '{print$1}');do
		cat .fsopen |grep open |grep -v "$qsopen" >> .fsopen1
		mv .fsopen1 .fsopen
	done

	delta=$(cat .fsopen |wc -l)

	if [[ "$delta" -gt "0" ]]; then
		echo -e "${GREEN}[!]${NC}   Full Scan identified $(cat .fsopen |wc -l) additional TCP port(s) on $target" "\a"  |tee -a reckon
		for nports in $(cat .fsopen |awk '{print$1}'); do 
			echo "[-]      $nports" |tee -a reckon
		done
		mv .fsopen .openports

		echo -e "${GREEN}[!]${NC} Running Version Scan against open port(s)"  |tee -a reckon
		versionscantcp
	
		echo -e "${GREEN}[!]${NC} Running Enumeration Scans against $(cat .openports |wc -l) open port(s)" |tee -a reckon
		enumscans
	else
		echo -e "${GREEN}[!]${NC}   No additional TCP ports identified" |tee -a reckon
	fi
}

alludpscan(){ # Scans for all UDP ports but excludes previously discovered ports in output
	nmap -Pn -sU $target -oN fulludpscan -p- --open >/dev/null 2>&1;
	cat fulludpscan |grep open |grep -v filtered |grep -v nmap > .fsopen

	for qsopen in $(cat quickudpscan |grep open |grep -v filtered |grep -v nmap |awk '{print$1}');do
		cat .fsopen |grep open |grep -v "$qsopen" >> .fsopen1
		mv .fsopen1 .fsopen
	done

	delta=$(cat .fsopen |wc -l)

	if [[ "$delta" -gt "0" ]]; then
		echo -e "${GREEN}[!]${NC}   Full Scan identified $(cat .fsopen |wc -l) additional UDP port(s) on $target" "\a"  |tee -a reckon
		for nports in $(cat .fsopen |awk '{print$1}'); do 
			echo "[-]      $nports" |tee -a reckon
		done
		mv .fsopen .openudpports

		echo -e "${GREEN}[!]${NC} Running Version Scan against $(cat .openudpports |wc -l 2> /dev/null) UDP port(s)"  |tee -a reckon
		versionscanudp
	
		echo -e "${GREEN}[!]${NC} Running Enumeration Scans against $(cat .openudpports |wc -l 2> /dev/null) UDP ports(s)" |tee -a reckon
		enumscans
	else
		echo -e "${GREEN}[!]${NC}   No additional UDP ports identified" |tee -a reckon
	fi
}

waitforscans(){ # Holds the terminal open until all Nikto scans have completed
    scansrunning=$(ps -aux |grep $target |grep -v grep |grep -v reckon |wc -l)
	echo -e "${GREEN}[!]${NC} Waiting on $scansrunning scan(s) to complete"

	nikrun=$(ps -aux |grep $target |grep nikto |wc -l)
	if [[ "$nikrun" -gt "0" ]]; then 
	echo "[-]      Nikto still running" |tee -a reckon
	fi

	dirbrun=$(ps -aux |grep $target |grep dirb |wc -l)
	if [[ "$dbirun" -gt "0" ]]; then 
	echo "[-]      Dirb still running" |tee -a reckon
	fi

	if [[ "$scansrunning" -gt "0" ]]; then
		while [[ "$scansrunning" -gt "0" ]]; do 
			sleep 1
			scansrunning=$(ps -aux |grep $target |grep -v grep |grep -v reckon |wc -l)	
		done 
	fi
}

generate_vulnerability_report() { # Consolidate findings into a report
	echo -e "${GREEN}[!]${NC} Generating Vulnerability Assessment Report" |tee -a reckon
	
	report_file="VULNERABILITY_REPORT_$(date +%s).txt"
	
	echo "========================================" > $report_file
	echo "  VULNERABILITY ASSESSMENT REPORT" >> $report_file
	echo "  Target: $target" >> $report_file
	echo "  Scan Date: $(date)" >> $report_file
	echo "========================================" >> $report_file
	echo "" >> $report_file
	
	# Critical Issues
	echo "[CRITICAL FINDINGS]" >> $report_file
	cat *-version 2>/dev/null | grep -i "vulnerable\|critical\|exploit" | sort -u >> $report_file
	cat *-nse 2>/dev/null | grep -i "vulnerable\|critical" | cut -c 3- | sort -u >> $report_file
	grep -r "VULNERABLE" . 2>/dev/null | grep -v ".git" | sort -u >> $report_file
	echo "" >> $report_file
	
	# High Risk
	echo "[HIGH RISK FINDINGS]" >> $report_file
	cat *-owasp 2>/dev/null | grep "|" | cut -c 3- >> $report_file
	cat *-nukeli 2>/dev/null | sort -u >> $report_file
	echo "" >> $report_file
	
	# Medium Risk
	echo "[MEDIUM RISK - Service Information]" >> $report_file
	cat *-version 2>/dev/null | grep "open" | head -20 >> $report_file
	echo "" >> $report_file
	
	# Web Server Issues
	if [[ -f "VULNERABILITY_REPORT_*.txt" ]]; then
		echo "[WEB SERVER FINDINGS]" >> $report_file
		grep -h "^|-" *-nikto 2>/dev/null | sort -u | head -20 >> $report_file
		grep -h "^|-" *-dirb 2>/dev/null | sort -u | head -20 >> $report_file
		echo "" >> $report_file
	fi
	
	# SSL/TLS Issues
	if [[ $(ls *-ssl-test 2>/dev/null | wc -l) -gt 0 ]]; then
		echo "[SSL/TLS VULNERABILITIES]" >> $report_file
		cat *-ssl-test 2>/dev/null | grep -E "VULNERABLE|WARN" >> $report_file
		echo "" >> $report_file
	fi
	
	# SMB Vulnerabilities
	if [[ $(ls smb-* 2>/dev/null | wc -l) -gt 0 ]]; then
		echo "[SMB VULNERABILITIES]" >> $report_file
		cat smb-* 2>/dev/null | grep -E "vulnerable|exploit" -i | sort -u >> $report_file
		echo "" >> $report_file
	fi
	
	# DNS Issues
	if [[ -f "dns-axfr" ]] && [[ $(wc -l < dns-axfr) -gt 5 ]]; then
		echo "[DNS VULNERABILITIES - ZONE TRANSFER SUCCESSFUL]" >> $report_file
		head -20 dns-axfr >> $report_file
		echo "" >> $report_file
	fi
	
	# Summary Statistics
	echo "[SCAN STATISTICS]" >> $report_file
	echo "Total Open TCP Ports: $(cat .openports 2>/dev/null | wc -l)" >> $report_file
	echo "Total Open UDP Ports: $(cat .openudpports 2>/dev/null | wc -l)" >> $report_file
	echo "Services Identified: $(cat *-version 2>/dev/null | grep open | wc -l)" >> $report_file
	echo "Vulnerability Findings: $(grep -r "VULNERABLE\|vulnerable" . 2>/dev/null | wc -l)" >> $report_file
	echo "" >> $report_file
	
	echo -e "${GREEN}[!]${NC} Report saved to: $report_file" |tee -a reckon
}

enumerate_users() { # Attempt user enumeration on identified services
	echo -e "${GREEN}[!]${NC} Attempting user enumeration" |tee -a reckon
	
	# SMTP user enumeration
	smtp_ports=$(cat .openports 2>/dev/null |grep smtp |wc -l)
	if [[ "$smtp_ports" -gt "0" ]]; then
		for smtpport in $(cat .openports |grep smtp |awk '{print$1}' |awk -F "/" '{print$1}'); do
			echo "[-]      SMTP user enumeration on port $smtpport" |tee -a reckon
			nmap --script smtp-enum-users -p $smtpport $target -oN $smtpport-smtp-users 2>/dev/null 1>/dev/null
			cat $smtpport-smtp-users |grep "|" |cut -c 3- |tee -a reckon
		done
	fi
	
	# SNMP enumeration
	snmp_ports=$(cat .openports 2>/dev/null |grep snmp |wc -l)
	if [[ "$snmp_ports" -gt "0" ]] || [[ "$snmp_ports" -gt "0" ]]; then
		echo "[-]      SNMP enumeration" |tee -a reckon
		nmap --script snmp-sysdescr,snmp-processes -p 161 $target -oN snmp-enum 2>/dev/null 1>/dev/null
		cat snmp-enum |grep "|" |cut -c 3- |tee -a reckon
	fi
}

# === API TESTING MODULE ===
api_testing_module() {
	if [[ "$api_testing" != "True" ]]; then
		return
	fi
	
	echo -e "${BLUE}[*]${NC} ===== API TESTING MODULE =====" |tee -a reckon
	
	# REST API endpoint discovery
	rest_api_scan() {
		echo -e "${GREEN}[!]${NC} Scanning for REST API endpoints" |tee -a reckon
		
		for wport in $(cat .openports |grep http |awk '{print$1}' |awk -F "/" '{print$1}'); do
			if [[ "$wport" == "443" ]]; then
				web_url="https://$target"
			else
				web_url="http://$target:$wport"
			fi
			
			# Common API paths
			for api_path in "/api" "/api/v1" "/api/v2" "/rest" "/graphql" "/soap" "/services" "/webservices"; do
				response=$(curl -s -o /dev/null -w "%{http_code}" "$web_url$api_path" 2>/dev/null)
				if [[ "$response" != "404" ]] && [[ "$response" != "000" ]]; then
					echo "[-]      Found API endpoint: $web_url$api_path (HTTP $response)" |tee -a reckon
				fi
			done
		done
	}
	
	# GraphQL introspection
	graphql_introspection() {
		echo -e "${GREEN}[!]${NC} Testing for GraphQL endpoints" |tee -a reckon
		
		for wport in $(cat .openports |grep http |awk '{print$1}' |awk -F "/" '{print$1}'); do
			if [[ "$wport" == "443" ]]; then
				web_url="https://$target"
			else
				web_url="http://$target:$wport"
			fi
			
			# Test GraphQL endpoints
			for graphql_path in "/graphql" "/api/graphql" "/gql"; do
				response=$(curl -s -X POST -H "Content-Type: application/json" \
					-d '{"query":"{ __schema { types { name } } }"}' \
					"$web_url$graphql_path" 2>/dev/null)
				
				if [[ "$response" == *"__schema"* ]] || [[ "$response" == *"types"* ]]; then
					echo -e "${RED}[-] GraphQL endpoint found: $web_url$graphql_path${NC}" |tee -a reckon
					echo "$response" | head -5 |tee -a reckon
				fi
			done
		done
	}
	
	# JWT token detection and analysis
	jwt_token_scan() {
		echo -e "${GREEN}[!]${NC} Scanning for JWT tokens in responses" |tee -a reckon
		
		for wport in $(cat .openports |grep http |awk '{print$1}' |awk -F "/" '{print$1}'); do
			if [[ "$wport" == "443" ]]; then
				web_url="https://$target"
			else
				web_url="http://$target:$wport"
			fi
			
			# Check for JWT in common locations
			response=$(curl -s -i "$web_url" 2>/dev/null | grep -i "eyJ")
			if [[ ! -z "$response" ]]; then
				echo "[-]      JWT token detected in responses" |tee -a reckon
			fi
		done
	}
	
	# Run API tests
	rest_api_scan
	graphql_introspection
	jwt_token_scan
	
	echo "[-]      API Testing Module Complete" |tee -a reckon
}

# === CLOUD TESTING MODULE ===
cloud_testing_module() {
	if [[ "$cloud_testing" != "True" ]]; then
		return
	fi
	
	echo -e "${BLUE}[*]${NC} ===== CLOUD TESTING MODULE =====" |tee -a reckon
	
	# AWS S3 bucket enumeration (from DNS/WHOIS data)
	aws_s3_enum() {
		echo -e "${GREEN}[!]${NC} Attempting AWS S3 bucket discovery" |tee -a reckon
		
		# Extract domain from target
		domain=$(echo $target | grep -oE '[a-zA-Z0-9-]+\.[a-zA-Z]{2,}' | head -1)
		
		if [[ ! -z "$domain" ]]; then
			# Common S3 bucket patterns
			for pattern in "$domain" "www-$domain" "api-$domain" "assets-$domain" "backup-$domain"; do
				bucket_name=${pattern//./-}
				
				# Check S3 accessibility
				response=$(curl -s -I "https://$bucket_name.s3.amazonaws.com" 2>/dev/null | head -1)
				
				if [[ "$response" == *"200"* ]] || [[ "$response" == *"301"* ]]; then
					echo -e "${RED}[-] VULNERABLE: S3 bucket found: $bucket_name${NC}" |tee -a reckon
				fi
			done
		fi
	}
	
	# Azure blob storage detection
	azure_blob_enum() {
		echo -e "${GREEN}[!]${NC} Scanning for Azure blob storage" |tee -a reckon
		
		domain=$(echo $target | grep -oE '[a-zA-Z0-9-]+\.[a-zA-Z]{2,}' | head -1)
		
		if [[ ! -z "$domain" ]]; then
			for pattern in "$domain" "backup" "data" "files"; do
				storage_name=${pattern//./-}
				
				response=$(curl -s -I "https://$storage_name.blob.core.windows.net" 2>/dev/null | head -1)
				
				if [[ "$response" == *"200"* ]] || [[ "$response" == *"301"* ]]; then
					echo -e "${RED}[-] VULNERABLE: Azure blob found: $storage_name${NC}" |tee -a reckon
				fi
			done
		fi
	}
	
	# Google Cloud Storage detection
	gcs_enum() {
		echo -e "${GREEN}[!]${NC} Scanning for Google Cloud Storage buckets" |tee -a reckon
		
		domain=$(echo $target | grep -oE '[a-zA-Z0-9-]+\.[a-zA-Z]{2,}' | head -1)
		
		if [[ ! -z "$domain" ]]; then
			for pattern in "$domain" "backup-$domain" "cdn-$domain"; do
				bucket_name=${pattern//./-}
				
				response=$(curl -s -I "https://storage.googleapis.com/$bucket_name" 2>/dev/null | head -1)
				
				if [[ "$response" == *"200"* ]]; then
					echo -e "${RED}[-] VULNERABLE: GCS bucket found: $bucket_name${NC}" |tee -a reckon
				fi
			done
		fi
	}
	
	# CloudFlare configuration detection
	cloudflare_check() {
		echo -e "${GREEN}[!]${NC} Checking CloudFlare configuration" |tee -a reckon
		
		# Check if target uses CloudFlare
		cf_check=$(dig $target +short 2>/dev/null | grep -i "cloudflare" | wc -l)
		
		if [[ "$cf_check" -gt "0" ]]; then
			echo "[-]      Target is protected by CloudFlare CDN" |tee -a reckon
		fi
	}
	
	# Run cloud tests
	aws_s3_enum
	azure_blob_enum
	gcs_enum
	cloudflare_check
	
	echo "[-]      Cloud Testing Module Complete" |tee -a reckon
}

# === CONTAINER TESTING MODULE ===
container_testing_module() {
	if [[ "$container_testing" != "True" ]]; then
		return
	fi
	
	echo -e "${BLUE}[*]${NC} ===== CONTAINER TESTING MODULE =====" |tee -a reckon
	
	# Docker registry detection
	docker_registry_scan() {
		echo -e "${GREEN}[!]${NC} Scanning for Docker registry endpoints" |tee -a reckon
		
		# Common Docker registry ports
		for registry_port in 5000 5001 2375 2376; do
			response=$(curl -s -i http://$target:$registry_port/v2/ 2>/dev/null | head -1)
			
			if [[ "$response" == *"200"* ]] || [[ "$response" == *"401"* ]]; then
				echo -e "${RED}[-] Docker registry found on port $registry_port${NC}" |tee -a reckon
				
				# List repositories
				repos=$(curl -s http://$target:$registry_port/v2/_catalog 2>/dev/null)
				echo "[-]      Repositories: $repos" |tee -a reckon
			fi
		done
	}
	
	# Kubernetes API detection
	kubernetes_scan() {
		echo -e "${GREEN}[!]${NC} Scanning for Kubernetes API endpoints" |tee -a reckon
		
		# Common K8s API ports
		for k8s_port in 6443 8443 10250 10251 10252 8080; do
			response=$(curl -s -k -i https://$target:$k8s_port/api/v1 2>/dev/null | head -1)
			
			if [[ "$response" == *"200"* ]] || [[ "$response" == *"403"* ]]; then
				echo -e "${RED}[-] Kubernetes API endpoint found on port $k8s_port${NC}" |tee -a reckon
			fi
		done
	}
	
	# Container escape vulnerabilities
	container_escape_check() {
		echo -e "${GREEN}[!]${NC} Checking for container escape vulnerabilities" |tee -a reckon
		
		# Check for privileged container indicators
		for indicator in "docker.sock" "cgroup" "proc/cmdline"; do
			check=$(curl -s http://$target/admin/$indicator 2>/dev/null | wc -l)
			if [[ "$check" -gt "0" ]]; then
				echo "[-]      Potential container escape vector: $indicator" |tee -a reckon
			fi
		done
	}
	
	# Run container tests
	docker_registry_scan
	kubernetes_scan
	container_escape_check
	
	echo "[-]      Container Testing Module Complete" |tee -a reckon
}

# === INFRASTRUCTURE AS CODE TESTING MODULE ===
iac_testing_module() {
	if [[ "$iac_testing" != "True" ]]; then
		return
	fi
	
	echo -e "${BLUE}[*]${NC} ===== INFRASTRUCTURE AS CODE TESTING MODULE =====" |tee -a reckon
	
	# Terraform misconfiguration detection
	terraform_scan() {
		echo -e "${GREEN}[!]${NC} Scanning for Terraform files and misconfigurations" |tee -a reckon
		
		# Look for .tf files in common locations
		for tf_path in "/.terraform" "/.git" "/config" "/infrastructure" "/terraform"; do
			response=$(curl -s -r 0-0 http://$target:80$tf_path 2>/dev/null | head -1)
			
			if [[ ! -z "$response" ]] && [[ "$response" != *"404"* ]]; then
				echo "[-]      Potential Terraform directory exposed: $tf_path" |tee -a reckon
			fi
		done
		
		# Common Terraform misconfigurations
		echo "[-]      Checking for Terraform state files" |tee -a reckon
	}
	
	# CloudFormation template detection
	cloudformation_scan() {
		echo -e "${GREEN}[!]${NC} Scanning for CloudFormation templates" |tee -a reckon
		
		for cf_path in "/.aws" "/cloudformation" "/templates"; do
			response=$(curl -s -i http://$target:80$cf_path 2>/dev/null | head -1)
			
			if [[ "$response" != *"404"* ]]; then
				echo "[-]      Potential CloudFormation path found: $cf_path" |tee -a reckon
			fi
		done
	}
	
	# Helm chart scanning
	helm_scan() {
		echo -e "${GREEN}[!]${NC} Scanning for Helm chart vulnerabilities" |tee -a reckon
		
		# Check for Chart.yaml indicators
		for helm_path in "/helm" "/charts" "/kubernetes/charts"; do
			response=$(curl -s http://$target:80$helm_path/Chart.yaml 2>/dev/null | head -1)
			
			if [[ ! -z "$response" ]]; then
				echo "[-]      Helm chart found at: $helm_path" |tee -a reckon
			fi
		done
	}
	
	# Secrets detection in configuration
	secrets_scan() {
		echo -e "${GREEN}[!]${NC} Scanning for exposed secrets in IaC" |tee -a reckon
		
		# Common secret patterns to check
		echo "[-]      Checking for hardcoded credentials patterns" |tee -a reckon
	}
	
	# Run IaC tests
	terraform_scan
	cloudformation_scan
	helm_scan
	secrets_scan
	
	echo "[-]      Infrastructure as Code Testing Module Complete" |tee -a reckon
}

# === NETWORK MONITORING MODULE ===
network_monitor_module() {
	echo -e "${GREEN}[!]${NC} ============ Network Monitoring Module ============" |tee -a reckon
	
	# Create pcap output directory
	mkdir -p "$pcap_output_dir" 2> /dev/null
	
	# List available network interfaces
	echo -e "${YELLOW}[?]${NC} Available Network Interfaces:" |tee -a reckon
	local -i counter=1
	local -a interfaces
	
	# Get all active interfaces
	if command -v ifconfig &> /dev/null; then
		interfaces=($(ifconfig -l 2>/dev/null | tr ' ' '\n'))
	elif command -v ip &> /dev/null; then
		interfaces=($(ip link show | grep "^[0-9]:" | awk -F': ' '{print $2}'))
	else
		echo -e "${RED}[ER]${NC} Neither ifconfig nor ip command found" |tee -a reckon
		return 1
	fi
	
	# Display available interfaces with details
	for iface in "${interfaces[@]}"; do
		if [[ "$iface" != "lo" && "$iface" != "lo0" ]]; then
			if command -v ifconfig &> /dev/null; then
				local ip=$(ifconfig "$iface" 2>/dev/null | grep "inet " | awk '{print $2}')
			else
				local ip=$(ip addr show "$iface" 2>/dev/null | grep "inet " | awk '{print $2}')
			fi
			echo -e "    ${BLUE}[$counter]${NC} $iface ${ip:+($ip)}"
			counter=$((counter + 1))
		fi
	done
	
	# Let user select interface
	echo ""
	read -p "Select interface number (or enter custom interface name): " interface_choice
	
	# Validate and set interface
	if [[ "$interface_choice" =~ ^[0-9]+$ ]]; then
		selected_interface="${interfaces[$((interface_choice - 1))]}"
	else
		selected_interface="$interface_choice"
	fi
	
	# Verify interface exists
	if ! ip link show "$selected_interface" &> /dev/null && ! ifconfig "$selected_interface" &> /dev/null; then
		echo -e "${RED}[ER]${NC} Invalid interface: $selected_interface" |tee -a reckon
		return 1
	fi
	
	echo -e "${GREEN}[✓]${NC} Selected interface: $selected_interface" |tee -a reckon
	
	# Ask for capture filter
	echo ""
	read -p "Enter tcpdump filter (empty for all traffic, examples: 'tcp port 80', 'udp port 53'): " filter_choice
	if [[ -z "$filter_choice" ]]; then
		filter_choice=""
	fi
	
	# Generate output filename with timestamp
	local timestamp=$(date +%Y%m%d_%H%M%S)
	local pcap_file="$pcap_output_dir/capture_${selected_interface}_${timestamp}.pcap"
	
	echo ""
	echo -e "${YELLOW}[*]${NC} Starting packet capture on $selected_interface" |tee -a reckon
	echo -e "    Output file: $pcap_file" |tee -a reckon
	echo -e "    Filter: ${filter_choice:-'all traffic'}" |tee -a reckon
	echo -e "    ${BLUE}Press Ctrl+C to stop capture${NC}" |tee -a reckon
	echo ""
	
	# Start tcpdump with elevated privileges if needed
	if [[ $EUID -ne 0 ]]; then
		echo -e "${YELLOW}[!]${NC} tcpdump requires elevated privileges. Using sudo..." |tee -a reckon
		sudo tcpdump -i "$selected_interface" -w "$pcap_file" $filter_choice
	else
		tcpdump -i "$selected_interface" -w "$pcap_file" $filter_choice
	fi
	
	# Show capture statistics
	if [[ -f "$pcap_file" ]]; then
		local packet_count=$(tcpdump -r "$pcap_file" 2>/dev/null | wc -l)
		local file_size=$(du -h "$pcap_file" | cut -f1)
		
		echo ""
		echo -e "${GREEN}[✓]${NC} Packet capture complete" |tee -a reckon
		echo -e "    Packets captured: $packet_count" |tee -a reckon
		echo -e "    File size: $file_size" |tee -a reckon
		echo -e "    Location: $(pwd)/$pcap_file" |tee -a reckon
		
		# Ask if user wants to analyze the capture
		echo ""
		read -p "View packet summary? (y/n): " view_choice
		if [[ "$view_choice" == "y" ]]; then
			echo -e "\n${BLUE}[*]${NC} Packet Summary:" |tee -a reckon
			tcpdump -r "$pcap_file" 2>/dev/null | head -20 |tee -a reckon
			echo "    ... (showing first 20 packets, view full file with: tcpdump -r $pcap_file)" |tee -a reckon
		fi
	fi
}

mainfunction(){ # Runs enumeration functions for a single host $1 user arguement
	workdir=$(pwd)
	mkdir $workdir/$target 2> /dev/null
	cd $workdir/$target
	echo -e "${GREEN}[!]${NC} Testing directory created at: $(pwd) " |tee -a reckon

	# Check tool availability
	check_tools_availability
	
	# ===== PHASE 1: DISCOVERY =====
	echo -e "${BLUE}[*]${NC} ===== PHASE 1: DISCOVERY =====" |tee -a reckon
	
	if [[ "$dns_enum" == "True" ]]; then
		dns_recon
		whois_lookup
	fi

	echo -e "${GREEN}[!]${NC} Running Quick Scan against the top $tports TCP/UDP ports" |tee -a reckon
	topscan

	openports=$(cat .open* |wc -l)
	if [[ "$openports" -gt "0" ]]; then
	echo -e "${GREEN}[!]${NC} Running Version Scans against open ports"  |tee -a reckon
	fi

	tcpports=$(cat .openports |grep open |wc -l)
	if [[ "$tcpports" -gt "0" ]]; then	
	versionscantcp
	fi

	udpports=$(cat .openudpports |grep open |wc -l 2> /dev/null)
	if [[ "$udpports" -gt "0" ]]; then
	versionscanudp
	fi

	# ===== PHASE 2: VULNERABILITY SCANNING =====
	echo -e "${BLUE}[*]${NC} ===== PHASE 2: VULNERABILITY SCANNING =====" |tee -a reckon
	
	if [[ "$service_vuln_scan" == "True" ]]; then
		service_vuln_check
		cve_check_services
	fi

	if [[ "$tcpports" -gt "0" ]]; then
	echo -e "${GREEN}[!]${NC} Running Enumeration Scripts against identified TCP ports" |tee -a reckon
	enumscans
	fi

	# ===== PHASE 3: DEEP SCANNING =====
	echo -e "${BLUE}[*]${NC} ===== PHASE 3: DEEP SCANNING =====" |tee -a reckon
	
	echo -e "${GREEN}[!]${NC} Running Full TCP Scan" |tee -a reckon
	alltcpscan
	
	if [[ "$enumerate_users" == "True" ]]; then
		enumerate_users
	fi

	# Enabling this will do a full UDP scan, which will take a significant amount of time.
	# echo -e "${GREEN}[!]${NC} Running Full UDP Scan. Get comfortable, this may take awhile.." |tee -a reckon
	# alludpscan

	scansrunning=$(ps -aux |grep $target |grep -v grep |grep -v reckon |wc -l)
	if [[ "$scansrunning" -gt "0" ]]; then	
	waitforscans
	fi

	# ===== PHASE 4: REPORTING & CONSOLIDATION =====
	echo -e "${BLUE}[*]${NC} ===== PHASE 4: REPORTING & CONSOLIDATION =====" |tee -a reckon
	
	# ===== MODULE EXECUTION (if enabled) =====
	if [[ "$api_testing" == "True" ]]; then
		api_testing_module
	fi
	
	if [[ "$cloud_testing" == "True" ]]; then
		cloud_testing_module
	fi
	
	if [[ "$container_testing" == "True" ]]; then
		container_testing_module
	fi
	
	if [[ "$iac_testing" == "True" ]]; then
		iac_testing_module
	fi
	
	generate_vulnerability_report
	
	#rm .openports
	#rm .openudpports
	
	echo -e "${GREEN}[!]${NC} ---------------------------------------- " |tee -a reckon
	echo -e "${GREEN}[!]${NC}  The following files have been created   " |tee -a reckon
	echo -e "${GREEN}[!]${NC} ---------------------------------------- " |tee -a reckon
	ls |sort -n > .files
	for files in $(cat .files); do
		echo "[-]          $files" |tee -a reckon
	done
	echo -e "${GREEN}[!]${NC} ---------------------------------------- " |tee -a reckon
	echo -e "${GREEN}[!]${NC}    $(($SECONDS / 3600)) hours, $((($SECONDS / 60) % 60)) minutes, and $(($SECONDS % 60)) seconds" |tee -a reckon
	echo -e "${GREEN}[!]${NC} --------- Reckon Scan Complete --------- " |tee -a reckon
}

splash(){ # Banner just because
	echo -e "${GREEN} ---------------------------------${NC}"
	echo -e "${GREEN} |  _ \ ___  ___| | _____  _ __   ${NC}"
	echo -e "${GREEN} | |_) / _ \/ __| |/ / _ \| '_ \  ${NC}"
	echo -e "${GREEN} |  _ <  __/ (__|   < (_) | | | | ${NC}"
	echo -e "${GREEN} |_| \_\___|\___|_|\_\___/|_| |_| ${NC}"
	echo -e "${GREEN} ---------------------------------${NC}"
	echo -e "${GREEN} --- Written by MaliceInChains ---${NC}"
	echo -e ""
}

usage(){ # To be printed when user input is not valid
		echo -e "All scan results will be stored in the current working directory"
		echo -e ""
		echo -e "${BLUE}[!] BASIC USAGE:${NC}"
		echo -e "[-] ./wreckon.sh 192.168.1.100           # Scan single host"
		echo -e "[-] ./wreckon.sh scanme.nmap.org         # Scan by domain"
		echo -e "[-] ./wreckon.sh /home/user/hostlist.txt # Scan multiple hosts"
		echo -e ""
		echo -e "${BLUE}[!] NETWORK MONITORING (SEPARATE from scanning):${NC}"
		echo -e "[-] ./wreckon.sh --monitor       # Start packet capture (interactive)"
		echo -e "[-] ./wreckon.sh -m              # Short form"
		echo -e ""
		echo -e "${YELLOW}NOTE: Network monitoring runs INDEPENDENTLY of scanning${NC}"
		echo -e "      Run ./wreckon.sh --monitor in ONE terminal"
		echo -e "      Run ./wreckon.sh 10.10.10.10 in ANOTHER terminal"
		echo -e "      Both capture and scan happen simultaneously"
		echo -e ""
		echo -e "${BLUE}[!] INTERACTIVE CONFIGURATION (Metasploit-style):${NC}"
		echo -e "[-] ./wreckon.sh --config        # Enter interactive config mode"
		echo -e "[-] ./wreckon.sh --show-options  # Show all options without scanning"
		echo -e ""
		echo -e "${YELLOW}Configuration Commands:${NC}"
		echo -e "    SET api_testing = true              # Enable API testing"
		echo -e "    SET cloud_testing = false           # Disable cloud testing"
		echo -e "    SET tports 500                      # Scan top 500 ports"
		echo -e "    SET network_monitor true            # Enable packet capture during scan"
		echo -e "    SET monitor_interface eth0          # Change interface"
		echo -e "    SET pcap_filter 'tcp port 80'       # Set capture filter"
		echo -e ""
		echo -e "${BLUE}[!] Configuration File Editing:${NC}"
		echo -e "[-] Edit the top of wreckon.sh directly to change defaults:"
		echo -e "    dns_enum, ssl_scan, owasp_scan, web_vuln_scan, service_vuln_scan"
		echo -e "    api_testing, cloud_testing, container_testing, iac_testing"
		echo ""
}

validate(){ # Validates $1 user argument and determines single host, or host file
	userinput=$1
	testinput=$(ping -w1 $userinput 2>&1)
	singlehost=$(echo $testinput |egrep '(bytes of data|data bytes)' |wc -l)
	hostlist=$(echo $testinput |grep "Name or service not known" |wc -l)

	if [[ -z "$userinput" ]]; then
		echo ""
		usage
		exit 1
	fi

	if [[ "$singlehost" -gt "0" ]];then
		target=$userinput
		mainfunction $target

	elif [[ "$hostlist" -gt "0" ]];then
		filecheck=$(file $userinput |grep "ASCII text" |wc -l)

		if [[ "$filecheck" -gt "0" ]]; then
			listcnt=$(cat $userinput |wc -l)	
				echo -e "${GREEN}[!]${NC} Host list detected. Scanning $listcnt total hosts" 
				for target in $(cat $userinput); do 
					testinput=$(ping -w1 $target 2>&1)
					hostlisttarget=$(echo $testinput |grep "bytes of data" |wc -l)

						if [[ "$hostlisttarget" -gt "0" ]];then
							mainfunction $target $userinput
						else 
							echo -e "${RED}[ER] Host list error: $1 is not a valid IP or domain ${NC}"
						fi
				done
		else 
			echo ""
			echo -e "${RED}[ER]  Error: $1 is not a valid IP, domain, or host list ${NC}"
			echo ""
			usage
		fi
	fi
}

splash

# Check for special commands
case "$1" in
	--monitor|--network-monitor|-m)
		echo ""
		network_monitor_module
		exit 0
		;;
	--config|-c)
		echo ""
		interactive_config
		exit 0
		;;
	--show-options|-o)
		echo ""
		show_options
		exit 0
		;;
	--help|-h)
		usage
		exit 0
		;;
	"")
		usage
		exit 1
		;;
	*)
		validate $*
		;;
esac

# === MODULE FRAMEWORK FOR FUTURE EXPANSION ===
# API Testing Module (placeholder for future integration)
# api_testing_module() {
#	echo -e "${GREEN}[!]${NC} Starting API Testing Module"
#	# Postman collection import
#	# Burp Suite integration
#	# REST API fuzzing
#	# GraphQL endpoint detection
#	# JWT token analysis
# }

# Cloud Testing Module (placeholder for future integration)
# cloud_testing_module() {
#	echo -e "${GREEN}[!]${NC} Starting Cloud Testing Module"
#	# AWS S3 bucket enumeration & misconfiguration
#	# Azure blob enumeration
#	# Google Cloud Storage scanning
#	# CloudFlare configuration review
#	# CDN misconfiguration detection
# }

# Container Scanning Module (placeholder for future integration)
# container_scanning_module() {
#	echo -e "${GREEN}[!]${NC} Starting Container Scanning Module"
#	# Docker registry scanning
#	# Kubernetes cluster assessment
#	# Container escape testing
#	# Dockerfile vulnerability analysis
# }

# IaC Scanning Module (placeholder for future integration)
# iac_scanning_module() {
#	echo -e "${GREEN}[!]${NC} Starting Infrastructure as Code Scanning Module"
#	# Terraform vulnerability scanning
#	# CloudFormation analysis
#	# Helm chart security review
# }
