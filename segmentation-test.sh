#!/bin/bash
# Network Segmentation Testing Tool for wReckon
# Focuses on firewall rule detection and network boundary mapping
# Written by SwampSec - Companion to wReckon v2.2+
# -----------------------------------------------------------------

# === CONFIGURATION ===
# Default target
target=""
# Network interface to monitor (eth0, en0, tun0, etc)
monitor_interface="eth0"
# Packet capture filter
pcap_filter=""
# Enable packet capture during tests
enable_capture=False
# Test both IPv4 and IPv6
test_ipv6=False
# Auto-manage /etc/hosts for hostname resolution (useful for HackTheBox)
auto_hosts=False
# Hosts file paths
hosts_file="/etc/hosts"
hosts_backup="/etc/hosts.segmentation.bak"
# Output directory
output_dir="segmentation_tests"

# Color Variables
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Runtime tracking
SECONDS=0

# === UTILITY FUNCTIONS ===

# Hosts file management
manage_hosts_entry() {
	local ip=$1
	local hostname=$2
	
	if [[ "$auto_hosts" != "True" ]]; then
		return
	fi
	
	if [[ -z "$ip" ]] || [[ -z "$hostname" ]]; then
		return
	fi
	
	echo -e "${GREEN}[!]${NC} Managing hosts file entry for $hostname" |tee -a segmentation-scan.log
	
	# Check if running as root
	if [[ $EUID -ne 0 ]]; then
		echo -e "${YELLOW}[!]${NC} Hosts file management requires sudo" |tee -a segmentation-scan.log
		echo "[-]      Run: sudo -s" |tee -a segmentation-scan.log
		return
	fi
	
	# Create backup if it doesn't exist
	if [[ ! -f "$hosts_backup" ]]; then
		cp "$hosts_file" "$hosts_backup"
		echo "[-]      Backed up original hosts file to $hosts_backup" |tee -a segmentation-scan.log
	fi
	
	# Check if entry already exists
	if grep -q "^${ip}[[:space:]].*${hostname}" "$hosts_file"; then
		echo -e "${GREEN}[✓]${NC} Entry already exists in hosts file" |tee -a segmentation-scan.log
		return
	fi
	
	# Add entry to hosts file
	echo "$ip    $hostname" >> "$hosts_file"
	echo -e "${GREEN}[✓]${NC} Added to hosts file: $ip $hostname" |tee -a segmentation-scan.log
}

detect_ip_version() {
	local target_host=$1
	
	# Check if it's already an IP (IPv4)
	if [[ $target_host =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
		echo "ipv4"
		return 0
	fi
	
	# Check for IPv6 format
	if [[ $target_host =~ : ]]; then
		echo "ipv6"
		return 0
	fi
	
	# Try to resolve domain and detect version
	if command -v "dig" &> /dev/null; then
		# Check for IPv4
		local ipv4_result=$(dig +short $target_host A 2>/dev/null | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | head -1)
		
		# Check for IPv6
		local ipv6_result=$(dig +short $target_host AAAA 2>/dev/null | grep ':' | head -1)
		
		if [[ -n "$ipv6_result" ]] && [[ "$test_ipv6" == "True" ]]; then
			echo "ipv6"
		elif [[ -n "$ipv4_result" ]]; then
			echo "ipv4"
		else
			echo "ipv4"
		fi
	else
		echo "ipv4"
	fi
}

# === ICMP RECONNAISSANCE ===
icmp_test() {
	local test_target=$1
	local ip_type=$2
	
	echo -e "${GREEN}[!]${NC} ICMP/Ping Test (${ip_type^^})" |tee -a segmentation-scan.log
	
	# Determine ping command
	local ping_cmd="ping"
	if [[ "$ip_type" == "ipv6" ]]; then
		ping_cmd="ping6"
	fi
	
	# Send pings
	echo "[-]      Sending 4 ICMP packets..." |tee -a segmentation-scan.log
	$ping_cmd -c 4 -W 2 $test_target > icmp-test-${ip_type}.txt 2>&1
	
	# Check if responsive
	if grep -q "bytes from\|ms" icmp-test-${ip_type}.txt; then
		echo -e "${GREEN}[✓]${NC} Target responds to ICMP" |tee -a segmentation-scan.log
		
		# Extract response times
		local avg_time=$(grep "avg" icmp-test-${ip_type}.txt | grep -oE "avg=[0-9.]+")
		if [[ -n "$avg_time" ]]; then
			echo "[-]      $avg_time" |tee -a segmentation-scan.log
		fi
		
		# Extract TTL
		local ttl=$(grep "ttl=" icmp-test-${ip_type}.txt | head -1 | grep -oE "ttl=[0-9]+")
		if [[ -z "$ttl" ]]; then
			ttl=$(grep "hlim=" icmp-test-${ip_type}.txt | head -1 | grep -oE "hlim=[0-9]+")
		fi
		
		if [[ -n "$ttl" ]]; then
			echo "[-]      TTL/HopLimit: $ttl (network hops indicator)" |tee -a segmentation-scan.log
		fi
	else
		echo -e "${YELLOW}[!]${NC} Target does not respond to ICMP" |tee -a segmentation-scan.log
		echo "[-]      Host may be blocking ICMP or behind firewall" |tee -a segmentation-scan.log
	fi
	
	echo "" |tee -a segmentation-scan.log
}

# === TCP CONNECTIVITY TESTING ===
tcp_connectivity_test() {
	local test_target=$1
	local ip_type=$2
	
	echo -e "${GREEN}[!]${NC} TCP Connectivity Tests (${ip_type^^})" |tee -a segmentation-scan.log
	
	# Common ports to test
	local ports=(22 25 53 80 110 143 443 445 3306 3389 5432 8080 8443)
	
	echo "[-]      Testing ports: ${ports[@]}" |tee -a segmentation-scan.log
	
	for port in "${ports[@]}"; do
		if command -v "nc" &> /dev/null; then
			if [[ "$ip_type" == "ipv6" ]]; then
				timeout 2 nc -6 -zv -w 1 $test_target $port 2>&1 | grep -E "open|refused|timeout" >> tcp-test-${ip_type}.txt 2>&1
			else
				timeout 2 nc -zv -w 1 $test_target $port 2>&1 | grep -E "open|refused|timeout" >> tcp-test-${ip_type}.txt 2>&1
			fi
		elif command -v "nmap" &> /dev/null; then
			if [[ "$ip_type" == "ipv6" ]]; then
				nmap -6 -p $port --open -n $test_target 2>/dev/null | grep "open" >> tcp-test-${ip_type}.txt 2>&1
			else
				nmap -p $port --open -n $test_target 2>/dev/null | grep "open" >> tcp-test-${ip_type}.txt 2>&1
			fi
		fi
	done
	
	# Display results
	if [[ -f "tcp-test-${ip_type}.txt" ]] && [[ -s "tcp-test-${ip_type}.txt" ]]; then
		echo -e "${GREEN}[✓]${NC} Accessible TCP ports:" |tee -a segmentation-scan.log
		cat tcp-test-${ip_type}.txt |tee -a segmentation-scan.log
	else
		echo -e "${YELLOW}[!]${NC} No open TCP ports detected" |tee -a segmentation-scan.log
	fi
	
	echo "" |tee -a segmentation-scan.log
}

# === UDP CONNECTIVITY TESTING ===
udp_connectivity_test() {
	local test_target=$1
	local ip_type=$2
	
	echo -e "${GREEN}[!]${NC} UDP Connectivity Tests (${ip_type^^})" |tee -a segmentation-scan.log
	
	# Common UDP ports
	local ports=(53 67 68 123 161 162 500 5353)
	
	echo "[-]      Testing ports: ${ports[@]}" |tee -a segmentation-scan.log
	
	for port in "${ports[@]}"; do
		if command -v "nc" &> /dev/null; then
			if [[ "$ip_type" == "ipv6" ]]; then
				timeout 2 nc -u6 -zv -w 1 $test_target $port 2>&1 | grep -E "open|refused|timeout" >> udp-test-${ip_type}.txt 2>&1
			else
				timeout 2 nc -u -zv -w 1 $test_target $port 2>&1 | grep -E "open|refused|timeout" >> udp-test-${ip_type}.txt 2>&1
			fi
		fi
	done
	
	# Display results
	if [[ -f "udp-test-${ip_type}.txt" ]] && [[ -s "udp-test-${ip_type}.txt" ]]; then
		echo -e "${GREEN}[✓]${NC} Accessible UDP ports:" |tee -a segmentation-scan.log
		cat udp-test-${ip_type}.txt |tee -a segmentation-scan.log
	else
		echo -e "${YELLOW}[!]${NC} No open UDP ports detected" |tee -a segmentation-scan.log
	fi
	
	echo "" |tee -a segmentation-scan.log
}

# === TRACEROUTE ANALYSIS ===
traceroute_test() {
	local test_target=$1
	local ip_type=$2
	
	echo -e "${GREEN}[!]${NC} Traceroute Analysis (${ip_type^^})" |tee -a segmentation-scan.log
	
	if command -v "traceroute" &> /dev/null; then
		echo "[-]      Tracing route to target..." |tee -a segmentation-scan.log
		
		if [[ "$ip_type" == "ipv6" ]]; then
			traceroute -m 15 -w 2 $test_target 2>&1 | head -20 > traceroute-${ip_type}.txt
		else
			traceroute -m 15 -w 2 $test_target 2>&1 | head -20 > traceroute-${ip_type}.txt
		fi
		
		if [[ -s "traceroute-${ip_type}.txt" ]]; then
			echo -e "${GREEN}[✓]${NC} Route:" |tee -a segmentation-scan.log
			cat traceroute-${ip_type}.txt |tee -a segmentation-scan.log
		fi
	else
		echo "[-]      traceroute not available" |tee -a segmentation-scan.log
	fi
	
	echo "" |tee -a segmentation-scan.log
}

# === PACKET CAPTURE ===
start_packet_capture() {
	local capture_file="$1"
	
	if [[ "$enable_capture" != "True" ]]; then
		return
	fi
	
	if ! command -v "tcpdump" &> /dev/null; then
		echo -e "${YELLOW}[!]${NC} tcpdump not available, skipping capture" |tee -a segmentation-scan.log
		return
	fi
	
	echo -e "${GREEN}[!]${NC} Starting packet capture on $monitor_interface" |tee -a segmentation-scan.log
	echo "[-]      Filter: ${pcap_filter:-'all traffic'}" |tee -a segmentation-scan.log
	echo "[-]      File: $capture_file" |tee -a segmentation-scan.log
	
	# Start tcpdump in background
	if [[ $EUID -ne 0 ]]; then
		sudo tcpdump -i "$monitor_interface" -w "$capture_file" $pcap_filter &
	else
		tcpdump -i "$monitor_interface" -w "$capture_file" $pcap_filter &
	fi
	
	capture_pid=$!
	echo $capture_pid > .capture_pid
}

stop_packet_capture() {
	if [[ ! -f ".capture_pid" ]]; then
		return
	fi
	
	local capture_pid=$(cat .capture_pid)
	kill $capture_pid 2>/dev/null
	wait $capture_pid 2>/dev/null
	rm .capture_pid
}

# === ANALYSIS & REPORTING ===
generate_report() {
	echo "" |tee -a segmentation-scan.log
	echo -e "${BLUE}======= Network Segmentation Test Report =======${NC}" |tee -a segmentation-scan.log
	echo "" |tee -a segmentation-scan.log
	
	echo -e "${GREEN}[!] Target: $target${NC}" |tee -a segmentation-scan.log
	echo -e "${GREEN}[!] Scan Duration: $(($SECONDS / 60)) minutes, $((($SECONDS % 60))) seconds${NC}" |tee -a segmentation-scan.log
	echo "" |tee -a segmentation-scan.log
	
	# Summary of findings
	echo -e "${GREEN}[!] ICMP Summary:${NC}" |tee -a segmentation-scan.log
	if grep -q "responds to ICMP" segmentation-scan.log; then
		echo "[-]      ✓ Target responds to ICMP (not firewalled)" |tee -a segmentation-scan.log
	else
		echo "[-]      ✗ Target blocks ICMP (firewall/ACL)" |tee -a segmentation-scan.log
	fi
	
	echo "" |tee -a segmentation-scan.log
	echo -e "${GREEN}[!] TCP Results:${NC}" |tee -a segmentation-scan.log
	if grep -r "open" tcp-test-*.txt 2>/dev/null | wc -l | grep -qv "^0$"; then
		echo "[-]      Some TCP ports are accessible" |tee -a segmentation-scan.log
	else
		echo "[-]      All TCP ports filtered" |tee -a segmentation-scan.log
	fi
	
	echo "" |tee -a segmentation-scan.log
	echo -e "${GREEN}[!] UDP Results:${NC}" |tee -a segmentation-scan.log
	if grep -r "open" udp-test-*.txt 2>/dev/null | wc -l | grep -qv "^0$"; then
		echo "[-]      Some UDP ports are accessible" |tee -a segmentation-scan.log
	else
		echo "[-]      All UDP ports filtered" |tee -a segmentation-scan.log
	fi
	
	echo "" |tee -a segmentation-scan.log
	echo -e "${GREEN}[!] Output Files:${NC}" |tee -a segmentation-scan.log
	ls -1 | grep -E "^(icmp|tcp|udp|traceroute)" |tee -a segmentation-scan.log
	
	echo "" |tee -a segmentation-scan.log
}

# === HELP & USAGE ===
usage() {
	echo -e "${BLUE}wReckon Network Segmentation Testing Tool${NC}"
	echo ""
	echo "Usage: $0 <target> [options]"
	echo ""
	echo "Required:"
	echo "  <target>                Target IP, IPv6, or domain"
	echo ""
	echo "Options:"
	echo "  --ipv6                  Test IPv6 (requires dual-stack target)"
	echo "  --capture               Enable packet capture (requires tcpdump)"
	echo "  --interface <iface>     Network interface for capture (default: eth0)"
	echo "  --filter <filter>       tcpdump filter (e.g., 'icmp', 'tcp port 80')"
	echo "  --help, -h              Show this help message"
	echo ""
	echo "Examples:"
	echo "  $0 192.168.1.100"
	echo "  $0 example.com --capture --filter 'icmp'"
	echo "  $0 2001:db8::1 --ipv6"
	echo "  $0 10.10.10.10 --capture --interface eth0 --filter 'tcp or udp'"
	echo ""
}

# === MAIN EXECUTION ===
main() {
	if [[ -z "$target" ]]; then
		usage
		exit 1
	fi
	
	# Create output directory
	mkdir -p "$output_dir"
	cd "$output_dir"
	
	echo -e "${GREEN} ====== Network Segmentation Testing Tool ====== ${NC}"
	echo ""
	
	# Detect IP version
	local ip_version=$(detect_ip_version "$target")
	echo -e "${GREEN}[!]${NC} Target type detected: ${ip_version^^}"
	echo ""
	
	# Manage hosts file entry if enabled
	if [[ "$auto_hosts" == "True" ]]; then
		manage_hosts_entry "$target" "$target"
	fi
	
	# Start packet capture if enabled
	if [[ "$enable_capture" == "True" ]]; then
		local timestamp=$(date +%Y%m%d_%H%M%S)
		start_packet_capture "capture_${ip_version}_${timestamp}.pcap"
		sleep 2
	fi
	
	# Run tests for detected IP version
	icmp_test "$target" "$ip_version"
	tcp_connectivity_test "$target" "$ip_version"
	udp_connectivity_test "$target" "$ip_version"
	traceroute_test "$target" "$ip_version"
	
	# Test IPv6 if requested and target has both
	if [[ "$test_ipv6" == "True" ]] && [[ "$ip_version" == "ipv4" ]]; then
		if command -v "dig" &> /dev/null; then
			local ipv6_addr=$(dig +short example.com AAAA 2>/dev/null | head -1)
			if [[ -n "$ipv6_addr" ]]; then
				echo -e "${GREEN}[!]${NC} Also testing IPv6"
				echo ""
				icmp_test "$target" "ipv6"
				tcp_connectivity_test "$target" "ipv6"
				udp_connectivity_test "$target" "ipv6"
			fi
		fi
	fi
	
	# Stop packet capture
	if [[ "$enable_capture" == "True" ]]; then
		sleep 2
		stop_packet_capture
	fi
	
	# Generate report
	generate_report
	
	echo -e "${GREEN}[!]${NC} Scan complete. Results saved to: $(pwd)"
	echo ""
}

# === COMMAND LINE PARSING ===
if [[ $# -eq 0 ]]; then
	usage
	exit 1
fi

# Parse arguments
while [[ $# -gt 0 ]]; do
	case $1 in
		--help|-h)
			usage
			exit 0
			;;
		--ipv6)
			test_ipv6=True
			shift
			;;
		--capture)
			enable_capture=True
			shift
			;;
		--interface)
			monitor_interface="$2"
			shift 2
			;;
		--filter)
			pcap_filter="$2"
			shift 2
			;;
		*)
			if [[ -z "$target" ]]; then
				target="$1"
			fi
			shift
			;;
	esac
done

# Run main function
main
