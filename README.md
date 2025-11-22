# Reckon
Is a simple wrapper script written in bash. It was written in preparation for the OSCP exam to help me be more time efficient during testing by automating some basic tasks and scans with a focus on enumerating the more targetable services like HTTP and SMB.

* Reckon adhears to all OSCP exam restrictions: https://support.offensive-security.com/#!oscp-exam-guide.md

### Prerequisites
Reckon will run on any recent Kali Linux image and is currently wrapping tools and scripts such as: Nmap, Nmap-NSE, Curl, Enum4linux, Nikto, and Dirb. Reckon shouldn't have issue running on other Linux distros provided these tools are installed and are in the users $PATH.

### Example Usage
``` ./wreckon.sh 10.10.10.10 ```

``` ./wreckon.sh scanme.nmap.org```

``` ./wreckon.sh /home/user/hostlist.txt```

``` ./wreckon.sh --monitor ``` (Interactive network packet capture)

``` ./wreckon.sh -m ``` (Short form for network monitor)

``` ./wreckon.sh --config ``` (Interactive configuration - Metasploit style)

``` ./wreckon.sh --show-options ``` (View all current settings)

---

## Interactive Configuration (Metasploit-style)

wReckon now includes Metasploit-inspired configuration commands:

```bash
./wreckon.sh --config

# In the interactive prompt, use SET commands:
SET api_testing = true
SET cloud_testing = false
SET tports 500
SET network_monitor true
SET monitor_interface eth0
SET pcap_filter tcp port 80

# Type 'done' to exit and return to shell
```

**Available Options:**
- `tports` - Number of top ports to scan (default: 100)
- `tcp` / `udp` - Enable/disable TCP/UDP scanning (True/False)
- `dns_enum` - DNS reconnaissance (True/False)
- `ssl_scan` - SSL/TLS vulnerability scanning (True/False)
- `owasp_scan` - OWASP Top 10 scanning (True/False)
- `web_vuln_scan` - Web app vulnerability scanning (True/False)
- `service_vuln_scan` - Service-specific testing (True/False)
- `password_test` - Password policy testing (True/False)
- `api_testing` - API testing module (True/False)
- `cloud_testing` - Cloud platform testing (True/False)
- `container_testing` - Container security scanning (True/False)
- `iac_testing` - Infrastructure as Code scanning (True/False)
- `network_monitor` - Network packet capture (True/False)
- `monitor_interface` - Network interface to use (eth0, en0, tun0, etc.)
- `pcap_filter` - tcpdump filter (tcp port 80, udp port 53, etc.)

---

## Network Monitoring + Scanning (How They Work Together)

**Important:** Network monitoring is **SEPARATE** and **INDEPENDENT** from scanning.

### How to Use Them Together:

**Terminal 1 - Start Packet Capture:**
```bash
$ ./wreckon.sh --monitor

[!] Available Network Interfaces:
    [1] eth0 (192.168.1.100)
    [2] tun0 (10.8.0.5)

Select interface number: 1
Enter tcpdump filter (leave blank for all): tcp port 80 and host 10.10.10.100

[*] Starting packet capture on eth0
[-] Output file: pcap_captures/capture_eth0_20251121_101530.pcap
[*] Press Ctrl+C to stop capture
# ... capturing packets ...
```

**Terminal 2 - Run Your Scan (While monitor is running):**
```bash
$ ./wreckon.sh 10.10.10.100

[!] Testing directory created at: 10.10.10.100/
[!] Running Quick Scan...
[!] Performing DNS Reconnaissance...
[!] Running SSL/TLS Vulnerability Scanning...
# ... scanning continues while capture runs in Terminal 1 ...
```

**Result:**
- Terminal 1: Packets saved to `pcap_captures/capture_eth0_20251121_101530.pcap`
- Terminal 2: Scan results saved to `10.10.10.100/` directory
- Both happen simultaneously!

### Why Run Them Separately?

✅ **Flexibility** - Monitor any interface while scanning any target  
✅ **Evidence** - Preserve packet captures independently  
✅ **Performance** - Each runs independently, no interference  
✅ **Security** - Monitor encrypted or unencrypted traffic  
✅ **Forensics** - Analyze PCAP files with Wireshark or tcpdump tools  

### Full Pentesting Example:

```bash
# Terminal 1: Start capturing HTTP traffic to target
./wreckon.sh --monitor
# Select eth0, filter: tcp port 80 and host 10.10.10.100
# Let it run (Ctrl+C to stop later)

# Terminal 2: Run comprehensive scan
./wreckon.sh --config
# SET api_testing = true
# SET ssl_scan = true
# SET tports 500
# done

# Terminal 3: Actually start the target scan
./wreckon.sh 10.10.10.100

# Now you have:
# - Terminal 1: Capturing all HTTP traffic
# - Terminal 3: Running full vulnerability scan
# Both happening at the same time!

# When done, stop Terminal 1 with Ctrl+C
# Analyze captured packets:
tcpdump -r pcap_captures/capture_eth0_*.pcap
```

### Workflow
Reckon's work flow was designed to provide incremental results so you an progress through manual enumeration while waiting on results from longer scans such as Nikto, Dirb or some NSE Scripts. Again, the intent of this wrapper is to increase time efficiency by minimize wait/downtime. One could run a massive NMAP scan with all possible NSE scripts but you will likely be waiting 3 hours before you even know what ports are open which isn't very efficient.

### Reckon runs in five stages

* <b>Stage 1:</b> Directory Creation - Upon execution, a target directory will be created in the current working directory. The results of scans will be filtered, organized, and printed to terminal while copies of the scans results will be stored in the current working directory. This stage takes less than a second to complete.

* <b>Stage 2:</b> QuickScan - Using nmap --top-port arugement to scan for the top 100 common tcp ports. This number can be changed by modifying the tports variable (line 5). The purpose of this scan is to give quick (non-verbose) results so the tester can immediately begin prioritizing where to focus manual efforts. This stage usually completes in 10 seconds or less.

* <b>Stage 3:</b> VersionScan - Run an nmap version scan (sV) targeting the open ports previously identified in the quickscan. The scan will not only attempt to identify running services but also identify services running on non-standard ports. As example, a web server running on tcp port 25 would be flagged and addressed the same as port 80 or 443 in next stages.

* <b>Stage 4:</b> EnumerationScan - Reckon will begin running NSE Default scripts followed by more aggressive scans/scripts such as NSE Vuln Scripts, Nikto, and Dirb against the previously identified ports/services when/where appropriate. Services are currently prioritized by HTTP, SMB, Other respectively. Identified HTTP and SMB services are given more time and attention than "Others". It's also important to note that in attempt to prevent inaccurate results, DoS conditions, and general performance issues, Reckon only allows one instance of Nikto (or Dirb) to run at a time but will create queue if Reckon is being run against a hostlist or a single target has multiple HTTP services running. 

* <b>Stage 5:</b> FullScan - At this point only the top 100 tcp and udp ports have been identified and scanned. In this stage, Reckon will begin scanning the remaining 65435 (65535 - 100) tcp and udp ports. Previously identified ports will not be rescanned however any newly identified open ports will be sent through Stages 3 and 4. This phase is really for peace of mind for the event that a target server is running obscure services on epimeral ports. 

### Limitations
* Reckon is only a simple bash script running mostly default scans for the scripts/tools it is wrapping. It should not be considered "Aggressive Enumeration" by any means and should not replace manual enumeration. This script is intended to automate and provide results to simplistic/common tasks during the discovery and enumeration phase.
