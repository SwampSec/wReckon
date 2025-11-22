# wReckon v2.3: Hosts File Management Feature

## Overview

Added automatic `/etc/hosts` DNS entry management to both `wreckon.sh` and `segmentation-test.sh` to support HackTheBox and other pentest scenarios that require hostname resolution for web services.

**Problem Solved:** Many HackTheBox machines (and similar CTF/lab environments) cannot be reached on port 80/443 unless the hostname is properly resolved in `/etc/hosts`. Previously, users had to manually add entries like:

```
10.10.10.10    example.htb
```

Now this is automated via the `auto_hosts` configuration option.

---

## Features

### 1. **Automatic Hostname Entry Management**
- Automatically adds target IP and hostname to `/etc/hosts`
- Works with both IPv4 and IPv6 addresses
- Performs reverse DNS lookups to discover hostnames
- Falls back to target name if reverse DNS fails

### 2. **Backup & Restore Protection**
- Creates backup of original `/etc/hosts` before modification
- Backup file: `/etc/hosts.wreckon.bak` (wreckon.sh) or `/etc/hosts.segmentation.bak` (segmentation-test.sh)
- Manual restore command shown to user if needed

### 3. **Safe Execution**
- Checks for root privileges before writing to `/etc/hosts`
- Prevents duplicate entries (checks before adding)
- Graceful degradation (skips if `auto_hosts` disabled)
- Clear console output for all operations

### 4. **Configuration Options**
```bash
# Enable/disable hosts file management
auto_hosts=False

# Paths (automatically set, but configurable)
hosts_file="/etc/hosts"
hosts_backup="/etc/hosts.wreckon.bak"  # or .segmentation.bak
```

---

## Usage

### wreckon.sh

#### Enable via Configuration:
```bash
# Edit the script or use interactive mode
sudo ./wreckon.sh 10.10.10.10 --target 10.10.10.10

# Then in SET command mode:
SET auto_hosts = true
SET target = 10.10.10.10
```

#### Enable at Runtime:
```bash
# Edit line 48 in wreckon.sh
auto_hosts=True
sudo ./wreckon.sh 10.10.10.10
```

#### Output Example:
```
[!] Managing hosts file entry for example.htb
[✓] Added to hosts file: 10.10.10.10 example.htb
```

### segmentation-test.sh

#### Enable via Configuration:
```bash
# Edit line 15 in segmentation-test.sh
auto_hosts=True

# Then run as root
sudo ./segmentation-test.sh 10.10.10.10 --capture
```

#### Check Configuration:
```bash
grep "auto_hosts" segmentation-test.sh
# Output: auto_hosts=False
```

---

## Implementation Details

### Functions Added

#### `manage_hosts_entry()`
Adds a single hostname/IP pair to `/etc/hosts`:

```bash
manage_hosts_entry() {
    local ip=$1              # Target IP address
    local hostname=$2        # Target hostname
    
    # Checks:
    # - auto_hosts is enabled
    # - Valid IP and hostname provided
    # - Running as root (if not, notifies user)
    # - No duplicate entries exist
    
    # Actions:
    # - Backs up original /etc/hosts if needed
    # - Adds IP   hostname entry
    # - Logs all operations
}
```

#### `cleanup_hosts_entry()`
Cleanup function for future use (manual restoration available):

```bash
cleanup_hosts_entry() {
    # Shows restoration command to user
    # Example: sudo cp /etc/hosts.wreckon.bak /etc/hosts
}
```

### Integration Points

**wreckon.sh** - Called from `dns_recon()` function:
```bash
dns_recon() {
    # ... DNS lookups ...
    
    # Extract hostname for hosts file management
    local resolved_hostname=$(cat dns-reverse-lookup | grep -o '^[^ ]*' | sed 's/\.$//' | head -1)
    if [[ -z "$resolved_hostname" ]]; then
        resolved_hostname="$target"
    fi
    manage_hosts_entry "$target" "$resolved_hostname"
}
```

**segmentation-test.sh** - Called from `main()` function:
```bash
main() {
    # ... detect IP version ...
    
    # Manage hosts file entry if enabled
    if [[ "$auto_hosts" == "True" ]]; then
        manage_hosts_entry "$target" "$target"
    fi
    
    # ... run tests ...
}
```

---

## HackTheBox Integration Example

### Typical HTB Workflow

1. **Start a machine** on HackTheBox (gets IP like `10.10.10.10`)
2. **Run wreckon with hosts management**:
```bash
# Edit wreckon.sh: auto_hosts=True
sudo ./wreckon.sh 10.10.10.10

# The script automatically adds:
# 10.10.10.10    10.10.10.10    (or resolved hostname)
```

3. **Access the machine**:
```bash
# Now these work without manual hosts editing:
curl http://10.10.10.10
nikto -h http://10.10.10.10
curl https://10.10.10.10
```

4. **Restore original /etc/hosts** (if needed):
```bash
sudo cp /etc/hosts.wreckon.bak /etc/hosts
```

---

## Security Considerations

### Root Privileges
The feature requires `sudo` to modify `/etc/hosts`. It checks this and gracefully degrades:
```
[!] Hosts file management requires sudo
[-] Run: sudo -s
```

### Backup Safety
Original `/etc/hosts` is backed up before any modifications:
```
[-] Backed up original hosts file to /etc/hosts.wreckon.bak
```

### No Privileged Execution Shortcuts
Scripts do NOT request sudo automatically. User must:
1. Run script with `sudo ./wreckon.sh`
2. Set `auto_hosts=True` in configuration
3. Feature gracefully skips if not running as root

---

## Configuration Menu Integration

Both scripts support SET command configuration:

```bash
# Interactive configuration
wreckon> SET auto_hosts = true
[+] Set auto_hosts = true

wreckon> SHOW OPTIONS
  auto_hosts          => True           (Auto-add target to /etc/hosts)

wreckon> SAVE CONFIG
[+] Configuration saved to /path/to/config.json
```

---

## Technical Specifications

| Aspect | Details |
|--------|---------|
| **Scripts Updated** | wreckon.sh (v2.3), segmentation-test.sh (v2.3) |
| **Functions Added** | `manage_hosts_entry()`, `cleanup_hosts_entry()` |
| **Configuration Variables** | `auto_hosts`, `hosts_file`, `hosts_backup` |
| **Root Required** | Yes (for /etc/hosts modification) |
| **Backward Compatible** | Yes (disabled by default) |
| **Tested On** | macOS, Linux |
| **Dependencies** | Standard: grep, sed, cp (already present) |

---

## Troubleshooting

### Issue: "Entry already exists in hosts file"
**Solution:** The script detected a duplicate. This is safe and expected behavior on subsequent runs.

### Issue: "Hosts file management requires sudo"
**Solution:** Run the script with `sudo`:
```bash
sudo ./wreckon.sh 10.10.10.10
```

### Issue: Cannot access target even after adding to hosts
**Solution:** Check the entry was added correctly:
```bash
grep "10.10.10.10" /etc/hosts
```

If missing, verify:
1. Script ran with `sudo` 
2. `auto_hosts=True` in configuration
3. No syntax errors in script

### Restore Original /etc/hosts
```bash
# If backup exists
sudo cp /etc/hosts.wreckon.bak /etc/hosts

# Verify restoration
cat /etc/hosts
```

---

## Version History

### v2.3 (Current)
- ✅ Added hosts file management to both scripts
- ✅ Automatic hostname discovery via reverse DNS
- ✅ Safe backup/restore mechanism
- ✅ Integration into dns_recon() and segmentation tests
- ✅ Configuration menu support
- ✅ HackTheBox compatibility

### v2.2
- Added Metasploit-style interactive configuration
- Network monitoring with tcpdump module

### v2.1
- Interactive network monitoring

### v2.0
- Rebranded to wreckon.sh
- Comprehensive vulnerability scanning framework

---

## Future Enhancements

Potential improvements for future versions:
- [ ] Automatic hostname extraction from SSL certificates
- [ ] Support for `/etc/hosts.d/` entries on modern systems
- [ ] Scheduled automatic cleanup/restoration
- [ ] Integration with systemd for persistent entries
- [ ] Multi-target hostname management
- [ ] Reverse proxy support (local DNS server mode)

---

## Files Modified

```
wreckon.sh
├── Added: manage_hosts_entry() function (46 lines)
├── Added: cleanup_hosts_entry() function (12 lines)
├── Modified: Configuration section (3 new variables)
├── Modified: show_options() function (2 new lines)
├── Modified: interactive_config() case statement (1 new case)
└── Modified: dns_recon() function (4 new lines)

segmentation-test.sh
├── Added: manage_hosts_entry() function (46 lines)
├── Modified: Configuration section (3 new variables)
└── Modified: main() function (4 new lines)
```

**Total changes:** ~100 lines of new functionality

---

## References

- **GitHub Repository:** https://github.com/SwampSec/wReckon
- **Related Guides:** 
  - NETWORK_SEGMENTATION_GUIDE.md
  - HTB_TESTING_GUIDE.md
  - NETWORK_MONITOR_GUIDE.md

---

**Last Updated:** 2024
**Author:** SwampSec
**License:** As per LICENSE file
