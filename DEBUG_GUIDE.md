# Debug Logging Guide - Diagnosing OWASP/Nikto Hangs

## Overview
The debug feature provides comprehensive logging to diagnose when and where OWASP and Nikto scans hang or fail during reconnaissance operations.

## Quick Start

### Enable Debug Mode
```bash
# Start wreckon with debug enabled
./wreckon.sh
SET debug True
SET owasp_scan True
SET ssl_scan True
done
```

Or pass configuration at startup:
```bash
./wreckon.sh
SET debug=True owasp_scan=True
done
```

## What Gets Logged

### Debug Log File
When enabled, all debug output is written to: `wreckon_debug.log`

### Log Format
```
[YYYY-MM-DD HH:MM:SS] [LEVEL] message
```

### Log Levels
- **INFO**: Normal scan progression events
- **DEBUG**: Command execution details
- **WARN**: Potential issues (timeouts)
- **ERROR**: Scan failures or non-zero exits

## Timeout Protection

### OWASP Scans
- **Timeout**: 180 seconds (3 minutes) per port
- **Detection**: Reports "possible hang detected" if timeout occurs
- **Log Entry**: `OWASP scan TIMEOUT on port [port]`

### Nikto Scans
- **Timeout**: 300 seconds (5 minutes) per port
- **Detection**: Reports "possible hang" if timeout occurs
- **Log Entry**: `Nikto TIMEOUT on http://[target]:[port]`

## Example Debug Output

### Successful Scan
```
[2024-01-15 10:30:45] [INFO] Starting OWASP scan on port 80 for 192.168.1.100
[2024-01-15 10:30:45] [DEBUG] Command: nmap --script http-vuln*,http-csrf*,http-slowloris* -p 80 192.168.1.100 -oN 80-owasp
[2024-01-15 10:31:20] [INFO] OWASP scan completed successfully on port 80
[2024-01-15 10:31:20] [INFO] Starting Nikto scan on port 80 for 192.168.1.100
[2024-01-15 10:31:20] [DEBUG] Running: timeout 300 nikto -h http://192.168.1.100:80 -T 5
[2024-01-15 10:33:15] [INFO] Nikto scan completed for http://192.168.1.100:80
```

### Hang Detection
```
[2024-01-15 10:30:45] [INFO] Starting OWASP scan on port 80 for 192.168.1.100
[2024-01-15 10:30:45] [DEBUG] Command: nmap --script http-vuln*,http-csrf*,http-slowloris* -p 80 192.168.1.100 -oN 80-owasp
[2024-01-15 10:33:45] [WARN] OWASP scan TIMEOUT on port 80 (180 seconds exceeded)
[stderr] [!] OWASP scan timeout on port 80 (possible hang detected)
```

## Diagnostic Workflow

### 1. Identify Problematic Port
Look for timeout entries in `wreckon_debug.log`:
```bash
grep "TIMEOUT\|ERROR" wreckon_debug.log
```

### 2. Check Process Status
While scan is running, check for hung processes:
```bash
ps aux | grep nikto
ps aux | grep nmap
```

### 3. Review Command Details
Find the exact command that hung:
```bash
grep "Command:" wreckon_debug.log
grep "Running:" wreckon_debug.log
```

### 4. Test Manually
Run the command directly to reproduce:
```bash
timeout 300 nikto -h http://target:port -T 5
timeout 180 nmap --script http-vuln* -p port target -oN output.txt
```

## Configuration Options

### View Debug Status
```bash
./wreckon.sh
# Shows current setting
```

### Toggle Debug
```bash
# Enable debug
SET debug True

# Disable debug
SET debug False

# Save setting and exit
done
```

### Debug with Other Options
```bash
SET debug True
SET owasp_scan True
SET ssl_scan True
SET nikto True
done
```

## Log Analysis Commands

### Find all timeouts
```bash
grep "TIMEOUT" wreckon_debug.log
```

### Find all errors
```bash
grep "ERROR\|WARN" wreckon_debug.log
```

### Show Nikto timing
```bash
grep "Nikto" wreckon_debug.log | head -20
```

### Show OWASP timing
```bash
grep "OWASP" wreckon_debug.log | head -20
```

### Extract port causing hang
```bash
grep "TIMEOUT" wreckon_debug.log | awk -F'port' '{print $2}' | awk '{print $1}'
```

## Debugging Tips

### Port Not Responding?
Check responsiveness first:
```bash
nc -zv -w 3 target port
telnet target port
curl -m 5 http://target:port/
```

### Nikto Hangs on Specific Port
- May indicate unresponsive service
- Check `check_port_responsive()` function
- Consider increasing timeout in config

### OWASP Script Hangs
- Often due to NSE scripts with network timeouts
- `-T 5` aggressive timing not always helpful
- Consider disabling specific scripts

### Check System Resources
```bash
# Monitor during scan
top -b -d 1

# Check network connectivity
netstat -an | grep ESTABLISHED
lsof -p $(pidof nikto)
```

## Performance Impact

### Debug Overhead
- ~1-2% additional CPU for logging
- ~0.5 MB per 1000 debug entries
- No impact on scan accuracy

### Log Rotation
Keep debug log rotated to prevent huge files:
```bash
# Archive old logs
mv wreckon_debug.log wreckon_debug.log.$(date +%s)
```

## Exit Codes

When debug is enabled, watch for these exit codes:

- **0**: Successful completion
- **124**: Command timeout (TIMEOUT)
- **1**: General error
- **139**: Segmentation fault
- **127**: Command not found

## Common Issues & Solutions

### Issue: "possible hang detected"
**Solution**: 
- Check port responsiveness
- Increase timeout values if legitimate scan
- Verify target service is actually responding

### Issue: Log file growing too large
**Solution**:
- Archive logs: `mv wreckon_debug.log wreckon_debug.log.bak`
- Start fresh scan

### Issue: Debug output too verbose
**Solution**:
- Disable debug after identifying issue
- Filter log file for specific keywords

## Integration with Reckon Log

Debug logs are separate from main reckon log:
```
wreckon_debug.log          ← Debug-specific entries
reckon                     ← Main scan output (always created)
VULNERABILITY_REPORT_*.txt ← Final report
```

## Examples

### Debug a Single Port Scan
```bash
./wreckon.sh target.com
SET debug True
SET owasp_scan True
SET tcp True
SET tports 100
done

# Monitor output
tail -f wreckon_debug.log
```

### Find Problematic Service
```bash
# After scan completes
grep "TIMEOUT\|ERROR" wreckon_debug.log | head -5

# Extract port info
grep "TIMEOUT" wreckon_debug.log | grep -oE "port [0-9]+" | sort -u
```

### Analyze Timing
```bash
# Show scan timeline
grep "Starting\|completed\|TIMEOUT" wreckon_debug.log
```

## Version Information
- **Feature**: Debug Logging v1.0
- **Added**: November 2024
- **Timeout**: OWASP=180s, Nikto=300s
- **Log Format**: Timestamp + Level + Message

---

**Remember**: Debug logs can grow large quickly. Archive them regularly and use grep to filter specific issues.
