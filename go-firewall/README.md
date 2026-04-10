# Go Firewall - Process Monitor

A real-time process monitoring firewall for Ubuntu that detects:
- New processes
- High RAM usage
- Malicious files (viruses, miners)
- Multi-instance processes
- Unknown origin processes

## Features

- **Process Monitoring**: Scans all running processes every 5 seconds
- **File Hash Checking**: SHA256 hash comparison against known malware
- **RAM Monitoring**: Detects processes using excessive memory (>1GB default)
- **Multi-Instance Detection**: Alerts when a process runs more than 5 instances
- **REST API**: Access logs and reports via HTTP on port 8080
- **SQLite Database**: Persistent storage for logs and history
- **Whitelist**: Mark processes/files as safe

## Installation

```bash
# Build
go build -o go-firewall .

# Run
sudo ./go-firewall
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API info |
| `/health` | GET | Health check |
| `/api/logs` | GET | All logs (limit param) |
| `/api/logs/recent` | GET | Recent logs |
| `/api/logs/suspicious` | GET | Suspicious logs only |
| `/api/logs/type/:type` | GET | Filter by type |
| `/api/logs/severity/:severity` | GET | Filter by severity |
| `/api/logs/search?q=keyword` | GET | Search logs |
| `/api/logs/export` | GET | Export logs (json/csv) |
| `/api/processes` | GET | All processes |
| `/api/processes/suspicious` | GET | Suspicious processes |
| `/api/processes/high-ram` | GET | High RAM processes |
| `/api/processes/stats` | GET | Process statistics |
| `/api/processes/scan` | POST | Scan a file |
| `/api/history` | GET | Process history |
| `/api/statistics` | GET | System statistics |
| `/api/statistics/daily` | GET | Daily statistics |
| `/api/whitelist` | GET/POST | Manage whitelist |
| `/api/alerts/rules` | GET | Get alert rules |

## Examples

```bash
# Get recent logs
curl http://localhost:8080/api/logs/recent?limit=20

# Get suspicious processes
curl http://localhost:8080/api/processes/suspicious

# Get statistics
curl http://localhost:8080/api/statistics

# Search logs
curl "http://localhost:8080/api/logs/search?q=miner"

# Scan a file
curl -X POST http://localhost:8080/api/processes/scan \
  -H "Content-Type: application/json" \
  -d '{"path":"/usr/bin/somefile"}'

# Export logs to CSV
curl "http://localhost:8080/api/logs/export?format=csv" -o logs.csv

# Clean old logs (older than 30 days)
curl -X POST http://localhost:8080/api/clean -d '{"days":30}'
```

## Configuration

Edit `main.go` to modify:
- `highRAMLimit`: Memory threshold in MB (default: 1000)
- `maxInstances`: Max allowed instances per process (default: 5)
- API port (default: 8080)

## Adding Known Malware Hashes

Add hashes to `malware_hashes.txt`:
```
a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6:Generic.Malware
xmrig_hash_here:Cryptominer.XMRig
```

Format: `hash:threat_name`

## Systemd Service (Ubuntu)

Create `/etc/systemd/system/go-firewall.service`:
```ini
[Unit]
Description=Go Firewall Process Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/go-firewall
ExecStart=/opt/go-firewall/go-firewall
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable go-firewall
sudo systemctl start go-firewall
```

## Log Severity Levels

- **critical**: Known malware, cryptominers detected
- **warning**: High RAM, multi-instance, suspicious activity
- **info**: New processes, system reports

## Response Format

```json
{
  "success": true,
  "data": [...],
  "message": "optional message"
}
```
