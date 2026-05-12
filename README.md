# Recon Pipeline

A Flask/SocketIO web application that orchestrates external security scanning tools into automated reconnaissance workflows. Provides a web UI for configuring scans, real-time progress via WebSockets, a dashboard for historical results, and Telegram alerting.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-green)
![MongoDB](https://img.shields.io/badge/MongoDB-6.x-green)

## Features

- **13-stage scan pipeline**: Subfinder, PureDNS, DNSx, Cut-CDN, Nmap, TLSx, HTTPx, Katana, VHost, SNI, Nuclei, FFUF, Gowitness
- **Real-time progress**: WebSocket-driven UI updates as each stage runs
- **Resume support**: Stop and resume scans from the last completed stage
- **Scheduling**: One-time, daily, weekly, or monthly recurring scans
- **Dashboard**: Historical scan results with per-tool counts, filters, and CSV export
- **Telegram alerts**: Notifications on scan completion, new subdomain discovery
- **Continuous monitoring**: Background thread checks for new subdomains every 4 hours
- **Saved targets**: Save and reuse target domains across scans

## Architecture

Single-file monolith (`app16v5.py`, ~2600 lines) containing:

- Flask routes and API endpoints
- `ScanRunner` class for sequential tool execution
- MongoDB integration for scan storage
- SocketIO for real-time updates
- Embedded HTML template and JavaScript frontend
- Background scheduler and continuous monitor threads

## Prerequisites

- Python 3.10+
- MongoDB 6.x+ (running locally or remotely)
- Go 1.21+ (for installing security tools)
- Nmap (`apt install nmap`)

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Amirhosseing/recon-pipeline.git
cd recon-pipeline
```

### 2. Python dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Install security tools

Most tools are written in Go and installed via `go install`:

```bash
# Install Go (if not already installed)
wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# Subdomain enumeration
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# DNS brute-forcing
go install github.com/d3mondev/puredns/v2@latest

# DNS resolution
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# TLS analysis
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest

# HTTP probing
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Web crawling
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Vulnerability scanning
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Directory fuzzing
go install github.com/ffuf/ffuf/v2@latest

# Screenshots
go install github.com/sensepost/gowitness@latest

# CDN filtering
go install github.com/dollcub/cut-cdn@latest

# Nmap (via apt)
sudo apt install nmap
```

### 4. Verify installation

```bash
python3 -c "from app16v5 import check_dependencies; check_dependencies()"
```

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `super_secret_key_change_in_prod` | Flask session secret |
| `ADMIN_USER` | `administrator` | Login username |
| `ADMIN_PASS` | `Qwer12#$` | Login password |
| `MONGO_URI` | `mongodb://localhost:27017/` | MongoDB connection string |
| `DB_NAME` | `recon_pipeline` | MongoDB database name |
| `TELEGRAM_BOT_TOKEN` | *(empty)* | Telegram bot API token |
| `TELEGRAM_CHAT_ID` | *(empty)* | Telegram chat ID for alerts |

```bash
# Example: production configuration
export SECRET_KEY=$(openssl rand -hex 32)
export ADMIN_USER=myuser
export ADMIN_PASS=$(openssl rand -base64 24)
export MONGO_URI="mongodb://user:pass@mongo-host:27017/recon?authSource=admin"
export TELEGRAM_BOT_TOKEN="123456:ABC-DEF..."
export TELEGRAM_CHAT_ID="-100123456789"

python app16v5.py
```

## Usage

### Starting the app

```bash
source venv/bin/activate
python app16v5.py
```

The server starts on `http://0.0.0.0:5000`.

### Running a scan

1. Open the web UI and log in
2. Enter target domains in the text area (one per line)
3. Select which tools to enable
4. Optionally configure:
   - Wordlists for PureDNS and FFUF
   - Nuclei templates and severity levels
   - Proxy settings per tool
   - Custom arguments for each tool
5. Click **Start Scan**
6. Watch real-time progress in the pipeline status panel

### Scheduling scans

1. Set a date/time in the schedule field
2. Choose frequency: once, daily, weekly, or monthly
3. Click **Start Scan** — it will be queued and run at the scheduled time

## Scan Pipeline

Stages execute sequentially. Each stage can be skipped during resume if already completed.

| # | Tool | Purpose | Input | Output |
|---|------|---------|-------|--------|
| 1 | Subfinder | Passive subdomain enumeration | Target domains | `subfinder.json`, `subfinder.txt` |
| 2 | PureDNS | Active DNS brute-force | Target domains + wordlist | `puredns_all.txt` |
| 3 | DNSx | DNS resolution | All subdomains | `dnsx.json`, `dnsx.txt` |
| 4 | Cut-CDN | Filter CDN IPs | Resolved IPs | `active_ips.txt` |
| 5 | Nmap | Port scanning | Non-CDN IPs | `nmap.xml` |
| 6 | TLSx | TLS certificate analysis | All subdomains | `tlsx.json`, `tlsx.txt` |
| 7 | HTTPx | Live web server probing | Subdomains + Nmap targets | `httpx.json`, `httpx.txt` |
| 8 | Katana | Web crawling | Live URLs | `katana.jsonl`, `katana.txt` |
| 9 | VHost | Virtual host discovery | Non-CDN IPs + wordlist | `vhost_*.json`, `vhost_all.txt` |
| 10 | SNI | SNI-based vhost discovery | Non-CDN IPs | `sni.json`, `sni.txt` |
| 11 | Nuclei | Vulnerability scanning | Live URLs + Nmap targets | `nuclei.jsonl`, `nuclei.txt` |
| 12 | FFUF | Directory fuzzing | Live URLs + wordlist | `ffuf_dir.json`, `ffuf_dir.txt` |
| 13 | Gowitness | Screenshot capture | Live URLs | `screenshots/`, `gowitness.sqlite3` |

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/POST | `/login` | Authentication |
| GET | `/logout` | End session |
| GET | `/` | Main scanner UI |
| GET | `/api/targets` | List saved targets |
| POST | `/api/targets` | Save a target |
| GET | `/api/local_wordlists` | List available wordlists |
| POST | `/start_scan` | Create and start a scan |
| GET | `/scan_status/<id>` | Get scan status |
| GET | `/api/history` | Paginated scan history |
| GET | `/download/<id>` | Download scan results (ZIP) |
| GET | `/api/scan_files/<id>` | List scan output files |
| GET | `/api/view_file/<id>/<file>` | View a scan output file |
| GET | `/export_csv/<id>` | Export Nuclei findings as CSV |
| POST | `/api/stop_scan/<id>` | Stop a running scan |
| POST | `/api/resume_scan/<id>` | Resume a stopped scan |
| DELETE | `/api/delete_scan/<id>` | Delete a scan and its files |

## Testing

```bash
source venv/bin/activate
pip install pytest mongomock
pytest test_app16v5.py -v
```

The test suite covers:
- Authentication and access control
- Scan lifecycle (create, stop, resume, delete)
- History API with pagination and filters
- File operations and path traversal protection
- CSV export
- ScanRunner helper methods
- Telegram alerting
- Background scheduler and monitor
- Utility functions

## Security Notes

Before deploying in production:

1. **Change default credentials** — set `SECRET_KEY`, `ADMIN_USER`, and `ADMIN_PASS` environment variables
2. **Use HTTPS** — deploy behind a reverse proxy (nginx/caddy) with TLS
3. **Restrict network access** — bind to `127.0.0.1` or use firewall rules
4. **Secure MongoDB** — enable authentication and restrict access
5. **Review tool arguments** — custom args are passed to subprocess commands
6. **Set up Telegram** — configure `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` for alerts

## License

This project is for authorized security testing and educational purposes only. Ensure you have proper authorization before scanning any targets.
