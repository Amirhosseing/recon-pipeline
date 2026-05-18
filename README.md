# Recon Pipeline

An automated attack surface management tool that orchestrates a 13-stage security reconnaissance pipeline through a Flask web UI with real-time WebSocket progress, MongoDB persistence, Telegram alerting, and AI-powered analysis.

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-green)
![MongoDB](https://img.shields.io/badge/MongoDB-7.x-green)
![Docker](https://img.shields.io/badge/Docker-Compose-blue)

## Features

- **13-stage pipeline** — Subfinder, PureDNS, DNSx, CDNCheck, Nmap, TLSx, HTTPx, Katana, VHost, SNI, Nuclei, FFUF, Gowitness
- **AI security analysis** — Structured risk assessment via OpenAI-compatible LLM (Ollama, vLLM, etc.)
- **Real-time progress** — WebSocket-driven UI updates as each stage runs
- **Resume support** — Stop and resume scans from the last completed stage
- **Scheduling** — One-time, daily, weekly, or monthly recurring scans
- **Dashboard** — Historical scan results with per-tool counts, filters, and CSV export
- **Telegram alerts** — Notifications on scan start/completion, new subdomain discovery
- **Continuous monitoring** — Background thread checks for new subdomains every 4 hours
- **Docker deployment** — Full stack with MongoDB and all Go security tools pre-installed

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/Amirhosseing/recon-pipeline.git
cd recon-pipeline
docker-compose up --build -d
```

The app starts at `http://localhost:5000` with MongoDB and all security tools included.

### Manual Setup

```bash
# Install Python dependencies
pip install -r requirements.txt

# Ensure MongoDB is running locally
# Ensure security tools are in $PATH or ~/go/bin

# Set environment variables
export SECRET_KEY="your-secret-key"
export ADMIN_USER="administrator"
export ADMIN_PASS="your-password"
export MONGO_URI="mongodb://localhost:27017/"
export DB_NAME="recon_pipeline"

# Optional
export TELEGRAM_BOT_TOKEN="your-bot-token"
export TELEGRAM_CHAT_ID="your-chat-id"
export LLM_API_KEY="your-api-key"
export LLM_BASE_URL="http://localhost:11434/v1"
export LLM_MODEL="qwen3:8b"

python app.py
```

### Installing Security Tools

```bash
# Subdomain enumeration
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# DNS brute-forcing (requires massdns)
go install github.com/d3mondev/puredns/v2@latest

# DNS resolution
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# CDN/WAF filtering
go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest

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

# Screenshots (requires chromium)
go install github.com/sensepost/gowitness@latest

# Port scanning
sudo apt install nmap
```

Verify installation:

```bash
python -c "import utils; utils.check_dependencies()"
```

## Architecture

Modular Flask application split across several files:

| File | Purpose |
|------|---------|
| `app.py` | Entry point — starts server and background threads |
| `config.py` | Environment config, logging, `ANALYSIS_SCHEMA` |
| `extensions.py` | Flask app, SocketIO, MongoDB client, global state |
| `utils.py` | Tool resolver, JSON parser, scan ID generator |
| `templates.py` | Inline HTML/CSS/JS (login + dashboard UI) |
| `telegram.py` | Telegram alert helpers |
| `routes/all_routes.py` | All Flask routes: auth, scan CRUD, file ops, AI analysis |
| `core/scanner.py` | `ScanRunner` — 13-stage pipeline orchestrator |
| `core/background.py` | Scheduler loop + continuous subfinder monitor |

### Scan Pipeline

Stages execute sequentially. Each stage can be skipped during resume if already completed.

| # | Tool | Purpose | Output |
|---|------|---------|--------|
| 1 | Subfinder | Passive subdomain enumeration | `subfinder.json` |
| 2 | PureDNS | Active DNS brute-force | `puredns_all.txt` |
| 3 | DNSx | DNS resolution (A, CNAME, NS, MX, TXT) | `dnsx.json` |
| 4 | CDNCheck | Filter CDN/WAF/Cloud IPs | `active_ips.txt` |
| 5 | Nmap | Port scanning | `nmap.xml` |
| 6 | TLSx | TLS certificate analysis | `tlsx.json` |
| 7 | HTTPx | Live web server probing | `httpx.json` |
| 8 | Katana | Web crawling | `katana.jsonl` |
| 9 | VHost | Virtual host discovery | `vhost_*.json` |
| 10 | SNI | SNI-based vhost discovery | `sni_*.json` |
| 11 | Nuclei | Vulnerability scanning | `nuclei.jsonl` |
| 12 | FFUF | Directory fuzzing | `ffuf_dir.json` |
| 13 | Gowitness | Screenshot capture | `screenshots/` |

### Data Flow

```
target_list (original domains)
    ├── Subfinder ──→ current_targets (accumulated subdomains)
    ├── PureDNS   ──→ current_targets
    └── DNSx ──→ safe_ips ──→ CDNCheck ──→ safe_ips (filtered)
                                ├── Nmap ──→ nmap_targets (IP:port)
                                ├── VHost
                                └── SNI Check

current_targets + nmap_targets
    └── HTTPx ──→ live_urls
                    ├── Katana
                    ├── FFUF
                    ├── Gowitness
                    └── Nuclei
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | *(insecure)* | Flask session secret |
| `ADMIN_USER` | `administrator` | Login username |
| `ADMIN_PASS` | `Qwer12#$` | Login password |
| `MONGO_URI` | `mongodb://localhost:27017/` | MongoDB connection string |
| `DB_NAME` | `recon_pipeline` | MongoDB database name |
| `TELEGRAM_BOT_TOKEN` | *(empty)* | Telegram bot API token |
| `TELEGRAM_CHAT_ID` | *(empty)* | Telegram chat ID for alerts |
| `LLM_API_KEY` | *(empty)* | OpenAI-compatible API key |
| `LLM_BASE_URL` | `http://host.docker.internal:11434/v1` | LLM endpoint |
| `LLM_MODEL` | `qwen3:8b` | LLM model name |

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/POST | `/login` | Authentication |
| GET | `/logout` | End session |
| GET | `/` | Main scanner UI |
| GET | `/api/targets` | List saved targets |
| POST | `/api/targets` | Save a target |
| POST | `/start_scan` | Create and start a scan |
| GET | `/scan_status/<id>` | Get scan status |
| GET | `/api/history` | Paginated scan history |
| GET | `/download/<id>` | Download scan results (ZIP) |
| GET | `/api/scan_files/<id>` | List scan output files |
| GET | `/api/view_file/<id>/<file>` | View a scan output file |
| GET | `/export_csv/<id>` | Export Nuclei findings as CSV |
| POST | `/api/stop_scan/<id>` | Stop a running scan |
| POST | `/api/resume_scan/<id>` | Resume a stopped scan |
| POST | `/api/ai_analysis/<id>` | AI security analysis |
| DELETE | `/api/delete_scan/<id>` | Delete a scan and its files |

## Testing

```bash
pip install pytest mongomock
pytest tests/test_app.py -v

# Run a single test class
pytest tests/test_app.py -v -k TestAuthentication

# Run a single test method
pytest tests/test_app.py -v -k test_login_success
```

The test suite covers authentication, scan lifecycle, history API, file operations, CSV export, ScanRunner helpers, Telegram alerting, AI analysis, background threads, and utility functions.

## Security Notes

1. **Change default credentials** — set `SECRET_KEY`, `ADMIN_USER`, and `ADMIN_PASS`
2. **Use HTTPS** — deploy behind a reverse proxy with TLS
3. **Restrict network access** — bind to `127.0.0.1` or use firewall rules
4. **Secure MongoDB** — enable authentication and restrict access
5. **Review tool arguments** — custom args are passed to subprocess commands

## License

This project is for authorized security testing and educational purposes only. Ensure you have proper authorization before scanning any targets.
