# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Recon Pipeline — an automated attack surface management tool. It orchestrates a multi-stage security reconnaissance pipeline through a Flask web UI with real-time WebSocket progress, MongoDB persistence, and Telegram alerting.

## Build & Run

```bash
# Install Python dependencies (includes pysocks for SOCKS5 proxy support)
pip install -r requirements.txt

# Ensure MongoDB is running locally (default: mongodb://localhost:27017)

# Set environment variables (required for production)
export SECRET_KEY="your-secret-key"
export ADMIN_USER="administrator"
export ADMIN_PASS="your-password"
export MONGO_URI="mongodb://localhost:27017/"
export DB_NAME="recon_pipeline"
export TELEGRAM_BOT_TOKEN="your-bot-token"    # optional
export TELEGRAM_CHAT_ID="your-chat-id"        # optional
export LLM_API_KEY="your-api-key"             # optional, for AI analysis
export LLM_BASE_URL="http://localhost:11434/v1"  # OpenAI-compatible endpoint (Ollama, vLLM, etc.)
export LLM_MODEL="qwen3:8b"                  # model name

# Run the application
python app.py
# Server starts on http://0.0.0.0:5000
```

### Docker (recommended — includes all Go security tools)

```bash
# Build and run with Docker Compose (includes MongoDB)
docker-compose up --build -d

# Proxy is pre-configured: container reaches host SOCKS5 proxy via
# host.docker.internal:10808 (set in docker-compose.yml env vars)
```

### Required External Tools

The pipeline shells out to these CLI tools (must be in `$PATH` or `~/go/bin`; all pre-installed in Docker):

`subfinder`, `puredns`, `dnsx`, `cdncheck`, `tlsx`, `httpx`, `katana`, `nmap`, `nuclei`, `ffuf`, `gowitness`

Note: The tool is **cdncheck** (not `cut-cdn`). CDN filtering uses `cdncheck -silent -nc -e` to exclude CDN/WAF/Cloud IPs.

## Development

```bash
# Run the application
python app.py

# Check tool dependencies (also runs automatically on startup)
python -c "import utils; utils.check_dependencies()"
```

### Testing

The test suite is in `tests/test_app.py` and uses `pytest` with `mongomock` to mock MongoDB. All external dependencies (subprocess, requests, SocketIO) are mocked.

```bash
# Install test dependencies
pip install pytest mongomock

# Run all tests
pytest tests/test_app.py -v

# Run a single test class
pytest tests/test_app.py -v -k TestAuthentication

# Run a single test method
pytest tests/test_app.py -v -k test_login_success
```

## Architecture

**Modular Flask application** split across several files:

- `app.py` — Entry point. Starts the Flask-SocketIO server and launches background threads (scheduler, continuous subfinder monitor).
- `extensions.py` — Flask app, SocketIO, MongoDB client, and global state (`scan_queue`, `db`) initialized at import time.
- `config.py` — Environment-based configuration, logging setup, `REQUIRED_TOOLS` list, and custom `MongoJSONProvider` for ObjectId/datetime serialization.
- `utils.py` — `get_tool_path()` (LRU-cached binary resolver), `parse_json_lines_helper()`, `count_file_lines()`, `generate_unique_scan_id()`.
- `telegram.py` — Telegram alert helpers. Alerts route through SOCKS5 proxy at `host.docker.internal:10808`.
- `templates.py` — Inline HTML templates (login page and main dashboard UI). Contains all per-tool argument input fields in the "Advanced Tool Arguments" section.
- `routes/all_routes.py` — All Flask routes: auth, scan CRUD, file viewing, CSV export, target management. Collects per-tool args from form fields keyed `args_<toolname>`.
- `core/scanner.py` — `ScanRunner` class, the core pipeline orchestrator.
- `core/background.py` — Background threads: `scheduler_loop()` and `continuous_subfinder_monitor()`.

### Key Components

- **`ScanRunner` class** (`core/scanner.py`): Core pipeline orchestrator. Each scan runs in its own thread via `ScanRunner.run()`. The pipeline has 13 sequential stages:
  1. Subfinder (passive subdomain enumeration)
  2. PureDNS (bruteforce subdomain discovery — runs only on original target domains, NOT discovered subdomains)
  3. DNSx (DNS resolution with A, CNAME, NS, MX, TXT records)
  4. CDNCheck (filter out CDN/WAF/Cloud IPs using `cdncheck -e`)
  5. Nmap (port scanning on non-CDN IPs)
  6. TLSx (TLS certificate scanning)
  7. HTTPx (web server probing)
  8. Katana (web crawling)
  9. VHost (virtual host bruteforce via FFUF — two phases: wordlist bruteforce then discovered subdomain scan)
  10. SNI Check (SNI-based host discovery via FFUF)
  11. Nuclei (vulnerability scanning with category/severity filters)
  12. FFUF (directory fuzzing on live URLs)
  13. Gowitness (screenshot capture)

- **Flask routes** (`routes/all_routes.py`): REST API for scan CRUD, file viewing, CSV export, and target management. All routes require session-based authentication (`@login_required`). Tool args collected for: `subfinder`, `dnsx`, `puredns`, `httpx`, `katana`, `nmap`, `tlsx`, `vhost`, `ffuf`, `nuclei`, `gowitness`.

- **AI Analysis** (`POST /api/ai_analysis/<id>`): Sends clean `.txt` output files (capped at 100KB) to an OpenAI-compatible LLM for structured security analysis. Returns JSON matching `ANALYSIS_SCHEMA` (defined in `config.py`) with fields: `executive_summary`, `risk_level`, `risk_justification`, `attack_surface`, `findings[]`, `recommendations[]`. Results are persisted in the scan document as `ai_analysis`. Markdown is generated server-side via `generate_analysis_markdown()` for UI display. Configured via `LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL` env vars.

- **WebSocket (`SocketIO`)**: Real-time `stage_update` events pushed per-scan to a room keyed by `scan_id`. Frontend joins the room after scan creation.

- **Background threads**:
  - `scheduler_loop()` — polls MongoDB every 10s for scheduled scans, supports recurring scans (daily/weekly/monthly). Creates a *new* scan document with a fresh `scan_id` for each recurrence.
  - `continuous_subfinder_monitor()` — runs subfinder every 4 hours on saved targets (domains only — IPs and CIDR are excluded), alerts on new subdomains

- **MongoDB collections**:
  - `scans` — scan documents with config, status, stages, results (indexed on `scan_id`, `status+scheduled_time`, `targets+created_at`)
  - `saved_targets` — reusable target lists (unique on `value`)
  - `known_subdomains` — tracks all discovered subdomains for the periodic monitor (unique on `subdomain`)

### Data Flow

Targets flow through the pipeline via mutable lists that stages read from and write to:

- **`target_list`** — original user-provided domains only. Never grows. PureDNS bruteforce iterates over this, not `current_targets`.
- **`current_targets`** — accumulates all discovered subdomains (from Subfinder, PureDNS) plus original domains. Fed into DNSx, TLSx, HTTPx.
- **`live_urls`** — URLs discovered by HTTPx. Fed into Katana, FFUF, Gowitness, and Nuclei.
- **`nmap_targets`** — `IP:port` pairs extracted from Nmap XML output. Fed into HTTPx alongside `current_targets` for comprehensive probing.
- **`safe_ips`** — IP set from DNSx (extracted from `a` and `ans` fields), filtered by CDNCheck. Fed into Nmap, VHost, and SNI Check.

Each stage reads from these lists and writes output to `scans/<scan_id>/`. Tools produce JSON/JSONL/XML output; `generate_clean_output()` creates human-readable `.txt` summaries. Results counts are stored in the scan document's `results` dict and displayed in the dashboard.

### File Output Conventions

Each tool writes to specific files that `generate_clean_output()` and resume logic depend on:

| Tool | Raw Output | Clean Output |
|------|-----------|--------------|
| subfinder | `subfinder.json` (JSONL) | `subfinder.txt` |
| puredns | `puredns_all.txt` | — |
| dnsx | `dnsx.json` (JSONL) | `dnsx.txt` |
| cdncheck | `active_ips.txt` | — |
| nmap | `nmap.xml` | `nmap.txt` |
| tlsx | `tlsx.json` (JSONL) | `tlsx.txt` |
| httpx | `httpx.json` (JSONL) | `httpx.txt` |
| katana | `katana.jsonl` | `katana.txt` |
| vhost | `vhost_brute_*.json`, `vhost_discover_*.json` | `vhost_all.txt` |
| sni | `sni_*.json` | `sni.txt` |
| nuclei | `nuclei.jsonl` | `nuclei.txt` |
| ffuf | `ffuf_dir.json` | `ffuf.txt` |
| gowitness | `screenshots/*.png`, `gowitness.sqlite3` | — |

### Important Design Decisions

- PureDNS bruteforce iterates over `target_list` (original domains only), not `current_targets` — this is intentional, not a bug (see comments in `core/scanner.py`).
- **`get_args()` fallback pattern**: When form sends empty strings for tool args, `get_args()` must fall back to defaults. The implementation is:
  ```python
  def get_args(tool_key, default=""):
      val = self.tool_args.get(tool_key, default)
      return shlex.split(val) if val else shlex.split(default)
  ```
  Do NOT simplify to `shlex.split(self.tool_args.get(tool_key, default))` — empty-string values bypass `dict.get()` defaults.
- Scan resume mode skips completed stages by checking `stages.<tool>.status` in MongoDB. Each completed stage re-reads its output files to repopulate in-memory target lists. Adding a new stage requires implementing both the forward path and the resume path.
- **Error handling pattern for stages**: Use `if err or not outfile.exists()` to catch both command failures and silent failures (empty/missing output). Do NOT use `if err and not exists` — that silently reports 0 results on failure.
- FFUF directory fuzzing creates temporary output files per URL (`ffuf_temp_<hash>.json`), merges results, then cleans up. VHost and SNI stages also create per-IP output files.
- Proxy injection is tool-specific: `-proxy` for subfinder/httpx/tlsx/katana/nuclei, `-x` for ffuf, `--proxies` for nmap. PureDNS and DNSx do not support standard proxies.
- Tool paths are resolved via `get_tool_path()` with LRU caching, checking `$PATH`, `~/go/bin`, and other common locations.
- Stuck scans are reset to `interrupted` on server restart (`extensions.py`).
- Docker containers use `extra_hosts: host.docker.internal:host-gateway` to reach the Windows host's SOCKS5 proxy at port 10808.

### Security-Critical Patterns

- **Double-layered path traversal protection**: `secure_filename()` sanitizes scan IDs, then `Path.resolve().is_relative_to()` enforces sandbox on file-serving routes (`read_scan_file`). Returns 403 on violation.
- **Regex escaping on target filter**: Dots and wildcards are escaped before MongoDB `$regex` queries to prevent ReDoS (`api_history`).
- **Target length cap**: 255 characters, whitespace-trimmed, empty lines filtered.
- **Command argument sanitization**: `cmd = [str(c) for c in cmd]` ensures all arguments are strings before `subprocess.Popen`.
