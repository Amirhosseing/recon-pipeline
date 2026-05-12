# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **Security Reconnaissance Pipeline** — a Flask/SocketIO web application that orchestrates external security scanning tools (subfinder, puredns, dnsx, cut-cdn, tlsx, httpx, katana, nmap, nuclei, ffuf, gowitness) into automated scan workflows. It provides a web UI for configuring scans, real-time progress via WebSockets, a dashboard for historical results, Telegram alerts, and a continuous subdomain monitoring background thread.

## Running the Application

The application is a single-file Flask app (`app16v5.py`).

```bash
# Install dependencies first
pip install flask flask-socketio pymongo requests bson

# Ensure MongoDB is running locally (or set MONGO_URI)
# Ensure all required external tools are installed:
#   subfinder, puredns, dnsx, cut-cdn, tlsx, httpx, katana, nmap, nuclei, ffuf, gowitness

# Run the application
python app16v5.py
```

The server starts on `http://0.0.0.0:5000`.

**Environment Variables:**
- `SECRET_KEY` — Flask session secret (defaults to insecure value; required in production)
- `ADMIN_USER` / `ADMIN_PASS` — Login credentials (defaults to `administrator` / `Qwer12#$`)
- `MONGO_URI` — MongoDB connection string (default: `mongodb://localhost:27017/`)
- `DB_NAME` — MongoDB database name (default: `recon_pipeline`)
- `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` — Optional Telegram alerting

## Architecture

### Single-File Monolith

All backend logic, HTML templates (as Python string literals), and JavaScript are contained in `app16v5.py` (~2600 lines). There are no separate template files or static assets — everything is inline.

### Key Components

1. **Flask Routes & API** (`@app.route` handlers, ~2260+)
   - `/` — Main scanner UI (requires login)
   - `/login`, `/logout` — Session-based authentication
   - `/start_scan` — Accepts form data, creates scan document in MongoDB, launches `ScanRunner` in a daemon thread
   - `/api/history` — Paginated scan history with filtering by status, target, date range
   - `/api/stop_scan/<id>`, `/api/resume_scan/<id>` — Scan lifecycle control
   - `/download/<scan_id>` — Zips the `scans/<scan_id>/` directory for download
   - `/api/view_file/<scan_id>/<filename>` — Reads individual result files with path-traversal guards (`is_relative_to`)
   - `/export_csv/<scan_id>` — Exports Nuclei findings to CSV

2. **ScanRunner Class** (~1194–2107)
   - Encapsulates a single scan execution.
   - Each scan writes outputs to `scans/<scan_id>/`.
   - Stages run sequentially: subfinder → puredns → dnsx → cut-cdn → nmap → tlsx → httpx → katana → vhost → sni → nuclei → ffuf → gowitness.
   - **Resume logic:** When `resume_mode=True`, stages already marked `completed` in MongoDB are skipped, and their prior output files are re-read to rebuild state (`current_targets`, `live_urls`, `safe_ips`).
   - **Proxy support:** Per-tool proxy injection via `-proxy`, `-x`, or `--proxies` flags depending on the tool.
   - **Process management:** `run_command` uses `subprocess.Popen`, stores the handle in `self.current_process`, and supports termination via `stop()`.

3. **Background Threads** (started in `if __name__ == '__main__'`)
   - `scheduler_loop` — Every 10 seconds, polls MongoDB for scans with `status: scheduled` and `scheduled_time <= now`, then dispatches them. Supports recurring frequencies (`daily`, `weekly`, `monthly`) by cloning the scan document with a future `scheduled_time`.
   - `continuous_subfinder_monitor` — Every 4 hours, runs `subfinder` against all saved targets, compares results against `known_subdomains` collection, and sends Telegram alerts for newly discovered subdomains.

4. **MongoDB Collections**
   - `scans` — Scan metadata, config, stage statuses, and result counts.
   - `saved_targets` — User-saved target strings for quick re-use and periodic monitoring.
   - `known_subdomains` — Tracks subdomains discovered by the periodic monitor to avoid duplicate alerts.

5. **Frontend** (embedded in `HTML_TEMPLATE` string literal)
   - Two-tab UI: **Scanner** and **Dashboard**.
   - Uses Socket.IO for real-time stage updates (`stage_update` events).
   - Polls `/scan_status/<id>` every 3 seconds as a fallback.
   - Dashboard renders paginated historical scan summaries with per-tool result counts.

### Data Flow

```
User submits scan form
    → POST /start_scan
    → Insert scan doc into MongoDB
    → Instantiate ScanRunner
    → Thread(target=runner.run).start()
    → Runner executes tools sequentially, updating MongoDB + Socket.IO room
    → Frontend receives stage_update events and updates progress UI
    → On completion, Telegram alert sent, results available for download
```

## Important Implementation Details

- **Tool binary resolution:** `get_tool_path()` uses `shutil.which()` plus a hardcoded list of common paths (`~/go/bin`, `/usr/local/bin`, etc.) and is LRU-cached.
- **Target list semantics:** `target_list` always contains the original user-provided domains. `current_targets` accumulates discovered subdomains and is fed to downstream tools. **PureDNS specifically iterates `target_list`, not `current_targets`**, because it brute-forces subdomains against the base domain.
- **Nmap XML parsing:** Nmap outputs XML; `generate_clean_output` parses it with `xml.etree.ElementTree`. The IP:port pairs extracted from Nmap XML are appended to `nmap_targets` and fed into `httpx`.
- **File security:** `secure_filename` is used on `scan_id` before filesystem access. `Path.resolve()` + `is_relative_to()` prevents path traversal in `/api/view_file`.
- **Telegram proxy:** Alerts are sent via a hardcoded SOCKS5 proxy at `socks5://127.0.0.1:9050` (Tor). If Tor is not running, Telegram alerts will fail silently.
- **Default wordlists:** If no wordlist is selected or found, the app creates a minimal fallback `wordlist.txt` (`www`, `mail`, `dev`, `admin`) in the working directory.
- **No test suite:** There are no unit tests, integration tests, or linting configurations in this repository.
