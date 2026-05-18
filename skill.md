# Skill Reference for Recon Pipeline

This document outlines the key skills, patterns, and domain knowledge needed to work effectively in this codebase.

## Domain: Security Reconnaissance Pipeline

This is an attack surface management tool. Understanding the reconnaissance workflow is essential:

1. **Subdomain Discovery** (passive via Subfinder + brute force via PureDNS)
2. **DNS Resolution** (multi-record: A, CNAME, NS, MX, TXT via DNSx)
3. **CDN Filtering** (identify real IPs via `cdncheck -e`)
4. **Port Scanning** (service discovery via Nmap)
5. **TLS Scanning** (certificate details via TLSx)
6. **Web Probing** (find live HTTP services via HTTPx)
7. **Crawling** (discover endpoints via Katana)
8. **VHost/SNI Discovery** (virtual host enumeration via FFUF)
9. **Vulnerability Scanning** (Nuclei templates)
10. **Directory Fuzzing** (FFUF)
11. **Screenshotting** (visual reconnaissance via Gowitness)

## Key Technical Skills

### 1. Flask + SocketIO Real-time Updates

The app uses Flask-SocketIO for real-time pipeline progress. When modifying scan stages:

- Emit updates via `self.emit_stage_update(stage, status, output, progress)`
- Frontend listens on `stage_update` events in a room keyed by `scan_id`
- Always update MongoDB stage status atomically alongside the SocketIO emit

### 2. MongoDB Document Design

Scans are stored as documents with nested `stages` and `results` dicts:

```python
# Stage status update pattern
db.scans.update_one(
    {'scan_id': scan_id},
    {'$set': {f'stages.{stage}': {'status': status, 'output': output}}}
)
```

Indexes to maintain: `scan_id` (unique), `status+scheduled_time`, `targets+created_at`.

### 3. Subprocess Orchestration

All external tools run via `subprocess.Popen`. Key patterns:

- Always sanitize: `cmd = [str(c) for c in cmd]`
- Use `get_tool_path()` for binary resolution (checks `$PATH`, `~/go/bin`, etc.)
- Handle timeouts gracefully; kill unresponsive processes
- Some tools exit non-zero on legitimate findings (Nuclei) — don't treat all non-zero exits as failures

### 4. `get_args()` Fallback Pattern

Per-tool args come from the UI form fields (`args_<toolname>`). The fallback logic must handle empty strings:

```python
def get_args(tool_key, default=""):
    val = self.tool_args.get(tool_key, default)
    return shlex.split(val) if val else shlex.split(default)
```

**Do NOT** simplify to `shlex.split(self.tool_args.get(tool_key, default))` — when the form sends `""`, `dict.get()` returns the empty string (key exists), bypassing the default entirely.

### 5. Stage Error Handling Pattern

After running a tool, always use `or` not `and` to catch both command failures and silent failures:

```python
_, err = self.run_command(cmd)
if not self.stopped:
    if err or not outfile.exists():
        self.update_stage(tool, 'error', f"{tool} failed: {_}", progress=0)
    else:
        # parse results
```

**Do NOT** use `if err and not outfile.exists()` — this silently proceeds to parse an empty/missing file and reports 0 results.

### 6. Resume Mode Logic

When adding a new pipeline stage, you must implement both paths:

**Forward path:** Execute the tool, parse output, update target lists.

**Resume path:** Check `self.status['stages'][tool]['status'] == 'completed'`, then re-read output files to repopulate in-memory target lists (`current_targets`, `live_urls`, `safe_ips`, `nmap_targets`).

See existing stages in `core/scanner.py` for the pattern.

### 7. File Output Conventions

Each tool writes to a specific file in `scans/<scan_id>/`. `generate_clean_output()` and resume logic depend on these filenames. When adding a tool, follow the naming convention and create both raw and clean outputs.

### 8. Target List Management

Understand which list each stage consumes:

- `target_list` — original domains only (never grows)
- `current_targets` — original + discovered subdomains (feeds DNSx, TLSx, HTTPx)
- `live_urls` — HTTPx results (feeds Katana, FFUF, Gowitness, Nuclei)
- `nmap_targets` — `IP:port` from Nmap XML (feeds HTTPx)
- `safe_ips` — IPs extracted from DNSx `a` and `ans` fields, then filtered by CDNCheck (feeds Nmap, VHost, SNI)

### 9. Proxy Configuration

Proxy injection is tool-specific. If adding a new tool that supports proxies:

```python
if tool_name in ['subfinder', 'httpx', 'tlsx', 'katana', 'nuclei']:
    cmd.extend(['-proxy', proxy_url])
elif tool_name == 'ffuf':
    cmd.extend(['-x', proxy_url])
elif tool_name == 'nmap':
    cmd.extend(['--proxies', proxy_url])
```

Docker setup: container reaches host proxy via `host.docker.internal:10808` (SOCKS5), configured through `docker-compose.yml` env vars and `extra_hosts`.

### 10. CDNCheck (formerly cut-cdn)

The CDN filtering tool is `cdncheck`, not `cut-cdn`. Usage:

```bash
# Pipe IPs, exclude CDN/WAF/Cloud, output only clean IPs
echo "1.1.1.1\n93.184.216.34" | cdncheck -silent -nc -e
# Output: 93.184.216.34  (1.1.1.1 filtered as CDN)
```

Key flags: `-silent` (no banner), `-nc` (no color), `-e` (exclude detected IPs from output).

### 11. AI Analysis (LLM Integration)

The `POST /api/ai_analysis/<scan_id>` endpoint sends scan results to an OpenAI-compatible LLM for structured security analysis.

**How it works:**
1. Gathers all clean `.txt` output files from `scans/<scan_id>/`, capped at 100KB total
2. Includes scan metadata (targets, results counts) in the prompt
3. Sends to LLM with `response_format={"type": "json_object"}` requesting structured output matching `ANALYSIS_SCHEMA`
4. Parses JSON response, persists to MongoDB as `ai_analysis` field, generates markdown for UI

**Output schema** (`ANALYSIS_SCHEMA` in `config.py`):
```json
{
  "executive_summary": "2-3 sentence overview",
  "risk_level": "critical|high|medium|low",
  "risk_justification": "Why this risk level",
  "attack_surface": {
    "subdomains": 0, "live_urls": 0, "open_ports": 0,
    "vulnerabilities": 0, "unique_ips": 0
  },
  "findings": [
    {
      "severity": "critical|high|medium|low|info",
      "category": "Short title",
      "description": "What was found",
      "evidence": "Specific hosts/ports/URLs",
      "source_tool": "Which pipeline stage"
    }
  ],
  "recommendations": [
    {
      "priority": "immediate|short_term|long_term",
      "action": "What to do",
      "rationale": "Why it matters"
    }
  ]
}
```

**Claude Code skill**: `.claude/skills/analyze-scan.md` — invoke with `/analyze-scan <scan_id>` for interactive analysis using the same framework.

**Configuration** (env vars in `config.py`):
- `LLM_API_KEY` — API key (can be `"dummy"` for local Ollama)
- `LLM_BASE_URL` — OpenAI-compatible endpoint (default: `http://host.docker.internal:11434/v1`)
- `LLM_MODEL` — model name (default: `qwen3:8b`)

**Proxy bypass pattern**: The LLM call temporarily removes `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` env vars before creating the `httpx.Client`, because the SOCKS proxy (used for tools/Telegram) interferes with direct HTTPS calls to the LLM endpoint. Restored in a `finally` block.

```python
_proxy_keys = ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy']
_saved_proxies = {k: os.environ.pop(k) for k in _proxy_keys if k in os.environ}
try:
    http_client = httpx.Client(timeout=60.0)
    client = OpenAI(base_url=LLM_BASE_URL, api_key=LLM_API_KEY or "dummy", http_client=http_client)
    # ... call API with response_format={"type": "json_object"} ...
finally:
    os.environ.update(_saved_proxies)
```

**Markdown generation**: `generate_analysis_markdown()` in `routes/all_routes.py` converts the structured JSON to formatted markdown. The frontend `formatAnalysis()` renders it with risk badge and attack surface stats.

### 12. Security Patterns

- **Path traversal**: Always use `secure_filename()` + `Path.resolve().is_relative_to()` for file serving
- **Regex injection**: Escape dots/wildcards before MongoDB `$regex` queries
- **Command injection**: Never pass user input directly to shell commands; use lists with `subprocess.Popen`
- **Target validation**: Cap at 255 chars, trim whitespace, filter empty lines

## Testing Patterns

The test suite uses `mongomock` and extensive mocking:

- Patch `pymongo.MongoClient` with `mongomock.MongoClient` before importing modules
- Use `tmp_path` for filesystem operations
- Mock `subprocess.Popen`, `requests.post`, `threading.Thread` for unit tests
- The `reset_app_state` fixture clears `scan_queue` and drops collections between tests

## Common Tasks

### Adding a New Pipeline Stage

1. Add tool name to `REQUIRED_TOOLS` in `config.py` (optional)
2. Add tool name to the `tool_args` collection dict in `routes/all_routes.py` (key: `args_<toolname>`)
3. Add stage execution in `ScanRunner.run()` after the appropriate predecessor
4. Implement resume logic: check `stages.<tool>.status` and re-read output files
5. Add file output mapping in `generate_clean_output()` — the AI analysis endpoint auto-discovers `*.txt` files, so creating a clean output is enough
6. Add proxy support in `add_proxy()` if applicable
7. Add tool args input field in `templates.py` ("Advanced Tool Arguments" section)
8. Add stage display in `templates.py` (`.stage` div with `data-stage="<toolname>"`)
9. Add tests in `tests/test_app.py`

### Modifying Target Flow

If you change which list a stage reads from or writes to:

1. Update the Data Flow section in CLAUDE.md and this doc
2. Check all downstream stages that consume that list
3. Update resume logic for affected stages
4. Verify `generate_clean_output()` handles the new output format

### Adding New Routes

1. Define route in `routes/all_routes.py`
2. Apply `@login_required` decorator
3. Use `secure_filename()` for any user-provided filenames
4. Use `Path.resolve().is_relative_to()` for file system access
5. Add corresponding tests in `tests/test_app.py`

### Adding a New Tool Args Field

1. Add the tool key to the dict in `routes/all_routes.py` line: `tool_args = {f'args_{k}': ... for k in [...]}`
2. Add an `<input>` in `templates.py` under the "Advanced Tool Arguments" section
3. Add the default value in `get_args()` call within `core/scanner.py`'s `ScanRunner.run()`
